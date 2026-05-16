// TLSRelay — modern TLS HTTPS client for iOS 6, bundled mbedTLS 2.28 LTS.

#import <Foundation/Foundation.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/time.h>

#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"

static void TLSRelayLog(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *line = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *full = [NSString stringWithFormat:@"[TLSRelay] %@\n", line];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:@"/tmp/podcastfix.log"];
    if (!fh) {
        [full writeToFile:@"/tmp/podcastfix.log" atomically:NO encoding:NSUTF8StringEncoding error:nil];
        return;
    }
    [fh seekToEndOfFile];
    [fh writeData:[full dataUsingEncoding:NSUTF8StringEncoding]];
    [fh closeFile];
}

// Read raw bytes from already-set-up TLS or plain socket. Returns NSData* on
// success, nil on outright failure. Closes the connection (peer or fatal err).
static NSData *TLSRelayReadAll(mbedtls_ssl_context *ssl, int fd, BOOL isTLS, NSUInteger maxBytes) {
    NSMutableData *raw = [NSMutableData data];
    unsigned char chunk[4096];
    while (1) {
        int ret;
        if (isTLS) {
            ret = mbedtls_ssl_read(ssl, chunk, sizeof(chunk));
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
            if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || ret == 0) break;
            if (ret < 0) { TLSRelayLog(@"read fail -%x len=%lu", -ret, (unsigned long)raw.length); break; }
            NSUInteger room = maxBytes > 0 && raw.length < maxBytes ? maxBytes - raw.length : (NSUInteger)ret;
            NSUInteger take = maxBytes > 0 ? MIN((NSUInteger)ret, room) : (NSUInteger)ret;
            if (take > 0) [raw appendBytes:chunk length:take];
            if (maxBytes > 0 && raw.length >= maxBytes) {
                TLSRelayLog(@"read cap hit max=%lu", (unsigned long)maxBytes);
                break;
            }
        } else {
            ssize_t r = read(fd, chunk, sizeof(chunk));
            if (r <= 0) break;
            NSUInteger room = maxBytes > 0 && raw.length < maxBytes ? maxBytes - raw.length : (NSUInteger)r;
            NSUInteger take = maxBytes > 0 ? MIN((NSUInteger)r, room) : (NSUInteger)r;
            if (take > 0) [raw appendBytes:chunk length:take];
            if (maxBytes > 0 && raw.length >= maxBytes) {
                TLSRelayLog(@"read cap hit max=%lu", (unsigned long)maxBytes);
                break;
            }
        }
    }
    return raw;
}

static NSData *TLSRelayDecodeChunked(NSData *body, NSMutableDictionary *headers) {
    NSMutableData *decoded = [NSMutableData data];
    const uint8_t *bytes = body.bytes;
    NSUInteger pos = 0;
    NSUInteger len = body.length;
    while (pos < len) {
        NSUInteger lineEnd = pos;
        while (lineEnd + 1 < len && !(bytes[lineEnd] == '\r' && bytes[lineEnd+1] == '\n')) lineEnd++;
        if (lineEnd + 1 >= len) break;
        NSString *sizeStr = [[NSString alloc] initWithBytes:bytes + pos length:lineEnd - pos encoding:NSUTF8StringEncoding];
        NSScanner *scanner = [NSScanner scannerWithString:sizeStr];
        unsigned chunkSize = 0;
        if (![scanner scanHexInt:&chunkSize]) break;
        pos = lineEnd + 2;
        if (chunkSize == 0) break;
        if (pos + chunkSize > len) break;
        [decoded appendBytes:bytes + pos length:chunkSize];
        pos += chunkSize + 2;
    }
    [headers removeObjectForKey:@"Transfer-Encoding"];
    [headers removeObjectForKey:@"transfer-encoding"];
    headers[@"Content-Length"] = [NSString stringWithFormat:@"%lu", (unsigned long)decoded.length];
    return decoded;
}

static NSData *TLSRelayFetchOne(NSURL *url, NSString *method, NSDictionary *reqHeaders, NSData *reqBody, NSString *rangeHeader, NSString *userAgentOverride,
                                NSHTTPURLResponse **outResponse, NSError **outError);

static BOOL TLSRelaySendAllFD(int fd, const void *bytes, NSUInteger length) {
    const char *cursor = (const char *)bytes;
    NSUInteger remaining = length;
    while (remaining > 0) {
        ssize_t sent = send(fd, cursor, remaining, 0);
        if (sent <= 0) return NO;
        cursor += sent;
        remaining -= (NSUInteger)sent;
    }
    return YES;
}

static int TLSRelayReadSome(mbedtls_ssl_context *ssl, int fd, BOOL isTLS, unsigned char *buf, size_t len) {
    if (isTLS) {
        while (1) {
            int ret = mbedtls_ssl_read(ssl, buf, len);
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
            return ret;
        }
    }
    return (int)read(fd, buf, len);
}

static BOOL TLSRelayWriteAllUpstream(mbedtls_ssl_context *ssl, int fd, BOOL isTLS, const unsigned char *buf, size_t len) {
    size_t written = 0;
    while (written < len) {
        int ret;
        if (isTLS) {
            ret = mbedtls_ssl_write(ssl, buf + written, len - written);
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
        } else {
            ret = (int)write(fd, buf + written, len - written);
        }
        if (ret <= 0) return NO;
        written += (size_t)ret;
    }
    return YES;
}

static NSString *TLSRelayHTTPReason(NSInteger statusCode) {
    switch (statusCode) {
        case 200: return @"OK";
        case 206: return @"Partial Content";
        case 301: return @"Moved Permanently";
        case 302: return @"Found";
        case 303: return @"See Other";
        case 307: return @"Temporary Redirect";
        case 308: return @"Permanent Redirect";
        case 400: return @"Bad Request";
        case 403: return @"Forbidden";
        case 404: return @"Not Found";
        case 416: return @"Range Not Satisfiable";
        case 500: return @"Internal Server Error";
        case 502: return @"Bad Gateway";
        default: return @"OK";
    }
}

static __attribute__((unused)) BOOL TLSRelayParseRange(NSString *rangeHeader, long long *outStart, long long *outEnd) {
    if (!rangeHeader.length) return NO;
    NSScanner *scanner = [NSScanner scannerWithString:rangeHeader];
    long long start = 0, end = 0;
    if (![scanner scanString:@"bytes=" intoString:NULL]) return NO;
    if (![scanner scanLongLong:&start]) return NO;
    if (![scanner scanString:@"-" intoString:NULL]) return NO;
    if (![scanner scanLongLong:&end]) return NO;
    if (end < start) return NO;
    if (outStart) *outStart = start;
    if (outEnd) *outEnd = end;
    return YES;
}

static __attribute__((unused)) long long TLSRelayContentRangeTotal(NSString *contentRange) {
    if (!contentRange.length) return -1;
    NSRange slash = [contentRange rangeOfString:@"/" options:NSBackwardsSearch];
    if (slash.location == NSNotFound || slash.location + 1 >= contentRange.length) return -1;
    NSString *tail = [contentRange substringFromIndex:slash.location + 1];
    if ([tail isEqualToString:@"*"]) return -1;
    return [tail longLongValue];
}

static NSString *TLSRelayRequestTargetForURL(NSURL *url) {
    NSString *absolute = url.absoluteString ?: @"";
    NSRange scheme = [absolute rangeOfString:@"://"];
    if (scheme.location == NSNotFound) {
        NSString *path = url.path.length ? url.path : @"/";
        NSString *query = url.query;
        return query.length ? [NSString stringWithFormat:@"%@?%@", path, query] : path;
    }

    NSUInteger hostStart = scheme.location + scheme.length;
    NSRange slash = [absolute rangeOfString:@"/"
                                     options:0
                                       range:NSMakeRange(hostStart, absolute.length - hostStart)];
    if (slash.location == NSNotFound) return @"/";

    NSString *target = [absolute substringFromIndex:slash.location];
    return target.length ? target : @"/";
}

// Unwrap analytics-tracker redirect chains like:
//   dts.podtrac.com/redirect.mp3/prfx.byspotify.com/e/claritaspod.com/measure/
//     arttrk.com/p/PDPN1/pscrb.fm/rss/p/rss.art19.com/episodes/<uuid>.mp3
// down to the canonical media URL (https://rss.art19.com/episodes/<uuid>.mp3).
// We can't afford to walk the chain via real redirects on iPhone 4S — by the
// time we reach the final signed-URL host, the pscrb validation timestamp has
// expired and the CDN returns 400.
static NSURL *TLSRelayUnwrapTrackerURL(NSURL *url) {
    NSString *host = url.host.lowercaseString;
    if (![host isEqualToString:@"dts.podtrac.com"] &&
        ![host hasSuffix:@".podtrac.com"] &&
        ![host isEqualToString:@"chrt.fm"] &&
        ![host isEqualToString:@"chartable.com"]) {
        return url;
    }
    NSString *path = url.path;
    if (![path hasPrefix:@"/redirect."] && ![path hasPrefix:@"/track/"]) return url;

    // Strip leading "/redirect.mp3/" or "/track/<id>/"
    NSRange firstSlash = [path rangeOfString:@"/" options:0 range:NSMakeRange(1, path.length - 1)];
    if (firstSlash.location == NSNotFound) return url;
    NSString *remainder = [path substringFromIndex:firstSlash.location + 1];

    NSArray *segments = [remainder componentsSeparatedByString:@"/"];
    // Walk backwards: find the last segment that looks like a hostname (has a dot
    // and a known TLD). Everything from there becomes the direct media URL.
    NSInteger hostIndex = -1;
    for (NSInteger i = segments.count - 2; i >= 0; i--) {
        NSString *seg = segments[i];
        NSRange dot = [seg rangeOfString:@"." options:NSBackwardsSearch];
        if (dot.location == NSNotFound) continue;
        NSString *tld = [seg substringFromIndex:dot.location + 1].lowercaseString;
        if ([@[@"com", @"fm", @"org", @"net", @"io", @"co", @"app", @"audio"] containsObject:tld]) {
            hostIndex = i;
            break;
        }
    }
    if (hostIndex < 0) return url;

    NSString *newHost = segments[hostIndex];
    NSArray *pathSegs = [segments subarrayWithRange:NSMakeRange(hostIndex + 1, segments.count - hostIndex - 1)];
    NSString *newPath = [@"/" stringByAppendingString:[pathSegs componentsJoinedByString:@"/"]];
    NSString *query = url.query.length ? [@"?" stringByAppendingString:url.query] : @"";
    NSString *direct = [NSString stringWithFormat:@"https://%@%@%@", newHost, newPath, query];
    NSURL *directURL = [NSURL URLWithString:direct];
    if (!directURL) return url;
    TLSRelayLog(@"unwrap %@ -> %@", url.absoluteString, direct);
    return directURL;
}

NSData *TLSRelayFetch(NSURL *url,
                      NSString *method,
                      NSDictionary *reqHeaders,
                      NSData *reqBody,
                      NSString *rangeHeader,
                      NSString *userAgentOverride,
                      NSHTTPURLResponse **outResponse,
                      NSError **outError) {
    NSURL *current = TLSRelayUnwrapTrackerURL(url);
    for (int hop = 0; hop < 12; hop++) {
        NSHTTPURLResponse *resp = nil;
        NSError *err = nil;
        NSData *body = TLSRelayFetchOne(current, method, reqHeaders, reqBody, rangeHeader, userAgentOverride, &resp, &err);
        if (!body) {
            if (outResponse) *outResponse = resp;
            if (outError) *outError = err;
            return nil;
        }
        NSInteger status = resp.statusCode;
        if (status == 301 || status == 302 || status == 303 || status == 307 || status == 308) {
            NSString *loc = resp.allHeaderFields[@"Location"] ?: resp.allHeaderFields[@"location"];
            if (!loc.length) { if (outResponse) *outResponse = resp; return body; }
            NSURL *next = [NSURL URLWithString:loc relativeToURL:current];
            if (!next) { if (outResponse) *outResponse = resp; return body; }
            TLSRelayLog(@"redirect %ld: %@ -> %@", (long)status, current.host, next.absoluteString);
            current = next;
            // Keep media Range across tracker/CDN redirects. Dropping it here
            // makes the relay read full podcast files into RAM and jetsam Podcasts.
            continue;
        }
        if (outResponse) *outResponse = resp;
        return body;
    }
    TLSRelayLog(@"too many redirects from %@", url.absoluteString);
    if (outError) *outError = [NSError errorWithDomain:@"TLSRelay" code:-2
                                              userInfo:@{NSLocalizedDescriptionKey: @"too many redirects"}];
    return nil;
}

BOOL TLSRelayStreamToClient(NSURL *url,
                            NSString *rangeHeader,
                            NSString *userAgentOverride,
                            int clientFD,
                            BOOL headOnly,
                            NSError **outError) {
    NSURL *current = TLSRelayUnwrapTrackerURL(url);
    NSString *ua = userAgentOverride ?: @"AppleCoreMedia/1.0.0.10B500 (iPhone; U; CPU OS 6_1_3 like Mac OS X; en_us)";

    for (int hop = 0; hop < 12; hop++) {
        NSString *host = current.host ?: @"";
        NSInteger port = current.port.integerValue;
        BOOL isTLS = ![current.scheme.lowercaseString isEqualToString:@"http"];
        if (port == 0) port = isTLS ? 443 : 80;
        NSString *portStr = [NSString stringWithFormat:@"%ld", (long)port];
        NSString *fullPath = TLSRelayRequestTargetForURL(current);
        NSMutableString *request = [NSMutableString stringWithFormat:
            @"GET %@ HTTP/1.1\r\nHost: %@\r\nUser-Agent: %@\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n",
            fullPath, host, ua];
        if (rangeHeader.length) [request appendFormat:@"Range: %@\r\n", rangeHeader];
        [request appendString:@"\r\n"];

        mbedtls_net_context srv;
        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_ssl_context ssl;
        mbedtls_ssl_config conf;
        mbedtls_net_init(&srv);
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        mbedtls_ssl_init(&ssl);
        mbedtls_ssl_config_init(&conf);

        BOOL completed = NO;
        BOOL redirected = NO;
        NSURL *redirectURL = nil;

        do {
            const char *pers = "PodcastsXStreamRelay";
            int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                            (const unsigned char *)pers, strlen(pers));
            if (ret != 0) { TLSRelayLog(@"stream ctr_drbg_seed -%x", -ret); break; }

            struct addrinfo hints, *res = NULL;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            if (getaddrinfo(host.UTF8String, portStr.UTF8String, &hints, &res) != 0 || !res) {
                TLSRelayLog(@"stream getaddrinfo(v4) failed %@", host);
                break;
            }
            int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
            if (fd < 0) { TLSRelayLog(@"stream socket() failed %@", host); freeaddrinfo(res); break; }

            int set = 1;
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (void *)&set, sizeof(int));

            int flags = fcntl(fd, F_GETFL, 0);
            fcntl(fd, F_SETFL, flags | O_NONBLOCK);
            int cr = connect(fd, res->ai_addr, res->ai_addrlen);
            BOOL connected = (cr == 0);
            if (cr < 0 && errno == EINPROGRESS) {
                fd_set wset; FD_ZERO(&wset); FD_SET(fd, &wset);
                struct timeval tv = { 8, 0 };
                if (select(fd + 1, NULL, &wset, NULL, &tv) > 0) {
                    int soerr = 0; socklen_t l = sizeof(soerr);
                    getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &l);
                    connected = (soerr == 0);
                }
            }
            freeaddrinfo(res);
            if (!connected) {
                TLSRelayLog(@"stream connect timeout/fail %@:%@", host, portStr);
                close(fd);
                break;
            }
            fcntl(fd, F_SETFL, flags);

            struct timeval io = { 30, 0 };
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &io, sizeof(io));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &io, sizeof(io));
            srv.fd = fd;

            if (isTLS) {
                ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                                  MBEDTLS_SSL_TRANSPORT_STREAM,
                                                  MBEDTLS_SSL_PRESET_DEFAULT);
                if (ret != 0) { TLSRelayLog(@"stream config_defaults -%x", -ret); break; }
                mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
                mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
                mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
                if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) { TLSRelayLog(@"stream ssl_setup -%x", -ret); break; }
                if ((ret = mbedtls_ssl_set_hostname(&ssl, host.UTF8String)) != 0) { TLSRelayLog(@"stream set_hostname -%x", -ret); break; }
                mbedtls_ssl_set_bio(&ssl, &srv, mbedtls_net_send, mbedtls_net_recv, NULL);
                BOOL handshakeFailed = NO;
                while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
                    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                        char errbuf[128];
                        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
                        TLSRelayLog(@"stream handshake fail -%x %s host=%@", -ret, errbuf, host);
                        handshakeFailed = YES;
                        break;
                    }
                }
                if (handshakeFailed) break;
                TLSRelayLog(@"stream handshake OK %@:%ld cipher=%s", host, (long)port, mbedtls_ssl_get_ciphersuite(&ssl));
            }

            NSData *requestData = [request dataUsingEncoding:NSUTF8StringEncoding];
            if (!TLSRelayWriteAllUpstream(&ssl, srv.fd, isTLS, requestData.bytes, requestData.length)) {
                TLSRelayLog(@"stream write request failed %@", host);
                break;
            }

            NSMutableData *raw = [NSMutableData data];
            NSData *terminator = [@"\r\n\r\n" dataUsingEncoding:NSUTF8StringEncoding];
            NSRange headerEnd = NSMakeRange(NSNotFound, 0);
            unsigned char chunk[8192];
            while (raw.length < 262144) {
                int r = TLSRelayReadSome(&ssl, srv.fd, isTLS, chunk, sizeof(chunk));
                if (r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || r == 0) break;
                if (r < 0) { TLSRelayLog(@"stream header read fail -%x len=%lu", -r, (unsigned long)raw.length); break; }
                [raw appendBytes:chunk length:(NSUInteger)r];
                headerEnd = [raw rangeOfData:terminator options:0 range:NSMakeRange(0, raw.length)];
                if (headerEnd.location != NSNotFound) break;
            }
            if (headerEnd.location == NSNotFound) {
                TLSRelayLog(@"stream no header terminator len=%lu", (unsigned long)raw.length);
                break;
            }

            NSData *headerData = [raw subdataWithRange:NSMakeRange(0, headerEnd.location)];
            NSString *headerStr = [[NSString alloc] initWithData:headerData encoding:NSUTF8StringEncoding];
            NSArray *lines = [headerStr componentsSeparatedByString:@"\r\n"];
            NSString *statusLine = lines.count ? lines[0] : @"";
            NSArray *statusParts = [statusLine componentsSeparatedByString:@" "];
            NSInteger statusCode = statusParts.count >= 2 ? [statusParts[1] integerValue] : 0;
            NSMutableDictionary *headers = [NSMutableDictionary dictionary];
            for (NSUInteger i = 1; i < lines.count; i++) {
                NSString *line = lines[i];
                NSRange colon = [line rangeOfString:@":"];
                if (colon.location == NSNotFound) continue;
                NSString *k = [line substringToIndex:colon.location];
                NSString *v = [[line substringFromIndex:colon.location + 1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
                headers[k] = v;
            }

            NSData *initialBody = [raw subdataWithRange:NSMakeRange(headerEnd.location + 4, raw.length - headerEnd.location - 4)];
            TLSRelayLog(@"stream %@ -> %ld ct=%@ len=%@ cr=%@ initial=%lu",
                        current.host, (long)statusCode,
                        headers[@"Content-Type"] ?: headers[@"content-type"],
                        headers[@"Content-Length"] ?: headers[@"content-length"] ?: @"-",
                        headers[@"Content-Range"] ?: headers[@"content-range"] ?: @"-",
                        (unsigned long)initialBody.length);

            if (statusCode == 301 || statusCode == 302 || statusCode == 303 || statusCode == 307 || statusCode == 308) {
                NSString *loc = headers[@"Location"] ?: headers[@"location"];
                if (!loc.length) break;
                redirectURL = [NSURL URLWithString:loc relativeToURL:current];
                if (!redirectURL) break;
                TLSRelayLog(@"stream redirect %ld: %@ -> %@", (long)statusCode, current.host, redirectURL.absoluteString);
                redirected = YES;
                break;
            }

            // Stream the full requested range. The 8KB chunk loop below is already
            // memory-safe — we never buffer the full file. iOS 6 CoreMedia (networkbuffering
            // thread) crashes with SIGSEGV if we return fewer bytes than requested, so we
            // must serve the complete range or return 416. Never cap body here.
            unsigned long long bodyLimit = 0;
            NSString *clientContentRange = headers[@"Content-Range"] ?: headers[@"content-range"];
            NSString *clientContentLength = headers[@"Content-Length"] ?: headers[@"content-length"];

            NSMutableString *clientHeader = [NSMutableString stringWithFormat:@"HTTP/1.1 %ld %@\r\n",
                                             (long)statusCode, TLSRelayHTTPReason(statusCode)];
            NSString *ct = headers[@"Content-Type"] ?: headers[@"content-type"] ?: @"audio/mpeg";
            NSString *arange = headers[@"Accept-Ranges"] ?: headers[@"accept-ranges"] ?: @"bytes";
            [clientHeader appendFormat:@"Content-Type: %@\r\n", ct];
            if (clientContentLength.length) [clientHeader appendFormat:@"Content-Length: %@\r\n", clientContentLength];
            if (clientContentRange.length) [clientHeader appendFormat:@"Content-Range: %@\r\n", clientContentRange];
            if (arange.length) [clientHeader appendFormat:@"Accept-Ranges: %@\r\n", arange];
            
            for (NSString *k in headers) {
                NSString *lowerK = k.lowercaseString;
                if ([lowerK isEqualToString:@"content-type"] ||
                    [lowerK isEqualToString:@"content-length"] ||
                    [lowerK isEqualToString:@"content-range"] ||
                    [lowerK isEqualToString:@"accept-ranges"] ||
                    [lowerK isEqualToString:@"connection"] ||
                    [lowerK isEqualToString:@"transfer-encoding"]) continue;
                [clientHeader appendFormat:@"%@: %@\r\n", k, headers[k]];
            }
            [clientHeader appendString:@"Connection: close\r\n\r\n"];
            NSData *clientHeaderData = [clientHeader dataUsingEncoding:NSUTF8StringEncoding];
            if (!TLSRelaySendAllFD(clientFD, clientHeaderData.bytes, clientHeaderData.length)) break;

            unsigned long long sentBody = 0;
            if (!headOnly && initialBody.length) {
                NSUInteger initialToSend = initialBody.length;
                if (bodyLimit && initialToSend > bodyLimit) initialToSend = (NSUInteger)bodyLimit;
                if (!TLSRelaySendAllFD(clientFD, initialBody.bytes, initialToSend)) {
                    TLSRelayLog(@"stream client closed after initial body");
                    completed = YES;
                    break;
                }
                sentBody += initialToSend;
            }
            while (!headOnly) {
                if (bodyLimit && sentBody >= bodyLimit) break;
                int r = TLSRelayReadSome(&ssl, srv.fd, isTLS, chunk, sizeof(chunk));
                if (r == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || r == 0) break;
                if (r < 0) {
                    TLSRelayLog(@"stream body read fail -%x sent=%llu", -r, sentBody);
                    break;
                }
                NSUInteger toSend = (NSUInteger)r;
                if (bodyLimit && sentBody + toSend > bodyLimit) {
                    toSend = (NSUInteger)(bodyLimit - sentBody);
                }
                if (!TLSRelaySendAllFD(clientFD, chunk, toSend)) {
                    TLSRelayLog(@"stream client closed sent=%llu", sentBody);
                    break;
                }
                sentBody += toSend;
            }
            TLSRelayLog(@"stream complete %@ range=%@ status=%ld sent=%llu",
                        current.host, rangeHeader ?: @"-", (long)statusCode, sentBody);
            completed = YES;
        } while (0);

        if (isTLS) {
            mbedtls_ssl_close_notify(&ssl);
            mbedtls_ssl_free(&ssl);
            mbedtls_ssl_config_free(&conf);
        }
        mbedtls_net_free(&srv);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);

        if (completed) return YES;
        if (redirected && redirectURL) {
            current = redirectURL;
            continue;
        }
        break;
    }

    if (outError) {
        *outError = [NSError errorWithDomain:@"TLSRelay" code:-3
                                    userInfo:@{NSLocalizedDescriptionKey: @"TLS relay stream failed"}];
    }
    return NO;
}

static NSData *TLSRelayFetchOne(NSURL *url,
                                NSString *method,
                                NSDictionary *reqHeaders,
                                NSData *reqBody,
                                NSString *rangeHeader,
                                NSString *userAgentOverride,
                                NSHTTPURLResponse **outResponse,
                                NSError **outError) {
    NSString *host = url.host ?: @"";
    NSInteger port = url.port.integerValue;
    BOOL isTLS = ![url.scheme.lowercaseString isEqualToString:@"http"];
    if (port == 0) port = isTLS ? 443 : 80;

    NSString *fullPath = TLSRelayRequestTargetForURL(url);
    NSString *ua = userAgentOverride ?: @"AppleCoreMedia/1.0.0.10B500 (iPhone; U; CPU OS 6_1_3 like Mac OS X; en_us)";
    
    NSString *reqMethod = method.length ? method : @"GET";
    NSMutableString *request = [NSMutableString stringWithFormat:
        @"%@ %@ HTTP/1.1\r\nHost: %@\r\nUser-Agent: %@\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n",
        reqMethod, fullPath, host, ua];
    if (rangeHeader.length) [request appendFormat:@"Range: %@\r\n", rangeHeader];
    
    for (NSString *k in reqHeaders) {
        NSString *lowerK = k.lowercaseString;
        if ([lowerK isEqualToString:@"host"] || [lowerK isEqualToString:@"user-agent"] ||
            [lowerK isEqualToString:@"accept"] || [lowerK isEqualToString:@"accept-encoding"] ||
            [lowerK isEqualToString:@"connection"] || [lowerK isEqualToString:@"range"] ||
            [lowerK isEqualToString:@"content-length"]) continue;
        [request appendFormat:@"%@: %@\r\n", k, reqHeaders[k]];
    }
    if (reqBody.length > 0) {
        [request appendFormat:@"Content-Length: %lu\r\n", (unsigned long)reqBody.length];
    }
    [request appendString:@"\r\n"];
    
    NSMutableData *fullRequestData = [[request dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    if (reqBody.length > 0) {
        [fullRequestData appendData:reqBody];
    }

    NSString *portStr = [NSString stringWithFormat:@"%ld", (long)port];

    mbedtls_net_context srv;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_net_init(&srv);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);

    NSData *result = nil;

    do {
        const char *pers = "PodcastsXTLSRelay";
        int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                        (const unsigned char *)pers, strlen(pers));
        if (ret != 0) { TLSRelayLog(@"ctr_drbg_seed -%x", -ret); break; }

        // Force IPv4: art19/pscrb-style CDNs sign a validation token bound to
        // the client IP seen by the signing host, then a *different* CDN host
        // checks it. If the relay reaches the signer over IPv6 but the CDN over
        // IPv4 (or vice versa), the IPs differ and the CDN returns 400. Pinning
        // to IPv4 keeps one consistent public IP across the whole chain.
        {
            struct addrinfo hints, *res = NULL;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;
            if (getaddrinfo(host.UTF8String, portStr.UTF8String, &hints, &res) != 0 || !res) {
                TLSRelayLog(@"getaddrinfo(v4) failed %@", host);
                break;
            }
            int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
            if (fd < 0) { TLSRelayLog(@"socket() failed %@", host); freeaddrinfo(res); break; }

            // Non-blocking connect with an 8s deadline so an unreachable or
            // stalled host can't hang the proxy thread (which would freeze the
            // audio stack and get the app watchdog-killed).
            int flags = fcntl(fd, F_GETFL, 0);
            fcntl(fd, F_SETFL, flags | O_NONBLOCK);
            int cr = connect(fd, res->ai_addr, res->ai_addrlen);
            BOOL connected = (cr == 0);
            if (cr < 0 && errno == EINPROGRESS) {
                fd_set wset; FD_ZERO(&wset); FD_SET(fd, &wset);
                struct timeval tv = { 8, 0 };
                if (select(fd + 1, NULL, &wset, NULL, &tv) > 0) {
                    int soerr = 0; socklen_t l = sizeof(soerr);
                    getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &l);
                    connected = (soerr == 0);
                }
            }
            freeaddrinfo(res);
            if (!connected) {
                TLSRelayLog(@"v4 connect timeout/fail %@:%@", host, portStr);
                close(fd);
                break;
            }
            fcntl(fd, F_SETFL, flags); // back to blocking

            // Bound every subsequent read/write so a slow peer can't hang us.
            struct timeval io = { 20, 0 };
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &io, sizeof(io));
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &io, sizeof(io));
            srv.fd = fd;
        }

        if (isTLS) {
            ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                              MBEDTLS_SSL_TRANSPORT_STREAM,
                                              MBEDTLS_SSL_PRESET_DEFAULT);
            if (ret != 0) { TLSRelayLog(@"config_defaults -%x", -ret); break; }
            mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
            mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
            mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
            if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) { TLSRelayLog(@"ssl_setup -%x", -ret); break; }
            if ((ret = mbedtls_ssl_set_hostname(&ssl, host.UTF8String)) != 0) { TLSRelayLog(@"set_hostname -%x", -ret); break; }
            mbedtls_ssl_set_bio(&ssl, &srv, mbedtls_net_send, mbedtls_net_recv, NULL);

            BOOL handshakeFailed = NO;
            while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
                if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                    char errbuf[128];
                    mbedtls_strerror(ret, errbuf, sizeof(errbuf));
                    TLSRelayLog(@"handshake fail -%x %s host=%@", -ret, errbuf, host);
                    handshakeFailed = YES;
                    break;
                }
            }
            if (handshakeFailed) break;
            TLSRelayLog(@"handshake OK %@:%ld cipher=%s", host, (long)port, mbedtls_ssl_get_ciphersuite(&ssl));

            const unsigned char *buf = (const unsigned char *)fullRequestData.bytes;
            size_t toWrite = fullRequestData.length;
            size_t written = 0;
            BOOL writeFailed = NO;
            while (written < toWrite) {
                ret = mbedtls_ssl_write(&ssl, buf + written, toWrite - written);
                if (ret > 0) { written += ret; continue; }
                if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                    TLSRelayLog(@"write fail -%x", -ret); writeFailed = YES; break;
                }
            }
            if (writeFailed) break;
        } else {
            const unsigned char *buf = (const unsigned char *)fullRequestData.bytes;
            size_t toWrite = fullRequestData.length;
            write(srv.fd, buf, toWrite);
        }

        NSUInteger maxRawBytes = rangeHeader.length ? (2 * 1024 * 1024) : 0;
        NSData *raw = TLSRelayReadAll(&ssl, srv.fd, isTLS, maxRawBytes);
        NSData *terminator = [@"\r\n\r\n" dataUsingEncoding:NSUTF8StringEncoding];
        NSRange headerEnd = [raw rangeOfData:terminator options:0 range:NSMakeRange(0, raw.length)];
        if (headerEnd.location == NSNotFound) {
            TLSRelayLog(@"no header terminator len=%lu", (unsigned long)raw.length);
            break;
        }
        NSData *headerData = [raw subdataWithRange:NSMakeRange(0, headerEnd.location)];
        NSString *headerStr = [[NSString alloc] initWithData:headerData encoding:NSUTF8StringEncoding];
        NSArray *lines = [headerStr componentsSeparatedByString:@"\r\n"];
        NSString *statusLine = lines.count ? lines[0] : @"";
        NSArray *statusParts = [statusLine componentsSeparatedByString:@" "];
        NSInteger statusCode = statusParts.count >= 2 ? [statusParts[1] integerValue] : 0;

        NSMutableDictionary *headers = [NSMutableDictionary dictionary];
        for (NSUInteger i = 1; i < lines.count; i++) {
            NSString *line = lines[i];
            NSRange colon = [line rangeOfString:@":"];
            if (colon.location == NSNotFound) continue;
            NSString *k = [line substringToIndex:colon.location];
            NSString *v = [[line substringFromIndex:colon.location + 1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            headers[k] = v;
        }

        NSData *body = [raw subdataWithRange:NSMakeRange(headerEnd.location + 4, raw.length - headerEnd.location - 4)];
        NSString *te = headers[@"Transfer-Encoding"] ?: headers[@"transfer-encoding"];
        if (te && [te.lowercaseString rangeOfString:@"chunked"].location != NSNotFound) {
            body = TLSRelayDecodeChunked(body, headers);
        }

        TLSRelayLog(@"%@ -> %ld ct=%@ len=%lu cr=%@",
                    url.host, (long)statusCode,
                    headers[@"Content-Type"] ?: headers[@"content-type"],
                    (unsigned long)body.length,
                    headers[@"Content-Range"] ?: headers[@"content-range"] ?: @"-");
        if (statusCode >= 400 && body.length > 0) {
            NSUInteger previewLen = MIN((NSUInteger)160, body.length);
            NSData *previewData = [body subdataWithRange:NSMakeRange(0, previewLen)];
            NSString *preview = [[NSString alloc] initWithData:previewData encoding:NSUTF8StringEncoding];
            if (preview.length) TLSRelayLog(@"%@ error body: %@", url.host, preview);
        }

        if (outResponse) {
            *outResponse = [[NSHTTPURLResponse alloc] initWithURL:url
                                                       statusCode:statusCode
                                                      HTTPVersion:@"HTTP/1.1"
                                                     headerFields:headers];
        }
        result = body;
    } while (0);

    if (isTLS) {
        mbedtls_ssl_close_notify(&ssl);
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&conf);
    }
    mbedtls_net_free(&srv);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    if (!result && outError) {
        *outError = [NSError errorWithDomain:@"TLSRelay" code:-1
                                    userInfo:@{NSLocalizedDescriptionKey: @"TLS relay fetch failed"}];
    }
    return result;
}
