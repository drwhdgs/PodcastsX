#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <MediaPlayer/MediaPlayer.h>
#import <AVFoundation/AVFoundation.h>
#import <Security/Security.h>
#import <Security/SecureTransport.h>
#import <CFNetwork/CFNetwork.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <unistd.h>
#import <objc/runtime.h>
#import <objc/message.h>

#define PODCASTX_PROXY_PORT 37626
#define PODCASTX_MAC_PROXY_HOST @"192.168.0.4"
#define PODCASTX_LOCAL_PROXY_HOST @"127.0.0.1"

static BOOL gPodcastsXBypassRequestHooks = NO;
static BOOL gPodcastsXBypassURLCreationHooks = NO;
static CFAbsoluteTime gPodcastsXLaunchTime = 0;

static NSString *storeRewriteString(NSString *URLString);
static BOOL shouldRelaxHTTPSHost(NSString *host);
static BOOL acceptServerTrustChallenge(NSURLAuthenticationChallenge *challenge, NSString *context);
static void allowAnyHTTPSCertificateForHost(NSString *host);

static void appendLog(NSString *line) {
    NSString *full = [line stringByAppendingString:@"\n"];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:@"/tmp/podcastfix.log"];
    if (!fh) {
        [full writeToFile:@"/tmp/podcastfix.log"
               atomically:NO
                 encoding:NSUTF8StringEncoding
                    error:nil];
        return;
    }
    [fh seekToEndOfFile];
    [fh writeData:[full dataUsingEncoding:NSUTF8StringEncoding]];
    [fh closeFile];
}

static NSString *debugURLishDescription(id object) {
    if (!object) return @"(nil)";

    NSMutableArray *parts = [NSMutableArray array];
    Class cls = object_getClass(object);
    unsigned int ivarCount = 0;
    Ivar *ivars = class_copyIvarList(cls, &ivarCount);
    for (unsigned int i = 0; i < ivarCount; i++) {
        const char *name = ivar_getName(ivars[i]);
        if (!name) continue;
        NSString *ivarName = [NSString stringWithUTF8String:name];
        NSString *lower = ivarName.lowercaseString;
        if ([lower rangeOfString:@"url"].location == NSNotFound &&
            [lower rangeOfString:@"request"].location == NSNotFound &&
            [lower rangeOfString:@"error"].location == NSNotFound) {
            continue;
        }

        @try {
            id value = object_getIvar(object, ivars[i]);
            if (value) {
                [parts addObject:[NSString stringWithFormat:@"%@=%@", ivarName, value]];
            }
        } @catch (NSException *exception) {
        }
    }
    if (ivars) free(ivars);

    for (NSString *selectorName in @[@"URL", @"url", @"request", @"URLRequest", @"error", @"response"]) {
        SEL sel = NSSelectorFromString(selectorName);
        if (![object respondsToSelector:sel]) continue;
        @try {
            id (*send)(id, SEL) = (id (*)(id, SEL))objc_msgSend;
            id value = send(object, sel);
            if (value) {
                [parts addObject:[NSString stringWithFormat:@"%@=%@", selectorName, value]];
            }
        } @catch (NSException *exception) {
        }
    }

    return parts.count ? [parts componentsJoinedByString:@" "] : [object description];
}

static NSMutableDictionary *gOriginalIMPs = nil;

static void podcastx_traceMethod(id self, SEL _cmd) {
    appendLog([NSString stringWithFormat:@"[StoreTrace %@ %@] %@",
               NSStringFromClass([self class]),
               NSStringFromSelector(_cmd),
               debugURLishDescription(self)]);

    NSValue *impValue = nil;
    Class cls = object_getClass(self);
    while (cls && !impValue) {
        NSString *key = [NSString stringWithFormat:@"%@.%@",
                         NSStringFromClass(cls),
                         NSStringFromSelector(_cmd)];
        impValue = gOriginalIMPs[key];
        cls = class_getSuperclass(cls);
    }

    if (impValue) {
        IMP orig = (IMP)[impValue pointerValue];
        ((void (*)(id, SEL))orig)(self, _cmd);
    } else {
        appendLog([NSString stringWithFormat:@"[StoreTrace missing orig %@ %@]",
                   NSStringFromClass([self class]),
                   NSStringFromSelector(_cmd)]);
    }
}

static void hookVoidNoArgMethod(Class cls, SEL sel) {
    Method method = class_getInstanceMethod(cls, sel);
    if (!method) return;
    // Capture the actual IMP (works whether the method is on cls or inherited)
    IMP original = method_getImplementation(method);
    const char *types = method_getTypeEncoding(method);
    IMP replacement = (IMP)podcastx_traceMethod;
    class_replaceMethod(cls, sel, replacement, types ?: "v@:");
    NSString *key = [NSString stringWithFormat:@"%@.%@",
                     NSStringFromClass(cls), NSStringFromSelector(sel)];
    gOriginalIMPs[key] = [NSValue valueWithPointer:original];
}

static void dumpClassMethods(NSString *className) {
    Class cls = NSClassFromString(className);
    if (!cls) { appendLog([NSString stringWithFormat:@"[Dump] %@ not found", className]); return; }
    unsigned int count = 0;
    Method *methods = class_copyMethodList(cls, &count);
    NSMutableArray *names = [NSMutableArray array];
    for (unsigned int i = 0; i < count; i++) {
        [names addObject:NSStringFromSelector(method_getName(methods[i]))];
    }
    if (methods) free(methods);
    [names sortUsingSelector:@selector(compare:)];
    appendLog([NSString stringWithFormat:@"[Dump %@] %@", className, [names componentsJoinedByString:@", "]]);
}

static void __attribute__((unused)) installStoreDiagnostics(void) {
    gOriginalIMPs = [NSMutableDictionary dictionary];
    NSArray *classNames = @[
        @"ISURLOperation",
        @"ISStoreURLOperation",
        @"ISLoadURLBagOperation",
        @"ISOperation",
        @"SSURLConnectionRequest",
        @"SSURLRequestProperties",
        @"SSMutableURLRequestProperties",
        @"SSDownload",
        @"SSDownloadManager"
    ];

    NSArray *selectorNames = @[@"start", @"run", @"main", @"load", @"resume", @"send"];
    for (NSString *className in classNames) {
        Class cls = NSClassFromString(className);
        appendLog([NSString stringWithFormat:@"[StoreClass] %@ %@", className, cls ? @"present" : @"missing"]);
        if (!cls) continue;
        for (NSString *selectorName in selectorNames) {
            hookVoidNoArgMethod(cls, NSSelectorFromString(selectorName));
        }
    }
}

@interface PodcastsXRedirectCatcher : NSObject <NSURLConnectionDelegate, NSURLConnectionDataDelegate>
@property (nonatomic, strong) NSURL *redirectURL;
@property (nonatomic, strong) NSURLResponse *response;
@property (nonatomic, strong) NSError *error;
@property (nonatomic, assign) BOOL done;
@end

@interface PodcastsXDataFetcher : NSObject <NSURLConnectionDelegate, NSURLConnectionDataDelegate>
@property (nonatomic, strong) NSMutableData *data;
@property (nonatomic, strong) NSURLResponse *response;
@property (nonatomic, strong) NSError *error;
@property (nonatomic, assign) BOOL done;
@end

@implementation PodcastsXRedirectCatcher
- (BOOL)connection:(NSURLConnection *)connection canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace {
    return [[protectionSpace authenticationMethod] isEqualToString:NSURLAuthenticationMethodServerTrust];
}

- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    if (acceptServerTrustChallenge(challenge, @"RedirectCatcher")) return;
    [challenge.sender performDefaultHandlingForAuthenticationChallenge:challenge];
}

- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    if (acceptServerTrustChallenge(challenge, @"RedirectCatcher legacy")) return;
    [challenge.sender performDefaultHandlingForAuthenticationChallenge:challenge];
}

- (NSURLRequest *)connection:(NSURLConnection *)connection
             willSendRequest:(NSURLRequest *)request
            redirectResponse:(NSURLResponse *)redirectResponse {
    if (redirectResponse) {
        self.redirectURL = request.URL;
        self.done = YES;
        [connection cancel];
        return nil;
    }

    return request;
}

- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response {
    self.response = response;
}

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error {
    self.error = error;
    self.done = YES;
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection {
    self.done = YES;
}
@end

@implementation PodcastsXDataFetcher
- (id)init {
    self = [super init];
    if (self) {
        self.data = [NSMutableData data];
    }
    return self;
}

- (BOOL)connection:(NSURLConnection *)connection canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace {
    return [[protectionSpace authenticationMethod] isEqualToString:NSURLAuthenticationMethodServerTrust];
}

- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    if (acceptServerTrustChallenge(challenge, @"DataFetcher")) return;
    [challenge.sender performDefaultHandlingForAuthenticationChallenge:challenge];
}

- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    if (acceptServerTrustChallenge(challenge, @"DataFetcher legacy")) return;
    [challenge.sender performDefaultHandlingForAuthenticationChallenge:challenge];
}

- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response {
    self.response = response;
    [self.data setLength:0];
}

- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data {
    [self.data appendData:data];
}

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error {
    self.error = error;
    self.done = YES;
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection {
    self.done = YES;
}
@end

static BOOL isAudioURL(NSString *s) {
    if (!s) return NO;
    NSString *lower = s.lowercaseString;
    return ([lower rangeOfString:@".mp3"].location != NSNotFound ||
            [lower rangeOfString:@".m4a"].location != NSNotFound ||
            [lower rangeOfString:@".mp4"].location != NSNotFound ||
            [lower rangeOfString:@".aac"].location != NSNotFound ||
            [lower rangeOfString:@"audio"].location != NSNotFound ||
            [lower rangeOfString:@"episode"].location != NSNotFound ||
            [lower rangeOfString:@"podcast"].location != NSNotFound);
}

static BOOL isStoreURL(NSString *s) {
    if (!s) return NO;
    NSString *lower = s.lowercaseString;
    if (![lower hasPrefix:@"https://"] && ![lower hasPrefix:@"http://"]) return NO;

    return (([lower rangeOfString:@"itunes.apple.com/"].location != NSNotFound ||
             [lower rangeOfString:@"podcasts.apple.com/"].location != NSNotFound ||
             [lower rangeOfString:@"itunes.com/"].location != NSNotFound ||
             [lower rangeOfString:@"ax.itunes.apple.com/"].location != NSNotFound ||
             [lower rangeOfString:@"bookkeeper.itunes.apple.com/"].location != NSNotFound ||
             [lower rangeOfString:@"upp.itunes.apple.com/"].location != NSNotFound ||
             [lower rangeOfString:@"phobos.apple.com/"].location != NSNotFound ||
             [lower rangeOfString:@"se.itunes.apple.com/"].location != NSNotFound ||
             [lower rangeOfString:@"init.itunes.apple.com/"].location != NSNotFound ||
             [lower rangeOfString:@"xp.apple.com/"].location != NSNotFound ||
             [lower rangeOfString:@"bag.itunes.apple.com/"].location != NSNotFound ||
             [lower rangeOfString:@"client-api.itunes.apple.com/"].location != NSNotFound ||
             [lower rangeOfString:@"mzstatic.com/"].location != NSNotFound) &&
            [lower rangeOfString:@"reportstream"].location == NSNotFound);
}

static BOOL isMZStaticArtworkURL(NSString *s) {
    if (!s) return NO;
    NSString *lower = s.lowercaseString;
    return ([lower rangeOfString:@"mzstatic.com/"].location != NSNotFound &&
            ([lower rangeOfString:@".jpg"].location != NSNotFound ||
             [lower rangeOfString:@".jpeg"].location != NSNotFound ||
             [lower rangeOfString:@".png"].location != NSNotFound ||
             [lower rangeOfString:@"/image/"].location != NSNotFound ||
             [lower rangeOfString:@"/image/thumb/"].location != NSNotFound));
}

static BOOL isHTTPURL(NSString *s) {
    NSString *lower = s.lowercaseString;
    return ([lower hasPrefix:@"http://"] || [lower hasPrefix:@"https://"]);
}

__attribute__((unused))
static BOOL isFeedOrArtworkURL(NSString *s) {
    if (!s) return NO;
    NSString *lower = s.lowercaseString;
    if (![lower hasPrefix:@"https://"]) return NO;
    if (isStoreURL(s)) return NO;
    if ([lower rangeOfString:@"itunes.apple.com/"].location != NSNotFound ||
        [lower rangeOfString:@"bookkeeper.itunes.apple.com/"].location != NSNotFound) {
        return NO;
    }

    return ([lower rangeOfString:@"/podcast/rss"].location != NSNotFound ||
            [lower rangeOfString:@"podcastone.com/podcast"].location != NSNotFound ||
            [lower rangeOfString:@"rss"].location != NSNotFound ||
            [lower rangeOfString:@"feed"].location != NSNotFound ||
            [lower rangeOfString:@".xml"].location != NSNotFound ||
            [lower rangeOfString:@".rss"].location != NSNotFound ||
            [lower rangeOfString:@".jpg"].location != NSNotFound ||
            [lower rangeOfString:@".jpeg"].location != NSNotFound ||
            [lower rangeOfString:@".png"].location != NSNotFound ||
            [lower rangeOfString:@"artwork"].location != NSNotFound ||
            [lower rangeOfString:@"image"].location != NSNotFound ||
            [lower rangeOfString:@"mzstatic.com"].location != NSNotFound);
}

static NSString *repairMissingSlashAfterScheme(NSString *s) {
    if (!s) return nil;

    NSMutableString *fixed = [s mutableCopy];
    NSArray *schemes = @[@"https:/", @"http:/"];

    for (NSString *needle in schemes) {
        NSUInteger searchStart = 0;
        while (searchStart < fixed.length) {
            NSRange found = [fixed rangeOfString:needle
                                         options:0
                                           range:NSMakeRange(searchStart, fixed.length - searchStart)];
            if (found.location == NSNotFound) break;

            NSUInteger afterOneSlash = found.location + needle.length;
            if (afterOneSlash >= fixed.length ||
                [fixed characterAtIndex:afterOneSlash] != '/') {
                [fixed insertString:@"/" atIndex:afterOneSlash];
                searchStart = afterOneSlash + 1;
            } else {
                searchStart = afterOneSlash + 1;
            }
        }
    }

    return fixed;
}

static NSString *decodedURLComponent(NSString *s) {
    NSString *decoded = [s stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
    return decoded ?: s;
}

static NSString *directMediaURLFromAnchorPlayURL(NSString *s) {
    if (!s) return nil;

    NSString *lower = s.lowercaseString;
    if ([lower rangeOfString:@"anchor.fm/"].location == NSNotFound ||
        [lower rangeOfString:@"/podcast/play/"].location == NSNotFound) {
        return nil;
    }

    NSArray *markers = @[@"/https:/", @"/http:/", @"/https%3a/", @"/http%3a/"];
    for (NSString *marker in markers) {
        NSRange markerRange = [lower rangeOfString:marker options:NSBackwardsSearch];
        if (markerRange.location == NSNotFound) continue;

        NSString *candidate = [s substringFromIndex:markerRange.location + 1];
        candidate = decodedURLComponent(candidate);
        candidate = repairMissingSlashAfterScheme(candidate);

        NSString *candidateLower = candidate.lowercaseString;
        if ([candidateLower hasPrefix:@"http://"] ||
            [candidateLower hasPrefix:@"https://"]) {
            return candidate;
        }
    }

    return nil;
}

static BOOL isAcastSphinxURL(NSURL *url) {
    NSString *host = url.host.lowercaseString;
    return [host isEqualToString:@"sphinx.acast.com"];
}

static BOOL isMegaphoneTrafficURL(NSURL *url) {
    NSString *host = url.host.lowercaseString;
    return [host isEqualToString:@"traffic.megaphone.fm"];
}

static BOOL isMegaphoneResolvedURL(NSURL *url) {
    NSString *host = url.host.lowercaseString;
    return ([host isEqualToString:@"dcs-cached.megaphone.fm"] ||
            [host isEqualToString:@"dcs-spotify.megaphone.fm"]);
}

static NSURL *megaphoneCachedHostURL(NSURL *url) {
    if (!url || ![url.host.lowercaseString isEqualToString:@"dcs-spotify.megaphone.fm"]) {
        return url;
    }

    NSString *rewrittenString = [url.absoluteString stringByReplacingOccurrencesOfString:@"https://dcs-spotify.megaphone.fm/"
                                                                              withString:@"https://dcs-cached.megaphone.fm/"
                                                                                 options:NSCaseInsensitiveSearch
                                                                                   range:NSMakeRange(0, url.absoluteString.length)];
    NSURL *rewritten = [NSURL URLWithString:rewrittenString];
    if (rewritten) {
        appendLog([NSString stringWithFormat:@"[Megaphone host rewrite] %@ -> %@",
                   url.absoluteString, rewritten.absoluteString]);
        return rewritten;
    }
    return url;
}

static BOOL shouldRelaxHTTPSHost(NSString *host) {
    NSString *lower = host.lowercaseString;
    return ([lower isEqualToString:@"traffic.megaphone.fm"] ||
            [lower isEqualToString:@"dcs-cached.megaphone.fm"] ||
            [lower isEqualToString:@"dcs-spotify.megaphone.fm"] ||
            [lower hasSuffix:@".megaphone.fm"] ||
            [lower hasSuffix:@".itunes.apple.com"] ||
            [lower isEqualToString:@"itunes.apple.com"] ||
            [lower isEqualToString:@"ax.init.itunes.apple.com"] ||
            [lower isEqualToString:@"init.itunes.apple.com"]);
}

static BOOL acceptServerTrustChallenge(NSURLAuthenticationChallenge *challenge, NSString *context) {
    NSURLProtectionSpace *space = challenge.protectionSpace;
    if (![[space authenticationMethod] isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        return NO;
    }

    NSURLCredential *credential = [NSURLCredential credentialForTrust:space.serverTrust];
    appendLog([NSString stringWithFormat:@"[%@ trust] accepting %@", context, space.host]);
    [challenge.sender useCredential:credential forAuthenticationChallenge:challenge];
    return YES;
}

static void allowAnyHTTPSCertificateForHost(NSString *host) {
    if (!host.length || !shouldRelaxHTTPSHost(host)) return;

    SEL selector = NSSelectorFromString(@"setAllowsAnyHTTPSCertificate:forHost:");
    for (Class cls in @[NSClassFromString(@"NSURLRequest"), NSClassFromString(@"NSURLConnection")]) {
        if (!cls || ![cls respondsToSelector:selector]) continue;
        @try {
            void (*send)(id, SEL, BOOL, id) = (void (*)(id, SEL, BOOL, id))objc_msgSend;
            send(cls, selector, YES, host);
            appendLog([NSString stringWithFormat:@"[HTTPSCert set] %@ %@", NSStringFromClass(cls), host]);
        } @catch (NSException *exception) {
            appendLog([NSString stringWithFormat:@"[HTTPSCert set failed] %@ %@",
                       NSStringFromClass(cls), exception]);
        }
    }
}

static BOOL isMacRelayedMediaURL(NSURL *url) {
    NSString *host = url.host.lowercaseString;
    return ([host isEqualToString:@"dts.podtrac.com"] ||
            [host isEqualToString:@"rss.art19.com"] ||
            [host isEqualToString:@"claritaspod.com"] ||
            [host isEqualToString:@"arttrk.com"] ||
            [host isEqualToString:@"pscrb.fm"] ||
            [host isEqualToString:@"prfx.byspotify.com"]);
}

static BOOL isDownloadableMediaURL(NSURL *url) {
    if (!url) return NO;

    NSString *s = url.absoluteString.lowercaseString;
    NSString *host = url.host.lowercaseString;
    if ([host isEqualToString:PODCASTX_MAC_PROXY_HOST] ||
        [host isEqualToString:PODCASTX_LOCAL_PROXY_HOST]) {
        return NO;
    }

    if ([s rangeOfString:@"reportstream"].location != NSNotFound ||
        [host rangeOfString:@"itunes.apple.com"].location != NSNotFound ||
        [host rangeOfString:@"itunes.com"].location != NSNotFound ||
        [host rangeOfString:@"apple.com"].location != NSNotFound) {
        return NO;
    }

    if (isMegaphoneTrafficURL(url) ||
        isMegaphoneResolvedURL(url) ||
        isAcastSphinxURL(url) ||
        isMacRelayedMediaURL(url)) {
        return YES;
    }

    if (![s hasPrefix:@"https://"]) return NO;
    return ([s rangeOfString:@".mp3"].location != NSNotFound ||
            [s rangeOfString:@".m4a"].location != NSNotFound ||
            [s rangeOfString:@".aac"].location != NSNotFound ||
            [s rangeOfString:@".mp4"].location != NSNotFound ||
            [s rangeOfString:@"/podcast/play/"].location != NSNotFound ||
            [s rangeOfString:@"/episodes/"].location != NSNotFound ||
            [s rangeOfString:@"/media.mp3"].location != NSNotFound);
}

static NSString *stringByReplacingPrefix(NSString *s, NSString *prefix, NSString *replacement) {
    if (![s hasPrefix:prefix]) return s;
    return [replacement stringByAppendingString:[s substringFromIndex:prefix.length]];
}

__attribute__((unused))
static NSString *urlEncode(NSString *s) {
    return (__bridge_transfer NSString *)CFURLCreateStringByAddingPercentEscapes(NULL,
                                                                                 (__bridge CFStringRef)s,
                                                                                 NULL,
                                                                                 CFSTR(":/?#[]@!$&'()*+,;="),
                                                                                 kCFStringEncodingUTF8);
}

static NSString *storeRewriteString(NSString *URLString) {
    // iTunesStoreX rewrites init.itunes.apple.com -> search.itunes.apple.com,
    // which is what keeps the iTunes app's Store working on iOS 6. But the
    // Podcasts app's Store tab fetches MZStore.woa endpoints directly from
    // itunes.apple.com (bypassing init.itunes), so iTunesStoreX never sees
    // them and they fail at TLS time. Mirror the same trick for those paths.
    if (!URLString) return URLString;
    // Redirect bookkeeper (syncing) to the local proxy /fetch endpoint to use mbedTLS.
    // iOS 6 SecureTransport gets dropped during ClientHello because it lacks modern ciphers.
    if ([URLString rangeOfString:@"bookkeeper.itunes.apple.com/"].location != NSNotFound ||
        [URLString rangeOfString:@"upp.itunes.apple.com/"].location != NSNotFound ||
        [URLString rangeOfString:@"client-api.itunes.apple.com/"].location != NSNotFound) {
        CFStringRef encoded = CFURLCreateStringByAddingPercentEscapes(
            kCFAllocatorDefault, (__bridge CFStringRef)URLString, NULL,
            CFSTR("!*'();:@&=+$,/?#[]"), kCFStringEncodingUTF8);
        NSString *encNS = (__bridge_transfer NSString *)encoded;
        
        NSString *processName = [[NSProcessInfo processInfo] processName];
        int port = [processName isEqualToString:@"itunesstored"] ? 37627 : 37626;
        return [NSString stringWithFormat:@"http://127.0.0.1:%d/fetch?u=%@", port, encNS ?: URLString];
    }
    // Routes iOS 6 TLS rejects: itunes.apple.com MZStoreServices.woa (charts/
    // genres) and /us/lookup. Send these through the in-process proxy which
    // uses bundled mbedTLS to negotiate modern TLS upstream.
    if ([URLString rangeOfString:@"itunes.apple.com/WebObjects/MZStoreServices.woa/"].location != NSNotFound ||
        [URLString rangeOfString:@"itunes.apple.com/us/lookup"].location != NSNotFound) {
        CFStringRef encoded = CFURLCreateStringByAddingPercentEscapes(
            kCFAllocatorDefault, (__bridge CFStringRef)URLString, NULL,
            CFSTR("!*'();:@&=+$,/?#[]"), kCFStringEncodingUTF8);
        NSString *encNS = (__bridge_transfer NSString *)encoded;
        NSString *processName = [[NSProcessInfo processInfo] processName];
        int port = [processName isEqualToString:@"itunesstored"] ? 37627 : 37626;
        return [NSString stringWithFormat:@"http://127.0.0.1:%d/fetch?u=%@", port, encNS ?: URLString];
    }
    if ([URLString rangeOfString:@"/WebObjects/MZStore.woa/"].location == NSNotFound) {
        return URLString;
    }
    NSString *rewritten = URLString;
    // Both itunes.apple.com and podcasts.apple.com host MZStore.woa. The iOS 6
    // device's TLS handshake against either is unreliable; search.itunes.apple.com
    // serves the same endpoints and consistently accepts the handshake.
    rewritten = [rewritten stringByReplacingOccurrencesOfString:@"https://itunes.apple.com/WebObjects/MZStore.woa/"
                                                     withString:@"https://search.itunes.apple.com/WebObjects/MZStore.woa/"];
    rewritten = [rewritten stringByReplacingOccurrencesOfString:@"http://itunes.apple.com/WebObjects/MZStore.woa/"
                                                     withString:@"http://search.itunes.apple.com/WebObjects/MZStore.woa/"];
    rewritten = [rewritten stringByReplacingOccurrencesOfString:@"https://podcasts.apple.com/WebObjects/MZStore.woa/"
                                                     withString:@"https://search.itunes.apple.com/WebObjects/MZStore.woa/"];
    rewritten = [rewritten stringByReplacingOccurrencesOfString:@"http://podcasts.apple.com/WebObjects/MZStore.woa/"
                                                     withString:@"http://search.itunes.apple.com/WebObjects/MZStore.woa/"];
    return rewritten;
}

@interface PodcastsXStoreURLProtocol : NSURLProtocol <NSURLConnectionDelegate>
@property (nonatomic, strong) NSURLConnection *connection;
@end

@implementation PodcastsXStoreURLProtocol
+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    if ([NSURLProtocol propertyForKey:@"PodcastsXStoreURLProtocolHandled" inRequest:request]) {
        return NO;
    }

    NSString *urlString = request.URL.absoluteString;
    if (!urlString) return NO;

    NSString *rewritten = storeRewriteString(urlString);
    if (![rewritten isEqualToString:urlString]) return YES;

    NSString *lower = urlString.lowercaseString;
    return ([lower rangeOfString:@"init.itunes.apple.com/"].location != NSNotFound ||
            [lower rangeOfString:@"search.itunes.apple.com/htmlresources"].location != NSNotFound);
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

- (void)startLoading {
    NSMutableURLRequest *request = [[self request] mutableCopy];
    NSString *original = request.URL.absoluteString;
    NSString *rewritten = storeRewriteString(original);
    if (![rewritten isEqualToString:original]) {
        request.URL = [NSURL URLWithString:rewritten];
        appendLog([NSString stringWithFormat:@"[StoreURLProtocol rewrite] %@ -> %@",
                   original, rewritten]);
    } else {
        appendLog([NSString stringWithFormat:@"[StoreURLProtocol pass] %@",
                   original]);
    }

    [NSURLProtocol setProperty:[NSNumber numberWithBool:YES]
                         forKey:@"PodcastsXStoreURLProtocolHandled"
                      inRequest:request];
    self.connection = [NSURLConnection connectionWithRequest:request delegate:self];
}

- (void)stopLoading {
    [self.connection cancel];
    self.connection = nil;
}

- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response {
    [[self client] URLProtocol:self didReceiveResponse:response cacheStoragePolicy:NSURLCacheStorageNotAllowed];
}

- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data {
    [[self client] URLProtocol:self didLoadData:data];
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection {
    [[self client] URLProtocolDidFinishLoading:self];
}

- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    if (acceptServerTrustChallenge(challenge, @"StoreURLProtocol")) return;
    [challenge.sender performDefaultHandlingForAuthenticationChallenge:challenge];
}

- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    if (acceptServerTrustChallenge(challenge, @"StoreURLProtocol legacy")) return;
    [challenge.sender performDefaultHandlingForAuthenticationChallenge:challenge];
}

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error {
    appendLog([NSString stringWithFormat:@"[StoreURLProtocol fail] %@", error]);
    [[self client] URLProtocol:self didFailWithError:error];
}
@end

static NSString *urlDecode(NSString *s) {
    return [s stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding] ?: s;
}

static NSString *queryValue(NSString *query, NSString *key) {
    NSArray *parts = [query componentsSeparatedByString:@"&"];
    NSString *prefix = [key stringByAppendingString:@"="];
    for (NSString *part in parts) {
        if ([part hasPrefix:prefix]) {
            return urlDecode([part substringFromIndex:prefix.length]);
        }
    }
    return nil;
}

static NSData *cfTrustedDataForURL(NSURL *url, NSString *rangeHeader, BOOL defaultToInitialRange, NSHTTPURLResponse **outResponse, NSError **outError) {
    if (!url) return nil;

    appendLog([NSString stringWithFormat:@"[CFHTTP fetch start] %@ range=%@ defaultRange=%d",
               url.host, rangeHeader, defaultToInitialRange]);
    allowAnyHTTPSCertificateForHost(url.host);

    CFHTTPMessageRef message = CFHTTPMessageCreateRequest(kCFAllocatorDefault,
                                                          CFSTR("GET"),
                                                          (__bridge CFURLRef)url,
                                                          kCFHTTPVersion1_1);
    if (!message) return nil;

    CFHTTPMessageSetHeaderFieldValue(message, CFSTR("Accept"), CFSTR("audio/mpeg,*/*;q=0.9"));
    CFHTTPMessageSetHeaderFieldValue(message, CFSTR("User-Agent"), CFSTR("AppleCoreMedia/1.0.0.10B500 (iPhone; U; CPU OS 6_1_3 like Mac OS X; en_us)"));
    if (rangeHeader.length) {
        CFHTTPMessageSetHeaderFieldValue(message, CFSTR("Range"), (__bridge CFStringRef)rangeHeader);
    } else if (defaultToInitialRange) {
        CFHTTPMessageSetHeaderFieldValue(message, CFSTR("Range"), CFSTR("bytes=0-1048575"));
    }

    CFReadStreamRef stream = CFReadStreamCreateForHTTPRequest(kCFAllocatorDefault, message);
    CFRelease(message);
    if (!stream) return nil;

    NSDictionary *sslSettings = @{
        (__bridge id)kCFStreamSSLValidatesCertificateChain: [NSNumber numberWithBool:NO],
        (__bridge id)kCFStreamSSLAllowsAnyRoot: [NSNumber numberWithBool:YES],
        (__bridge id)kCFStreamSSLAllowsExpiredCertificates: [NSNumber numberWithBool:YES],
        (__bridge id)kCFStreamSSLAllowsExpiredRoots: [NSNumber numberWithBool:YES],
        (__bridge id)kCFStreamSSLLevel: (__bridge id)kCFStreamSocketSecurityLevelNegotiatedSSL
    };
    CFReadStreamSetProperty(stream, kCFStreamPropertySSLSettings, (__bridge CFTypeRef)sslSettings);

    NSMutableData *data = [NSMutableData data];
    BOOL opened = CFReadStreamOpen(stream);
    if (!opened) {
        CFErrorRef cfError = CFReadStreamCopyError(stream);
        NSError *error = cfError ? CFBridgingRelease(cfError) : [NSError errorWithDomain:@"PodcastsXCFHTTP"
                                                                                    code:-1
                                                                                userInfo:@{NSLocalizedDescriptionKey: @"CFReadStreamOpen failed"}];
        appendLog([NSString stringWithFormat:@"[CFHTTP open failed] %@ err=%@",
                   url.host, error]);
        if (outError) {
            *outError = error;
        }
        CFRelease(stream);
        return nil;
    }

    UInt8 buffer[16384];
    while (1) {
        CFIndex read = CFReadStreamRead(stream, buffer, sizeof(buffer));
        if (read > 0) {
            [data appendBytes:buffer length:(NSUInteger)read];
            continue;
        }
        if (read == 0) break;

        CFErrorRef cfError = CFReadStreamCopyError(stream);
        NSError *error = cfError ? CFBridgingRelease(cfError) : [NSError errorWithDomain:@"PodcastsXCFHTTP"
                                                                                    code:(NSInteger)read
                                                                                userInfo:@{NSLocalizedDescriptionKey: @"CFReadStreamRead failed"}];
        appendLog([NSString stringWithFormat:@"[CFHTTP read failed] %@ err=%@",
                   url.host, error]);
        if (outError) {
            *outError = error;
        }
        CFReadStreamClose(stream);
        CFRelease(stream);
        return nil;
    }

    CFHTTPMessageRef responseMessage = (CFHTTPMessageRef)CFReadStreamCopyProperty(stream, kCFStreamPropertyHTTPResponseHeader);
    if (responseMessage) {
        NSInteger statusCode = (NSInteger)CFHTTPMessageGetResponseStatusCode(responseMessage);
        NSDictionary *headers = CFBridgingRelease(CFHTTPMessageCopyAllHeaderFields(responseMessage));
        if (outResponse) {
            *outResponse = [[NSHTTPURLResponse alloc] initWithURL:url
                                                       statusCode:statusCode
                                                      HTTPVersion:@"HTTP/1.1"
                                                     headerFields:headers];
        }
        CFRelease(responseMessage);
    }

    CFReadStreamClose(stream);
    CFRelease(stream);
    appendLog([NSString stringWithFormat:@"[CFHTTP fetch] %@ len=%lu",
               url.host, (unsigned long)data.length]);
    return data;
}

__attribute__((unused))
static NSData *trustedDataForURL(NSURL *url, NSString *rangeHeader, BOOL defaultToInitialRange, NSHTTPURLResponse **outResponse, NSError **outError) {
    allowAnyHTTPSCertificateForHost(url.host);
    gPodcastsXBypassRequestHooks = YES;
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url
                                                           cachePolicy:NSURLRequestReloadIgnoringLocalAndRemoteCacheData
                                                       timeoutInterval:20.0];
    gPodcastsXBypassRequestHooks = NO;
    [request setHTTPMethod:@"GET"];
    [request setValue:@"audio/mpeg,*/*;q=0.9" forHTTPHeaderField:@"Accept"];
    [request setValue:@"AppleCoreMedia/1.0.0.10B500 (iPhone; U; CPU OS 6_1_3 like Mac OS X; en_us)"
   forHTTPHeaderField:@"User-Agent"];
    if (rangeHeader.length) {
        [request setValue:rangeHeader forHTTPHeaderField:@"Range"];
    } else if (defaultToInitialRange) {
        [request setValue:@"bytes=0-1048575" forHTTPHeaderField:@"Range"];
    }

    PodcastsXDataFetcher *delegate = [[PodcastsXDataFetcher alloc] init];
    NSURLConnection *connection = [[NSURLConnection alloc] initWithRequest:request
                                                                  delegate:delegate
                                                          startImmediately:NO];
    [connection start];

    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:25.0];
    while (!delegate.done && [deadline timeIntervalSinceNow] > 0) {
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                                 beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
    }

    if (!delegate.done) {
        [connection cancel];
        if (outError) {
            *outError = [NSError errorWithDomain:@"PodcastsXProxy"
                                            code:-1
                                        userInfo:@{NSLocalizedDescriptionKey: @"Proxy fetch timed out"}];
        }
        return nil;
    }

    if (outResponse) {
        *outResponse = [delegate.response isKindOfClass:[NSHTTPURLResponse class]] ? (NSHTTPURLResponse *)delegate.response : nil;
    }
    if (outError) {
        *outError = delegate.error;
    }
    if (!delegate.error) return delegate.data;

    if (shouldRelaxHTTPSHost(url.host)) {
        appendLog([NSString stringWithFormat:@"[Proxy fallback CFHTTP] %@ err=%@",
                   url.host, delegate.error]);
        if (outError) *outError = nil;
        return cfTrustedDataForURL(url, rangeHeader, defaultToInitialRange, outResponse, outError);
    }

    return nil;
}

static void sendAll(int fd, NSData *data) {
    const char *bytes = (const char *)data.bytes;
    NSUInteger remaining = data.length;
    while (remaining > 0) {
        ssize_t sent = send(fd, bytes, remaining, 0);
        if (sent <= 0) return;
        bytes += sent;
        remaining -= sent;
    }
}

static void handleProxyClient(int client) {
    // Bound client socket I/O so a stuck worker can't hold a concurrency slot
    // forever (which would deadlock the whole proxy under the semaphore cap).
    struct timeval ctv = { 25, 0 };
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &ctv, sizeof(ctv));
    setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &ctv, sizeof(ctv));
    NSMutableData *clientData = [NSMutableData data];
    NSData *terminator = [NSData dataWithBytes:"\r\n\r\n" length:4];
    NSRange headerEnd = NSMakeRange(NSNotFound, 0);
    while (1) {
        char buffer[8192];
        ssize_t received = recv(client, buffer, sizeof(buffer), 0);
        if (received <= 0) break;
        [clientData appendBytes:buffer length:(NSUInteger)received];
        headerEnd = [clientData rangeOfData:terminator options:0 range:NSMakeRange(0, clientData.length)];
        if (headerEnd.location != NSNotFound) break;
    }
    if (headerEnd.location == NSNotFound) {
        close(client);
        return;
    }

    NSData *headerData = [clientData subdataWithRange:NSMakeRange(0, headerEnd.location)];
    NSString *requestText = [[NSString alloc] initWithData:headerData encoding:NSUTF8StringEncoding] ?: @"";
    NSArray *lines = [requestText componentsSeparatedByString:@"\r\n"];
    NSString *firstLine = lines.count ? [lines objectAtIndex:0] : @"";
    NSArray *firstParts = [firstLine componentsSeparatedByString:@" "];
    NSString *method = firstParts.count > 0 ? [firstParts objectAtIndex:0] : @"GET";
    BOOL isHeadRequest = [method.uppercaseString isEqualToString:@"HEAD"];
    NSString *path = firstParts.count > 1 ? [firstParts objectAtIndex:1] : @"";

    NSMutableDictionary *reqHeaders = [NSMutableDictionary dictionary];
    for (NSUInteger i = 1; i < lines.count; i++) {
        NSString *line = lines[i];
        NSRange colon = [line rangeOfString:@":"];
        if (colon.location != NSNotFound) {
            NSString *k = [line substringToIndex:colon.location];
            NSString *v = [[line substringFromIndex:colon.location + 1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            reqHeaders[k] = v;
        }
    }

    NSUInteger contentLength = (NSUInteger)[[reqHeaders objectForKey:@"Content-Length"] ?: [reqHeaders objectForKey:@"content-length"] integerValue];
    NSMutableData *reqBody = [NSMutableData data];
    NSUInteger bodyRead = clientData.length - (headerEnd.location + 4);
    if (bodyRead > 0) {
        [reqBody appendData:[clientData subdataWithRange:NSMakeRange(headerEnd.location + 4, bodyRead)]];
    }
    while (reqBody.length < contentLength) {
        char buffer[8192];
        ssize_t received = recv(client, buffer, MIN(sizeof(buffer), contentLength - reqBody.length), 0);
        if (received <= 0) break;
        [reqBody appendBytes:buffer length:(NSUInteger)received];
    }

    BOOL isDownloadRequest = [path hasPrefix:@"/download"];
    NSRange question = [path rangeOfString:@"?"];
    NSString *query = question.location == NSNotFound ? @"" : [path substringFromIndex:question.location + 1];
    NSString *target = queryValue(query, @"u");
    NSString *rangeHeader = nil;

    for (NSString *line in lines) {
        if ([line.lowercaseString hasPrefix:@"range:"]) {
            rangeHeader = [[line substringFromIndex:6] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            break;
        }
    }

    if (isDownloadRequest) {
        appendLog([NSString stringWithFormat:@"[Proxy download req] method=%@ range=%@",
                   method, rangeHeader ?: @"(none)"]);
    }

    BOOL isMediaPath = [path hasPrefix:@"/megaphone"] || [path hasPrefix:@"/audio"] || isDownloadRequest;
    // Preserve CoreMedia's exact byte ranges. Clamping large ranges made some
    // players treat the asset as truncated and could crash during resume.
    if (isMediaPath && !isDownloadRequest && !rangeHeader.length) {
        rangeHeader = @"bytes=0-1048575";
    }
    // dcs-cached.megaphone.fm and similar CDNs return 200 with 0 body bytes
    // when there is no Range header — they require a Range to serve content.
    // Force an open-ended range so the CDN sends a proper 206 with the body.
    // NOT for HEAD: the iOS 6 download manager opens every download with a
    // no-Range HEAD size probe and expects a 200 + full Content-Length.
    // Forcing a range turns that into a 206, which wedges the download at
    // "Waiting…". A HEAD has no body, so the 0-byte-body CDN issue is moot.
    if (isDownloadRequest && !isHeadRequest && !rangeHeader.length) {
        rangeHeader = @"bytes=0-";
    }

    NSURL *url = target ? [NSURL URLWithString:target] : nil;
    if (!url) {
        NSData *body = [@"Bad Request" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *header = [[NSString stringWithFormat:@"HTTP/1.1 400 Bad Request\r\nContent-Length: %lu\r\nConnection: close\r\n\r\n",
                           (unsigned long)body.length] dataUsingEncoding:NSUTF8StringEncoding];
        sendAll(client, header);
        sendAll(client, body);
        close(client);
        return;
    }

    NSHTTPURLResponse *response = nil;
    NSError *error = nil;
    // Use the bundled-mbedTLS relay (modern ciphers) instead of NSURLConnection,
    // which uses iOS 6 SecureTransport and gets -9824 from modern CDNs.
    extern NSData *TLSRelayFetch(NSURL *url, NSString *method, NSDictionary *reqHeaders, NSData *reqBody, NSString *rangeHeader, NSString *uaOverride,
                                 NSHTTPURLResponse **outResponse, NSError **outError);
    extern BOOL TLSRelayStreamToClient(NSURL *url, NSString *rangeHeader, NSString *uaOverride,
                                       int clientFD, BOOL headOnly, NSError **outError);
    if (isMediaPath) {
        // Serialize heavy media streams (>2MB) to prevent concurrent TLS relay
        // connections from OOM-killing the 512 MB iPhone 4S. When switching
        // episodes, AVFoundation destroys the old AVPlayerItem, which natively
        // closes the client socket, causing the old stream to exit and release
        // the lock for the new stream.
        static dispatch_semaphore_t mediaStreamSem;
        static dispatch_once_t mediaOnce;
        dispatch_once(&mediaOnce, ^{ mediaStreamSem = dispatch_semaphore_create(2); });

        BOOL isHeavyStream = NO;
        {
            NSScanner *sc = [NSScanner scannerWithString:rangeHeader ?: @""];
            long long s = 0, e = 0;
            if ([sc scanString:@"bytes=" intoString:NULL] &&
                [sc scanLongLong:&s] && [sc scanString:@"-" intoString:NULL] &&
                [sc scanLongLong:&e] && (e - s + 1) > (2 * 1024 * 1024)) {
                isHeavyStream = YES;
            }
        }

        if (isHeavyStream) {
            appendLog(@"[Proxy stream wait] acquiring semaphore");
            dispatch_semaphore_wait(mediaStreamSem, DISPATCH_TIME_FOREVER);
            appendLog(@"[Proxy stream wait] acquired");
        }

        appendLog([NSString stringWithFormat:@"[Proxy stream begin] %@ range=%@",
                   url.absoluteString, rangeHeader ?: @"-"]);
        BOOL ok = TLSRelayStreamToClient(url, rangeHeader, nil, client, isHeadRequest, &error);

        if (isHeavyStream) {
            dispatch_semaphore_signal(mediaStreamSem);
            appendLog(@"[Proxy stream wait] released");
        }

        if (ok) {
            appendLog([NSString stringWithFormat:@"[Proxy streamed] %@ range=%@",
                       url.host, rangeHeader ?: @"-"]);
            close(client);
            return;
        }
        appendLog([NSString stringWithFormat:@"[Proxy stream failed] %@ err=%@", url.absoluteString, error]);
    }
    NSData *body = TLSRelayFetch(url, method, reqHeaders, reqBody, rangeHeader, nil, &response, &error);
    // Log first 500 bytes of sync-API responses to diagnose partial subscription sync.
    if (body) {
        NSString *h = url.host.lowercaseString;
        if ([h isEqualToString:@"bookkeeper.itunes.apple.com"] ||
            [h isEqualToString:@"client-api.itunes.apple.com"] ||
            [h isEqualToString:@"upp.itunes.apple.com"]) {
            NSUInteger previewLen = MIN(body.length, (NSUInteger)500);
            NSString *preview = [[NSString alloc] initWithData:[body subdataWithRange:NSMakeRange(0, previewLen)]
                                                      encoding:NSUTF8StringEncoding];
            appendLog([NSString stringWithFormat:@"[SyncAPI] %@ status=%ld len=%lu body=%@",
                       h, (long)response.statusCode, (unsigned long)body.length, preview ?: @"(binary)"]);
        }
    }
    if (!body) {
        appendLog([NSString stringWithFormat:@"[Proxy failed] %@ err=%@", url.absoluteString, error]);
        NSData *errorBody = [@"Proxy Fetch Failed" dataUsingEncoding:NSUTF8StringEncoding];
        NSData *header = [[NSString stringWithFormat:@"HTTP/1.1 502 Bad Gateway\r\nContent-Length: %lu\r\nConnection: close\r\n\r\n",
                           (unsigned long)errorBody.length] dataUsingEncoding:NSUTF8StringEncoding];
        sendAll(client, header);
        sendAll(client, errorBody);
        close(client);
        return;
    }

    NSInteger statusCode = response.statusCode ?: 206;
    NSString *reason = statusCode == 206 ? @"Partial Content" : @"OK";
    NSDictionary *headers = response.allHeaderFields;
    NSString *contentRange = [headers objectForKey:@"Content-Range"] ?: [headers objectForKey:@"content-range"];
    NSMutableString *headerString = [NSMutableString stringWithFormat:@"HTTP/1.1 %ld %@\r\nContent-Type: %@\r\nContent-Length: %lu\r\nAccept-Ranges: bytes\r\nConnection: close\r\n",
                                     (long)statusCode,
                                     reason,
                                     response.MIMEType ?: @"audio/mpeg",
                                     (unsigned long)body.length];
    if (contentRange.length) {
        [headerString appendFormat:@"Content-Range: %@\r\n", contentRange];
    }
    [headerString appendString:@"\r\n"];

    appendLog([NSString stringWithFormat:@"[Proxy served] %@ range=%@ status=%ld len=%lu",
               url.host, rangeHeader, (long)statusCode, (unsigned long)body.length]);
    sendAll(client, [headerString dataUsingEncoding:NSUTF8StringEncoding]);
    if (!isHeadRequest) {
        sendAll(client, body);
    }
    close(client);
}

// iOS 6 episode downloads run in itunesstored, not the Podcasts app. Both
// processes load this dylib (see PodcastsX.plist), but two processes can't
// share one loopback port — so each gets its own in-process proxy: Podcasts
// keeps 37626 (playback path, unchanged), itunesstored uses 37627 (downloads).
static int podcastxProxyPort(void) {
    static int port = 0;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *pn = [[NSProcessInfo processInfo] processName];
        port = [pn isEqualToString:@"itunesstored"] ? 37627 : PODCASTX_PROXY_PORT;
    });
    return port;
}

static void startProxyServer(void) {
    static BOOL started = NO;
    if (started) return;
    started = YES;

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        int server = socket(AF_INET, SOCK_STREAM, 0);
        if (server < 0) {
            appendLog(@"[Proxy] socket failed");
            return;
        }

        int opt = 1;
        setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(podcastxProxyPort());
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");

        if (bind(server, (struct sockaddr *)&addr, sizeof(addr)) < 0 || listen(server, 4) < 0) {
            appendLog(@"[Proxy] bind/listen failed");
            close(server);
            return;
        }

        appendLog([NSString stringWithFormat:@"[Proxy] listening on 127.0.0.1:%d (%@)",
                   podcastxProxyPort(), [[NSProcessInfo processInfo] processName]]);
        // Cap concurrent proxy workers. AVFoundation opens parallel range
        // connections; keep enough lanes for episode switches without letting
        // mbedTLS handshakes and buffers explode on the 512MB iPhone 4S.
        static dispatch_semaphore_t proxySem;
        static dispatch_once_t once;
        dispatch_once(&once, ^{ proxySem = dispatch_semaphore_create(4); });
        while (1) {
            int client = accept(server, NULL, NULL);
            if (client < 0) continue;
            
            // Prevent SIGPIPE from crashing the app when AVFoundation closes the socket
            int set = 1;
            setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, (void *)&set, sizeof(int));
            
            dispatch_semaphore_wait(proxySem, DISPATCH_TIME_FOREVER);
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                @autoreleasepool {
                    handleProxyClient(client);
                }
                dispatch_semaphore_signal(proxySem);
            });
        }
    });
}

// In-process relay URL builder: routes traffic to the proxy server that
// startProxyServer() runs on 127.0.0.1:37626 inside the Podcasts process.
// We use this only for hosts whose TLS handshake fails when initiated by
// mediaserverd (e.g. modern megaphone CDN) — NSURLConnection inside the
// Podcasts process can still negotiate those handshakes successfully.
static NSURL *localProxyURLForURL(NSURL *url, NSString *path) {
    if (!url) return nil;
    NSString *raw = url.absoluteString;
    CFStringRef encoded = CFURLCreateStringByAddingPercentEscapes(
        kCFAllocatorDefault, (__bridge CFStringRef)raw, NULL,
        CFSTR("!*'();:@&=+$,/?#[]"), kCFStringEncodingUTF8);
    NSString *encodedNS = (__bridge_transfer NSString *)encoded;
    NSString *leaf = url.lastPathComponent.length ? url.lastPathComponent : nil;
    if (![leaf.lowercaseString hasSuffix:@".mp3"] &&
        ![leaf.lowercaseString hasSuffix:@".m4a"] &&
        ![leaf.lowercaseString hasSuffix:@".aac"]) {
        leaf = nil;
    }
    NSString *route = leaf.length ? [NSString stringWithFormat:@"%@/%@", path, leaf] : path;
    
    int targetPort = podcastxProxyPort();
    if ([path isEqualToString:@"download"]) {
        targetPort = 37627;
    }
    
    NSString *proxy = [NSString stringWithFormat:@"http://%@:%d/%@?u=%@",
                       PODCASTX_LOCAL_PROXY_HOST,
                       targetPort,
                       route,
                       encodedNS ?: raw];
    return [NSURL URLWithString:proxy];
}

static NSURL *feedOrArtworkProxyURL(NSURL *url, NSString *context) {
    if (!url) return nil;
    NSString *scheme = url.scheme.lowercaseString;
    // Route HTTPS feed and artwork fetches through the mbedtls proxy because
    // native iOS 6 SecureTransport lacks modern ciphers, causing NSURLConnection
    // to fail (-9824/-9803) with CDNs like Libsyn and Megaphone.
    // Skip media/download URLs, which must be routed to the /download streaming endpoint instead.
    // isAudioURL() matches any URL containing "podcast" or "episode" — too broad.
    // Many RSS feed URLs (anchor.fm/s/.../podcast/rss, podcastone.com/...) match,
    // causing feedOrArtworkProxyURL to skip them and fall back to iOS 6 native TLS
    // which fails → zero episodes on newly-synced shows. isDownloadableMediaURL()
    // is the precise guard: it checks actual audio extensions + known CDN hosts.
    if ([scheme isEqualToString:@"https"] &&
        (!isStoreURL(url.absoluteString) || isMZStaticArtworkURL(url.absoluteString)) &&
        !isDownloadableMediaURL(url)) {
        return localProxyURLForURL(url, @"feed");
    }
    return url;
}

static NSString *fixedURLStringForCreation(NSString *URLString, NSString *context) {
    if (!URLString) return URLString;
    if (gPodcastsXBypassURLCreationHooks) return URLString;

    NSString *fixedString = repairMissingSlashAfterScheme(URLString);
    if (fixedString && ![fixedString isEqualToString:URLString]) {
        appendLog([NSString stringWithFormat:@"[%@ fix] %@ -> %@", context, URLString, fixedString]);
        URLString = fixedString;
    }

    if (isMZStaticArtworkURL(URLString)) {
        gPodcastsXBypassURLCreationHooks = YES;
        NSURL *originalURL = [NSURL URLWithString:URLString];
        gPodcastsXBypassURLCreationHooks = NO;
        NSURL *proxiedURL = feedOrArtworkProxyURL(originalURL, context);
        if (proxiedURL && proxiedURL != originalURL) {
            appendLog([NSString stringWithFormat:@"[%@ mzstatic artwork proxy] %@ -> %@",
                       context, URLString, proxiedURL.absoluteString]);
            return proxiedURL.absoluteString ?: URLString;
        }
    }

    if (isStoreURL(URLString)) {
        NSString *rewritten = storeRewriteString(URLString);
        if (![rewritten isEqualToString:URLString]) {
            appendLog([NSString stringWithFormat:@"[%@ store rewrite] %@ -> %@",
                       context, URLString, rewritten]);
        }
        return rewritten;
    }

    if (isFeedOrArtworkURL(URLString)) {
        gPodcastsXBypassURLCreationHooks = YES;
        NSURL *originalURL = [NSURL URLWithString:URLString];
        gPodcastsXBypassURLCreationHooks = NO;
        NSURL *proxiedURL = feedOrArtworkProxyURL(originalURL, context);
        if (proxiedURL && proxiedURL != originalURL) {
            appendLog([NSString stringWithFormat:@"[%@ feed creation proxy] %@ -> %@",
                       context, URLString, proxiedURL.absoluteString]);
            return proxiedURL.absoluteString ?: URLString;
        }
    }

    return URLString;
}

static void logURLStringIfInteresting(NSString *URLString, NSString *context) {
    if (isAudioURL(URLString) || isStoreURL(URLString)) {
        appendLog([NSString stringWithFormat:@"[%@ %@] %@",
                   context,
                   isStoreURL(URLString) ? @"store" : @"audio",
                   URLString]);
    } else if (isHTTPURL(URLString)) {
        appendLog([NSString stringWithFormat:@"[%@ http] %@", context, URLString]);
    }
}

static NSURL *firstRedirectURLForURL(NSURL *url, NSString *context) {
    gPodcastsXBypassRequestHooks = YES;
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url
                                                           cachePolicy:NSURLRequestReloadIgnoringLocalAndRemoteCacheData
                                                       timeoutInterval:8.0];
    gPodcastsXBypassRequestHooks = NO;
    [request setHTTPMethod:@"GET"];
    [request setValue:@"bytes=0-1" forHTTPHeaderField:@"Range"];
    [request setValue:@"audio/mpeg,*/*;q=0.9" forHTTPHeaderField:@"Accept"];
    [request setValue:@"AppleCoreMedia/1.0.0.10B500 (iPhone; U; CPU OS 6_1_3 like Mac OS X; en_us)"
   forHTTPHeaderField:@"User-Agent"];

    PodcastsXRedirectCatcher *delegate = [[PodcastsXRedirectCatcher alloc] init];
    NSURLConnection *connection = [[NSURLConnection alloc] initWithRequest:request
                                                                  delegate:delegate
                                                          startImmediately:NO];
    [connection start];

    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:8.0];
    while (!delegate.done && [deadline timeIntervalSinceNow] > 0) {
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                                 beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
    }

    if (!delegate.done) {
        [connection cancel];
        appendLog([NSString stringWithFormat:@"[%@ redirect timeout] %@",
                   context, url.absoluteString]);
        return nil;
    }

    if (delegate.error) {
        appendLog([NSString stringWithFormat:@"[%@ redirect failed] err=%@ url=%@",
                   context, delegate.error, url.absoluteString]);
        return nil;
    }

    return delegate.redirectURL;
}

static NSURL *resolvedAcastPlaybackURL(NSURL *url, NSString *context) {
    if (!isAcastSphinxURL(url)) return url;

    NSString *probeString = stringByReplacingPrefix(url.absoluteString, @"https://", @"http://");
    NSURL *probeURL = [NSURL URLWithString:probeString];
    NSURL *redirectURL = firstRedirectURLForURL(probeURL, context);
    if (!redirectURL) {
        appendLog([NSString stringWithFormat:@"[%@ acast resolve failed] url=%@",
                   context, url.absoluteString]);
        return url;
    }

    NSURL *playbackURL = redirectURL;

    appendLog([NSString stringWithFormat:@"[%@ acast resolve] %@ -> %@",
               context,
               url.absoluteString,
               playbackURL.absoluteString]);
    return playbackURL;
}

static NSURL *resolvedMegaphonePlaybackURL(NSURL *url, NSString *context) {
    if (!isMegaphoneTrafficURL(url)) return url;

    NSURL *redirectURL = firstRedirectURLForURL(url, context);
    if (!redirectURL) {
        appendLog([NSString stringWithFormat:@"[%@ megaphone resolve failed] url=%@",
                   context, url.absoluteString]);
        return url;
    }

    appendLog([NSString stringWithFormat:@"[%@ megaphone resolve] %@ -> %@",
               context,
               url.absoluteString,
               redirectURL.absoluteString]);
    // Do NOT rewrite dcs-spotify -> dcs-cached: dcs-cached.megaphone.fm is on
    // Google Cloud LB which rejects iOS 6's TLS ClientHello (-9824). The
    // dcs-spotify host is on Akamai and accepts iOS 6 handshakes.
    // mediaserverd's SecureTransport can't negotiate with the megaphone CDN
    // (errSSLPeerHandshakeFail -9824 — modern Google Cloud LB rejects iOS 6's
    // cipher list even with TLS 1.2 forced). Route through the in-process
    // proxy on 127.0.0.1:37626, which fetches via NSURLConnection inside the
    // Podcasts process and serves the bytes back over plain HTTP.
    NSURL *proxyURL = localProxyURLForURL(redirectURL, @"megaphone");
    appendLog([NSString stringWithFormat:@"[%@ megaphone via local proxy] %@ -> %@",
               context,
               redirectURL.absoluteString,
               proxyURL.absoluteString]);
    return proxyURL ?: redirectURL;
}

static NSURL *resolvedMacRelayedMediaURL(NSURL *url, NSString *context) {
    // No-op: we no longer relay megaphone CDN URLs through an external proxy.
    return url;
}

static NSDictionary *assetOptionsForURL(NSURL *url) {
    NSString *host = url.host.lowercaseString;
    if (!isMegaphoneResolvedURL(url) &&
        ![host isEqualToString:@"traffic.megaphone.fm"] &&
        ![host isEqualToString:@"stitcher2.acast.com"]) {
        return nil;
    }

    NSDictionary *headers = @{
        @"Accept": @"audio/mpeg,*/*;q=0.9",
        @"User-Agent": @"AppleCoreMedia/1.0.0.10B500 (iPhone; U; CPU OS 6_1_3 like Mac OS X; en_us)"
    };
    return @{ @"AVURLAssetHTTPHeaderFieldsKey": headers };
}

static NSDictionary *mergedAssetOptions(NSDictionary *options, NSURL *url) {
    NSDictionary *extraOptions = assetOptionsForURL(url);
    if (!extraOptions) return options;

    NSMutableDictionary *merged = options ? [options mutableCopy] : [NSMutableDictionary dictionary];
    [merged addEntriesFromDictionary:extraOptions];
    appendLog([NSString stringWithFormat:@"[AVURLAsset options] %@ %@", url.absoluteString, extraOptions]);
    return merged;
}

static NSURL *resolvedKnownHostPlaybackURL(NSURL *url, NSString *context) {
    NSURL *resolved = resolvedAcastPlaybackURL(url, context);
    if (resolved != url) return resolved;

    resolved = resolvedMegaphonePlaybackURL(url, context);
    if (resolved != url) return resolved;

    resolved = resolvedMacRelayedMediaURL(url, context);
    if (resolved != url) return resolved;

    // Catch-all: any HTTPS audio URL with a host that doesn't belong to our
    // own proxy gets routed through the mbedTLS relay. iOS 6 SecureTransport
    // rejects modern CDNs (podtrac, art19, anchor, libsyn HTTPS, etc.) so
    // even non-megaphone podcasts need the bundled-TLS path.
    NSString *host = url.host.lowercaseString;
    if (!host.length) return url;
    if ([host isEqualToString:PODCASTX_LOCAL_PROXY_HOST] ||
        [host isEqualToString:PODCASTX_MAC_PROXY_HOST]) return url;
    NSString *scheme = url.scheme.lowercaseString;
    if (![scheme isEqualToString:@"https"]) return url;
    NSString *lower = url.absoluteString.lowercaseString;
    if ([lower rangeOfString:@".mp3"].location == NSNotFound &&
        [lower rangeOfString:@".m4a"].location == NSNotFound &&
        [lower rangeOfString:@".aac"].location == NSNotFound &&
        [lower rangeOfString:@".caf"].location == NSNotFound &&
        [lower rangeOfString:@"redirect.mp3"].location == NSNotFound) {
        return url;
    }
    NSURL *proxyURL = localProxyURLForURL(url, @"megaphone");
    appendLog([NSString stringWithFormat:@"[%@ audio via tls relay] %@ -> %@",
               context, url.absoluteString, proxyURL.absoluteString]);
    return proxyURL ?: url;
}

static NSURL *fixedPlaybackURL(NSURL *url, NSString *context) {
    if (!url) return url;

    NSString *original = url.absoluteString;
    NSString *fixedString = directMediaURLFromAnchorPlayURL(original);
    if (!fixedString) {
        fixedString = repairMissingSlashAfterScheme(original);
    }

    if (!fixedString || [fixedString isEqualToString:original]) {
        return resolvedKnownHostPlaybackURL(url, context);
    }

    NSURL *fixedURL = [NSURL URLWithString:fixedString];
    if (!fixedURL) {
        appendLog([NSString stringWithFormat:@"[%@ fix failed] %@ -> %@",
                   context, original, fixedString]);
        return url;
    }

    appendLog([NSString stringWithFormat:@"[%@ fix] %@ -> %@",
               context, original, fixedURL.absoluteString]);
    return resolvedKnownHostPlaybackURL(fixedURL, context);
}

static NSURL *fixedDownloadURL(NSURL *url, NSString *context) {
    if (!url || !isDownloadableMediaURL(url)) return url;

    NSString *original = url.absoluteString;
    // Do NOT strip anchor.fm /podcast/play/ wrappers down to the embedded CDN
    // URL. The bare CDN object (e.g. dated /staging/ CloudFront paths) returns
    // a valid 206 header but CloudFront resets the body — it requires
    // anchor.fm's redirect to issue the authorized/fresh URL. Passing the
    // anchor.fm URL through lets TLSRelay follow that redirect, the same way
    // podtrac/art19 downloads already work.
    NSString *fixedString = repairMissingSlashAfterScheme(original);

    NSURL *fixedURL = url;
    if (fixedString && ![fixedString isEqualToString:original]) {
        fixedURL = [NSURL URLWithString:fixedString] ?: url;
        appendLog([NSString stringWithFormat:@"[%@ download fix] %@ -> %@",
                   context, original, fixedURL.absoluteString]);
    }

    NSURL *resolvedURL = fixedURL;
    if (isMegaphoneTrafficURL(fixedURL)) {
        NSURL *redirectURL = firstRedirectURLForURL(fixedURL, context);
        if (redirectURL) {
            appendLog([NSString stringWithFormat:@"[%@ download megaphone resolve] %@ -> %@",
                       context, fixedURL.absoluteString, redirectURL.absoluteString]);
            resolvedURL = megaphoneCachedHostURL(redirectURL);
        } else {
            appendLog([NSString stringWithFormat:@"[%@ download megaphone resolve failed] %@",
                       context, fixedURL.absoluteString]);
        }
    } else if (isAcastSphinxURL(fixedURL)) {
        resolvedURL = resolvedAcastPlaybackURL(fixedURL, context);
    }

    NSString *host = resolvedURL.host.lowercaseString;
    if ([host isEqualToString:PODCASTX_MAC_PROXY_HOST] ||
        [host isEqualToString:PODCASTX_LOCAL_PROXY_HOST]) {
        return resolvedURL;
    }

    // Route downloads through our local proxy. itunesstored runs out-of-process
    // and uses native iOS 6 SecureTransport, which fails TLS handshakes with
    // modern CDNs. Our proxy handles the connection and streams the data.
    appendLog([NSString stringWithFormat:@"[%@ download proxy] %@ -> %@",
               context, resolvedURL.absoluteString, localProxyURLForURL(resolvedURL, @"download").absoluteString]);
    return localProxyURLForURL(resolvedURL, @"download");
}

static NSURL *fixedRequestURL(NSURL *url, NSString *context) {
    if (gPodcastsXBypassRequestHooks) return url;

    // Apply store rewrites here too — many iTunesStore operations create
    // NSURLs via CFURL or plist deserialization, bypassing our NSURL hooks,
    // so the URL only reaches us when a request is built around it.
    NSString *original = url.absoluteString;
    NSString *rewritten = fixedURLStringForCreation(original, context);
    if (rewritten && ![rewritten isEqualToString:original]) {
        NSURL *rewrittenURL = [NSURL URLWithString:rewritten];
        if (rewrittenURL) return rewrittenURL;
    }

    NSURL *proxiedURL = feedOrArtworkProxyURL(url, context);
    if (proxiedURL != url) return proxiedURL;

    return fixedDownloadURL(url, context);
}

// Catch ALL NSURL creation — filter for audio/episode URLs
%hook NSURL

+ (id)URLWithString:(NSString *)URLString {
    logURLStringIfInteresting(URLString, @"NSURL+");
    return %orig(fixedURLStringForCreation(URLString, @"NSURL+"));
}

+ (id)URLWithString:(NSString *)URLString relativeToURL:(NSURL *)baseURL {
    logURLStringIfInteresting(URLString, @"NSURL+ rel");
    return %orig(fixedURLStringForCreation(URLString, @"NSURL+ rel"), baseURL);
}

- (id)initWithString:(NSString *)URLString {
    logURLStringIfInteresting(URLString, @"NSURL");
    return %orig(fixedURLStringForCreation(URLString, @"NSURL"));
}

- (id)initWithString:(NSString *)URLString relativeToURL:(NSURL *)baseURL {
    logURLStringIfInteresting(URLString, @"NSURL rel");
    return %orig(fixedURLStringForCreation(URLString, @"NSURL rel"), baseURL);
}

%end

// Hook ALL SU* view controllers to find which one actually appears
%hook SUNetworkLockoutViewController
- (void)viewDidLoad {
    appendLog(@"[SUNetworkLockout] viewDidLoad — network check failed!");
    %orig;
}
- (void)viewWillAppear:(BOOL)animated {
    appendLog(@"[SUNetworkLockout] viewWillAppear");
    %orig;
}
%end

%hook SUPlaceholderViewController
- (void)viewWillAppear:(BOOL)animated {
    appendLog(@"[SUPlaceholder] viewWillAppear");
    %orig;
}
%end

%hook SUClientController
- (void)loadSections {
    appendLog(@"[SUClientController] loadSections");
    %orig;
}
- (void)sectionsDidLoad:(id)sections {
    appendLog([NSString stringWithFormat:@"[SUClientController] sectionsDidLoad: %@", sections]);
    %orig;
}
- (void)sectionsDidFailWithError:(id)error {
    appendLog([NSString stringWithFormat:@"[SUClientController] sectionsDidFail: %@", error]);
    %orig;
}
- (BOOL)isStoreEnabled {
    BOOL result = %orig;
    appendLog([NSString stringWithFormat:@"[SUClientController] isStoreEnabled -> %d", result]);
    return result;
}
- (void)bagDidLoadNotification:(id)notification {
    appendLog(@"[SUClientController] bagDidLoadNotification:");
    %orig(notification);
}
- (NSString *)storeContentLanguage {
    NSString *result = %orig;
    appendLog([NSString stringWithFormat:@"[SUClientController] storeContentLanguage -> %@", result]);
    return result;
}
%end

%hook ISLoadURLBagOperation
- (void)run {
    appendLog(@"[ISLoadURLBag] run — entering");
    %orig;
    appendLog(@"[ISLoadURLBag] run — exited");
}
- (void)start {
    appendLog(@"[ISLoadURLBag] start — entering");
    %orig;
    appendLog(@"[ISLoadURLBag] start — exited");
}
- (void)main {
    appendLog(@"[ISLoadURLBag] main — entering");
    %orig;
    appendLog(@"[ISLoadURLBag] main — exited");
}
%end

%hook SULoadSectionsOperation
- (void)start {
    NSOperation *op = (NSOperation *)self;
    appendLog([NSString stringWithFormat:@"[SULoadSectionsOp] start (logos) — isReady=%d isExecuting=%d isFinished=%d isCancelled=%d",
               [op isReady], [op isExecuting], [op isFinished], [op isCancelled]]);
    %orig;
    appendLog([NSString stringWithFormat:@"[SULoadSectionsOp] start (logos) returned — isReady=%d isExecuting=%d isFinished=%d",
               [op isReady], [op isExecuting], [op isFinished]]);
    // Force-run and notification posting disabled — were causing crashes
}
- (void)main {
    appendLog(@"[SULoadSectionsOp] main — entering");
    %orig;
    appendLog(@"[SULoadSectionsOp] main — exited");
}
- (void)run {
    appendLog(@"[SULoadSectionsOp] run — entering");
    %orig;
    appendLog(@"[SULoadSectionsOp] run — exited");
}
- (void)_loadSectionsFromNetworkWithDictionary:(NSDictionary *)dict {
    appendLog([NSString stringWithFormat:@"[SULoadSectionsOp] fromNetwork dict=%@", dict]);
    %orig(dict);
    appendLog(@"[SULoadSectionsOp] fromNetwork returned");
}
- (void)_loadSectionsFromCacheForVersion:(NSString *)version {
    appendLog([NSString stringWithFormat:@"[SULoadSectionsOp] fromCache version=%@", version]);
    %orig(version);
}
- (void)_setSectionsResponse:(id)response {
    appendLog([NSString stringWithFormat:@"[SULoadSectionsOp] setSectionsResponse: %@", response]);
    %orig(response);
}
- (void)setShouldUseCache:(BOOL)useCache {
    appendLog([NSString stringWithFormat:@"[SULoadSectionsOp] setShouldUseCache: %d", useCache]);
    %orig(useCache);
}
%end

// Hook the Podcasts store's custom web view
%hook SUWebView
- (void)loadArchive:(id)archive {
    appendLog([NSString stringWithFormat:@"[SUWebView loadArchive] %@", [archive class]]);
    %orig(archive);
}
- (void)loadRequest:(NSURLRequest *)request {
    appendLog([NSString stringWithFormat:@"[SUWebView loadRequest] %@", request.URL.absoluteString]);
    %orig(request);
}
- (void)loadHTMLString:(NSString *)string baseURL:(NSURL *)baseURL {
    appendLog([NSString stringWithFormat:@"[SUWebView loadHTML] base=%@ len=%lu", baseURL.absoluteString, (unsigned long)string.length]);
    %orig(string, baseURL);
}
- (void)stopLoading {
    appendLog(@"[SUWebView stopLoading]");
    %orig;
}
%end

%hook SUScriptViewController
- (void)viewDidLoad {
    appendLog(@"[SUScriptVC viewDidLoad]");
    %orig;
}
- (void)viewWillAppear:(BOOL)animated {
    appendLog(@"[SUScriptVC viewWillAppear]");
    %orig;
}
%end

%hook SUStorePageViewController
- (void)viewDidLoad {
    appendLog(@"[SUStorePageVC viewDidLoad]");
    %orig;
}
- (void)viewWillAppear:(BOOL)animated {
    appendLog(@"[SUStorePageVC viewWillAppear]");
    %orig;
}
%end

// Catch the alert
%hook UIAlertView
- (void)show {
    appendLog([NSString stringWithFormat:@"[Alert] %@ / %@", self.title, self.message]);
    // Suppress the iOS 6 "Cannot connect to iTunes Store" alert. The actual
    // sections/grouping data loads fine through search.itunes.apple.com (see
    // SULoadSectionsOp setSectionsResponse: <non-null>), but ancillary store
    // operations whose endpoints iOS 6's TLS can't reach trigger this alert.
    // Suppressing it lets the Store tab render its actual content.
    if ([self.title rangeOfString:@"iTunes Store" options:NSCaseInsensitiveSearch].location != NSNotFound ||
        [self.message rangeOfString:@"iTunes Store" options:NSCaseInsensitiveSearch].location != NSNotFound) {
        appendLog(@"[Alert suppressed iTunes Store]");
        return;
    }
    
    // Suppress "Playback Failed" during the 15-second launch window where we intentionally
    // reject oversized media requests with 416 to prevent OOMs.
    if ([self.message rangeOfString:@"Playback Failed" options:NSCaseInsensitiveSearch].location != NSNotFound &&
        gPodcastsXLaunchTime > 0 &&
        CFAbsoluteTimeGetCurrent() - gPodcastsXLaunchTime < 15.0) {
        appendLog(@"[Alert suppressed Playback Failed (launch window)]");
        return;
    }
    
    %orig;
}
%end

%hook UIWebView
- (void)loadRequest:(NSURLRequest *)request {
    appendLog([NSString stringWithFormat:@"[UIWebView loadRequest] %@", request.URL.absoluteString]);
    %orig(request);
}

- (void)loadHTMLString:(NSString *)string baseURL:(NSURL *)baseURL {
    appendLog([NSString stringWithFormat:@"[UIWebView loadHTML] base=%@ len=%lu",
               baseURL.absoluteString, (unsigned long)string.length]);
    %orig(string, baseURL);
}
%end

// MPMoviePlayerController — all variants
%hook MPMoviePlayerController
- (id)initWithContentURL:(NSURL *)url {
    appendLog([NSString stringWithFormat:@"[MPMovie init] %@", url.absoluteString]);
    return %orig(fixedPlaybackURL(url, @"MPMovie init"));
}
- (void)setContentURL:(NSURL *)url {
    appendLog([NSString stringWithFormat:@"[MPMovie setURL] %@", url.absoluteString]);
    %orig(fixedPlaybackURL(url, @"MPMovie setURL"));
}
- (void)play {
    appendLog(@"[MPMovie play]");
    %orig;
}
%end

// AVPlayer / AVPlayerItem / AVAsset
%hook AVPlayer
+ (id)playerWithURL:(NSURL *)URL {
    appendLog([NSString stringWithFormat:@"[AVPlayer+] %@", URL.absoluteString]);
    return %orig(fixedPlaybackURL(URL, @"AVPlayer+"));
}
- (id)initWithURL:(NSURL *)URL {
    appendLog([NSString stringWithFormat:@"[AVPlayer init] %@", URL.absoluteString]);
    return %orig(fixedPlaybackURL(URL, @"AVPlayer init"));
}
- (void)play {
    appendLog(@"[AVPlayer play]");
    %orig;
}
%end

%hook AVPlayerItem
+ (id)playerItemWithURL:(NSURL *)URL {
    appendLog([NSString stringWithFormat:@"[AVItem+] %@", URL.absoluteString]);
    return %orig(fixedPlaybackURL(URL, @"AVItem+"));
}
- (id)initWithURL:(NSURL *)URL {
    appendLog([NSString stringWithFormat:@"[AVItem init] %@", URL.absoluteString]);
    return %orig(fixedPlaybackURL(URL, @"AVItem init"));
}
%end

%hook AVURLAsset
+ (id)URLAssetWithURL:(NSURL *)URL options:(NSDictionary *)options {
    appendLog([NSString stringWithFormat:@"[AVURLAsset+] %@", URL.absoluteString]);
    NSURL *fixedURL = fixedPlaybackURL(URL, @"AVURLAsset+");
    return %orig(fixedURL, mergedAssetOptions(options, fixedURL));
}

- (id)initWithURL:(NSURL *)URL options:(NSDictionary *)options {
    appendLog([NSString stringWithFormat:@"[AVURLAsset init] %@", URL.absoluteString]);
    NSURL *fixedURL = fixedPlaybackURL(URL, @"AVURLAsset init");
    return %orig(fixedURL, mergedAssetOptions(options, fixedURL));
}
%end

%hook NSURLRequest
+ (id)requestWithURL:(NSURL *)URL {
    if (isAudioURL(URL.absoluteString) || isStoreURL(URL.absoluteString)) {
        appendLog([NSString stringWithFormat:@"[NSURLRequest+] %@", URL.absoluteString]);
    }
    return %orig(fixedRequestURL(URL, @"NSURLRequest+"));
}

+ (id)requestWithURL:(NSURL *)URL cachePolicy:(NSURLRequestCachePolicy)cachePolicy timeoutInterval:(NSTimeInterval)timeoutInterval {
    if (isAudioURL(URL.absoluteString) || isStoreURL(URL.absoluteString)) {
        appendLog([NSString stringWithFormat:@"[NSURLRequest+ policy] %@", URL.absoluteString]);
    }
    return %orig(fixedRequestURL(URL, @"NSURLRequest+ policy"), cachePolicy, timeoutInterval);
}

- (id)initWithURL:(NSURL *)URL {
    if (isAudioURL(URL.absoluteString) || isStoreURL(URL.absoluteString)) {
        appendLog([NSString stringWithFormat:@"[NSURLRequest init] %@", URL.absoluteString]);
    }
    return %orig(fixedRequestURL(URL, @"NSURLRequest init"));
}

- (id)initWithURL:(NSURL *)URL cachePolicy:(NSURLRequestCachePolicy)cachePolicy timeoutInterval:(NSTimeInterval)timeoutInterval {
    if (isAudioURL(URL.absoluteString) || isStoreURL(URL.absoluteString)) {
        appendLog([NSString stringWithFormat:@"[NSURLRequest init policy] %@", URL.absoluteString]);
    }
    return %orig(fixedRequestURL(URL, @"NSURLRequest init policy"), cachePolicy, timeoutInterval);
}
%end

%hook NSMutableURLRequest
- (void)setURL:(NSURL *)URL {
    if (isAudioURL(URL.absoluteString) || isStoreURL(URL.absoluteString)) {
        appendLog([NSString stringWithFormat:@"[NSMutableURLRequest setURL] %@", URL.absoluteString]);
    }
    %orig(fixedRequestURL(URL, @"NSMutableURLRequest setURL"));
}
%end

%hook NSURLConnection
+ (NSData *)sendSynchronousRequest:(NSURLRequest *)request returningResponse:(NSURLResponse **)response error:(NSError **)error {
    BOOL isInteresting = isAudioURL(request.URL.absoluteString) || isStoreURL(request.URL.absoluteString);
    if (isInteresting) {
        appendLog([NSString stringWithFormat:@"[NSURLConnection sync] %@", request.URL.absoluteString]);
    } else if ([request.URL.host.lowercaseString rangeOfString:@"apple"].location != NSNotFound ||
               [request.URL.host.lowercaseString rangeOfString:@"itunes"].location != NSNotFound) {
        appendLog([NSString stringWithFormat:@"[NSURLConnection sync APPLE] %@", request.URL.absoluteString]);
    }
    NSData *data = %orig(request, response, error);
    if (isInteresting) {
        appendLog([NSString stringWithFormat:@"[NSURLConnection sync done] url=%@ len=%lu err=%@ resp=%@",
                   request.URL.absoluteString, (unsigned long)data.length, error ? *error : nil, response ? *response : nil]);
    } else if ([request.URL.host.lowercaseString rangeOfString:@"apple"].location != NSNotFound ||
               [request.URL.host.lowercaseString rangeOfString:@"itunes"].location != NSNotFound) {
        appendLog([NSString stringWithFormat:@"[NSURLConnection sync APPLE done] url=%@ len=%lu err=%@",
                   request.URL.absoluteString, (unsigned long)data.length, error ? *error : nil]);
    }
    return data;
}

+ (NSURLConnection *)connectionWithRequest:(NSURLRequest *)request delegate:(id)delegate {
    if (isAudioURL(request.URL.absoluteString) || isStoreURL(request.URL.absoluteString)) {
        appendLog([NSString stringWithFormat:@"[NSURLConnection+] %@", request.URL.absoluteString]);
    }
    return %orig(request, delegate);
}

- (id)initWithRequest:(NSURLRequest *)request delegate:(id)delegate {
    if (isAudioURL(request.URL.absoluteString) || isStoreURL(request.URL.absoluteString)) {
        appendLog([NSString stringWithFormat:@"[NSURLConnection init] %@", request.URL.absoluteString]);
    }
    return %orig(request, delegate);
}

- (id)initWithRequest:(NSURLRequest *)request delegate:(id)delegate startImmediately:(BOOL)startImmediately {
    if (isAudioURL(request.URL.absoluteString) || isStoreURL(request.URL.absoluteString)) {
        appendLog([NSString stringWithFormat:@"[NSURLConnection init start=%d] %@", startImmediately, request.URL.absoluteString]);
    }
    return %orig(request, delegate, startImmediately);
}
%end

%hook AVAsset
+ (id)assetWithURL:(NSURL *)URL {
    appendLog([NSString stringWithFormat:@"[AVAsset] %@", URL.absoluteString]);
    return %orig(fixedPlaybackURL(URL, @"AVAsset"));
}
%end

// Hook SSDownload to observe its URL and state transitions.
// SSDownload is the private itunesstored class that owns each episode download.
// Logging its URL tells us whether it holds our proxy URL or the original CDN URL.
%hook SSDownload
- (NSURL *)url {
    return %orig;
}
- (void)resume {
    NSURL *url = [(id)self url];
    appendLog([NSString stringWithFormat:@"[SSDownload resume] %@", url.absoluteString ?: @"nil"]);
    %orig;
}
- (void)stop {
    appendLog(@"[SSDownload stop]");
    %orig;
}
- (void)setState:(NSInteger)state {
    NSURL *url = [(id)self url];
    appendLog([NSString stringWithFormat:@"[SSDownload setState:%ld] %@",
               (long)state, url.absoluteString ?: @"nil"]);
    %orig(state);
}
%end

// Hook NSURLDownload to catch download-to-disk requests that itunesstored
// may issue separately from its HEAD probe via SSURLConnectionRequest.
// Without this hook, the GET step could use the original CDN URL (bypassing
// our proxy) and fail with iOS 6 TLS error -9824, leaving download at "Waiting…".
%hook NSURLDownload
- (id)initWithRequest:(NSURLRequest *)request delegate:(id)delegate {
    NSString *urlStr = request.URL.absoluteString;
    appendLog([NSString stringWithFormat:@"[NSURLDownload init] %@", urlStr]);
    NSURLRequest *fixed = [NSURLRequest requestWithURL:fixedRequestURL(request.URL, @"NSURLDownload")];
    return %orig(fixed, delegate);
}
%end

// Hook SSURLConnectionRequest to see what URLs it's trying to fetch
%hook SSURLConnectionRequest
- (id)initWithRequest:(NSURLRequest *)request {
    if (request && request.URL) {
        NSString *urlStr = request.URL.absoluteString;
        if ([urlStr.lowercaseString rangeOfString:@"apple"].location != NSNotFound ||
            [urlStr.lowercaseString rangeOfString:@"itunes"].location != NSNotFound ||
            isAudioURL(urlStr) || isStoreURL(urlStr)) {
            appendLog([NSString stringWithFormat:@"[SSURLConnectionRequest init] %@", urlStr]);
        }
    }
    return %orig(request);
}

- (void)setRequest:(NSURLRequest *)request {
    if (request && request.URL) {
        NSString *urlStr = request.URL.absoluteString;
        if ([urlStr.lowercaseString rangeOfString:@"apple"].location != NSNotFound ||
            [urlStr.lowercaseString rangeOfString:@"itunes"].location != NSNotFound ||
            isAudioURL(urlStr) || isStoreURL(urlStr)) {
            appendLog([NSString stringWithFormat:@"[SSURLConnectionRequest setRequest] %@", urlStr]);
        }
    }
    %orig(request);
}
%end

// Force TLS 1.2 on all SSL contexts — iOS 6 supports TLS 1.2 but defaults to TLS 1.0
// kTLSProtocol1=4  kTLSProtocol11=7  kTLSProtocol12=8
static OSStatus (*orig_SSLSetProtocolVersionMax)(SSLContextRef context, SSLProtocol maxVersion);
static OSStatus my_SSLSetProtocolVersionMax(SSLContextRef context, SSLProtocol maxVersion) {
    appendLog([NSString stringWithFormat:@"[SSL] SetProtocolVersionMax: %u -> forcing 8 (TLS1.2)", (unsigned)maxVersion]);
    OSStatus r = orig_SSLSetProtocolVersionMax(context, (SSLProtocol)8);
    if (r != errSecSuccess) {
        appendLog([NSString stringWithFormat:@"[SSL] TLS1.2 max rejected (%d), using %u", (int)r, (unsigned)maxVersion]);
        r = orig_SSLSetProtocolVersionMax(context, maxVersion);
    }
    return r;
}

static OSStatus (*orig_SSLSetProtocolVersionMin)(SSLContextRef context, SSLProtocol minVersion);
static OSStatus my_SSLSetProtocolVersionMin(SSLContextRef context, SSLProtocol minVersion) {
    appendLog([NSString stringWithFormat:@"[SSL] SetProtocolVersionMin: %u", (unsigned)minVersion]);
    return orig_SSLSetProtocolVersionMin(context, minVersion);
}

static OSStatus (*orig_SSLHandshake)(SSLContextRef context);
static OSStatus my_SSLHandshake(SSLContextRef context) {
    OSStatus r = orig_SSLHandshake(context);
    if (r != errSecSuccess && r != -9854) { // -9854 = errSSLWouldBlock (async, not an error)
        appendLog([NSString stringWithFormat:@"[SSL] Handshake result: %d", (int)r]);
    } else if (r == errSecSuccess) {
        appendLog(@"[SSL] Handshake succeeded");
    }
    return r;
}

// Hook CFHTTPMessageCreateRequest to capture exact CFNetwork-level request URLs
static CFHTTPMessageRef (*orig_CFHTTPMessageCreateRequest)(CFAllocatorRef alloc, CFStringRef requestMethod, CFURLRef requestURL, CFStringRef httpVersion);
static CFHTTPMessageRef my_CFHTTPMessageCreateRequest(CFAllocatorRef alloc, CFStringRef requestMethod, CFURLRef requestURL, CFStringRef httpVersion) {
    if (requestURL) {
        NSString *urlStr = (__bridge NSString *)CFURLGetString(requestURL);
        if (urlStr) {
            NSString *lower = urlStr.lowercaseString;
            if ([lower rangeOfString:@"apple.com"].location != NSNotFound ||
                [lower rangeOfString:@"itunes.com"].location != NSNotFound ||
                [lower rangeOfString:@"mzstatic"].location != NSNotFound) {
                NSString *method = (__bridge NSString *)requestMethod ?: @"?";
                appendLog([NSString stringWithFormat:@"[CFHTTP] %@ %@", method, urlStr]);
            }
        }
    }
    return orig_CFHTTPMessageCreateRequest(alloc, requestMethod, requestURL, httpVersion);
}

// Hook connect() to capture every TCP connection attempt
static int (*orig_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
static int my_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (addr) {
        if (addr->sa_family == AF_INET) {
            struct sockaddr_in *in4 = (struct sockaddr_in *)addr;
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &in4->sin_addr, ip, sizeof(ip));
            uint16_t port = ntohs(in4->sin_port);
            appendLog([NSString stringWithFormat:@"[connect4] %s:%d", ip, port]);
        } else if (addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr;
            char ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &in6->sin6_addr, ip, sizeof(ip));
            uint16_t port = ntohs(in6->sin6_port);
            appendLog([NSString stringWithFormat:@"[connect6] %s:%d", ip, port]);
        }
    }
    return orig_connect(sockfd, addr, addrlen);
}

// Bypass SSL validation for store hosts redirected via /etc/hosts
static OSStatus (*orig_SecTrustEvaluate)(SecTrustRef trust, SecTrustResultType *result);
static OSStatus my_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    OSStatus status = orig_SecTrustEvaluate(trust, result);
    if (result) {
        if (*result == kSecTrustResultRecoverableTrustFailure ||
            *result == kSecTrustResultFatalTrustFailure ||
            *result == kSecTrustResultDeny) {
            appendLog([NSString stringWithFormat:@"[SecTrust] bypassing failure %d", (int)*result]);
            *result = kSecTrustResultProceed;
            return errSecSuccess;
        }
    }
    return status;
}

static BOOL (*orig_NSURLRequestAllowsAnyHTTPSCertificateForHost)(id self, SEL _cmd, NSString *host);
static BOOL podcastx_NSURLRequestAllowsAnyHTTPSCertificateForHost(id self, SEL _cmd, NSString *host) {
    if (shouldRelaxHTTPSHost(host)) {
        appendLog([NSString stringWithFormat:@"[HTTPSCert NSURLRequest] allow %@", host]);
        return YES;
    }
    return orig_NSURLRequestAllowsAnyHTTPSCertificateForHost ? orig_NSURLRequestAllowsAnyHTTPSCertificateForHost(self, _cmd, host) : NO;
}

static BOOL (*orig_NSURLConnectionAllowsAnyHTTPSCertificateForHost)(id self, SEL _cmd, NSString *host);
static BOOL podcastx_NSURLConnectionAllowsAnyHTTPSCertificateForHost(id self, SEL _cmd, NSString *host) {
    if (shouldRelaxHTTPSHost(host)) {
        appendLog([NSString stringWithFormat:@"[HTTPSCert NSURLConnection] allow %@", host]);
        return YES;
    }
    return orig_NSURLConnectionAllowsAnyHTTPSCertificateForHost ? orig_NSURLConnectionAllowsAnyHTTPSCertificateForHost(self, _cmd, host) : NO;
}

static void installHTTPSCertificateBypassMethods(void) {
    SEL selector = NSSelectorFromString(@"allowsAnyHTTPSCertificateForHost:");
    Class requestClass = NSClassFromString(@"NSURLRequest");
    Class requestMeta = object_getClass(requestClass);
    if (class_getClassMethod(requestClass, selector)) {
        MSHookMessageEx(requestMeta,
                        selector,
                        (IMP)podcastx_NSURLRequestAllowsAnyHTTPSCertificateForHost,
                        (IMP *)&orig_NSURLRequestAllowsAnyHTTPSCertificateForHost);
    } else {
        class_addMethod(requestMeta,
                        selector,
                        (IMP)podcastx_NSURLRequestAllowsAnyHTTPSCertificateForHost,
                        "c@:@");
    }

    Class connectionClass = NSClassFromString(@"NSURLConnection");
    Class connectionMeta = object_getClass(connectionClass);
    if (class_getClassMethod(connectionClass, selector)) {
        MSHookMessageEx(connectionMeta,
                        selector,
                        (IMP)podcastx_NSURLConnectionAllowsAnyHTTPSCertificateForHost,
                        (IMP *)&orig_NSURLConnectionAllowsAnyHTTPSCertificateForHost);
    } else {
        class_addMethod(connectionMeta,
                        selector,
                        (IMP)podcastx_NSURLConnectionAllowsAnyHTTPSCertificateForHost,
                        "c@:@");
    }

    appendLog(@"[HTTPSCert] bypass methods installed");
}

%ctor {
    gPodcastsXLaunchTime = CFAbsoluteTimeGetCurrent();
    NSString *processName = [[NSProcessInfo processInfo] processName];
    appendLog([NSString stringWithFormat:@"[PodcastFix] dylib loaded in %@", processName]);
    // StoreURLProtocol disabled: iTunesStoreX handles all Store URL rewriting in this process.

    installHTTPSCertificateBypassMethods();
    MSHookFunction((void *)SecTrustEvaluate, (void *)my_SecTrustEvaluate, (void **)&orig_SecTrustEvaluate);
    appendLog(@"[SecTrust] hook installed");
    MSHookFunction((void *)CFHTTPMessageCreateRequest, (void *)my_CFHTTPMessageCreateRequest, (void **)&orig_CFHTTPMessageCreateRequest);
    appendLog(@"[CFHTTP] hook installed");
    MSHookFunction((void *)connect, (void *)my_connect, (void **)&orig_connect);
    appendLog(@"[connect] hook installed");
    MSHookFunction((void *)SSLSetProtocolVersionMax, (void *)my_SSLSetProtocolVersionMax, (void **)&orig_SSLSetProtocolVersionMax);
    MSHookFunction((void *)SSLSetProtocolVersionMin, (void *)my_SSLSetProtocolVersionMin, (void **)&orig_SSLSetProtocolVersionMin);
    MSHookFunction((void *)SSLHandshake, (void *)my_SSLHandshake, (void **)&orig_SSLHandshake);
    appendLog(@"[SSL] hooks installed");
    // The broad StoreTrace hook is useful for discovery, but it destabilizes
    // iTunesStore operations once inherited start/main/run calls are forwarded.
    // Keep the targeted Store hooks below instead.
    if ([processName isEqualToString:@"Podcasts"]) {
        startProxyServer();
        dumpClassMethods(@"SUClientController");
        dumpClassMethods(@"SULoadSectionsOperation");
        dumpClassMethods(@"SUWebView");
        dumpClassMethods(@"ISLoadURLBagOperation");
        dumpClassMethods(@"ISOperation");
    }
    if ([processName isEqualToString:@"itunesstored"]) {
        startProxyServer();
        dumpClassMethods(@"ISLoadURLBagOperation");
        dumpClassMethods(@"ISOperation");
        dumpClassMethods(@"SSDownload");
        dumpClassMethods(@"SSURLConnectionRequest");
    }

    [[NSNotificationCenter defaultCenter]
        addObserverForName:@"MPMoviePlayerPlaybackDidFinishNotification"
                    object:nil
                     queue:nil
                usingBlock:^(NSNotification *note) {
        NSInteger reason = [[note.userInfo objectForKey:@"MPMoviePlayerPlaybackDidFinishReasonUserInfoKey"] integerValue];
        NSError *err = [note.userInfo objectForKey:@"error"];
        appendLog([NSString stringWithFormat:@"[MPMovieFinish] reason=%ld err=%@",
                   (long)reason, err]);
    }];

    [[NSNotificationCenter defaultCenter]
        addObserverForName:@"AVPlayerItemFailedToPlayToEndTimeNotification"
                    object:nil
                     queue:nil
                usingBlock:^(NSNotification *note) {
        NSError *err = [note.userInfo objectForKey:@"AVPlayerItemFailedToPlayToEndTimeErrorKey"];
        appendLog([NSString stringWithFormat:@"[AVItemFailed] err=%@ userInfo=%@",
                   err, note.userInfo]);
    }];

    [[NSNotificationCenter defaultCenter]
        addObserverForName:@"AVPlayerItemNewErrorLogEntryNotification"
                    object:nil
                     queue:nil
                usingBlock:^(NSNotification *note) {
        AVPlayerItem *item = (AVPlayerItem *)note.object;
        appendLog([NSString stringWithFormat:@"[AVItemErrorLog] %@",
                   item.errorLog.events]);
    }];
}
