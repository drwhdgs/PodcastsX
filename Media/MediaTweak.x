// PodcastsXMedia — minimal in-process patch for mediaserverd on iOS 6.
//
// Keep TINY. A crash here takes down audio device-wide until respring.

#import <Security/Security.h>
#import <Security/SecureTransport.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>

extern void MSHookFunction(void *symbol, void *replace, void **result);

#define PXM_LOG_PATH "/tmp/podcastxmedia.log"

static void pxm_log(const char *fmt, ...) {
    FILE *f = fopen(PXM_LOG_PATH, "a");
    if (!f) return;
    time_t now = time(NULL);
    char ts[32];
    strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&now));
    fprintf(f, "[%s pid=%d] ", ts, (int)getpid());
    va_list ap; __builtin_va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    __builtin_va_end(ap);
    fputc('\n', f);
    fclose(f);
}

// kTLSProtocol12 = 8
static OSStatus (*orig_SSLSetProtocolVersionMax)(SSLContextRef, SSLProtocol);
static OSStatus my_SSLSetProtocolVersionMax(SSLContextRef ctx, SSLProtocol maxVersion) {
    OSStatus r = orig_SSLSetProtocolVersionMax(ctx, (SSLProtocol)8);
    pxm_log("SSLSetProtocolVersionMax req=%u forced=8 r=%d", (unsigned)maxVersion, (int)r);
    if (r != errSecSuccess) {
        r = orig_SSLSetProtocolVersionMax(ctx, maxVersion);
    }
    return r;
}

static OSStatus (*orig_SSLSetProtocolVersionMin)(SSLContextRef, SSLProtocol);
static OSStatus my_SSLSetProtocolVersionMin(SSLContextRef ctx, SSLProtocol minVersion) {
    pxm_log("SSLSetProtocolVersionMin req=%u", (unsigned)minVersion);
    return orig_SSLSetProtocolVersionMin(ctx, minVersion);
}

static OSStatus (*orig_SSLHandshake)(SSLContextRef);
static OSStatus my_SSLHandshake(SSLContextRef ctx) {
    OSStatus r = orig_SSLHandshake(ctx);
    if (r != errSecSuccess && r != -9803 /* errSSLWouldBlock */ && r != -9854) {
        pxm_log("SSLHandshake r=%d", (int)r);
    } else if (r == errSecSuccess) {
        pxm_log("SSLHandshake OK");
    }
    return r;
}

static OSStatus (*orig_SecTrustEvaluate)(SecTrustRef, SecTrustResultType *);
static OSStatus my_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    OSStatus status = orig_SecTrustEvaluate(trust, result);
    if (result) {
        SecTrustResultType original = *result;
        if (*result == kSecTrustResultRecoverableTrustFailure ||
            *result == kSecTrustResultFatalTrustFailure ||
            *result == kSecTrustResultDeny) {
            pxm_log("SecTrustEvaluate bypass %d -> Proceed", (int)original);
            *result = kSecTrustResultProceed;
            return errSecSuccess;
        }
    }
    return status;
}

__attribute__((constructor))
static void PodcastsXMediaInit(void) {
    pxm_log("loaded");
    MSHookFunction((void *)SSLSetProtocolVersionMax,
                   (void *)my_SSLSetProtocolVersionMax,
                   (void **)&orig_SSLSetProtocolVersionMax);
    MSHookFunction((void *)SSLSetProtocolVersionMin,
                   (void *)my_SSLSetProtocolVersionMin,
                   (void **)&orig_SSLSetProtocolVersionMin);
    MSHookFunction((void *)SSLHandshake,
                   (void *)my_SSLHandshake,
                   (void **)&orig_SSLHandshake);
    MSHookFunction((void *)SecTrustEvaluate,
                   (void *)my_SecTrustEvaluate,
                   (void **)&orig_SecTrustEvaluate);
    pxm_log("hooks installed");
}
