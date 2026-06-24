#line 1 "Tweak.xm"
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <fishhook.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>

#pragma clang diagnostic ignored "-Wunused-function"
#pragma clang diagnostic ignored "-Wunused-variable"

static NSString *g_hapPath = nil;
static NSString *g_hapBundleID = nil;
static NSString *g_hapChecksum = nil;
static NSString *g_hapMD5 = nil;
static NSString *g_hapSHA1 = nil;
static BOOL     g_intercept = NO;
static NSFileHandle *g_hapFileHandle = nil;
static long long g_hapFileSize = 0;
static NSInteger g_hapChunkSize = 0;       
static NSString  *g_hapOffsetKey = nil;    
static NSInteger g_utilChunkCount = 0;        





@interface WSSCommonFileInfo : NSObject
@end

static NSMutableArray *g_logs = nil;
static void HWSLog(NSString *msg) {
    if (!g_logs) g_logs = [NSMutableArray new];
    dispatch_async(dispatch_get_main_queue(), ^{
        NSDateFormatter *df = [NSDateFormatter new];
        [df setDateFormat:@"HH:mm:ss.SSS"];
        NSString *ts = [df stringFromDate:[NSDate date]];
        [g_logs addObject:[NSString stringWithFormat:@"[%@] %@", ts, msg]];
        if (g_logs.count > 5000) [g_logs removeObjectAtIndex:0];
    });
}





static NSString *fileSHA256(NSString *path) {
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data) return nil;
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for(int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++)
        [output appendFormat:@"%02x", digest[i]];
    return output;
}

static NSString *fileMD5(NSString *path) {
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data) return nil;
    uint8_t digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for(int i = 0; i < CC_MD5_DIGEST_LENGTH; i++)
        [output appendFormat:@"%02x", digest[i]];
    return output;
}

static NSString *fileSHA1(NSString *path) {
    NSData *data = [NSData dataWithContentsOfFile:path];
    if (!data) return nil;
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
    for(int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++)
        [output appendFormat:@"%02x", digest[i]];
    return output;
}





typedef OSStatus (*SecCodeCheckValidity_func)(void *code, uint32_t flags, void *req);
static SecCodeCheckValidity_func orig_SecCodeCheckValidity;
static OSStatus my_SecCodeCheckValidity(void *code, uint32_t flags, void *req) {
    return 0; 
}


typedef OSStatus (*SecTrustEvaluate_func)(SecTrustRef trust, SecTrustResultType *result);
static SecTrustEvaluate_func orig_SecTrustEvaluate;
static OSStatus my_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    HWSLog(@"🔐 [CertBypass] SecTrustEvaluate 被拦截！强制返回信任！");
    if (result) *result = kSecTrustResultProceed;
    return noErr;
}


typedef bool (*SecTrustEvaluateWithError_func)(SecTrustRef trust, CFErrorRef *error);
static SecTrustEvaluateWithError_func orig_SecTrustEvaluateWithError;
static bool my_SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error) {
    HWSLog(@"🔐 [CertBypass] SecTrustEvaluateWithError 被拦截！强制返回 YES！");
    if (error) *error = NULL;
    return YES;
}





#include <substrate.h>
#if defined(__clang__)
#if __has_feature(objc_arc)
#define _LOGOS_SELF_TYPE_NORMAL __unsafe_unretained
#define _LOGOS_SELF_TYPE_INIT __attribute__((ns_consumed))
#define _LOGOS_SELF_CONST const
#define _LOGOS_RETURN_RETAINED __attribute__((ns_returns_retained))
#else
#define _LOGOS_SELF_TYPE_NORMAL
#define _LOGOS_SELF_TYPE_INIT
#define _LOGOS_SELF_CONST
#define _LOGOS_RETURN_RETAINED
#endif
#else
#define _LOGOS_SELF_TYPE_NORMAL
#define _LOGOS_SELF_TYPE_INIT
#define _LOGOS_SELF_CONST
#define _LOGOS_RETURN_RETAINED
#endif

__asm__(".linker_option \"-framework\", \"CydiaSubstrate\"");

@class NSFileManager; @class NSFileHandle; @class UIWindow; @class NSMutableURLRequest; @class NSJSONSerialization; @class SHWatchAppStoreManager; @class NSData; @class SHDWiFiTransferManager; @class NSInputStream; @class WSSCommonFileMgrSendUtil; @class WSSCommonFileMgr; @class NSBundle; @class WSSCommonFileInfo; @class SHDWiFiCommandSend; @class NSNotificationCenter; @class NSURLSession; 
static NSString * (*_logos_orig$_ungrouped$NSBundle$bundleIdentifier)(_LOGOS_SELF_TYPE_NORMAL NSBundle* _LOGOS_SELF_CONST, SEL); static NSString * _logos_method$_ungrouped$NSBundle$bundleIdentifier(_LOGOS_SELF_TYPE_NORMAL NSBundle* _LOGOS_SELF_CONST, SEL); static id (*_logos_orig$_ungrouped$NSBundle$objectForInfoDictionaryKey$)(_LOGOS_SELF_TYPE_NORMAL NSBundle* _LOGOS_SELF_CONST, SEL, NSString *); static id _logos_method$_ungrouped$NSBundle$objectForInfoDictionaryKey$(_LOGOS_SELF_TYPE_NORMAL NSBundle* _LOGOS_SELF_CONST, SEL, NSString *); static NSMutableURLRequest* (*_logos_orig$_ungrouped$NSMutableURLRequest$initWithURL$)(_LOGOS_SELF_TYPE_INIT NSMutableURLRequest*, SEL, NSURL *) _LOGOS_RETURN_RETAINED; static NSMutableURLRequest* _logos_method$_ungrouped$NSMutableURLRequest$initWithURL$(_LOGOS_SELF_TYPE_INIT NSMutableURLRequest*, SEL, NSURL *) _LOGOS_RETURN_RETAINED; static NSMutableURLRequest* (*_logos_orig$_ungrouped$NSMutableURLRequest$initWithURL$cachePolicy$timeoutInterval$)(_LOGOS_SELF_TYPE_INIT NSMutableURLRequest*, SEL, NSURL *, NSURLRequestCachePolicy, NSTimeInterval) _LOGOS_RETURN_RETAINED; static NSMutableURLRequest* _logos_method$_ungrouped$NSMutableURLRequest$initWithURL$cachePolicy$timeoutInterval$(_LOGOS_SELF_TYPE_INIT NSMutableURLRequest*, SEL, NSURL *, NSURLRequestCachePolicy, NSTimeInterval) _LOGOS_RETURN_RETAINED; static void (*_logos_orig$_ungrouped$NSMutableURLRequest$setURL$)(_LOGOS_SELF_TYPE_NORMAL NSMutableURLRequest* _LOGOS_SELF_CONST, SEL, NSURL *); static void _logos_method$_ungrouped$NSMutableURLRequest$setURL$(_LOGOS_SELF_TYPE_NORMAL NSMutableURLRequest* _LOGOS_SELF_CONST, SEL, NSURL *); static void (*_logos_orig$_ungrouped$NSMutableURLRequest$setValue$forHTTPHeaderField$)(_LOGOS_SELF_TYPE_NORMAL NSMutableURLRequest* _LOGOS_SELF_CONST, SEL, NSString *, NSString *); static void _logos_method$_ungrouped$NSMutableURLRequest$setValue$forHTTPHeaderField$(_LOGOS_SELF_TYPE_NORMAL NSMutableURLRequest* _LOGOS_SELF_CONST, SEL, NSString *, NSString *); static void (*_logos_orig$_ungrouped$NSMutableURLRequest$addValue$forHTTPHeaderField$)(_LOGOS_SELF_TYPE_NORMAL NSMutableURLRequest* _LOGOS_SELF_CONST, SEL, NSString *, NSString *); static void _logos_method$_ungrouped$NSMutableURLRequest$addValue$forHTTPHeaderField$(_LOGOS_SELF_TYPE_NORMAL NSMutableURLRequest* _LOGOS_SELF_CONST, SEL, NSString *, NSString *); static void (*_logos_orig$_ungrouped$NSMutableURLRequest$setAllHTTPHeaderFields$)(_LOGOS_SELF_TYPE_NORMAL NSMutableURLRequest* _LOGOS_SELF_CONST, SEL, NSDictionary *); static void _logos_method$_ungrouped$NSMutableURLRequest$setAllHTTPHeaderFields$(_LOGOS_SELF_TYPE_NORMAL NSMutableURLRequest* _LOGOS_SELF_CONST, SEL, NSDictionary *); static void (*_logos_orig$_ungrouped$NSMutableURLRequest$setHTTPBody$)(_LOGOS_SELF_TYPE_NORMAL NSMutableURLRequest* _LOGOS_SELF_CONST, SEL, NSData *); static void _logos_method$_ungrouped$NSMutableURLRequest$setHTTPBody$(_LOGOS_SELF_TYPE_NORMAL NSMutableURLRequest* _LOGOS_SELF_CONST, SEL, NSData *); static BOOL (*_logos_orig$_ungrouped$NSFileManager$copyItemAtPath$toPath$error$)(_LOGOS_SELF_TYPE_NORMAL NSFileManager* _LOGOS_SELF_CONST, SEL, NSString *, NSString *, NSError **); static BOOL _logos_method$_ungrouped$NSFileManager$copyItemAtPath$toPath$error$(_LOGOS_SELF_TYPE_NORMAL NSFileManager* _LOGOS_SELF_CONST, SEL, NSString *, NSString *, NSError **); static BOOL (*_logos_orig$_ungrouped$NSFileManager$copyItemAtURL$toURL$error$)(_LOGOS_SELF_TYPE_NORMAL NSFileManager* _LOGOS_SELF_CONST, SEL, NSURL *, NSURL *, NSError **); static BOOL _logos_method$_ungrouped$NSFileManager$copyItemAtURL$toURL$error$(_LOGOS_SELF_TYPE_NORMAL NSFileManager* _LOGOS_SELF_CONST, SEL, NSURL *, NSURL *, NSError **); static BOOL (*_logos_orig$_ungrouped$NSFileManager$moveItemAtPath$toPath$error$)(_LOGOS_SELF_TYPE_NORMAL NSFileManager* _LOGOS_SELF_CONST, SEL, NSString *, NSString *, NSError **); static BOOL _logos_method$_ungrouped$NSFileManager$moveItemAtPath$toPath$error$(_LOGOS_SELF_TYPE_NORMAL NSFileManager* _LOGOS_SELF_CONST, SEL, NSString *, NSString *, NSError **); static BOOL (*_logos_orig$_ungrouped$NSFileManager$moveItemAtURL$toURL$error$)(_LOGOS_SELF_TYPE_NORMAL NSFileManager* _LOGOS_SELF_CONST, SEL, NSURL *, NSURL *, NSError **); static BOOL _logos_method$_ungrouped$NSFileManager$moveItemAtURL$toURL$error$(_LOGOS_SELF_TYPE_NORMAL NSFileManager* _LOGOS_SELF_CONST, SEL, NSURL *, NSURL *, NSError **); static NSDictionary * (*_logos_orig$_ungrouped$NSFileManager$attributesOfItemAtPath$error$)(_LOGOS_SELF_TYPE_NORMAL NSFileManager* _LOGOS_SELF_CONST, SEL, NSString *, NSError **); static NSDictionary * _logos_method$_ungrouped$NSFileManager$attributesOfItemAtPath$error$(_LOGOS_SELF_TYPE_NORMAL NSFileManager* _LOGOS_SELF_CONST, SEL, NSString *, NSError **); static id (*_logos_meta_orig$_ungrouped$NSJSONSerialization$JSONObjectWithData$options$error$)(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST, SEL, NSData *, NSJSONReadingOptions, NSError **); static id _logos_meta_method$_ungrouped$NSJSONSerialization$JSONObjectWithData$options$error$(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST, SEL, NSData *, NSJSONReadingOptions, NSError **); static BOOL (*_logos_orig$_ungrouped$NSData$writeToFile$atomically$)(_LOGOS_SELF_TYPE_NORMAL NSData* _LOGOS_SELF_CONST, SEL, NSString *, BOOL); static BOOL _logos_method$_ungrouped$NSData$writeToFile$atomically$(_LOGOS_SELF_TYPE_NORMAL NSData* _LOGOS_SELF_CONST, SEL, NSString *, BOOL); static BOOL (*_logos_orig$_ungrouped$NSData$writeToURL$atomically$)(_LOGOS_SELF_TYPE_NORMAL NSData* _LOGOS_SELF_CONST, SEL, NSURL *, BOOL); static BOOL _logos_method$_ungrouped$NSData$writeToURL$atomically$(_LOGOS_SELF_TYPE_NORMAL NSData* _LOGOS_SELF_CONST, SEL, NSURL *, BOOL); static NSData* (*_logos_meta_orig$_ungrouped$NSData$dataWithContentsOfFile$)(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST, SEL, NSString *); static NSData* _logos_meta_method$_ungrouped$NSData$dataWithContentsOfFile$(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST, SEL, NSString *); static NSData* (*_logos_meta_orig$_ungrouped$NSData$dataWithContentsOfURL$)(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST, SEL, NSURL *); static NSData* _logos_meta_method$_ungrouped$NSData$dataWithContentsOfURL$(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST, SEL, NSURL *); static NSData* (*_logos_orig$_ungrouped$NSData$initWithContentsOfFile$options$error$)(_LOGOS_SELF_TYPE_INIT NSData*, SEL, NSString *, NSDataReadingOptions, NSError **) _LOGOS_RETURN_RETAINED; static NSData* _logos_method$_ungrouped$NSData$initWithContentsOfFile$options$error$(_LOGOS_SELF_TYPE_INIT NSData*, SEL, NSString *, NSDataReadingOptions, NSError **) _LOGOS_RETURN_RETAINED; static NSData* (*_logos_orig$_ungrouped$NSData$initWithContentsOfURL$options$error$)(_LOGOS_SELF_TYPE_INIT NSData*, SEL, NSURL *, NSDataReadingOptions, NSError **) _LOGOS_RETURN_RETAINED; static NSData* _logos_method$_ungrouped$NSData$initWithContentsOfURL$options$error$(_LOGOS_SELF_TYPE_INIT NSData*, SEL, NSURL *, NSDataReadingOptions, NSError **) _LOGOS_RETURN_RETAINED; static NSFileHandle* (*_logos_meta_orig$_ungrouped$NSFileHandle$fileHandleForReadingAtPath$)(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST, SEL, NSString *); static NSFileHandle* _logos_meta_method$_ungrouped$NSFileHandle$fileHandleForReadingAtPath$(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST, SEL, NSString *); static NSInputStream* (*_logos_meta_orig$_ungrouped$NSInputStream$inputStreamWithFileAtPath$)(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST, SEL, NSString *); static NSInputStream* _logos_meta_method$_ungrouped$NSInputStream$inputStreamWithFileAtPath$(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST, SEL, NSString *); static NSInputStream* (*_logos_orig$_ungrouped$NSInputStream$initWithFileAtPath$)(_LOGOS_SELF_TYPE_INIT NSInputStream*, SEL, NSString *) _LOGOS_RETURN_RETAINED; static NSInputStream* _logos_method$_ungrouped$NSInputStream$initWithFileAtPath$(_LOGOS_SELF_TYPE_INIT NSInputStream*, SEL, NSString *) _LOGOS_RETURN_RETAINED; static NSURLSessionDataTask * (*_logos_orig$_ungrouped$NSURLSession$dataTaskWithRequest$completionHandler$)(_LOGOS_SELF_TYPE_NORMAL NSURLSession* _LOGOS_SELF_CONST, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *)); static NSURLSessionDataTask * _logos_method$_ungrouped$NSURLSession$dataTaskWithRequest$completionHandler$(_LOGOS_SELF_TYPE_NORMAL NSURLSession* _LOGOS_SELF_CONST, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *)); static void (*_logos_orig$_ungrouped$UIWindow$makeKeyAndVisible)(_LOGOS_SELF_TYPE_NORMAL UIWindow* _LOGOS_SELF_CONST, SEL); static void _logos_method$_ungrouped$UIWindow$makeKeyAndVisible(_LOGOS_SELF_TYPE_NORMAL UIWindow* _LOGOS_SELF_CONST, SEL); 

#line 110 "Tweak.xm"

static NSString * _logos_method$_ungrouped$NSBundle$bundleIdentifier(_LOGOS_SELF_TYPE_NORMAL NSBundle* _LOGOS_SELF_CONST __unused self, SEL __unused _cmd) {
    NSString *orig = _logos_orig$_ungrouped$NSBundle$bundleIdentifier(self, _cmd);
    if (!g_intercept) return orig; 
    
    
    void *addr = __builtin_return_address(0);
    Dl_info info;
    if (dladdr(addr, &info) != 0 && info.dli_fname != NULL) {
        
        if (strstr(info.dli_fname, "HuaweiWear") || 
            strstr(info.dli_fname, "SHSports") || 
            strstr(info.dli_fname, "iossporthealth")) {
            
            if (![orig isEqualToString:@"com.huawei.iossporthealth"]) {
                static dispatch_once_t onceLog;
                dispatch_once(&onceLog, ^{
                    HWSLog([NSString stringWithFormat:@"🛡️ [NSBundle] 精准伪装 bundleIdentifier: %@ -> com.huawei.iossporthealth", orig]);
                });
                return @"com.huawei.iossporthealth";
            }
        }
    }
    return orig;
}

static id _logos_method$_ungrouped$NSBundle$objectForInfoDictionaryKey$(_LOGOS_SELF_TYPE_NORMAL NSBundle* _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, NSString * key) {
    id orig = _logos_orig$_ungrouped$NSBundle$objectForInfoDictionaryKey$(self, _cmd, key);
    if (!g_intercept) return orig; 
    
    if ([key isEqualToString:@"CFBundleIdentifier"]) {
        void *addr = __builtin_return_address(0);
        Dl_info info;
        if (dladdr(addr, &info) != 0 && info.dli_fname != NULL) {
            if (strstr(info.dli_fname, "HuaweiWear") || 
                strstr(info.dli_fname, "SHSports") || 
                strstr(info.dli_fname, "iossporthealth")) {
                if (![orig isEqualToString:@"com.huawei.iossporthealth"]) {
                    return @"com.huawei.iossporthealth";
                }
            }
        }
    }
    return orig;
}









static NSString *g_realBundleId = nil;


static NSString *sanitizeString(NSString *str) {
    if (!g_realBundleId || !str) return str;
    if ([g_realBundleId isEqualToString:@"com.huawei.iossporthealth"]) return str;
    if ([str containsString:g_realBundleId]) {
        return [str stringByReplacingOccurrencesOfString:g_realBundleId 
                                              withString:@"com.huawei.iossporthealth"];
    }
    return str;
}



static NSMutableURLRequest* _logos_method$_ungrouped$NSMutableURLRequest$initWithURL$(_LOGOS_SELF_TYPE_INIT NSMutableURLRequest* __unused self, SEL __unused _cmd, NSURL * URL) _LOGOS_RETURN_RETAINED {
    if (!URL) return _logos_orig$_ungrouped$NSMutableURLRequest$initWithURL$(self, _cmd, URL);
    NSString *uStr = URL.absoluteString;
    NSString *fixed = sanitizeString(uStr);
    if (![uStr isEqualToString:fixed]) {
        return _logos_orig$_ungrouped$NSMutableURLRequest$initWithURL$(self, _cmd, [NSURL URLWithString:fixed]);
    }
    return _logos_orig$_ungrouped$NSMutableURLRequest$initWithURL$(self, _cmd, URL);
}

static NSMutableURLRequest* _logos_method$_ungrouped$NSMutableURLRequest$initWithURL$cachePolicy$timeoutInterval$(_LOGOS_SELF_TYPE_INIT NSMutableURLRequest* __unused self, SEL __unused _cmd, NSURL * URL, NSURLRequestCachePolicy cachePolicy, NSTimeInterval timeoutInterval) _LOGOS_RETURN_RETAINED {
    if (!URL) return _logos_orig$_ungrouped$NSMutableURLRequest$initWithURL$cachePolicy$timeoutInterval$(self, _cmd, URL, cachePolicy, timeoutInterval);
    NSString *uStr = URL.absoluteString;
    NSString *fixed = sanitizeString(uStr);
    if (![uStr isEqualToString:fixed]) {
        return _logos_orig$_ungrouped$NSMutableURLRequest$initWithURL$cachePolicy$timeoutInterval$(self, _cmd, [NSURL URLWithString:fixed], cachePolicy, timeoutInterval);
    }
    return _logos_orig$_ungrouped$NSMutableURLRequest$initWithURL$cachePolicy$timeoutInterval$(self, _cmd, URL, cachePolicy, timeoutInterval);
}

static void _logos_method$_ungrouped$NSMutableURLRequest$setURL$(_LOGOS_SELF_TYPE_NORMAL NSMutableURLRequest* _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, NSURL * URL) {
    if (!URL) { _logos_orig$_ungrouped$NSMutableURLRequest$setURL$(self, _cmd, URL); return; }
    NSString *uStr = URL.absoluteString;
    NSString *fixed = sanitizeString(uStr);
    if (![uStr isEqualToString:fixed]) {
        HWSLog([NSString stringWithFormat:@"🔐 URL Setter Replaced: %@", URL.host]);
        _logos_orig$_ungrouped$NSMutableURLRequest$setURL$(self, _cmd, [NSURL URLWithString:fixed]);
    } else {
        _logos_orig$_ungrouped$NSMutableURLRequest$setURL$(self, _cmd, URL);
    }
}

static void _logos_method$_ungrouped$NSMutableURLRequest$setValue$forHTTPHeaderField$(_LOGOS_SELF_TYPE_NORMAL NSMutableURLRequest* _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, NSString * value, NSString * field) {
    NSString *fixed = sanitizeString(value);
    if (value && ![value isEqualToString:fixed]) {
        HWSLog([NSString stringWithFormat:@"🔐 Header Setter Replaced: %@", field]);
    }
    _logos_orig$_ungrouped$NSMutableURLRequest$setValue$forHTTPHeaderField$(self, _cmd, fixed, field);
}

static void _logos_method$_ungrouped$NSMutableURLRequest$addValue$forHTTPHeaderField$(_LOGOS_SELF_TYPE_NORMAL NSMutableURLRequest* _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, NSString * value, NSString * field) {
    NSString *fixed = sanitizeString(value);
    if (value && ![value isEqualToString:fixed]) {
        HWSLog([NSString stringWithFormat:@"🔐 Header Add Replaced: %@", field]);
    }
    _logos_orig$_ungrouped$NSMutableURLRequest$addValue$forHTTPHeaderField$(self, _cmd, fixed, field);
}

static void _logos_method$_ungrouped$NSMutableURLRequest$setAllHTTPHeaderFields$(_LOGOS_SELF_TYPE_NORMAL NSMutableURLRequest* _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, NSDictionary * fields) {
    if (!fields) { _logos_orig$_ungrouped$NSMutableURLRequest$setAllHTTPHeaderFields$(self, _cmd, fields); return; }
    NSMutableDictionary *fixed = [fields mutableCopy];
    BOOL changed = NO;
    for (NSString *k in fields) {
        NSString *v = fields[k];
        if ([v isKindOfClass:[NSString class]]) {
            NSString *fv = sanitizeString(v);
            if (![v isEqualToString:fv]) {
                fixed[k] = fv;
                changed = YES;
            }
        }
    }
    if (changed) HWSLog(@"🔐 AllHeaders Replaced");
    _logos_orig$_ungrouped$NSMutableURLRequest$setAllHTTPHeaderFields$(self, _cmd, changed ? fixed : fields);
}

static void _logos_method$_ungrouped$NSMutableURLRequest$setHTTPBody$(_LOGOS_SELF_TYPE_NORMAL NSMutableURLRequest* _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, NSData * data) {
    if (data && g_realBundleId && data.length < 65536) {
        NSString *bs = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (bs) {
            NSString *fixed = sanitizeString(bs);
            if (![bs isEqualToString:fixed]) {
                HWSLog(@"🔐 Body Setter Replaced");
                _logos_orig$_ungrouped$NSMutableURLRequest$setHTTPBody$(self, _cmd, [fixed dataUsingEncoding:NSUTF8StringEncoding]);
                return;
            }
        }
    }
    _logos_orig$_ungrouped$NSMutableURLRequest$setHTTPBody$(self, _cmd, data);
}







static BOOL isTargetExt(NSString *path) {
    if (!path) return NO;
    NSString *low = path.lowercaseString;
    return [low containsString:@".hap"] || [low containsString:@".pkg"] || [low containsString:@".bin"];
}





static void dumpObjectProperties(id obj, NSString *tag) {
    if (!obj) {
        HWSLog([NSString stringWithFormat:@"[Object Dump: %@] Object is nil", tag]);
        return;
    }
    NSMutableString *str = [NSMutableString stringWithFormat:@"\n=== [Object Dump: %@] ===\nClass: %@\n", tag, NSStringFromClass([obj class])];
    
    unsigned int count;
    objc_property_t *properties = class_copyPropertyList([obj class], &count);
    for (int i = 0; i < count; i++) {
        objc_property_t property = properties[i];
        NSString *name = [NSString stringWithUTF8String:property_getName(property)];
        id value = nil;
        @try {
            value = [obj valueForKey:name];
        } @catch (NSException *e) {
            value = @"<Exception>";
        }
        [str appendFormat:@"@property %@ = %@\n", name, value];
    }
    if (properties) free(properties);
    [str appendString:@"=========================\n"];
    HWSLog(str);
}

static void replacePathAndSizeInFileInfo(id info) {
    if (!g_intercept || !g_hapPath || !info) return;
    @try {
        unsigned int count;
        objc_property_t *properties = class_copyPropertyList([info class], &count);
        for (int i = 0; i < count; i++) {
            objc_property_t property = properties[i];
            NSString *name = [NSString stringWithUTF8String:property_getName(property)];
            id value = [info valueForKey:name];
            NSString *lowerName = name.lowercaseString;
            
            if ([value isKindOfClass:[NSString class]]) {
                NSString *valStr = (NSString *)value;
                if ([valStr containsString:@".bin"] || [valStr containsString:@".hap"] || [valStr containsString:@".pkg"]) {
                    HWSLog([NSString stringWithFormat:@"✅ 发现潜在路径属性 [%@] = %@ \n尝试修改为: %@", name, valStr, g_hapPath]);
                    [info setValue:g_hapPath forKey:name];
                    HWSLog(@"✨ 路径修改成功！");
                } 
                else if (g_hapBundleID && g_hapBundleID.length > 0 && 
                         ([lowerName containsString:@"bundle"] || [lowerName containsString:@"package"] || [lowerName isEqualToString:@"appid"])) {
                    HWSLog([NSString stringWithFormat:@"✅ 发现应用包名属性 [%@] = %@ \n尝试修改为: %@", name, valStr, g_hapBundleID]);
                    [info setValue:g_hapBundleID forKey:name];
                }
                else if (g_hapChecksum && g_hapChecksum.length > 0 &&
                         ([lowerName containsString:@"check"] || [lowerName containsString:@"hash"] || [lowerName containsString:@"digest"])) {
                    HWSLog([NSString stringWithFormat:@"✅ 发现校验和属性 [%@] = %@ \n尝试修改为: %@", name, valStr, g_hapChecksum]);
                    [info setValue:g_hapChecksum forKey:name];
                }
            } else if ([lowerName containsString:@"size"]) {
                NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:g_hapPath error:nil];
                if (attrs) {
                    long long hapSize = [attrs fileSize];
                    if (hapSize > 0) {
                        HWSLog([NSString stringWithFormat:@"✅ 发现大小属性 [%@] = %@ \n尝试修改为: %lld", name, value, hapSize]);
                        [info setValue:@(hapSize) forKey:name];
                    }
                }
            }
        }
        if (properties) free(properties);
    } @catch (NSException *e) {
        HWSLog([NSString stringWithFormat:@"❌ 动态修改异常: %@", e]);
    }
}




@interface HWSLogViewer : UIViewController
@property (nonatomic, strong) UITextView *textView;
- (void)refreshLogs;
- (void)copyLogs;
- (void)dismiss;
@end

@implementation HWSLogViewer
- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor colorWithWhite:0.1 alpha:0.95];
    
    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(0, 40, self.view.bounds.size.width, 30)];
    title.text = @"HAP 侧载监控日志";
    title.textColor = [UIColor whiteColor];
    title.textAlignment = NSTextAlignmentCenter;
    title.font = [UIFont boldSystemFontOfSize:16];
    [self.view addSubview:title];
    
    self.textView = [[UITextView alloc] initWithFrame:CGRectMake(10, 80, self.view.bounds.size.width - 20, self.view.bounds.size.height - 160)];
    self.textView.backgroundColor = [UIColor clearColor];
    self.textView.textColor = [UIColor colorWithRed:0.2 green:0.9 blue:0.2 alpha:1.0];
    self.textView.font = [UIFont fontWithName:@"Menlo" size:11];
    self.textView.editable = NO;
    self.textView.layoutManager.allowsNonContiguousLayout = NO;
    [self.view addSubview:self.textView];
    
    UIButton *closeBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    closeBtn.frame = CGRectMake(20, self.view.bounds.size.height - 60, self.view.bounds.size.width/2 - 30, 40);
    closeBtn.backgroundColor = [UIColor darkGrayColor];
    closeBtn.layer.cornerRadius = 8;
    [closeBtn setTitle:@"关闭" forState:UIControlStateNormal];
    [closeBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [closeBtn addTarget:self action:@selector(dismiss) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:closeBtn];
    
    UIButton *copyBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    copyBtn.frame = CGRectMake(self.view.bounds.size.width/2 + 10, self.view.bounds.size.height - 60, self.view.bounds.size.width/2 - 30, 40);
    copyBtn.backgroundColor = [UIColor colorWithRed:0.2 green:0.6 blue:1.0 alpha:1.0];
    copyBtn.layer.cornerRadius = 8;
    [copyBtn setTitle:@"复制全部" forState:UIControlStateNormal];
    [copyBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    [copyBtn addTarget:self action:@selector(copyLogs) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:copyBtn];
    
    [self refreshLogs];
    
    
    [NSTimer scheduledTimerWithTimeInterval:1.0 target:self selector:@selector(refreshLogs) userInfo:nil repeats:YES];
}

- (void)refreshLogs {
    if (g_logs) {
        self.textView.text = [g_logs componentsJoinedByString:@"\n"];
        
        if (self.textView.text.length > 0) {
            NSRange range = NSMakeRange(self.textView.text.length - 1, 1);
            [self.textView scrollRangeToVisible:range];
        }
    }
}

- (void)copyLogs {
    if (g_logs) {
        UIPasteboard *pb = [UIPasteboard generalPasteboard];
        [pb setString:[g_logs componentsJoinedByString:@"\n"]];
    }
}

- (void)dismiss {
    [self dismissViewControllerAnimated:YES completion:nil];
}
@end

static void (*_logos_orig$SideloadHooks$NSNotificationCenter$postNotificationName$object$userInfo$)(_LOGOS_SELF_TYPE_NORMAL NSNotificationCenter* _LOGOS_SELF_CONST, SEL, NSNotificationName, id, NSDictionary *); static void _logos_method$SideloadHooks$NSNotificationCenter$postNotificationName$object$userInfo$(_LOGOS_SELF_TYPE_NORMAL NSNotificationCenter* _LOGOS_SELF_CONST, SEL, NSNotificationName, id, NSDictionary *); static void (*_logos_meta_orig$SideloadHooks$SHDWiFiCommandSend$sendNotifiDeviceStartTransferFileWithFileInfo$)(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST, SEL, id); static void _logos_meta_method$SideloadHooks$SHDWiFiCommandSend$sendNotifiDeviceStartTransferFileWithFileInfo$(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST, SEL, id); static void (*_logos_meta_orig$SideloadHooks$SHDWiFiCommandSend$sendNotifiDeviceTransferFileInfoWithFileInfo$)(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST, SEL, id); static void _logos_meta_method$SideloadHooks$SHDWiFiCommandSend$sendNotifiDeviceTransferFileInfoWithFileInfo$(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST, SEL, id); static void (*_logos_meta_orig$SideloadHooks$SHDWiFiCommandSend$sendTransferFileInfo$)(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST, SEL, id); static void _logos_meta_method$SideloadHooks$SHDWiFiCommandSend$sendTransferFileInfo$(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST, SEL, id); static void (*_logos_orig$SideloadHooks$SHDWiFiTransferManager$transferFileInfo$callback$)(_LOGOS_SELF_TYPE_NORMAL id _LOGOS_SELF_CONST, SEL, id, id); static void _logos_method$SideloadHooks$SHDWiFiTransferManager$transferFileInfo$callback$(_LOGOS_SELF_TYPE_NORMAL id _LOGOS_SELF_CONST, SEL, id, id); static void (*_logos_orig$SideloadHooks$SHWatchAppStoreManager$pushFileProgress$)(_LOGOS_SELF_TYPE_NORMAL id _LOGOS_SELF_CONST, SEL, NSNotification *); static void _logos_method$SideloadHooks$SHWatchAppStoreManager$pushFileProgress$(_LOGOS_SELF_TYPE_NORMAL id _LOGOS_SELF_CONST, SEL, NSNotification *); static void (*_logos_orig$SideloadHooks$WSSCommonFileMgr$sendFileTransferNegotiate$errorCode$)(_LOGOS_SELF_TYPE_NORMAL WSSCommonFileMgr* _LOGOS_SELF_CONST, SEL, id, NSInteger); static void _logos_method$SideloadHooks$WSSCommonFileMgr$sendFileTransferNegotiate$errorCode$(_LOGOS_SELF_TYPE_NORMAL WSSCommonFileMgr* _LOGOS_SELF_CONST, SEL, id, NSInteger); static void (*_logos_orig$SideloadHooks$WSSCommonFileMgr$finishPushFileWithType$)(_LOGOS_SELF_TYPE_NORMAL WSSCommonFileMgr* _LOGOS_SELF_CONST, SEL, NSInteger); static void _logos_method$SideloadHooks$WSSCommonFileMgr$finishPushFileWithType$(_LOGOS_SELF_TYPE_NORMAL WSSCommonFileMgr* _LOGOS_SELF_CONST, SEL, NSInteger); static void (*_logos_orig$SideloadHooks$WSSCommonFileMgr$pausedTransferFile)(_LOGOS_SELF_TYPE_NORMAL WSSCommonFileMgr* _LOGOS_SELF_CONST, SEL); static void _logos_method$SideloadHooks$WSSCommonFileMgr$pausedTransferFile(_LOGOS_SELF_TYPE_NORMAL WSSCommonFileMgr* _LOGOS_SELF_CONST, SEL); static void (*_logos_orig$SideloadHooks$WSSCommonFileMgr$sendFileContentToDeviceWithDataInfo$)(_LOGOS_SELF_TYPE_NORMAL WSSCommonFileMgr* _LOGOS_SELF_CONST, SEL, id); static void _logos_method$SideloadHooks$WSSCommonFileMgr$sendFileContentToDeviceWithDataInfo$(_LOGOS_SELF_TYPE_NORMAL WSSCommonFileMgr* _LOGOS_SELF_CONST, SEL, id); static void (*_logos_orig$SideloadHooks$WSSCommonFileMgr$sendFileCheckMode$fileid$offsetSize$)(_LOGOS_SELF_TYPE_NORMAL WSSCommonFileMgr* _LOGOS_SELF_CONST, SEL, NSInteger, NSInteger, long long); static void _logos_method$SideloadHooks$WSSCommonFileMgr$sendFileCheckMode$fileid$offsetSize$(_LOGOS_SELF_TYPE_NORMAL WSSCommonFileMgr* _LOGOS_SELF_CONST, SEL, NSInteger, NSInteger, long long); static void (*_logos_orig$SideloadHooks$WSSCommonFileMgr$recevicedPushFileData$commondID$deviceIdentify$)(_LOGOS_SELF_TYPE_NORMAL WSSCommonFileMgr* _LOGOS_SELF_CONST, SEL, NSData *, NSInteger, NSString *); static void _logos_method$SideloadHooks$WSSCommonFileMgr$recevicedPushFileData$commondID$deviceIdentify$(_LOGOS_SELF_TYPE_NORMAL WSSCommonFileMgr* _LOGOS_SELF_CONST, SEL, NSData *, NSInteger, NSString *); static void (*_logos_meta_orig$SideloadHooks$WSSCommonFileMgrSendUtil$sendFileCheckMode$deviceInfo$fileInfo$fileid$offsetSize$)(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST, SEL, NSInteger, id, id, NSInteger, long long); static void _logos_meta_method$SideloadHooks$WSSCommonFileMgrSendUtil$sendFileCheckMode$deviceInfo$fileInfo$fileid$offsetSize$(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST, SEL, NSInteger, id, id, NSInteger, long long); static void (*_logos_meta_orig$SideloadHooks$WSSCommonFileMgrSendUtil$sendFileContentToDeviceWithDataInfo$fileData$deviceInfo$selectIndexArray$negotiate$)(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST, SEL, id, NSData *, id, id, id); static void _logos_meta_method$SideloadHooks$WSSCommonFileMgrSendUtil$sendFileContentToDeviceWithDataInfo$fileData$deviceInfo$selectIndexArray$negotiate$(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST, SEL, id, NSData *, id, id, id); static void (*_logos_meta_orig$SideloadHooks$WSSCommonFileMgrSendUtil$sendFileTransferNegotiate$deviceInfo$errorCode$)(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST, SEL, id, id, NSInteger); static void _logos_meta_method$SideloadHooks$WSSCommonFileMgrSendUtil$sendFileTransferNegotiate$deviceInfo$errorCode$(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST, SEL, id, id, NSInteger); static NSString * (*_logos_orig$SideloadHooks$WSSCommonFileInfo$filePath)(_LOGOS_SELF_TYPE_NORMAL WSSCommonFileInfo* _LOGOS_SELF_CONST, SEL); static NSString * _logos_method$SideloadHooks$WSSCommonFileInfo$filePath(_LOGOS_SELF_TYPE_NORMAL WSSCommonFileInfo* _LOGOS_SELF_CONST, SEL); static long long (*_logos_orig$SideloadHooks$WSSCommonFileInfo$fileSize)(_LOGOS_SELF_TYPE_NORMAL WSSCommonFileInfo* _LOGOS_SELF_CONST, SEL); static long long _logos_method$SideloadHooks$WSSCommonFileInfo$fileSize(_LOGOS_SELF_TYPE_NORMAL WSSCommonFileInfo* _LOGOS_SELF_CONST, SEL); static NSString * (*_logos_orig$SideloadHooks$WSSCommonFileInfo$sha256Result)(_LOGOS_SELF_TYPE_NORMAL WSSCommonFileInfo* _LOGOS_SELF_CONST, SEL); static NSString * _logos_method$SideloadHooks$WSSCommonFileInfo$sha256Result(_LOGOS_SELF_TYPE_NORMAL WSSCommonFileInfo* _LOGOS_SELF_CONST, SEL); static BOOL (*_logos_orig$SideloadHooks$WSSCommonFileInfo$isNeedVerify)(_LOGOS_SELF_TYPE_NORMAL WSSCommonFileInfo* _LOGOS_SELF_CONST, SEL); static BOOL _logos_method$SideloadHooks$WSSCommonFileInfo$isNeedVerify(_LOGOS_SELF_TYPE_NORMAL WSSCommonFileInfo* _LOGOS_SELF_CONST, SEL); 


static void _logos_method$SideloadHooks$NSNotificationCenter$postNotificationName$object$userInfo$(_LOGOS_SELF_TYPE_NORMAL NSNotificationCenter* _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, NSNotificationName aName, id anObject, NSDictionary * aUserInfo) {
    if ([aName isEqualToString:@"notif_pushfile_update_status"]) {
        id statusInfo = aUserInfo[@"statusInfo"];
        if (statusInfo) {
            static dispatch_once_t onceTokenDump;
            dispatch_once(&onceTokenDump, ^{
                dumpObjectProperties(statusInfo, @"statusInfo Initial Object State");
            });
            
            
            static NSInteger lastStatus = -1;
            static NSInteger lastErrCode = -1;
            static NSInteger lastProgress25 = -1; 
            @try {
                NSInteger curStatus = [[statusInfo valueForKey:@"currentStatus"] integerValue];
                NSInteger curErrCode = [[statusInfo valueForKey:@"errorCode"] integerValue];
                NSInteger curProgress = [[statusInfo valueForKey:@"progress"] integerValue];
                NSInteger progBucket = curProgress / 25; 
                
                BOOL statusChanged  = (curStatus != lastStatus);
                BOOL errCodeChanged = (curErrCode != lastErrCode);
                BOOL progressMilestone = (progBucket != lastProgress25);
                
                
                BOOL shouldLog = statusChanged || errCodeChanged ||
                                 (curStatus != 5) || progressMilestone;
                if (shouldLog) {
                    id errAttach = [statusInfo valueForKey:@"errAttachment"];
                    HWSLog([NSString stringWithFormat:@"  📌 statusInfo变化 -> status=%ld progress=%ld errorCode=%ld errAttach=%@",
                        (long)curStatus, (long)curProgress, (long)curErrCode, errAttach]);
                    lastStatus = curStatus;
                    lastErrCode = curErrCode;
                    lastProgress25 = progBucket;
                }
            } @catch (NSException *e) {}
            
            replacePathAndSizeInFileInfo(statusInfo);
        }
        
        _logos_orig$SideloadHooks$NSNotificationCenter$postNotificationName$object$userInfo$(self, _cmd, aName, anObject, aUserInfo);
        return;
    }
    _logos_orig$SideloadHooks$NSNotificationCenter$postNotificationName$object$userInfo$(self, _cmd, aName, anObject, aUserInfo);
}




static void _logos_meta_method$SideloadHooks$SHDWiFiCommandSend$sendNotifiDeviceStartTransferFileWithFileInfo$(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, id info) {
    HWSLog(@"\n\n🚀🚀🚀 [Hook Hit] sendNotifiDeviceStartTransferFileWithFileInfo:");
    dumpObjectProperties(info, @"FileInfo Object");
    replacePathAndSizeInFileInfo(info);
    _logos_meta_orig$SideloadHooks$SHDWiFiCommandSend$sendNotifiDeviceStartTransferFileWithFileInfo$(self, _cmd, info);
}

static void _logos_meta_method$SideloadHooks$SHDWiFiCommandSend$sendNotifiDeviceTransferFileInfoWithFileInfo$(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, id info) {
    HWSLog(@"\n\n🚀🚀🚀 [Hook Hit] sendNotifiDeviceTransferFileInfoWithFileInfo:");
    dumpObjectProperties(info, @"FileInfo Object");
    replacePathAndSizeInFileInfo(info);
    _logos_meta_orig$SideloadHooks$SHDWiFiCommandSend$sendNotifiDeviceTransferFileInfoWithFileInfo$(self, _cmd, info);
}

static void _logos_meta_method$SideloadHooks$SHDWiFiCommandSend$sendTransferFileInfo$(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, id info) {
    HWSLog(@"\n\n🚀🚀🚀 [Hook Hit] sendTransferFileInfo:");
    dumpObjectProperties(info, @"FileInfo Object");
    replacePathAndSizeInFileInfo(info);
    _logos_meta_orig$SideloadHooks$SHDWiFiCommandSend$sendTransferFileInfo$(self, _cmd, info);
}





static void _logos_method$SideloadHooks$SHDWiFiTransferManager$transferFileInfo$callback$(_LOGOS_SELF_TYPE_NORMAL id _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, id info, id cb) {
    HWSLog(@"\n\n🚀🚀🚀 [Hook Hit] transferFileInfo:callback:");
    dumpObjectProperties(info, @"FileInfo Object");
    replacePathAndSizeInFileInfo(info);
    _logos_orig$SideloadHooks$SHDWiFiTransferManager$transferFileInfo$callback$(self, _cmd, info, cb);
}




static void _logos_method$SideloadHooks$SHWatchAppStoreManager$pushFileProgress$(_LOGOS_SELF_TYPE_NORMAL id _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, NSNotification * notification) {
    
    _logos_orig$SideloadHooks$SHWatchAppStoreManager$pushFileProgress$(self, _cmd, notification);
}












static void _logos_method$SideloadHooks$WSSCommonFileMgr$sendFileTransferNegotiate$errorCode$(_LOGOS_SELF_TYPE_NORMAL WSSCommonFileMgr* _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, id negotiate, NSInteger errorCode) {
    HWSLog([NSString stringWithFormat:@"\n🔴 [WSSCommonFileMgr] sendFileTransferNegotiate!\n  ➤ errorCode = %ld\n  ➤ negotiate = %@", (long)errorCode, negotiate]);
    if (negotiate) { dumpObjectProperties(negotiate, @"Negotiate协商对象属性"); }
    _logos_orig$SideloadHooks$WSSCommonFileMgr$sendFileTransferNegotiate$errorCode$(self, _cmd, negotiate, errorCode);
}


static void _logos_method$SideloadHooks$WSSCommonFileMgr$finishPushFileWithType$(_LOGOS_SELF_TYPE_NORMAL WSSCommonFileMgr* _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, NSInteger type) {
    HWSLog(@"\n\n╬═══════════════════════════════╬");
    HWSLog([NSString stringWithFormat:@"🔴🔴🔴 [WSSCommonFileMgr] 传输完成！finishPushFileWithType = %ld (type=fileID 不是错误码)", (long)type]);
    HWSLog(@"╬═══════════════════════════════╬\n");
    @try { dumpObjectProperties(self, @"FileMgr最终状态"); } @catch (...) {}

    
    
    
    if (g_intercept) {
        __weak typeof(self) weakSelf = self;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            if (g_intercept) {
                g_intercept = NO;
                HWSLog(@"🔒 [v4.54] g_intercept 延迟关闭！");
            }
        });
    }

    
    static dispatch_once_t methodDumpOnce;
    Class selfClass = object_getClass(self); 
    dispatch_once(&methodDumpOnce, ^{
        unsigned int count = 0;
        Method *methods = class_copyMethodList(selfClass, &count);
        NSMutableString *allMethods = [NSMutableString stringWithFormat:@"📋 WSSCommonFileMgr 全部 %u 个方法:\n", count];
        for (unsigned int i = 0; i < count; i++) {
            [allMethods appendFormat:@"  · %@\n", NSStringFromSelector(method_getName(methods[i]))];
        }
        free(methods);
        HWSLog(allMethods);
    });


    
    __weak id weakSelf = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        id s = weakSelf;
        if (s) HWSLog([NSString stringWithFormat:@"⏱ [T+5s] isPushBusy=%@", [s valueForKey:@"isPushBusy"]]);
    });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        id s = weakSelf;
        if (s) HWSLog([NSString stringWithFormat:@"⏱ [T+15s] isPushBusy=%@", [s valueForKey:@"isPushBusy"]]);
    });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 30 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        id s = weakSelf;
        if (s) HWSLog([NSString stringWithFormat:@"⏱ [T+30s] isPushBusy=%@", [s valueForKey:@"isPushBusy"]]);
    });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 35 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        id s = weakSelf;
        if (s) HWSLog([NSString stringWithFormat:@"⏱ [T+35s] isPushBusy=%@ ← 最终状态", [s valueForKey:@"isPushBusy"]]);
    });

    _logos_orig$SideloadHooks$WSSCommonFileMgr$finishPushFileWithType$(self, _cmd, type);
}


static void _logos_method$SideloadHooks$WSSCommonFileMgr$pausedTransferFile(_LOGOS_SELF_TYPE_NORMAL WSSCommonFileMgr* _LOGOS_SELF_CONST __unused self, SEL __unused _cmd) {
    HWSLog(@"\n🟡 [WSSCommonFileMgr] pausedTransferFile 被调用！传输已暂停");
    _logos_orig$SideloadHooks$WSSCommonFileMgr$pausedTransferFile(self, _cmd);
}



static void _logos_method$SideloadHooks$WSSCommonFileMgr$sendFileContentToDeviceWithDataInfo$(_LOGOS_SELF_TYPE_NORMAL WSSCommonFileMgr* _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, id dataInfo) {
    static NSInteger chunkCount = 0;
    chunkCount++;
    if (chunkCount == 1) {
        HWSLog(@"\n🟢🟢🟢 [WSSCommonFileMgr] !!!! 数据传输正式开始！sendFileContentToDeviceWithDataInfo 第一次就呼了！!!!!");
        @try { dumpObjectProperties(dataInfo, @"DataInfo首包内容"); } @catch (...) {}
    } else if (chunkCount % 100 == 0) {
        HWSLog([NSString stringWithFormat:@"🟢 [WSSCommonFileMgr] 数据分包发送进度: 已发 %ld 包", (long)chunkCount]);
    }
    _logos_orig$SideloadHooks$WSSCommonFileMgr$sendFileContentToDeviceWithDataInfo$(self, _cmd, dataInfo);
}



static void _logos_method$SideloadHooks$WSSCommonFileMgr$sendFileCheckMode$fileid$offsetSize$(_LOGOS_SELF_TYPE_NORMAL WSSCommonFileMgr* _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, NSInteger checkMode, NSInteger fileid, long long offsetSize) {
    HWSLog([NSString stringWithFormat:@"\n🟡 [WSSCommonFileMgr] sendFileCheckMode!\n  ➤ checkMode = %ld (mode=3 是正确的，不要改！)\n  ➤ fileid = %ld, offsetSize = %lld", (long)checkMode, (long)fileid, (long long)offsetSize]);
    _logos_orig$SideloadHooks$WSSCommonFileMgr$sendFileCheckMode$fileid$offsetSize$(self, _cmd, checkMode, fileid, offsetSize);
}


static void _logos_method$SideloadHooks$WSSCommonFileMgr$recevicedPushFileData$commondID$deviceIdentify$(_LOGOS_SELF_TYPE_NORMAL WSSCommonFileMgr* _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, NSData * data, NSInteger commondID, NSString * deviceIdentify) {
    const uint8_t *bytes = (const uint8_t*)data.bytes;
    NSUInteger len = data.length;
    
    if (commondID == 5) {
        
        static NSInteger chunk5count = 0;
        chunk5count++;
        if (chunk5count == 1 || chunk5count % 20 == 0) {
            uint32_t offset = (len >= 9) ? ((bytes[5]<<24)|(bytes[6]<<16)|(bytes[7]<<8)|bytes[8]) : 0;
            HWSLog([NSString stringWithFormat:@"\n🔵 [commondID=5] 块ACK #%ld offset=%u字节 (每20块记录一次)", (long)chunk5count, offset]);
        }
    } else {
        
        NSMutableString *hexStr = [NSMutableString string];
        for (NSUInteger i = 0; i < len; i++) [hexStr appendFormat:@"%02X ", bytes[i]];
        HWSLog([NSString stringWithFormat:@"\n🔵 [WSSCommonFileMgr] recevicedPushFileData:\n  ➤ commondID = %ld, dataLen = %lu\n  ➤ RAW HEX: [%@]", (long)commondID, (unsigned long)len, hexStr]);
    }
    _logos_orig$SideloadHooks$WSSCommonFileMgr$recevicedPushFileData$commondID$deviceIdentify$(self, _cmd, data, commondID, deviceIdentify);
}







static void _logos_meta_method$SideloadHooks$WSSCommonFileMgrSendUtil$sendFileCheckMode$deviceInfo$fileInfo$fileid$offsetSize$(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, NSInteger checkMode, id deviceInfo, id fileInfo, NSInteger fileid, long long offsetSize) {
    HWSLog([NSString stringWithFormat:@"\n🟡 [WSSCommonFileMgrSendUtil] sendFileCheckMode!\n  ➤ checkMode = %ld (直接放行，不改！)\n  ➤ fileid = %ld, offsetSize = %lld", (long)checkMode, (long)fileid, (long long)offsetSize]);

    
    g_utilChunkCount = 0;

    
    static dispatch_once_t fOnce;
    dispatch_once(&fOnce, ^{
        if (fileInfo) dumpObjectProperties(fileInfo, @"[探针] sendFileCheckMode.fileInfo");
        if (deviceInfo) dumpObjectProperties(deviceInfo, @"[探针] sendFileCheckMode.deviceInfo");
    });
    
    if (g_intercept && fileInfo) {
        replacePathAndSizeInFileInfo(fileInfo);
    }
    
    _logos_meta_orig$SideloadHooks$WSSCommonFileMgrSendUtil$sendFileCheckMode$deviceInfo$fileInfo$fileid$offsetSize$(self, _cmd, checkMode, deviceInfo, fileInfo, fileid, offsetSize); 
}


static void _logos_meta_method$SideloadHooks$WSSCommonFileMgrSendUtil$sendFileContentToDeviceWithDataInfo$fileData$deviceInfo$selectIndexArray$negotiate$(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, id dataInfo, NSData * fileData, id deviceInfo, id selectIndexArray, id negotiate) {
    
    static dispatch_once_t probeOnce;
    dispatch_once(&probeOnce, ^{
        HWSLog(@"\n\n╔══════════════════════════════════════╗");
        HWSLog(@"║  🔬 [v4.54 探针] 第一包完整协议分析  ║");
        HWSLog(@"╚══════════════════════════════════════╝");

        
        if (dataInfo) {
            dumpObjectProperties(dataInfo, @"[探针] dataInfo");
        } else {
            HWSLog(@"⚠️ [探针] dataInfo == nil");
        }

        
        if (negotiate) {
            dumpObjectProperties(negotiate, @"[探针] negotiate");
        } else {
            HWSLog(@"⚠️ [探针] negotiate == nil");
        }

        
        if (deviceInfo) {
            dumpObjectProperties(deviceInfo, @"[探针] deviceInfo");
        }

        
        if (selectIndexArray) {
            HWSLog([NSString stringWithFormat:@"[探针] selectIndexArray class=%@ count=%@",
                NSStringFromClass([selectIndexArray class]), @([selectIndexArray count])]);
            if ([selectIndexArray count] > 0) {
                HWSLog([NSString stringWithFormat:@"[探针] selectIndexArray[0]=%@", selectIndexArray[0]]);
            }
        } else {
            HWSLog(@"⚠️ [探针] selectIndexArray == nil");
        }

        
        NSUInteger previewLen = MIN(128, fileData.length);
        const uint8_t *bytes = (const uint8_t *)fileData.bytes;
        NSMutableString *hex = [NSMutableString string];
        for (NSUInteger i = 0; i < previewLen; i++) {
            [hex appendFormat:@"%02X ", bytes[i]];
            if ((i + 1) % 16 == 0) [hex appendString:@"\n"];
        }
        HWSLog([NSString stringWithFormat:@"[探针] fileData 前128字节:\n%@", hex]);
        HWSLog([NSString stringWithFormat:@"[探针] fileData.length = %lu 字节", (unsigned long)fileData.length]);

        
        if (dataInfo) {
            unsigned int count;
            objc_property_t *props = class_copyPropertyList([dataInfo class], &count);
            for (unsigned int i = 0; i < count; i++) {
                NSString *pName = [NSString stringWithUTF8String:property_getName(props[i])];
                NSString *lp = pName.lowercaseString;
                if ([lp containsString:@"offset"] || [lp containsString:@"seek"] || [lp containsString:@"pos"]) {
                    g_hapOffsetKey = pName;
                    id val = [dataInfo valueForKey:pName];
                    HWSLog([NSString stringWithFormat:@"🔑 [探针] 发现 offset 字段: %@ = %@", pName, val]);
                }
            }
            if (!g_hapOffsetKey) {
                HWSLog(@"⚠️ [探针] 未自动发现 offset 字段，将使用 dataInfo 全属性查找");
                g_hapOffsetKey = @"__unresolved__";
            }
            if (props) free(props);
        }

        g_hapChunkSize = (NSInteger)fileData.length;
        HWSLog([NSString stringWithFormat:@"[探针] 记录块大小 = %ld 字节", (long)g_hapChunkSize]);
        HWSLog(@"══════════════════════════════════════\n");
    });

    _logos_meta_orig$SideloadHooks$WSSCommonFileMgrSendUtil$sendFileContentToDeviceWithDataInfo$fileData$deviceInfo$selectIndexArray$negotiate$(self, _cmd, dataInfo, fileData, deviceInfo, selectIndexArray, negotiate);
}




static void _logos_meta_method$SideloadHooks$WSSCommonFileMgrSendUtil$sendFileTransferNegotiate$deviceInfo$errorCode$(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, id negotiate, id deviceInfo, NSInteger errorCode) {
    HWSLog([NSString stringWithFormat:@"\n🟡 [WSSCommonFileMgrSendUtil] sendFileTransferNegotiate!\n  ➤ errorCode = %ld", (long)errorCode]);
    _logos_meta_orig$SideloadHooks$WSSCommonFileMgrSendUtil$sendFileTransferNegotiate$deviceInfo$errorCode$(self, _cmd, negotiate, deviceInfo, errorCode);
}






static NSString * _logos_method$SideloadHooks$WSSCommonFileInfo$filePath(_LOGOS_SELF_TYPE_NORMAL WSSCommonFileInfo* _LOGOS_SELF_CONST __unused self, SEL __unused _cmd) {
    NSString *orig = _logos_orig$SideloadHooks$WSSCommonFileInfo$filePath(self, _cmd);
    if (g_intercept && g_hapPath && orig) {
        if ([orig containsString:@".bin"] || [orig containsString:@".hap"] || [orig containsString:@".pkg"]) {
            
            return g_hapPath;
        }
    }
    return orig;
}

static long long _logos_method$SideloadHooks$WSSCommonFileInfo$fileSize(_LOGOS_SELF_TYPE_NORMAL WSSCommonFileInfo* _LOGOS_SELF_CONST __unused self, SEL __unused _cmd) {
    long long orig = _logos_orig$SideloadHooks$WSSCommonFileInfo$fileSize(self, _cmd);
    if (g_intercept && g_hapPath && orig > 0) {
        NSString *path = [self valueForKey:@"filePath"]; 
        if ([path isEqualToString:g_hapPath]) {
            NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:g_hapPath error:nil];
            if (attrs) {
                return [attrs fileSize];
            }
        }
    }
    return orig;
}

static NSString * _logos_method$SideloadHooks$WSSCommonFileInfo$sha256Result(_LOGOS_SELF_TYPE_NORMAL WSSCommonFileInfo* _LOGOS_SELF_CONST __unused self, SEL __unused _cmd) {
    NSString *orig = _logos_orig$SideloadHooks$WSSCommonFileInfo$sha256Result(self, _cmd);
    if (g_intercept && g_hapPath) {
        NSString *path = [self valueForKey:@"filePath"];
        if ([path isEqualToString:g_hapPath]) {
            return nil; 
        }
    }
    return orig;
}

static BOOL _logos_method$SideloadHooks$WSSCommonFileInfo$isNeedVerify(_LOGOS_SELF_TYPE_NORMAL WSSCommonFileInfo* _LOGOS_SELF_CONST __unused self, SEL __unused _cmd) {
    if (g_intercept && g_hapPath) {
        NSString *path = [self valueForKey:@"filePath"];
        if ([path isEqualToString:g_hapPath]) {
            return NO; 
        }
    }
    return _logos_orig$SideloadHooks$WSSCommonFileInfo$isNeedVerify(self, _cmd);
}







static BOOL _logos_method$_ungrouped$NSFileManager$copyItemAtPath$toPath$error$(_LOGOS_SELF_TYPE_NORMAL NSFileManager* _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, NSString * src, NSString * dst, NSError ** err) {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"Copy(P): %@ -> %@", src.lastPathComponent, dst.lastPathComponent]); }
    return _logos_orig$_ungrouped$NSFileManager$copyItemAtPath$toPath$error$(self, _cmd, src, dst, err);
}

static BOOL _logos_method$_ungrouped$NSFileManager$copyItemAtURL$toURL$error$(_LOGOS_SELF_TYPE_NORMAL NSFileManager* _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, NSURL * srcU, NSURL * dstU, NSError ** err) {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"Copy(U): %@ -> %@", srcU.lastPathComponent, dstU.lastPathComponent]); }
    return _logos_orig$_ungrouped$NSFileManager$copyItemAtURL$toURL$error$(self, _cmd, srcU, dstU, err);
}

static BOOL _logos_method$_ungrouped$NSFileManager$moveItemAtPath$toPath$error$(_LOGOS_SELF_TYPE_NORMAL NSFileManager* _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, NSString * src, NSString * dst, NSError ** err) {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"Move(P): %@ -> %@", src.lastPathComponent, dst.lastPathComponent]); }
    return _logos_orig$_ungrouped$NSFileManager$moveItemAtPath$toPath$error$(self, _cmd, src, dst, err);
}

static BOOL _logos_method$_ungrouped$NSFileManager$moveItemAtURL$toURL$error$(_LOGOS_SELF_TYPE_NORMAL NSFileManager* _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, NSURL * srcU, NSURL * dstU, NSError ** err) {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"Move(U): %@ -> %@", srcU.lastPathComponent, dstU.lastPathComponent]); }
    
    
    if (g_intercept && isTargetExt(dstU.path)) {
        HWSLog(@"💥 劫持 moveItemAtURL! 准备进行全宇宙扫描探测传输接口...");
        static dispatch_once_t onceToken;
        dispatch_once(&onceToken, ^{
            
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
                HWSLog(@"\n\n🎯🎯🎯 ====== [v4.53] 开始绝对精准探测底层传输接口 ======");
                
                NSArray *mKws = @[@"sendfile", @"transferfile", @"pushfile", @"installapp", @"sendpkg", @"transferpkg", @"startinstall", @"senddata", @"p2psend"];
                
                int n = objc_getClassList(NULL, 0);
                Class *classes = (Class *)malloc(sizeof(Class) * n);
                objc_getClassList(classes, n);
                
                int discovered = 0;
                for (int i = 0; i < n; i++) {
                    NSString *clsName = NSStringFromClass(classes[i]);
                    if ([clsName hasPrefix:@"UI"] || [clsName hasPrefix:@"NS"] || [clsName hasPrefix:@"_UI"] || [clsName hasPrefix:@"CA"] || [clsName hasPrefix:@"OS_"]) continue;
                    unsigned int count = 0;
                    Method *methods = class_copyMethodList(classes[i], &count);
                    for (unsigned int m = 0; m < count; m++) {
                        NSString *mName = NSStringFromSelector(method_getName(methods[m]));
                        for (NSString *kw in mKws) {
                            if ([mName localizedCaseInsensitiveContainsString:kw]) { discovered++; break; }
                        }
                    }
                    if (methods) free(methods);
                    methods = class_copyMethodList(object_getClass((id)classes[i]), &count);
                    for (unsigned int m = 0; m < count; m++) {
                        NSString *mName = NSStringFromSelector(method_getName(methods[m]));
                        for (NSString *kw in mKws) {
                            if ([mName localizedCaseInsensitiveContainsString:kw]) { discovered++; break; }
                        }
                    }
                    if (methods) free(methods);
                }
                free(classes);
                
                HWSLog([NSString stringWithFormat:@"🎯🎯🎯 ====== [v4.53] 扫描完成，共发现 %d 个关联方法 ======", discovered]);
            });

            HWSLog(@"\n======== [v4.53] 触发底层传输 ========");
            
        });

        
        return _logos_orig$_ungrouped$NSFileManager$moveItemAtURL$toURL$error$(self, _cmd, srcU, dstU, err);
    }
    return _logos_orig$_ungrouped$NSFileManager$moveItemAtURL$toURL$error$(self, _cmd, srcU, dstU, err);
}





static BOOL isInstallCommandDict(id obj) {
    if (![obj isKindOfClass:[NSDictionary class]]) return NO;
    NSDictionary *d = (NSDictionary *)obj;
    BOOL hasPkg  = NO;
    BOOL hasHash = NO;
    for (NSString *k in d) {
        NSString *lk = k.lowercaseString;
        if ([lk isEqualToString:@"packagename"] || [lk isEqualToString:@"package"]) hasPkg = YES;
        if ([lk isEqualToString:@"hashvalue"] || [lk isEqualToString:@"hash"] || [lk isEqualToString:@"sha256"] || [lk isEqualToString:@"digest"]) hasHash = YES;
    }
    return hasPkg && hasHash;
}


static BOOL containsInstallCommand(id obj) {
    if (isInstallCommandDict(obj)) return YES;
    if ([obj isKindOfClass:[NSArray class]]) {
        for (id item in (NSArray *)obj) {
            if (containsInstallCommand(item)) return YES;
        }
    } else if ([obj isKindOfClass:[NSDictionary class]]) {
        for (id v in [(NSDictionary *)obj allValues]) {
            if (containsInstallCommand(v)) return YES;
        }
    }
    return NO;
}

static id replaceTargetJson(id obj, long long hapSize) {
    if ([obj isKindOfClass:[NSDictionary class]]) {
        NSMutableDictionary *m = [NSMutableDictionary dictionary];
        for (NSString *k in (NSDictionary *)obj) {
            NSString *lk = k.lowercaseString;
            id val = [(NSDictionary *)obj objectForKey:k];
            
            if (hapSize > 0 && 
                ([lk isEqualToString:@"size"] || [lk isEqualToString:@"filesize"] || [lk isEqualToString:@"apksize"] || [lk isEqualToString:@"appsize"]) 
                && [val isKindOfClass:[NSNumber class]]) {
                HWSLog([NSString stringWithFormat:@"✨ 动态劫持 JSON 里的 size: %@ -> %lld", val, hapSize]);
                m[k] = @(hapSize);
            } else if ((g_hapChecksum || g_hapMD5) && 
                       ([lk isEqualToString:@"hash"] || [lk isEqualToString:@"sha256"] || [lk isEqualToString:@"digest"] || [lk isEqualToString:@"filehash"] || [lk isEqualToString:@"shash"] || [lk isEqualToString:@"hashvalue"]) 
                       && [val isKindOfClass:[NSString class]]) {
                if ([(NSString *)val length] == 32 && g_hapMD5) {
                    HWSLog([NSString stringWithFormat:@"✨ 动态劫持 JSON 里的 MD5 hash: %@ -> %@", val, g_hapMD5]);
                    m[k] = g_hapMD5;
                } else if ([(NSString *)val length] == 40 && g_hapSHA1) {
                    HWSLog([NSString stringWithFormat:@"✨ 动态劫持 JSON 里的 SHA1 hash: %@ -> %@", val, g_hapSHA1]);
                    m[k] = g_hapSHA1;
                } else if ([(NSString *)val length] == 64 && g_hapChecksum) {
                    HWSLog([NSString stringWithFormat:@"✨ 动态劫持 JSON 里的 SHA256 hash: %@ -> %@", val, g_hapChecksum]);
                    m[k] = g_hapChecksum;
                } else {
                    HWSLog([NSString stringWithFormat:@"✨ 默认劫持 JSON 里的 hash: %@ -> %@", val, g_hapChecksum]);
                    m[k] = g_hapChecksum;
                }
            } else if (g_hapBundleID && g_hapBundleID.length > 0 && 
                       ([lk isEqualToString:@"package"] || [lk isEqualToString:@"packagename"] || [lk isEqualToString:@"bundle"] || [lk isEqualToString:@"bundlename"]) 
                       && [val isKindOfClass:[NSString class]]) {
                HWSLog([NSString stringWithFormat:@"✨ 动态劫持 JSON 里的 bundle: %@ -> %@", val, g_hapBundleID]);
                m[k] = g_hapBundleID;
            } else if ([lk isEqualToString:@"installtype"] && [val isKindOfClass:[NSNumber class]]) {
                
                NSInteger origType = [val integerValue];
                HWSLog([NSString stringWithFormat:@"✨ installType: %ld -> 1 (尝试开发者模式)", (long)origType]);
                m[k] = @1;
            } else if ([val isKindOfClass:[NSString class]] && ([lk isEqualToString:@"sign"] || [lk isEqualToString:@"signature"] || [lk isEqualToString:@"cert"] || [lk isEqualToString:@"certsign"])) {
                HWSLog([NSString stringWithFormat:@"✨ 清除服务端签名约束: %@", k]);
                m[k] = @"";
            } else {
                m[k] = replaceTargetJson(val, hapSize);
            }
        }
        return m;
    } else if ([obj isKindOfClass:[NSArray class]]) {
        NSMutableArray *m = [NSMutableArray array];
        for (id item in (NSArray *)obj) {
            [m addObject:replaceTargetJson(item, hapSize)];
        }
        return m;
    }
    return obj;
}

static BOOL g_jsonHookActive = NO; 



static id _logos_meta_method$_ungrouped$NSJSONSerialization$JSONObjectWithData$options$error$(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, NSData * data, NSJSONReadingOptions opt, NSError ** error) {
    id orig = _logos_meta_orig$_ungrouped$NSJSONSerialization$JSONObjectWithData$options$error$(self, _cmd, data, opt, error);
    if (g_intercept && orig && g_hapPath && !g_jsonHookActive) {
        @try {
            
            if (containsInstallCommand(orig)) {
                g_jsonHookActive = YES; 
                HWSLog(@"💥 [核弹级伪装] 命中安装指令 JSON！执行外科手术级伪装...");
                
                
                HWSLog([NSString stringWithFormat:@"[原始协议] %@", orig]);
                
                NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:g_hapPath error:nil];
                long long hapSize = attrs ? [attrs fileSize] : 0;
                orig = replaceTargetJson(orig, hapSize);
                
                HWSLog([NSString stringWithFormat:@"[伪装后协议] %@", orig]);
                g_jsonHookActive = NO;
            }
        } @catch (NSException *e) {
            g_jsonHookActive = NO;
            HWSLog([NSString stringWithFormat:@"❌ JSON 修改异常: %@", e]);
        }
    }
    return orig;
}





static BOOL _logos_method$_ungrouped$NSData$writeToFile$atomically$(_LOGOS_SELF_TYPE_NORMAL NSData* _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, NSString * path, BOOL useAuxiliaryFile) {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"WriteFile: %@", path.lastPathComponent]); }
    if (g_intercept && g_hapPath && isTargetExt(path) && ![path isEqualToString:g_hapPath]) {
        HWSLog(@"💥 劫持 NSData writeToFile!");
        NSFileManager *fm = [NSFileManager defaultManager];
        [fm removeItemAtPath:path error:nil];
        return [fm copyItemAtPath:g_hapPath toPath:path error:nil];
    }
    return _logos_orig$_ungrouped$NSData$writeToFile$atomically$(self, _cmd, path, useAuxiliaryFile);
}

static BOOL _logos_method$_ungrouped$NSData$writeToURL$atomically$(_LOGOS_SELF_TYPE_NORMAL NSData* _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, NSURL * url, BOOL atomically) {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"WriteURL: %@", url.lastPathComponent]); }
    return _logos_orig$_ungrouped$NSData$writeToURL$atomically$(self, _cmd, url, atomically);
}

static NSData* _logos_meta_method$_ungrouped$NSData$dataWithContentsOfFile$(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, NSString * path) {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"Data ReadFile: %@", path.lastPathComponent]); }
    
    
    if (g_intercept && [path hasSuffix:@".cer"]) {
        NSArray *stack = [NSThread callStackSymbols];
        NSArray *top = [stack subarrayWithRange:NSMakeRange(0, MIN(12, stack.count))];
        HWSLog([NSString stringWithFormat:@"🔬 [CertRead 调用栈] 读取: %@\n%@",
            path.lastPathComponent, [top componentsJoinedByString:@"\n"]]);
    }
    
    if (g_intercept && g_hapPath && isTargetExt(path) && ![path isEqualToString:g_hapPath]) {
        HWSLog(@"💥 劫持 Data ReadFile!");
        return _logos_meta_orig$_ungrouped$NSData$dataWithContentsOfFile$(self, _cmd, g_hapPath);
    }
    return _logos_meta_orig$_ungrouped$NSData$dataWithContentsOfFile$(self, _cmd, path);
}


static NSData* _logos_meta_method$_ungrouped$NSData$dataWithContentsOfURL$(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, NSURL * url) {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"Data ReadURL: %@", url.lastPathComponent]); }
    if (g_intercept && g_hapPath && isTargetExt(url.path) && ![url.path isEqualToString:g_hapPath]) {
        HWSLog(@"💥 劫持 Data ReadURL!");
        return _logos_meta_orig$_ungrouped$NSData$dataWithContentsOfURL$(self, _cmd, [NSURL fileURLWithPath:g_hapPath]);
    }
    return _logos_meta_orig$_ungrouped$NSData$dataWithContentsOfURL$(self, _cmd, url);
}

static NSData* _logos_method$_ungrouped$NSData$initWithContentsOfFile$options$error$(_LOGOS_SELF_TYPE_INIT NSData* __unused self, SEL __unused _cmd, NSString * path, NSDataReadingOptions readOptionsMask, NSError ** errorPtr) _LOGOS_RETURN_RETAINED {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"Init ReadFile: %@", path.lastPathComponent]); }
    return _logos_orig$_ungrouped$NSData$initWithContentsOfFile$options$error$(self, _cmd, path, readOptionsMask, errorPtr);
}

static NSData* _logos_method$_ungrouped$NSData$initWithContentsOfURL$options$error$(_LOGOS_SELF_TYPE_INIT NSData* __unused self, SEL __unused _cmd, NSURL * url, NSDataReadingOptions readOptionsMask, NSError ** errorPtr) _LOGOS_RETURN_RETAINED {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"Init ReadURL: %@", url.lastPathComponent]); }
    if (g_intercept && g_hapPath && isTargetExt(url.path) && ![url.path isEqualToString:g_hapPath]) {
        HWSLog(@"💥 劫持 Init ReadURL!");
        return _logos_orig$_ungrouped$NSData$initWithContentsOfURL$options$error$(self, _cmd, [NSURL fileURLWithPath:g_hapPath], readOptionsMask, errorPtr);
    }
    return _logos_orig$_ungrouped$NSData$initWithContentsOfURL$options$error$(self, _cmd, url, readOptionsMask, errorPtr);
}




static NSDictionary * _logos_method$_ungrouped$NSFileManager$attributesOfItemAtPath$error$(_LOGOS_SELF_TYPE_NORMAL NSFileManager* _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, NSString * path, NSError ** err) {
    NSDictionary *origAttrs = _logos_orig$_ungrouped$NSFileManager$attributesOfItemAtPath$error$(self, _cmd, path, err);
    if (g_intercept && g_hapPath && isTargetExt(path) && ![path isEqualToString:g_hapPath]) {
        NSDictionary *hapAttrs = _logos_orig$_ungrouped$NSFileManager$attributesOfItemAtPath$error$(self, _cmd, g_hapPath, nil);
        if (hapAttrs && origAttrs) {
            NSMutableDictionary *newAttrs = [origAttrs mutableCopy];
            newAttrs[NSFileSize] = hapAttrs[NSFileSize];
            HWSLog([NSString stringWithFormat:@"💥 [系统欺骗] 将 .bin 伪装为 .hap 大小: %@ -> %@", origAttrs[NSFileSize], hapAttrs[NSFileSize]]);
            return newAttrs;
        }
    }
    return origAttrs;
}



static NSFileHandle* _logos_meta_method$_ungrouped$NSFileHandle$fileHandleForReadingAtPath$(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, NSString * path) {
    if (g_intercept && isTargetExt(path)) { 
        if (g_hapPath && ![path isEqualToString:g_hapPath]) {
            HWSLog([NSString stringWithFormat:@"💥 [底层流欺骗] C++ 引擎请求文件流，狸猫换太子，返回外挂 .hap!"]);
            return _logos_meta_orig$_ungrouped$NSFileHandle$fileHandleForReadingAtPath$(self, _cmd, g_hapPath);
        }
    }
    return _logos_meta_orig$_ungrouped$NSFileHandle$fileHandleForReadingAtPath$(self, _cmd, path);
}



static NSInputStream* _logos_meta_method$_ungrouped$NSInputStream$inputStreamWithFileAtPath$(_LOGOS_SELF_TYPE_NORMAL Class _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, NSString * path) {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"IS Read: %@", path.lastPathComponent]); }
    if (g_intercept && g_hapPath && isTargetExt(path) && ![path isEqualToString:g_hapPath]) {
        HWSLog(@"💥 劫持 NSInputStream!");
        return _logos_meta_orig$_ungrouped$NSInputStream$inputStreamWithFileAtPath$(self, _cmd, g_hapPath);
    }
    return _logos_meta_orig$_ungrouped$NSInputStream$inputStreamWithFileAtPath$(self, _cmd, path);
}
static NSInputStream* _logos_method$_ungrouped$NSInputStream$initWithFileAtPath$(_LOGOS_SELF_TYPE_INIT NSInputStream* __unused self, SEL __unused _cmd, NSString * path) _LOGOS_RETURN_RETAINED {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"IS Init: %@", path.lastPathComponent]); }
    if (g_intercept && g_hapPath && isTargetExt(path) && ![path isEqualToString:g_hapPath]) {
        HWSLog(@"💥 劫持 NSInputStream init!");
        return _logos_orig$_ungrouped$NSInputStream$initWithFileAtPath$(self, _cmd, g_hapPath);
    }
    return _logos_orig$_ungrouped$NSInputStream$initWithFileAtPath$(self, _cmd, path);
}






static NSURLSessionDataTask * _logos_method$_ungrouped$NSURLSession$dataTaskWithRequest$completionHandler$(_LOGOS_SELF_TYPE_NORMAL NSURLSession* _LOGOS_SELF_CONST __unused self, SEL __unused _cmd, NSURLRequest * request, void (^completionHandler)(NSData *, NSURLResponse *, NSError *)) {
    if (!g_intercept || !completionHandler) return _logos_orig$_ungrouped$NSURLSession$dataTaskWithRequest$completionHandler$(self, _cmd, request, completionHandler);

    
    void (^wrapped)(NSData *, NSURLResponse *, NSError *) = ^(NSData *data, NSURLResponse *response, NSError *error) {
        if (data && !error) {
            NSHTTPURLResponse *http = (NSHTTPURLResponse *)response;
            NSString *urlStr = http.URL.absoluteString;
            BOOL interesting = [urlStr containsString:@"appgallery"] ||
                               [urlStr containsString:@"appmarket"]  ||
                               [urlStr containsString:@"watchapp"]   ||
                               [urlStr containsString:@"wearapp"]    ||
                               [urlStr containsString:@"appstore"]   ||
                               [urlStr containsString:@"install"]    ||
                               [urlStr containsString:@"download"]   ||
                               [urlStr containsString:@"upgrade"];
            if (interesting) {
                NSString *body = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                if (body && (
                    [body containsString:@".bin"]        ||
                    [body containsString:@"bundleName"]  ||
                    [body containsString:@"packageName"] ||
                    [body containsString:@"appId"]       ||
                    [body containsString:@"fileSize"]    ||
                    [body containsString:@"checkSum"]    ||
                    [body containsString:@"digest"]
                )) {
                    NSString *preview = body.length > 2000 ? [body substringToIndex:2000] : body;
                    HWSLog([NSString stringWithFormat:@"\n🌐🌐🌐 [API探针] URL: %@\n响应:\n%@", urlStr, preview]);
                }
            }
        }
        completionHandler(data, response, error);
    };
    return _logos_orig$_ungrouped$NSURLSession$dataTaskWithRequest$completionHandler$(self, _cmd, request, wrapped);
}







static NSString *searchClasses(NSArray *keywords) {
    NSMutableString *r = [NSMutableString string];
    int n = objc_getClassList(NULL, 0);
    Class *cls = (Class *)malloc(sizeof(Class) * n);
    objc_getClassList(cls, n);
    for (NSString *kw in keywords) {
        int f = 0;
        [r appendFormat:@"\n[%@]\n", kw];
        for (int i = 0; i < n; i++) {
            NSString *name = NSStringFromClass(cls[i]);
            if ([name localizedCaseInsensitiveContainsString:kw]) {
                [r appendFormat:@"  %@\n", name];
                if (++f >= 15) { [r appendString:@"  ...\n"]; break; }
            }
        }
        if (!f) [r appendString:@"  (none)\n"];
    }
    free(cls);
    return r;
}

static NSString *dumpTargetClasses() {
    NSArray *targets = @[
        @"HuaweiWear.SHWatchAppStoreManager", 
        @"SHSports.SHNDownloader", 
        @"HuaweiWear.SHHapVersionRequest", 
        @"WatchFaceSDK.WFTrialThemesInstallObserver", 
        @"HuaweiWear.SHWatchAppStoreSetModel",
        @"AppProtection.APAppInstallationManager",
        @"SHSports.RoadNetworkGaoDeDownloader"
    ];
    NSMutableString *r = [NSMutableString string];
    int n = objc_getClassList(NULL, 0);
    Class *classes = (Class *)malloc(sizeof(Class) * n);
    objc_getClassList(classes, n);
    for (int i = 0; i < n; i++) {
        NSString *name = NSStringFromClass(classes[i]);
        for (NSString *t in targets) {
            if ([name isEqualToString:t] || [name hasSuffix:t]) {
                Class cls = classes[i];
                [r appendFormat:@"\n=== [%@] ===\n", name];
                
                
                unsigned int count;
                Method *methods = class_copyMethodList(cls, &count);
                for (int m = 0; m < count; m++) {
                    [r appendFormat:@"- %@\n", NSStringFromSelector(method_getName(methods[m]))];
                }
                free(methods);
                
                
                Method *classMethods = class_copyMethodList(object_getClass((id)cls), &count);
                for (int m = 0; m < count; m++) {
                    [r appendFormat:@"+ %@\n", NSStringFromSelector(method_getName(classMethods[m]))];
                }
                free(classMethods);
            }
        }
    }
    free(classes);
    return (r.length > 0) ? r : @"未找到目标类";
}







@interface HWSideloadUI : NSObject <UIDocumentPickerDelegate>
@property (nonatomic, strong) UIButton *btn;
+ (instancetype)shared;
@end

@implementation HWSideloadUI

+ (instancetype)shared {
    static HWSideloadUI *s;
    static dispatch_once_t t;
    dispatch_once(&t, ^{ s = [HWSideloadUI new]; });
    return s;
}

- (void)attach:(UIWindow *)w {
    if (!self.btn) {
        CGFloat sw = [UIScreen mainScreen].bounds.size.width;
        CGFloat sh = [UIScreen mainScreen].bounds.size.height;

        self.btn = [UIButton buttonWithType:UIButtonTypeSystem];
        self.btn.frame = CGRectMake(sw - 135, sh - 160, 120, 50);
        self.btn.backgroundColor = [UIColor colorWithRed:0.9 green:0.2 blue:0.15 alpha:0.95];
        [self.btn setTitle:@"侧载" forState:UIControlStateNormal];
        self.btn.titleLabel.font = [UIFont boldSystemFontOfSize:15];
        [self.btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        self.btn.layer.cornerRadius = 25;
        self.btn.layer.shadowColor = [UIColor blackColor].CGColor;
        self.btn.layer.shadowOffset = CGSizeMake(0, 3);
        self.btn.layer.shadowOpacity = 0.4;
        self.btn.layer.zPosition = 99999;

        [self.btn addTarget:self action:@selector(menu) forControlEvents:UIControlEventTouchUpInside];
        
        UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc]
            initWithTarget:self action:@selector(drag:)];
        [self.btn addGestureRecognizer:pan];
    }
    
    
    [self.btn removeFromSuperview];

    UIViewController *vc = w.rootViewController;
    if (vc && vc.view) {
        [vc.view addSubview:self.btn];
        [vc.view bringSubviewToFront:self.btn];
    } else {
        [w addSubview:self.btn];
        [w bringSubviewToFront:self.btn];
    }
}

- (void)drag:(UIPanGestureRecognizer *)r {
    CGPoint t = [r translationInView:r.view.superview];
    r.view.center = CGPointMake(r.view.center.x + t.x, r.view.center.y + t.y);
    [r setTranslation:CGPointZero inView:r.view.superview];
}

- (void)menu {
    NSString *bundleStatus = g_realBundleId
        ? [NSString stringWithFormat:@"真实ID: %@\n→ 已拦截网络层替换为官方ID", g_realBundleId]
        : @"Bundle ID: 未捕获";
    NSString *st = g_hapPath
        ? [NSString stringWithFormat:@"%@\n\nHAP: %@\n劫持: %@",
           bundleStatus, [g_hapPath lastPathComponent], g_intercept ? @"已开启" : @"已关闭"]
        : bundleStatus;

    
    UIAlertController *m = [UIAlertController
        alertControllerWithTitle:@"HAP 侧载 v5.0"
        message:st preferredStyle:UIAlertControllerStyleAlert];

    [m addAction:[UIAlertAction actionWithTitle:@"选择 .hap 文件"
        style:UIAlertActionStyleDefault handler:^(id a) {
        [self pickFile];
    }]];

    if (g_hapPath) {
        NSString *title = g_intercept ? @"关闭劫持" : @"开启劫持";
        [m addAction:[UIAlertAction actionWithTitle:title
            style:UIAlertActionStyleDefault handler:^(id a) {
            g_intercept = !g_intercept;
            [self.btn setTitle:(g_intercept ? @"开启" : @"侧载")
                      forState:UIControlStateNormal];
            self.btn.backgroundColor = g_intercept
                ? [UIColor colorWithRed:0.2 green:0.8 blue:0.3 alpha:0.95]
                : [UIColor colorWithRed:0.9 green:0.2 blue:0.15 alpha:0.95];
            
            if (g_intercept) {
                
                if (g_logs) [g_logs removeAllObjects];
            }
            
            NSString *msg = g_intercept
                ? @"劫持已开启。\n前往应用市场安装应用！"
                : @"劫持已关闭。";
            [self alert:@"状态" msg:msg];
        }]];
    }

    [m addAction:[UIAlertAction actionWithTitle:@"查看实时监控日志"
        style:UIAlertActionStyleDefault handler:^(id a) {
        HWSLogViewer *viewer = [[HWSLogViewer alloc] init];
        viewer.modalPresentationStyle = UIModalPresentationOverFullScreen;
        UIViewController *vc = [UIApplication sharedApplication].keyWindow.rootViewController;
        while (vc.presentedViewController) vc = vc.presentedViewController;
        [vc presentViewController:viewer animated:YES completion:nil];
    }]];


    [m addAction:[UIAlertAction actionWithTitle:@"取消"
        style:UIAlertActionStyleCancel handler:nil]];

    UIViewController *vc = [UIApplication sharedApplication].keyWindow.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    [vc presentViewController:m animated:YES completion:nil];
}

- (void)pickFile {
    UIDocumentPickerViewController *p = [[UIDocumentPickerViewController alloc]
        initWithDocumentTypes:@[@"public.data"] inMode:UIDocumentPickerModeImport];
    p.delegate = self;
    p.allowsMultipleSelection = NO;
    
    p.modalPresentationStyle = UIModalPresentationAutomatic;
    UIViewController *vc = [UIApplication sharedApplication].keyWindow.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    [vc presentViewController:p animated:YES completion:nil];
}


- (void)documentPicker:(UIDocumentPickerViewController *)c didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    NSURL *src = urls.firstObject;
    if (!src) return;

    BOOL a = [src startAccessingSecurityScopedResource];
    NSString *dir = [NSSearchPathForDirectoriesInDomains(
        NSCachesDirectory, NSUserDomainMask, YES) firstObject];
    NSString *dst = [dir stringByAppendingPathComponent:src.lastPathComponent];
    NSFileManager *fm = [NSFileManager defaultManager];
    [fm removeItemAtPath:dst error:nil];
    NSError *err;
    [fm copyItemAtPath:src.path toPath:dst error:&err];
    if (a) [src stopAccessingSecurityScopedResource];

    if (!err) {
        
        if (g_hapFileHandle) { [g_hapFileHandle closeFile]; g_hapFileHandle = nil; }

        g_hapPath = [dst copy];
        g_hapChecksum = fileSHA256(g_hapPath);
        g_hapMD5 = fileMD5(g_hapPath);
        g_hapSHA1 = fileSHA1(g_hapPath);
        NSDictionary *at = [fm attributesOfItemAtPath:dst error:nil];
        g_hapFileSize = [at fileSize];
        g_hapFileHandle = [NSFileHandle fileHandleForReadingAtPath:dst];
        if (!g_hapFileHandle) {
            HWSLog(@"❌ 无法打开 HAP 文件句柄！");
        } else {
            HWSLog([NSString stringWithFormat:@"✅ HAP 文件句柄已打开，size=%lld", g_hapFileSize]);
        }
        unsigned long long sz = g_hapFileSize;
        
        UIAlertController *a = [UIAlertController alertControllerWithTitle:@"准备就绪"
            message:[NSString stringWithFormat:@"已加载文件: %@\n大小: %.1f MB\n\n【重要】请输入您自己应用的包名 (Bundle ID，如 com.yourapp.watch):\n※ 如果您已经在表中修改了与载体一致则可留空", [dst lastPathComponent], sz/1048576.0]
            preferredStyle:UIAlertControllerStyleAlert];
            
        [a addTextFieldWithConfigurationHandler:^(UITextField *textField) {
            textField.placeholder = @"留空则使用载体应用默认值";
            textField.clearButtonMode = UITextFieldViewModeWhileEditing;
            
            if (g_hapBundleID) textField.text = g_hapBundleID;
        }];
        
        [a addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
            UITextField *tf = a.textFields.firstObject;
            NSString *bID = [tf.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            if (bID.length > 0) {
                g_hapBundleID = [bID copy];
                HWSLog([NSString stringWithFormat:@"已设置注入的 Bundle ID: %@", g_hapBundleID]);
            } else {
                g_hapBundleID = nil;
                HWSLog(@"未设置自定义 Bundle ID，将使用系统自带的");
            }
            [self alert:@"提示" msg:@"设置成功！\n请点击侧载按钮 > 开启劫持\n然后进入手表应用市场安装任意应用。"];
        }]];
        
        UIViewController *vc = [UIApplication sharedApplication].keyWindow.rootViewController;
        while (vc.presentedViewController) vc = vc.presentedViewController;
        [vc presentViewController:a animated:YES completion:nil];
    } else {
        [self alert:@"错误" msg:err.localizedDescription];
    }
}

- (void)alert:(NSString *)t msg:(NSString *)m {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:t
        message:m preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"确定"
        style:UIAlertActionStyleDefault handler:nil]];
    UIViewController *vc = [UIApplication sharedApplication].keyWindow.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    [vc presentViewController:a animated:YES completion:nil];
}

@end






static void _logos_method$_ungrouped$UIWindow$makeKeyAndVisible(_LOGOS_SELF_TYPE_NORMAL UIWindow* _LOGOS_SELF_CONST __unused self, SEL __unused _cmd) {
    _logos_orig$_ungrouped$UIWindow$makeKeyAndVisible(self, _cmd);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [[HWSideloadUI shared] attach:self];
    });
}


static void appDidBecomeActive(CFNotificationCenterRef center, void *observer, CFStringRef name, const void *object, CFDictionaryRef userInfo) {
    UIWindow *k = [UIApplication sharedApplication].keyWindow;
    if (k) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [[HWSideloadUI shared] attach:k];
        });
    }
}

static __attribute__((constructor)) void _logosLocalCtor_9b4d2dc8(int __unused argc, char __unused **argv, char __unused **envp) {
    g_realBundleId = [[[NSBundle mainBundle] bundleIdentifier] copy];
    NSLog(@"[HWSideload] Initializing main hooks.");
    {Class _logos_class$_ungrouped$NSBundle = objc_getClass("NSBundle"); { MSHookMessageEx(_logos_class$_ungrouped$NSBundle, @selector(bundleIdentifier), (IMP)&_logos_method$_ungrouped$NSBundle$bundleIdentifier, (IMP*)&_logos_orig$_ungrouped$NSBundle$bundleIdentifier);}{ MSHookMessageEx(_logos_class$_ungrouped$NSBundle, @selector(objectForInfoDictionaryKey:), (IMP)&_logos_method$_ungrouped$NSBundle$objectForInfoDictionaryKey$, (IMP*)&_logos_orig$_ungrouped$NSBundle$objectForInfoDictionaryKey$);}Class _logos_class$_ungrouped$NSMutableURLRequest = objc_getClass("NSMutableURLRequest"); { MSHookMessageEx(_logos_class$_ungrouped$NSMutableURLRequest, @selector(initWithURL:), (IMP)&_logos_method$_ungrouped$NSMutableURLRequest$initWithURL$, (IMP*)&_logos_orig$_ungrouped$NSMutableURLRequest$initWithURL$);}{ MSHookMessageEx(_logos_class$_ungrouped$NSMutableURLRequest, @selector(initWithURL:cachePolicy:timeoutInterval:), (IMP)&_logos_method$_ungrouped$NSMutableURLRequest$initWithURL$cachePolicy$timeoutInterval$, (IMP*)&_logos_orig$_ungrouped$NSMutableURLRequest$initWithURL$cachePolicy$timeoutInterval$);}{ MSHookMessageEx(_logos_class$_ungrouped$NSMutableURLRequest, @selector(setURL:), (IMP)&_logos_method$_ungrouped$NSMutableURLRequest$setURL$, (IMP*)&_logos_orig$_ungrouped$NSMutableURLRequest$setURL$);}{ MSHookMessageEx(_logos_class$_ungrouped$NSMutableURLRequest, @selector(setValue:forHTTPHeaderField:), (IMP)&_logos_method$_ungrouped$NSMutableURLRequest$setValue$forHTTPHeaderField$, (IMP*)&_logos_orig$_ungrouped$NSMutableURLRequest$setValue$forHTTPHeaderField$);}{ MSHookMessageEx(_logos_class$_ungrouped$NSMutableURLRequest, @selector(addValue:forHTTPHeaderField:), (IMP)&_logos_method$_ungrouped$NSMutableURLRequest$addValue$forHTTPHeaderField$, (IMP*)&_logos_orig$_ungrouped$NSMutableURLRequest$addValue$forHTTPHeaderField$);}{ MSHookMessageEx(_logos_class$_ungrouped$NSMutableURLRequest, @selector(setAllHTTPHeaderFields:), (IMP)&_logos_method$_ungrouped$NSMutableURLRequest$setAllHTTPHeaderFields$, (IMP*)&_logos_orig$_ungrouped$NSMutableURLRequest$setAllHTTPHeaderFields$);}{ MSHookMessageEx(_logos_class$_ungrouped$NSMutableURLRequest, @selector(setHTTPBody:), (IMP)&_logos_method$_ungrouped$NSMutableURLRequest$setHTTPBody$, (IMP*)&_logos_orig$_ungrouped$NSMutableURLRequest$setHTTPBody$);}Class _logos_class$_ungrouped$NSFileManager = objc_getClass("NSFileManager"); { MSHookMessageEx(_logos_class$_ungrouped$NSFileManager, @selector(copyItemAtPath:toPath:error:), (IMP)&_logos_method$_ungrouped$NSFileManager$copyItemAtPath$toPath$error$, (IMP*)&_logos_orig$_ungrouped$NSFileManager$copyItemAtPath$toPath$error$);}{ MSHookMessageEx(_logos_class$_ungrouped$NSFileManager, @selector(copyItemAtURL:toURL:error:), (IMP)&_logos_method$_ungrouped$NSFileManager$copyItemAtURL$toURL$error$, (IMP*)&_logos_orig$_ungrouped$NSFileManager$copyItemAtURL$toURL$error$);}{ MSHookMessageEx(_logos_class$_ungrouped$NSFileManager, @selector(moveItemAtPath:toPath:error:), (IMP)&_logos_method$_ungrouped$NSFileManager$moveItemAtPath$toPath$error$, (IMP*)&_logos_orig$_ungrouped$NSFileManager$moveItemAtPath$toPath$error$);}{ MSHookMessageEx(_logos_class$_ungrouped$NSFileManager, @selector(moveItemAtURL:toURL:error:), (IMP)&_logos_method$_ungrouped$NSFileManager$moveItemAtURL$toURL$error$, (IMP*)&_logos_orig$_ungrouped$NSFileManager$moveItemAtURL$toURL$error$);}{ MSHookMessageEx(_logos_class$_ungrouped$NSFileManager, @selector(attributesOfItemAtPath:error:), (IMP)&_logos_method$_ungrouped$NSFileManager$attributesOfItemAtPath$error$, (IMP*)&_logos_orig$_ungrouped$NSFileManager$attributesOfItemAtPath$error$);}Class _logos_class$_ungrouped$NSJSONSerialization = objc_getClass("NSJSONSerialization"); Class _logos_metaclass$_ungrouped$NSJSONSerialization = object_getClass(_logos_class$_ungrouped$NSJSONSerialization); { MSHookMessageEx(_logos_metaclass$_ungrouped$NSJSONSerialization, @selector(JSONObjectWithData:options:error:), (IMP)&_logos_meta_method$_ungrouped$NSJSONSerialization$JSONObjectWithData$options$error$, (IMP*)&_logos_meta_orig$_ungrouped$NSJSONSerialization$JSONObjectWithData$options$error$);}Class _logos_class$_ungrouped$NSData = objc_getClass("NSData"); Class _logos_metaclass$_ungrouped$NSData = object_getClass(_logos_class$_ungrouped$NSData); { MSHookMessageEx(_logos_class$_ungrouped$NSData, @selector(writeToFile:atomically:), (IMP)&_logos_method$_ungrouped$NSData$writeToFile$atomically$, (IMP*)&_logos_orig$_ungrouped$NSData$writeToFile$atomically$);}{ MSHookMessageEx(_logos_class$_ungrouped$NSData, @selector(writeToURL:atomically:), (IMP)&_logos_method$_ungrouped$NSData$writeToURL$atomically$, (IMP*)&_logos_orig$_ungrouped$NSData$writeToURL$atomically$);}{ MSHookMessageEx(_logos_metaclass$_ungrouped$NSData, @selector(dataWithContentsOfFile:), (IMP)&_logos_meta_method$_ungrouped$NSData$dataWithContentsOfFile$, (IMP*)&_logos_meta_orig$_ungrouped$NSData$dataWithContentsOfFile$);}{ MSHookMessageEx(_logos_metaclass$_ungrouped$NSData, @selector(dataWithContentsOfURL:), (IMP)&_logos_meta_method$_ungrouped$NSData$dataWithContentsOfURL$, (IMP*)&_logos_meta_orig$_ungrouped$NSData$dataWithContentsOfURL$);}{ MSHookMessageEx(_logos_class$_ungrouped$NSData, @selector(initWithContentsOfFile:options:error:), (IMP)&_logos_method$_ungrouped$NSData$initWithContentsOfFile$options$error$, (IMP*)&_logos_orig$_ungrouped$NSData$initWithContentsOfFile$options$error$);}{ MSHookMessageEx(_logos_class$_ungrouped$NSData, @selector(initWithContentsOfURL:options:error:), (IMP)&_logos_method$_ungrouped$NSData$initWithContentsOfURL$options$error$, (IMP*)&_logos_orig$_ungrouped$NSData$initWithContentsOfURL$options$error$);}Class _logos_class$_ungrouped$NSFileHandle = objc_getClass("NSFileHandle"); Class _logos_metaclass$_ungrouped$NSFileHandle = object_getClass(_logos_class$_ungrouped$NSFileHandle); { MSHookMessageEx(_logos_metaclass$_ungrouped$NSFileHandle, @selector(fileHandleForReadingAtPath:), (IMP)&_logos_meta_method$_ungrouped$NSFileHandle$fileHandleForReadingAtPath$, (IMP*)&_logos_meta_orig$_ungrouped$NSFileHandle$fileHandleForReadingAtPath$);}Class _logos_class$_ungrouped$NSInputStream = objc_getClass("NSInputStream"); Class _logos_metaclass$_ungrouped$NSInputStream = object_getClass(_logos_class$_ungrouped$NSInputStream); { MSHookMessageEx(_logos_metaclass$_ungrouped$NSInputStream, @selector(inputStreamWithFileAtPath:), (IMP)&_logos_meta_method$_ungrouped$NSInputStream$inputStreamWithFileAtPath$, (IMP*)&_logos_meta_orig$_ungrouped$NSInputStream$inputStreamWithFileAtPath$);}{ MSHookMessageEx(_logos_class$_ungrouped$NSInputStream, @selector(initWithFileAtPath:), (IMP)&_logos_method$_ungrouped$NSInputStream$initWithFileAtPath$, (IMP*)&_logos_orig$_ungrouped$NSInputStream$initWithFileAtPath$);}Class _logos_class$_ungrouped$NSURLSession = objc_getClass("NSURLSession"); { MSHookMessageEx(_logos_class$_ungrouped$NSURLSession, @selector(dataTaskWithRequest:completionHandler:), (IMP)&_logos_method$_ungrouped$NSURLSession$dataTaskWithRequest$completionHandler$, (IMP*)&_logos_orig$_ungrouped$NSURLSession$dataTaskWithRequest$completionHandler$);}Class _logos_class$_ungrouped$UIWindow = objc_getClass("UIWindow"); { MSHookMessageEx(_logos_class$_ungrouped$UIWindow, @selector(makeKeyAndVisible), (IMP)&_logos_method$_ungrouped$UIWindow$makeKeyAndVisible, (IMP*)&_logos_orig$_ungrouped$UIWindow$makeKeyAndVisible);}}
    NSLog(@"[HWSideload] 真实 Bundle ID: %@", g_realBundleId);
    
    dispatch_async(dispatch_get_main_queue(), ^{
        
        struct rebinding rb[] = {
            {"SecCodeCheckValidity", (void *)my_SecCodeCheckValidity, (void **)&orig_SecCodeCheckValidity},
            {"SecTrustEvaluate", (void *)my_SecTrustEvaluate, (void **)&orig_SecTrustEvaluate},
            {"SecTrustEvaluateWithError", (void *)my_SecTrustEvaluateWithError, (void **)&orig_SecTrustEvaluateWithError}
        };
        int hookResult = rebind_symbols(rb, sizeof(rb)/sizeof(struct rebinding));
        HWSLog([NSString stringWithFormat:@"🛡️ [Fishhook] 绑定环境检测绕过结果: %d (0=成功)", hookResult]);
        
        CFNotificationCenterAddObserver(CFNotificationCenterGetLocalCenter(), NULL,
            appDidBecomeActive, (CFStringRef)UIApplicationDidBecomeActiveNotification, NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
            
        
        Class wifiCls = NSClassFromString(@"HuaweiWear.SHDWiFiTransferManager");
        Class storeCls = NSClassFromString(@"HuaweiWear.SHWatchAppStoreManager");
        Class cmdCls = NSClassFromString(@"HuaweiWear.SHDWiFiCommandSend");
        if (wifiCls || storeCls || cmdCls) {
            NSLog(@"[HWSideload] ✅ 成功全局获取动态类句柄!");
            HWSLog(dumpTargetClasses());
            {Class _logos_class$SideloadHooks$NSNotificationCenter = objc_getClass("NSNotificationCenter"); { MSHookMessageEx(_logos_class$SideloadHooks$NSNotificationCenter, @selector(postNotificationName:object:userInfo:), (IMP)&_logos_method$SideloadHooks$NSNotificationCenter$postNotificationName$object$userInfo$, (IMP*)&_logos_orig$SideloadHooks$NSNotificationCenter$postNotificationName$object$userInfo$);}Class _logos_class$SideloadHooks$SHDWiFiCommandSend = cmdCls; Class _logos_metaclass$SideloadHooks$SHDWiFiCommandSend = object_getClass(_logos_class$SideloadHooks$SHDWiFiCommandSend); { MSHookMessageEx(_logos_metaclass$SideloadHooks$SHDWiFiCommandSend, @selector(sendNotifiDeviceStartTransferFileWithFileInfo:), (IMP)&_logos_meta_method$SideloadHooks$SHDWiFiCommandSend$sendNotifiDeviceStartTransferFileWithFileInfo$, (IMP*)&_logos_meta_orig$SideloadHooks$SHDWiFiCommandSend$sendNotifiDeviceStartTransferFileWithFileInfo$);}{ MSHookMessageEx(_logos_metaclass$SideloadHooks$SHDWiFiCommandSend, @selector(sendNotifiDeviceTransferFileInfoWithFileInfo:), (IMP)&_logos_meta_method$SideloadHooks$SHDWiFiCommandSend$sendNotifiDeviceTransferFileInfoWithFileInfo$, (IMP*)&_logos_meta_orig$SideloadHooks$SHDWiFiCommandSend$sendNotifiDeviceTransferFileInfoWithFileInfo$);}{ MSHookMessageEx(_logos_metaclass$SideloadHooks$SHDWiFiCommandSend, @selector(sendTransferFileInfo:), (IMP)&_logos_meta_method$SideloadHooks$SHDWiFiCommandSend$sendTransferFileInfo$, (IMP*)&_logos_meta_orig$SideloadHooks$SHDWiFiCommandSend$sendTransferFileInfo$);}Class _logos_class$SideloadHooks$SHDWiFiTransferManager = wifiCls; { MSHookMessageEx(_logos_class$SideloadHooks$SHDWiFiTransferManager, @selector(transferFileInfo:callback:), (IMP)&_logos_method$SideloadHooks$SHDWiFiTransferManager$transferFileInfo$callback$, (IMP*)&_logos_orig$SideloadHooks$SHDWiFiTransferManager$transferFileInfo$callback$);}Class _logos_class$SideloadHooks$SHWatchAppStoreManager = storeCls; { MSHookMessageEx(_logos_class$SideloadHooks$SHWatchAppStoreManager, @selector(pushFileProgress:), (IMP)&_logos_method$SideloadHooks$SHWatchAppStoreManager$pushFileProgress$, (IMP*)&_logos_orig$SideloadHooks$SHWatchAppStoreManager$pushFileProgress$);}Class _logos_class$SideloadHooks$WSSCommonFileMgr = objc_getClass("WSSCommonFileMgr"); { MSHookMessageEx(_logos_class$SideloadHooks$WSSCommonFileMgr, @selector(sendFileTransferNegotiate:errorCode:), (IMP)&_logos_method$SideloadHooks$WSSCommonFileMgr$sendFileTransferNegotiate$errorCode$, (IMP*)&_logos_orig$SideloadHooks$WSSCommonFileMgr$sendFileTransferNegotiate$errorCode$);}{ MSHookMessageEx(_logos_class$SideloadHooks$WSSCommonFileMgr, @selector(finishPushFileWithType:), (IMP)&_logos_method$SideloadHooks$WSSCommonFileMgr$finishPushFileWithType$, (IMP*)&_logos_orig$SideloadHooks$WSSCommonFileMgr$finishPushFileWithType$);}{ MSHookMessageEx(_logos_class$SideloadHooks$WSSCommonFileMgr, @selector(pausedTransferFile), (IMP)&_logos_method$SideloadHooks$WSSCommonFileMgr$pausedTransferFile, (IMP*)&_logos_orig$SideloadHooks$WSSCommonFileMgr$pausedTransferFile);}{ MSHookMessageEx(_logos_class$SideloadHooks$WSSCommonFileMgr, @selector(sendFileContentToDeviceWithDataInfo:), (IMP)&_logos_method$SideloadHooks$WSSCommonFileMgr$sendFileContentToDeviceWithDataInfo$, (IMP*)&_logos_orig$SideloadHooks$WSSCommonFileMgr$sendFileContentToDeviceWithDataInfo$);}{ MSHookMessageEx(_logos_class$SideloadHooks$WSSCommonFileMgr, @selector(sendFileCheckMode:fileid:offsetSize:), (IMP)&_logos_method$SideloadHooks$WSSCommonFileMgr$sendFileCheckMode$fileid$offsetSize$, (IMP*)&_logos_orig$SideloadHooks$WSSCommonFileMgr$sendFileCheckMode$fileid$offsetSize$);}{ MSHookMessageEx(_logos_class$SideloadHooks$WSSCommonFileMgr, @selector(recevicedPushFileData:commondID:deviceIdentify:), (IMP)&_logos_method$SideloadHooks$WSSCommonFileMgr$recevicedPushFileData$commondID$deviceIdentify$, (IMP*)&_logos_orig$SideloadHooks$WSSCommonFileMgr$recevicedPushFileData$commondID$deviceIdentify$);}Class _logos_class$SideloadHooks$WSSCommonFileMgrSendUtil = objc_getClass("WSSCommonFileMgrSendUtil"); Class _logos_metaclass$SideloadHooks$WSSCommonFileMgrSendUtil = object_getClass(_logos_class$SideloadHooks$WSSCommonFileMgrSendUtil); { MSHookMessageEx(_logos_metaclass$SideloadHooks$WSSCommonFileMgrSendUtil, @selector(sendFileCheckMode:deviceInfo:fileInfo:fileid:offsetSize:), (IMP)&_logos_meta_method$SideloadHooks$WSSCommonFileMgrSendUtil$sendFileCheckMode$deviceInfo$fileInfo$fileid$offsetSize$, (IMP*)&_logos_meta_orig$SideloadHooks$WSSCommonFileMgrSendUtil$sendFileCheckMode$deviceInfo$fileInfo$fileid$offsetSize$);}{ MSHookMessageEx(_logos_metaclass$SideloadHooks$WSSCommonFileMgrSendUtil, @selector(sendFileContentToDeviceWithDataInfo:fileData:deviceInfo:selectIndexArray:negotiate:), (IMP)&_logos_meta_method$SideloadHooks$WSSCommonFileMgrSendUtil$sendFileContentToDeviceWithDataInfo$fileData$deviceInfo$selectIndexArray$negotiate$, (IMP*)&_logos_meta_orig$SideloadHooks$WSSCommonFileMgrSendUtil$sendFileContentToDeviceWithDataInfo$fileData$deviceInfo$selectIndexArray$negotiate$);}{ MSHookMessageEx(_logos_metaclass$SideloadHooks$WSSCommonFileMgrSendUtil, @selector(sendFileTransferNegotiate:deviceInfo:errorCode:), (IMP)&_logos_meta_method$SideloadHooks$WSSCommonFileMgrSendUtil$sendFileTransferNegotiate$deviceInfo$errorCode$, (IMP*)&_logos_meta_orig$SideloadHooks$WSSCommonFileMgrSendUtil$sendFileTransferNegotiate$deviceInfo$errorCode$);}Class _logos_class$SideloadHooks$WSSCommonFileInfo = objc_getClass("WSSCommonFileInfo"); { MSHookMessageEx(_logos_class$SideloadHooks$WSSCommonFileInfo, @selector(filePath), (IMP)&_logos_method$SideloadHooks$WSSCommonFileInfo$filePath, (IMP*)&_logos_orig$SideloadHooks$WSSCommonFileInfo$filePath);}{ MSHookMessageEx(_logos_class$SideloadHooks$WSSCommonFileInfo, @selector(fileSize), (IMP)&_logos_method$SideloadHooks$WSSCommonFileInfo$fileSize, (IMP*)&_logos_orig$SideloadHooks$WSSCommonFileInfo$fileSize);}{ MSHookMessageEx(_logos_class$SideloadHooks$WSSCommonFileInfo, @selector(sha256Result), (IMP)&_logos_method$SideloadHooks$WSSCommonFileInfo$sha256Result, (IMP*)&_logos_orig$SideloadHooks$WSSCommonFileInfo$sha256Result);}{ MSHookMessageEx(_logos_class$SideloadHooks$WSSCommonFileInfo, @selector(isNeedVerify), (IMP)&_logos_method$SideloadHooks$WSSCommonFileInfo$isNeedVerify, (IMP*)&_logos_orig$SideloadHooks$WSSCommonFileInfo$isNeedVerify);}}
        } else {
            NSLog(@"[HWSideload] ❌ 获取动态类句柄失败!");
        }
    });
}

