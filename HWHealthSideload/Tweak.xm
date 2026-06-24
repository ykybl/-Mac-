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
static NSInteger g_hapChunkSize = 0;       // 从第一包探针获取的块大小
static NSString  *g_hapOffsetKey = nil;    // 从第一包探针获取的 offset 属性名
static NSInteger g_utilChunkCount = 0;        // WSSCommonFileMgrSendUtil 数据块计数器

// ============================================================================
// Part 0: Log Collector
// ============================================================================

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

// ============================================================================
// Part 0.5: Utils
// ============================================================================

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

// ============================================================================
// Part 1: 环境检测绕过
// ============================================================================

typedef OSStatus (*SecCodeCheckValidity_func)(void *code, uint32_t flags, void *req);
static SecCodeCheckValidity_func orig_SecCodeCheckValidity;
static OSStatus my_SecCodeCheckValidity(void *code, uint32_t flags, void *req) {
    return 0; // errSecSuccess
}

// 绕过手机端 .hap 证书验证（旧版 API）
typedef OSStatus (*SecTrustEvaluate_func)(SecTrustRef trust, SecTrustResultType *result);
static SecTrustEvaluate_func orig_SecTrustEvaluate;
static OSStatus my_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    HWSLog(@"🔐 [CertBypass] SecTrustEvaluate 被拦截！强制返回信任！");
    if (result) *result = kSecTrustResultProceed;
    return noErr;
}

// 绕过手机端 .hap 证书验证（新版 API）
typedef bool (*SecTrustEvaluateWithError_func)(SecTrustRef trust, CFErrorRef *error);
static SecTrustEvaluateWithError_func orig_SecTrustEvaluateWithError;
static bool my_SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error) {
    HWSLog(@"🔐 [CertBypass] SecTrustEvaluateWithError 被拦截！强制返回 YES！");
    if (error) *error = NULL;
    return YES;
}

// 屏蔽 ptrace 反调试
static int (*orig_ptrace)(int request, pid_t pid, caddr_t addr, int data);
static int my_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    if (request == 31) { // PT_DENY_ATTACH
        HWSLog(@"🛡️ [AntiDebug] 拦截 PT_DENY_ATTACH，反调试已绕过");
        return 0;
    }
    return orig_ptrace ? orig_ptrace(request, pid, addr, data) : 0;
}

// 屏蔽 sysctl 反调试 (清除 P_TRACED 标志)
#include <sys/sysctl.h>
static int (*orig_sysctl)(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = orig_sysctl ? orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen) : -1;
    if (ret == 0 && namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID && oldp && oldlenp) {
        // 清除 P_TRACED 标志
        // Note: kp_proc.p_flag 偏移可能因系统版本而异，但屏蔽它是通用策略
        int *p_flag = (int *)((char *)oldp + 0x08); // kp_proc.p_flag approximate offset
        if (p_flag) *p_flag &= ~0x00000800; // ~P_TRACED
    }
    return ret;
}

// 隐藏动态库
static uint32_t (*orig__dyld_image_count)(void);
static uint32_t my__dyld_image_count(void) {
    uint32_t count = orig__dyld_image_count ? orig__dyld_image_count() : 0;
    return count;
}

static const char* (*orig__dyld_get_image_name)(uint32_t image_index);
static const char* my__dyld_get_image_name(uint32_t image_index) {
    const char *name = orig__dyld_get_image_name ? orig__dyld_get_image_name(image_index) : NULL;
    if (name && (strstr(name, "HWHealthSideload.dylib") != NULL || strstr(name, "FridaGadget") != NULL)) {
        return "/usr/lib/libSystem.B.dylib";
    }
    return name;
}

// 隐藏文件系统痕迹
#include <sys/stat.h>
#include <unistd.h>
static int (*orig_access)(const char *path, int mode);
static int my_access(const char *path, int mode) {
    if (path && (strstr(path, "nb全能助手") || strstr(path, "Tweak") || strstr(path, "Signer") || strstr(path, "Troll"))) {
        return -1;
    }
    return orig_access ? orig_access(path, mode) : -1;
}

static int (*orig_stat)(const char *path, struct stat *buf);
static int my_stat(const char *path, struct stat *buf) {
    if (path && (strstr(path, "nb全能助手") || strstr(path, "Tweak") || strstr(path, "Signer") || strstr(path, "Troll"))) {
        return -1;
    }
    return orig_stat ? orig_stat(path, buf) : -1;
}

// ============================================================================
// Part 1.5: NSBundle 伪装 (精准身份欺骗)
// ============================================================================
%hook NSBundle
- (NSString *)bundleIdentifier {
    NSString *orig = %orig;
    
    // 获取调用者的地址信息
    Dl_info info;
    if (dladdr(__builtin_return_address(0), &info) != 0) {
        NSString *callerPath = [NSString stringWithUTF8String:info.dli_fname];
        
        // 仅当调用者是主程序或者华为 SDK 相关库时才进行伪装
        if ([callerPath containsString:@"HuaweiWear"] || 
            [callerPath containsString:@"SHSports"] || 
            [callerPath containsString:@"iossporthealth"]) {
            
            // 只要不是官方 bundle ID，就替换为官方的
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

- (id)objectForInfoDictionaryKey:(NSString *)key {
    id orig = %orig;
    if ([key isEqualToString:@"CFBundleIdentifier"]) {
        Dl_info info;
        if (dladdr(__builtin_return_address(0), &info) != 0) {
            NSString *callerPath = [NSString stringWithUTF8String:info.dli_fname];
            if ([callerPath containsString:@"HuaweiWear"] || 
                [callerPath containsString:@"SHSports"] || 
                [callerPath containsString:@"iossporthealth"]) {
                if (![orig isEqualToString:@"com.huawei.iossporthealth"]) {
                    return @"com.huawei.iossporthealth";
                }
            }
        }
    }
    return orig;
}
%end

// ============================================================================
// Part 2: 网络层 Bundle ID 注入 (精准伪装，不影响内部路由)
// ============================================================================

// 在所有向外发出的 HTTP 请求中，将包含真实 Bundle ID 信息的头部
// 替换成官方 Bundle ID，欺骗服务器鉴权。同时绝不影响 App 内部查询。

static NSString *g_realBundleId = nil;

// ---- 核心替换函数：安全替换字符串中的 Bundle ID ----
static NSString *sanitizeString(NSString *str) {
    if (!g_realBundleId || !str) return str;
    if ([g_realBundleId isEqualToString:@"com.huawei.iossporthealth"]) return str;
    if ([str containsString:g_realBundleId]) {
        return [str stringByReplacingOccurrencesOfString:g_realBundleId 
                                              withString:@"com.huawei.iossporthealth"];
    }
    return str;
}

%hook NSMutableURLRequest

- (instancetype)initWithURL:(NSURL *)URL {
    if (!URL) return %orig;
    NSString *uStr = URL.absoluteString;
    NSString *fixed = sanitizeString(uStr);
    if (![uStr isEqualToString:fixed]) {
        return %orig([NSURL URLWithString:fixed]);
    }
    return %orig;
}

- (instancetype)initWithURL:(NSURL *)URL cachePolicy:(NSURLRequestCachePolicy)cachePolicy timeoutInterval:(NSTimeInterval)timeoutInterval {
    if (!URL) return %orig;
    NSString *uStr = URL.absoluteString;
    NSString *fixed = sanitizeString(uStr);
    if (![uStr isEqualToString:fixed]) {
        return %orig([NSURL URLWithString:fixed], cachePolicy, timeoutInterval);
    }
    return %orig;
}

- (void)setURL:(NSURL *)URL {
    if (!URL) { %orig; return; }
    NSString *uStr = URL.absoluteString;
    NSString *fixed = sanitizeString(uStr);
    if (![uStr isEqualToString:fixed]) {
        HWSLog([NSString stringWithFormat:@"🔐 URL Setter Replaced: %@", URL.host]);
        %orig([NSURL URLWithString:fixed]);
    } else {
        %orig;
    }
}

- (void)setValue:(NSString *)value forHTTPHeaderField:(NSString *)field {
    NSString *fixed = sanitizeString(value);
    if (value && ![value isEqualToString:fixed]) {
        HWSLog([NSString stringWithFormat:@"🔐 Header Setter Replaced: %@", field]);
    }
    %orig(fixed, field);
}

- (void)addValue:(NSString *)value forHTTPHeaderField:(NSString *)field {
    NSString *fixed = sanitizeString(value);
    if (value && ![value isEqualToString:fixed]) {
        HWSLog([NSString stringWithFormat:@"🔐 Header Add Replaced: %@", field]);
    }
    %orig(fixed, field);
}

- (void)setAllHTTPHeaderFields:(NSDictionary *)fields {
    if (!fields) { %orig; return; }
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
    %orig(changed ? fixed : fields);
}

- (void)setHTTPBody:(NSData *)data {
    if (data && g_realBundleId && data.length < 65536) {
        NSString *bs = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (bs) {
            NSString *fixed = sanitizeString(bs);
            if (![bs isEqualToString:fixed]) {
                HWSLog(@"🔐 Body Setter Replaced");
                %orig([fixed dataUsingEncoding:NSUTF8StringEncoding]);
                return;
            }
        }
    }
    %orig;
}

%end

// ============================================================================
// Part 3: NSFileManager & NSData & NSURLSession 拦截 (侧载核心逻辑)
// ============================================================================

static BOOL isTargetExt(NSString *path) {
    if (!path) return NO;
    NSString *low = path.lowercaseString;
    return [low containsString:@".hap"] || [low containsString:@".pkg"] || [low containsString:@".bin"];
}

// ============================================================================
// Part 3.5: Dynamic Transfer Hooking (SideloadHooks)
// ============================================================================

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

// ============================================================================
// Part 3.6: Log Viewer UI
// ============================================================================
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
    
    // Auto refresh timer
    [NSTimer scheduledTimerWithTimeInterval:1.0 target:self selector:@selector(refreshLogs) userInfo:nil repeats:YES];
}

- (void)refreshLogs {
    if (g_logs) {
        self.textView.text = [g_logs componentsJoinedByString:@"\n"];
        // 自动滚动到底部
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

%group SideloadHooks

%hook NSNotificationCenter
- (void)postNotificationName:(NSNotificationName)aName object:(id)anObject userInfo:(NSDictionary *)aUserInfo {
    if ([aName isEqualToString:@"notif_pushfile_update_status"]) {
        id statusInfo = aUserInfo[@"statusInfo"];
        if (statusInfo) {
            static dispatch_once_t onceTokenDump;
            dispatch_once(&onceTokenDump, ^{
                dumpObjectProperties(statusInfo, @"statusInfo Initial Object State");
            });
            
            // 只在 status 或 errorCode 发生变化时才打印，避免每个传输块都刷满日志
            static NSInteger lastStatus = -1;
            static NSInteger lastErrCode = -1;
            static NSInteger lastProgress25 = -1; // 每25%打一次
            @try {
                NSInteger curStatus = [[statusInfo valueForKey:@"currentStatus"] integerValue];
                NSInteger curErrCode = [[statusInfo valueForKey:@"errorCode"] integerValue];
                NSInteger curProgress = [[statusInfo valueForKey:@"progress"] integerValue];
                NSInteger progBucket = curProgress / 25; // 0,25,50,75,100
                
                BOOL statusChanged  = (curStatus != lastStatus);
                BOOL errCodeChanged = (curErrCode != lastErrCode);
                BOOL progressMilestone = (progBucket != lastProgress25);
                
                // status!=5(传输中)的状态变化【永远】打印，5 才限制 25% 里程碑
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
        // 不再打印 userInfo 全内容（太占空间）
        %orig;
        return;
    }
    %orig;
}
%end

%hook SHDWiFiCommandSend

+ (void)sendNotifiDeviceStartTransferFileWithFileInfo:(id)info {
    HWSLog(@"\n\n🚀🚀🚀 [Hook Hit] sendNotifiDeviceStartTransferFileWithFileInfo:");
    dumpObjectProperties(info, @"FileInfo Object");
    replacePathAndSizeInFileInfo(info);
    %orig;
}

+ (void)sendNotifiDeviceTransferFileInfoWithFileInfo:(id)info {
    HWSLog(@"\n\n🚀🚀🚀 [Hook Hit] sendNotifiDeviceTransferFileInfoWithFileInfo:");
    dumpObjectProperties(info, @"FileInfo Object");
    replacePathAndSizeInFileInfo(info);
    %orig;
}

+ (void)sendTransferFileInfo:(id)info {
    HWSLog(@"\n\n🚀🚀🚀 [Hook Hit] sendTransferFileInfo:");
    dumpObjectProperties(info, @"FileInfo Object");
    replacePathAndSizeInFileInfo(info);
    %orig;
}

%end

%hook SHDWiFiTransferManager

- (void)transferFileInfo:(id)info callback:(id)cb {
    HWSLog(@"\n\n🚀🚀🚀 [Hook Hit] transferFileInfo:callback:");
    dumpObjectProperties(info, @"FileInfo Object");
    replacePathAndSizeInFileInfo(info);
    %orig;
}

%end

%hook SHWatchAppStoreManager
- (void)pushFileProgress:(NSNotification *)notification {
    // 已在 NSNotificationCenter hook 里处理，这里不再重复打印（避免每块打两条）
    %orig;
}
%end

// ============================================================================
// 新增：钩住 WSSCommonFileMgr 捕获手表端反馈 & 尝试绕过签名校验
// ============================================================================

%hook WSSCommonFileMgr

// 移除了容易导致崩溃的 addTaskWithFile: 和 transFileToDevice: Hook
// 改用底层属性 Hook 和 SendUtil Hook 进行更安全的替换

// 手表端返回文件传输协商结果时调用，errorCode 就是手表告诉我们的错误原因
- (void)sendFileTransferNegotiate:(id)negotiate errorCode:(NSInteger)errorCode {
    HWSLog([NSString stringWithFormat:@"\n🔴 [WSSCommonFileMgr] sendFileTransferNegotiate!\n  ➤ errorCode = %ld\n  ➤ negotiate = %@", (long)errorCode, negotiate]);
    if (negotiate) { dumpObjectProperties(negotiate, @"Negotiate协商对象属性"); }
    %orig;
}

// 文件传输完成时调用
- (void)finishPushFileWithType:(NSInteger)type {
    HWSLog(@"\n\n╬═══════════════════════════════╬");
    HWSLog([NSString stringWithFormat:@"🔴🔴🔴 [WSSCommonFileMgr] 传输完成！finishPushFileWithType = %ld (type=fileID 不是错误码)", (long)type]);
    HWSLog(@"╬═══════════════════════════════╬\n");
    @try { dumpObjectProperties(self, @"FileMgr最终状态"); } @catch (...) {}

    // ====== 🛑 v4.54 优化：延迟10秒关闭拦截 ======
    // v4.53 立即关闭会导致后续安装协商消息无法被劫持。
    // v4.54 改为延迟10秒关闭，既避免误劫持后续文件，又覆盖安装完成确认窗口。
    if (g_intercept) {
        __weak typeof(self) weakSelf = self;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            if (g_intercept) {
                g_intercept = NO;
                HWSLog(@"🔒 [v4.54] g_intercept 延迟关闭！");
            }
        });
    }

    // ====== 一次性 dump WSSCommonFileMgr 全部方法名，找 sendInstall* 方法 ======
    static dispatch_once_t methodDumpOnce;
    Class selfClass = object_getClass(self); // 避免 forward declaration 报错
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


    // ====== T+5/T+15/T+30 延时监控 isPushBusy，确认手表安装结果时机 ======
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

    %orig;
}

// 传输暂停时调用
- (void)pausedTransferFile {
    HWSLog(@"\n🟡 [WSSCommonFileMgr] pausedTransferFile 被调用！传输已暂停");
    %orig;
}


// 开始发送文件内容 — 这是确认数据传输开始的关键方法！
- (void)sendFileContentToDeviceWithDataInfo:(id)dataInfo {
    static NSInteger chunkCount = 0;
    chunkCount++;
    if (chunkCount == 1) {
        HWSLog(@"\n🟢🟢🟢 [WSSCommonFileMgr] !!!! 数据传输正式开始！sendFileContentToDeviceWithDataInfo 第一次就呼了！!!!!");
        @try { dumpObjectProperties(dataInfo, @"DataInfo首包内容"); } @catch (...) {}
    } else if (chunkCount % 100 == 0) {
        HWSLog([NSString stringWithFormat:@"🟢 [WSSCommonFileMgr] 数据分包发送进度: 已发 %ld 包", (long)chunkCount]);
    }
    %orig;
}

// 此方法发送 checkMode 到手表，允许华为协商自然进行
// 重要：不要改变 checkMode! 手表需要 mode=3，改为 0 会导致 errorCode=140001
- (void)sendFileCheckMode:(NSInteger)checkMode fileid:(NSInteger)fileid offsetSize:(long long)offsetSize {
    HWSLog([NSString stringWithFormat:@"\n🟡 [WSSCommonFileMgr] sendFileCheckMode!\n  ➤ checkMode = %ld (mode=3 是正确的，不要改！)\n  ➤ fileid = %ld, offsetSize = %lld", (long)checkMode, (long)fileid, (long long)offsetSize]);
    %orig;
}

// 手表返回数据时调用，commondID 里可能携带了错误码
- (void)recevicedPushFileData:(NSData *)data commondID:(NSInteger)commondID deviceIdentify:(NSString *)deviceIdentify {
    const uint8_t *bytes = (const uint8_t*)data.bytes;
    NSUInteger len = data.length;
    
    if (commondID == 5) {
        // commondID=5 是数据块ACK，每20块打一次，避免57条噪音
        static NSInteger chunk5count = 0;
        chunk5count++;
        if (chunk5count == 1 || chunk5count % 20 == 0) {
            uint32_t offset = (len >= 9) ? ((bytes[5]<<24)|(bytes[6]<<16)|(bytes[7]<<8)|bytes[8]) : 0;
            HWSLog([NSString stringWithFormat:@"\n🔵 [commondID=5] 块ACK #%ld offset=%u字节 (每20块记录一次)", (long)chunk5count, offset]);
        }
    } else {
        // 非5的 commondID（协商/错误/完成）全部打印带HEX
        NSMutableString *hexStr = [NSMutableString string];
        for (NSUInteger i = 0; i < len; i++) [hexStr appendFormat:@"%02X ", bytes[i]];
        HWSLog([NSString stringWithFormat:@"\n🔵 [WSSCommonFileMgr] recevicedPushFileData:\n  ➤ commondID = %ld, dataLen = %lu\n  ➤ RAW HEX: [%@]", (long)commondID, (unsigned long)len, hexStr]);
    }
    %orig;
}


%end

%hook WSSCommonFileMgrSendUtil

// Util 版本的 sendFileCheckMode：不改 checkMode，直接放行！
+ (void)sendFileCheckMode:(NSInteger)checkMode deviceInfo:(id)deviceInfo fileInfo:(id)fileInfo fileid:(NSInteger)fileid offsetSize:(long long)offsetSize {
    HWSLog([NSString stringWithFormat:@"\n🟡 [WSSCommonFileMgrSendUtil] sendFileCheckMode!\n  ➤ checkMode = %ld (直接放行，不改！)\n  ➤ fileid = %ld, offsetSize = %lld", (long)checkMode, (long)fileid, (long long)offsetSize]);

    // v4.54: 每轮传输开始时重置块计数器
    g_utilChunkCount = 0;

    // 每包 dump fileInfo/deviceInfo 的属性，首次探针
    static dispatch_once_t fOnce;
    dispatch_once(&fOnce, ^{
        if (fileInfo) dumpObjectProperties(fileInfo, @"[探针] sendFileCheckMode.fileInfo");
        if (deviceInfo) dumpObjectProperties(deviceInfo, @"[探针] sendFileCheckMode.deviceInfo");
    });
    // v5.1: 进一步保险，如果 fileInfo 存在，在此时替换属性
    if (g_intercept && fileInfo) {
        replacePathAndSizeInFileInfo(fileInfo);
    }
    
    %orig; // ← checkMode 保持原值=3，手表才不会拒绝！
}

// 开始发送文件内容（Util 版本）— 核心数据替换点
+ (void)sendFileContentToDeviceWithDataInfo:(id)dataInfo fileData:(NSData *)fileData deviceInfo:(id)deviceInfo selectIndexArray:(id)selectIndexArray negotiate:(id)negotiate {
    // ===== 第一包：完整探针 dump =====
    static dispatch_once_t probeOnce;
    dispatch_once(&probeOnce, ^{
        HWSLog(@"\n\n╔══════════════════════════════════════╗");
        HWSLog(@"║  🔬 [v4.54 探针] 第一包完整协议分析  ║");
        HWSLog(@"╚══════════════════════════════════════╝");

        // Dump dataInfo 属性
        if (dataInfo) {
            dumpObjectProperties(dataInfo, @"[探针] dataInfo");
        } else {
            HWSLog(@"⚠️ [探针] dataInfo == nil");
        }

        // Dump negotiate 属性
        if (negotiate) {
            dumpObjectProperties(negotiate, @"[探针] negotiate");
        } else {
            HWSLog(@"⚠️ [探针] negotiate == nil");
        }

        // Dump deviceInfo 属性
        if (deviceInfo) {
            dumpObjectProperties(deviceInfo, @"[探针] deviceInfo");
        }

        // Dump selectIndexArray
        if (selectIndexArray) {
            HWSLog([NSString stringWithFormat:@"[探针] selectIndexArray class=%@ count=%@",
                NSStringFromClass([selectIndexArray class]), @([selectIndexArray count])]);
            if ([selectIndexArray count] > 0) {
                HWSLog([NSString stringWithFormat:@"[探针] selectIndexArray[0]=%@", selectIndexArray[0]]);
            }
        } else {
            HWSLog(@"⚠️ [探针] selectIndexArray == nil");
        }

        // Dump fileData 前128字节 HEX（判断是否有包头）
        NSUInteger previewLen = MIN(128, fileData.length);
        const uint8_t *bytes = (const uint8_t *)fileData.bytes;
        NSMutableString *hex = [NSMutableString string];
        for (NSUInteger i = 0; i < previewLen; i++) {
            [hex appendFormat:@"%02X ", bytes[i]];
            if ((i + 1) % 16 == 0) [hex appendString:@"\n"];
        }
        HWSLog([NSString stringWithFormat:@"[探针] fileData 前128字节:\n%@", hex]);
        HWSLog([NSString stringWithFormat:@"[探针] fileData.length = %lu 字节", (unsigned long)fileData.length]);

        // 自动发现 offset 字段名
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

    %orig;
}

// 移除可能引起崩溃的 readFileDataFrom Hook，改为钩取模型属性

// 文件传输协商发送，errorCode 是我们反馈给手表的值
+ (void)sendFileTransferNegotiate:(id)negotiate deviceInfo:(id)deviceInfo errorCode:(NSInteger)errorCode {
    HWSLog([NSString stringWithFormat:@"\n🟡 [WSSCommonFileMgrSendUtil] sendFileTransferNegotiate!\n  ➤ errorCode = %ld", (long)errorCode]);
    %orig;
}

%end

// ===== v5.1 核心：直接拦截 WSSCommonFileInfo 数据模型，避免方法签名不匹配崩溃 =====
%hook WSSCommonFileInfo

- (NSString *)filePath {
    NSString *orig = %orig;
    if (g_intercept && g_hapPath && orig) {
        if ([orig containsString:@".bin"] || [orig containsString:@".hap"] || [orig containsString:@".pkg"]) {
            // HWSLog([NSString stringWithFormat:@"🔥 [WSSCommonFileInfo] filePath 拦截返回: %@", g_hapPath.lastPathComponent]); // 避免刷屏
            return g_hapPath;
        }
    }
    return orig;
}

- (long long)fileSize {
    long long orig = %orig;
    if (g_intercept && g_hapPath && orig > 0) {
        NSString *path = [self valueForKey:@"filePath"]; // 这里会调到上面的被劫持方法
        if ([path isEqualToString:g_hapPath]) {
            NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:g_hapPath error:nil];
            if (attrs) {
                return [attrs fileSize];
            }
        }
    }
    return orig;
}

- (NSString *)sha256Result {
    NSString *orig = %orig;
    if (g_intercept && g_hapPath) {
        NSString *path = [self valueForKey:@"filePath"];
        if ([path isEqualToString:g_hapPath]) {
            return nil; // 强制底层重新计算
        }
    }
    return orig;
}

- (BOOL)isNeedVerify {
    if (g_intercept && g_hapPath) {
        NSString *path = [self valueForKey:@"filePath"];
        if ([path isEqualToString:g_hapPath]) {
            return NO; // 禁用校验
        }
    }
    return %orig;
}

%end

%end

%hook NSFileManager

- (BOOL)copyItemAtPath:(NSString *)src toPath:(NSString *)dst error:(NSError **)err {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"Copy(P): %@ -> %@", src.lastPathComponent, dst.lastPathComponent]); }
    return %orig;
}

- (BOOL)copyItemAtURL:(NSURL *)srcU toURL:(NSURL *)dstU error:(NSError **)err {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"Copy(U): %@ -> %@", srcU.lastPathComponent, dstU.lastPathComponent]); }
    return %orig;
}

- (BOOL)moveItemAtPath:(NSString *)src toPath:(NSString *)dst error:(NSError **)err {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"Move(P): %@ -> %@", src.lastPathComponent, dst.lastPathComponent]); }
    return %orig;
}

- (BOOL)moveItemAtURL:(NSURL *)srcU toURL:(NSURL *)dstU error:(NSError **)err {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"Move(U): %@ -> %@", srcU.lastPathComponent, dstU.lastPathComponent]); }
    
    // v4.19: 只要开启劫持，不论选没选 HAP，只要看到 .bin 就开始全宇宙搜寻底层接口
    if (g_intercept && isTargetExt(dstU.path)) {
        HWSLog(@"💥 劫持 moveItemAtURL! 准备进行全宇宙扫描探测传输接口...");
        static dispatch_once_t onceToken;
        dispatch_once(&onceToken, ^{
            // v4.53: 精准扫描，去除了会误杀的 ble 和 ota
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
                // 只打印总数，不打印每个方法（避免几百行噪音）
                HWSLog([NSString stringWithFormat:@"🎯🎯🎯 ====== [v4.53] 扫描完成，共发现 %d 个关联方法 ======", discovered]);
            });

            HWSLog(@"\n======== [v4.53] 触发底层传输 ========");
            // SideloadHooks 已被移动至 %ctor 进行早期全局初始化，避免竞争遗漏
        });

        // 依然向原始文件放行，绕过 DRM 检查以命中传输逻辑
        return %orig;
    }
    return %orig;
}

%end

// 精准匹配：只有字典里同时存在 packageName（或 package）且 hashValue（或 hash）
// 才说明这是华为 AppGallery 下发的安装指令包，避免误触状态通知 JSON
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

// 递归检查数组 / 嵌套字典里是否存在安装指令
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
                // 尝试将 installType=0（市场正式安装）改为 1（开发者/更新模式，可能绕过证书验证）
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

static BOOL g_jsonHookActive = NO; // 重入保护，防止 hook 内调用 JSON 引发递归

%hook NSJSONSerialization

+ (id)JSONObjectWithData:(NSData *)data options:(NSJSONReadingOptions)opt error:(NSError **)error {
    id orig = %orig;
    if (g_intercept && orig && g_hapPath && !g_jsonHookActive) {
        @try {
            // 精准命中：只处理同时拥有 packageName + hashValue 的安装指令字典
            if (containsInstallCommand(orig)) {
                g_jsonHookActive = YES; // 开启重入锁，防止后面的序列化操作再次进入此 Hook
                HWSLog(@"💥 [核弹级伪装] 命中安装指令 JSON！执行外科手术级伪装...");
                
                // 打印原始协议（用 NSString 描述，不再调用 NSJSONSerialization 避免递归）
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

%end

%hook NSData

- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)useAuxiliaryFile {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"WriteFile: %@", path.lastPathComponent]); }
    if (g_intercept && g_hapPath && isTargetExt(path) && ![path isEqualToString:g_hapPath]) {
        HWSLog(@"💥 劫持 NSData writeToFile!");
        NSFileManager *fm = [NSFileManager defaultManager];
        [fm removeItemAtPath:path error:nil];
        return [fm copyItemAtPath:g_hapPath toPath:path error:nil];
    }
    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url atomically:(BOOL)atomically {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"WriteURL: %@", url.lastPathComponent]); }
    return %orig;
}

+ (instancetype)dataWithContentsOfFile:(NSString *)path {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"Data ReadFile: %@", path.lastPathComponent]); }
    
    // 🔑 关键：捕获 .cer 证书读取的调用栈，找出华为的证书验证函数！
    if (g_intercept && [path hasSuffix:@".cer"]) {
        NSArray *stack = [NSThread callStackSymbols];
        NSArray *top = [stack subarrayWithRange:NSMakeRange(0, MIN(12, stack.count))];
        HWSLog([NSString stringWithFormat:@"🔬 [CertRead 调用栈] 读取: %@\n%@",
            path.lastPathComponent, [top componentsJoinedByString:@"\n"]]);
    }
    
    if (g_intercept && g_hapPath && isTargetExt(path) && ![path isEqualToString:g_hapPath]) {
        HWSLog(@"💥 劫持 Data ReadFile!");
        return %orig(g_hapPath);
    }
    return %orig;
}


+ (instancetype)dataWithContentsOfURL:(NSURL *)url {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"Data ReadURL: %@", url.lastPathComponent]); }
    if (g_intercept && g_hapPath && isTargetExt(url.path) && ![url.path isEqualToString:g_hapPath]) {
        HWSLog(@"💥 劫持 Data ReadURL!");
        return %orig([NSURL fileURLWithPath:g_hapPath]);
    }
    return %orig;
}

- (instancetype)initWithContentsOfFile:(NSString *)path options:(NSDataReadingOptions)readOptionsMask error:(NSError **)errorPtr {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"Init ReadFile: %@", path.lastPathComponent]); }
    return %orig;
}

- (instancetype)initWithContentsOfURL:(NSURL *)url options:(NSDataReadingOptions)readOptionsMask error:(NSError **)errorPtr {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"Init ReadURL: %@", url.lastPathComponent]); }
    if (g_intercept && g_hapPath && isTargetExt(url.path) && ![url.path isEqualToString:g_hapPath]) {
        HWSLog(@"💥 劫持 Init ReadURL!");
        return %orig([NSURL fileURLWithPath:g_hapPath], readOptionsMask, errorPtr);
    }
    return %orig;
}

%end

%hook NSFileManager
- (NSDictionary *)attributesOfItemAtPath:(NSString *)path error:(NSError **)err {
    NSDictionary *origAttrs = %orig;
    if (g_intercept && g_hapPath && isTargetExt(path) && ![path isEqualToString:g_hapPath]) {
        NSDictionary *hapAttrs = %orig(g_hapPath, nil);
        if (hapAttrs && origAttrs) {
            NSMutableDictionary *newAttrs = [origAttrs mutableCopy];
            newAttrs[NSFileSize] = hapAttrs[NSFileSize];
            HWSLog([NSString stringWithFormat:@"💥 [系统欺骗] 将 .bin 伪装为 .hap 大小: %@ -> %@", origAttrs[NSFileSize], hapAttrs[NSFileSize]]);
            return newAttrs;
        }
    }
    return origAttrs;
}
%end

%hook NSFileHandle
+ (instancetype)fileHandleForReadingAtPath:(NSString *)path {
    if (g_intercept && isTargetExt(path)) { 
        if (g_hapPath && ![path isEqualToString:g_hapPath]) {
            HWSLog([NSString stringWithFormat:@"💥 [底层流欺骗] C++ 引擎请求文件流，狸猫换太子，返回外挂 .hap!"]);
            return %orig(g_hapPath);
        }
    }
    return %orig;
}
%end

%hook NSInputStream
+ (instancetype)inputStreamWithFileAtPath:(NSString *)path {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"IS Read: %@", path.lastPathComponent]); }
    if (g_intercept && g_hapPath && isTargetExt(path) && ![path isEqualToString:g_hapPath]) {
        HWSLog(@"💥 劫持 NSInputStream!");
        return %orig(g_hapPath);
    }
    return %orig;
}
- (instancetype)initWithFileAtPath:(NSString *)path {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"IS Init: %@", path.lastPathComponent]); }
    if (g_intercept && g_hapPath && isTargetExt(path) && ![path isEqualToString:g_hapPath]) {
        HWSLog(@"💥 劫持 NSInputStream init!");
        return %orig(g_hapPath);
    }
    return %orig;
}

%end

%hook NSURLSession

// 探针：捕获应用市场下载 API 的响应，用于定位 bundle ID / hash 字段
- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))completionHandler {
    if (!g_intercept || !completionHandler) return %orig;

    // Logos 不支持在 %orig 里直接内联 block，先声明再传入
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
    return %orig(request, wrapped);
}

%end

// ============================================================================
// Part 4: 运行时探测
// ============================================================================

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
                
                // Instance methods
                unsigned int count;
                Method *methods = class_copyMethodList(cls, &count);
                for (int m = 0; m < count; m++) {
                    [r appendFormat:@"- %@\n", NSStringFromSelector(method_getName(methods[m]))];
                }
                free(methods);
                
                // Class methods
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

// End of dynamic hooking logic moved above

// ============================================================================
// Part 5: UI
// ============================================================================

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
    if (self.btn) return;

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
    
    UIViewController *vc = w.rootViewController;
    if (vc && vc.view) {
        [vc.view addSubview:self.btn];
        [vc.view bringSubviewToFront:self.btn];
    } else {
        [w addSubview:self.btn];
    }

    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc]
        initWithTarget:self action:@selector(drag:)];
    [self.btn addGestureRecognizer:pan];
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

    // 使用 Alert 样式而非 ActionSheet，避免干扰 TabBar
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
                // 清空之前的日志以便新一轮监控
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
    // 不用 FullScreen，用默认样式，避免破坏 TabBar
    p.modalPresentationStyle = UIModalPresentationAutomatic;
    UIViewController *vc = [UIApplication sharedApplication].keyWindow.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    [vc presentViewController:p animated:YES completion:nil];
}

- (void)documentPicker:(UIDocumentPickerViewController *)c
    didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
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
        // 关闭旧句柄
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
            // 记录之前的 bundleID（如果多次操作）方便复用
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

// ============================================================================
// Part 6: Window Hook & Setup
// ============================================================================

%hook UIWindow
- (void)makeKeyAndVisible {
    %orig;
}
%end

static void appDidBecomeActive(CFNotificationCenterRef center, void *observer, CFStringRef name, const void *object, CFDictionaryRef userInfo) {
    UIWindow *k = [UIApplication sharedApplication].keyWindow;
    if (k) [[HWSideloadUI shared] attach:k];
}

%ctor {
    g_realBundleId = [[[NSBundle mainBundle] bundleIdentifier] copy];
    NSLog(@"[HWSideload] Initializing main hooks.");
    %init(_ungrouped);
    NSLog(@"[HWSideload] 真实 Bundle ID: %@", g_realBundleId);
    
    dispatch_async(dispatch_get_main_queue(), ^{
        // 【关键】绑定证书、反调试、隐藏痕迹函数
        struct Rebinding rb[] = {
            {"SecCodeCheckValidity", (void *)my_SecCodeCheckValidity, (void **)&orig_SecCodeCheckValidity},
            {"SecTrustEvaluate", (void *)my_SecTrustEvaluate, (void **)&orig_SecTrustEvaluate},
            {"SecTrustEvaluateWithError", (void *)my_SecTrustEvaluateWithError, (void **)&orig_SecTrustEvaluateWithError},
            {"ptrace", (void *)my_ptrace, (void **)&orig_ptrace},
            {"sysctl", (void *)my_sysctl, (void **)&orig_sysctl},
            {"_dyld_image_count", (void *)my__dyld_image_count, (void **)&orig__dyld_image_count},
            {"_dyld_get_image_name", (void *)my__dyld_get_image_name, (void **)&orig__dyld_get_image_name},
            {"access", (void *)my_access, (void **)&orig_access},
            {"stat", (void *)my_stat, (void **)&orig_stat}
        };
        int hookResult = rebind_symbols(rb, sizeof(rb)/sizeof(struct Rebinding));
        HWSLog([NSString stringWithFormat:@"🛡️ [Fishhook] 绑定环境检测绕过结果: %d (0=成功)", hookResult]);
        
        CFNotificationCenterAddObserver(CFNotificationCenterGetLocalCenter(), NULL,
            appDidBecomeActive, (CFStringRef)UIApplicationDidBecomeActiveNotification, NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
            
        // 只能调用一次 %init，所以在主队列 block 里执行以确保类已加载
        Class wifiCls = NSClassFromString(@"HuaweiWear.SHDWiFiTransferManager");
        Class storeCls = NSClassFromString(@"HuaweiWear.SHWatchAppStoreManager");
        Class cmdCls = NSClassFromString(@"HuaweiWear.SHDWiFiCommandSend");
        if (wifiCls || storeCls || cmdCls) {
            NSLog(@"[HWSideload] ✅ 成功全局获取动态类句柄!");
            HWSLog(dumpTargetClasses());
            %init(SideloadHooks, SHDWiFiTransferManager=wifiCls, SHWatchAppStoreManager=storeCls, SHDWiFiCommandSend=cmdCls);
        } else {
            NSLog(@"[HWSideload] ❌ 获取动态类句柄失败!");
        }
    });
}

