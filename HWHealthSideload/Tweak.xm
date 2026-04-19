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
            
            // 每次都打印 errorCode 和 currentStatus，以便实时监测手表错误反馈
            @try {
                id errCode = [statusInfo valueForKey:@"errorCode"];
                id curStatus = [statusInfo valueForKey:@"currentStatus"];
                id errAttach = [statusInfo valueForKey:@"errAttachment"];
                id progress  = [statusInfo valueForKey:@"progress"];
                if (errCode || curStatus) {
                    HWSLog([NSString stringWithFormat:@"  📌 statusInfo实时 -> status=%@ progress=%@ errorCode=%@ errAttach=%@",
                        curStatus, progress, errCode, errAttach]);
                }
            } @catch (NSException *e) {}
            
            replacePathAndSizeInFileInfo(statusInfo);
        }
        HWSLog([NSString stringWithFormat:@"\n🚀🚀 [Hook Hit] pushFileProgress: \nName: %@ \nUserInfo: %@", aName, aUserInfo]);
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
    if ([notification isKindOfClass:[NSNotification class]]) { // Ensure it's not a generic raw object
        HWSLog([NSString stringWithFormat:@"\n🚀🚀 [Hook Hit] pushFileProgress: \nName: %@ \nUserInfo: %@", notification.name, notification.userInfo]);
    } else {
        HWSLog(@"\n🚀🚀 [Hook Hit] pushFileProgress (Not an NSNotification)");
    }
    %orig;
}

%end

// ============================================================================
// 新增：钩住 WSSCommonFileMgr 捕获手表端反馈 & 尝试绕过签名校验
// ============================================================================

%hook WSSCommonFileMgr

// 手表端返回文件传输协商结果时调用，errorCode 就是手表告诉我们的错误原因
- (void)sendFileTransferNegotiate:(id)negotiate errorCode:(NSInteger)errorCode {
    HWSLog([NSString stringWithFormat:@"\n🔴 [WSSCommonFileMgr] sendFileTransferNegotiate 被调用！\n  ➤ errorCode(手表返回) = %ld\n  ➤ negotiate = %@", (long)errorCode, negotiate]);
    %orig;
}

// 文件传输完成时调用，type 代表完成类型（成功/失败）
- (void)finishPushFileWithType:(NSInteger)type {
    HWSLog([NSString stringWithFormat:@"\n🔴 [WSSCommonFileMgr] finishPushFileWithType: type = %ld (0=成功, 其他=失败)", (long)type]);
    %orig;
}

// 这是手机发往手表的"预检"指令，checkMode 决定手表用哪种模式校验文件
// checkMode=1 可能是"AppGallery签名校验"，改为 0 可能是"无校验/开发者模式"
- (void)sendFileCheckMode:(NSInteger)checkMode fileid:(NSInteger)fileid offsetSize:(long long)offsetSize {
    HWSLog([NSString stringWithFormat:@"\n🟡 [WSSCommonFileMgr] sendFileCheckMode 被劫持！\n  ➤ 原始 checkMode = %ld\n  ➤ fileid = %ld, offsetSize = %lld", (long)checkMode, (long)fileid, (long long)offsetSize]);
    if (g_intercept) {
        // 🔑 核心尝试：将 checkMode 强制改为 0，绕过手表侧的分发证书校验
        HWSLog(@"  ➤ ⚡⚡⚡ 强制将 checkMode 从原值改为 0，尝试绕过签名校验模式！");
        %orig(0, fileid, offsetSize);
    } else {
        %orig;
    }
}

// 手表返回数据时调用，commondID 里可能携带了错误码
- (void)recevicedPushFileData:(NSData *)data commondID:(NSInteger)commondID deviceIdentify:(NSString *)deviceIdentify {
    // 将原始字节转为 hex，这是解密手表回应的关键证据
    NSMutableString *hexStr = [NSMutableString string];
    const uint8_t *bytes = (const uint8_t*)data.bytes;
    for (NSUInteger i = 0; i < data.length; i++) {
        [hexStr appendFormat:@"%02X ", bytes[i]];
    }
    HWSLog([NSString stringWithFormat:@"\n🔵 [WSSCommonFileMgr] recevicedPushFileData:\n  ➤ commondID = %ld, dataLen = %lu\n  ➤ RAW HEX: [%@]", (long)commondID, (unsigned long)data.length, hexStr]);
    %orig;
}

%end

%hook WSSCommonFileMgrSendUtil

// 同步钩住 Util 版本的 sendFileCheckMode
+ (void)sendFileCheckMode:(NSInteger)checkMode deviceInfo:(id)deviceInfo fileInfo:(id)fileInfo fileid:(NSInteger)fileid offsetSize:(long long)offsetSize {
    HWSLog([NSString stringWithFormat:@"\n🟡 [WSSCommonFileMgrSendUtil] sendFileCheckMode!\n  ➤ 原始 checkMode = %ld", (long)checkMode]);
    if (g_intercept) {
        HWSLog(@"  ➤ ⚡ 强制将 checkMode 改为 0！");
        %orig(0, deviceInfo, fileInfo, fileid, offsetSize);
    } else {
        %orig;
    }
}

// 文件传输协商发送，errorCode 是我们反馈给手表的值
+ (void)sendFileTransferNegotiate:(id)negotiate deviceInfo:(id)deviceInfo errorCode:(NSInteger)errorCode {
    HWSLog([NSString stringWithFormat:@"\n🟡 [WSSCommonFileMgrSendUtil] sendFileTransferNegotiate!\n  ➤ errorCode = %ld", (long)errorCode]);
    %orig;
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
            // v4.44: 精准扫描，去除了会误杀的 ble 和 ota
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
                HWSLog(@"\n\n🎯🎯🎯 ====== [v4.44] 开始绝对精准探测底层传输接口 ======");
                
                NSArray *mKws = @[@"sendfile", @"transferfile", @"pushfile", @"installapp", @"sendpkg", @"transferpkg", @"startinstall", @"senddata", @"p2psend"];
                
                int n = objc_getClassList(NULL, 0);
                Class *classes = (Class *)malloc(sizeof(Class) * n);
                objc_getClassList(classes, n);
                
                for (int i = 0; i < n; i++) {
                    NSString *clsName = NSStringFromClass(classes[i]);
                    if ([clsName hasPrefix:@"UI"] || [clsName hasPrefix:@"NS"] || [clsName hasPrefix:@"_UI"] || [clsName hasPrefix:@"CA"] || [clsName hasPrefix:@"OS_"]) continue;
                    
                    unsigned int count = 0;
                    Method *methods = class_copyMethodList(classes[i], &count);
                    for (unsigned int m = 0; m < count; m++) {
                        NSString *mName = NSStringFromSelector(method_getName(methods[m]));
                        for (NSString *kw in mKws) {
                            if ([mName localizedCaseInsensitiveContainsString:kw]) {
                                HWSLog([NSString stringWithFormat:@"🎯 发现目标: -[%@ %@]", clsName, mName]);
                                break;
                            }
                        }
                    }
                    if (methods) free(methods);
                    
                    methods = class_copyMethodList(object_getClass((id)classes[i]), &count);
                    for (unsigned int m = 0; m < count; m++) {
                        NSString *mName = NSStringFromSelector(method_getName(methods[m]));
                        for (NSString *kw in mKws) {
                            if ([mName localizedCaseInsensitiveContainsString:kw]) {
                                HWSLog([NSString stringWithFormat:@"🎯 发现目标: +[%@ %@]", clsName, mName]);
                                break;
                            }
                        }
                    }
                    if (methods) free(methods);
                }
                free(classes);
                HWSLog(@"🎯🎯🎯 ====== 精准扫描完成 ======\n\n");
            });

            HWSLog(@"\n======== [v4.44] 触发底层传输 ========");
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
        alertControllerWithTitle:@"HAP 侧载 v4.44"
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

    [m addAction:[UIAlertAction actionWithTitle:@"查看底层监控日志"
        style:UIAlertActionStyleDefault handler:^(id a) {
        NSString *logStr = (g_logs && g_logs.count > 0) ? [g_logs componentsJoinedByString:@"\n"] : @"暂无监控日志。请先[开启劫持]并去市场安装。";
        UIPasteboard *pb = [UIPasteboard generalPasteboard];
        [pb setString:logStr];
        [self alert:@"日志已复制" msg:[NSString stringWithFormat:@"已抓取 %lu 条文件/网络行为监控记录，已复制到剪贴板！去黏贴发给 AI 分析看后缀是啥！", (unsigned long)g_logs.count]];
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
        g_hapPath = [dst copy];
        g_hapChecksum = fileSHA256(g_hapPath);
        g_hapMD5 = fileMD5(g_hapPath);
        g_hapSHA1 = fileSHA1(g_hapPath);
        NSDictionary *at = [fm attributesOfItemAtPath:dst error:nil];
        unsigned long long sz = [at fileSize];
        
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
        struct rebinding rb[1];
        rb[0].name = "SecCodeCheckValidity";
        rb[0].replacement = (void *)my_SecCodeCheckValidity;
        rb[0].replaced = (void **)&orig_SecCodeCheckValidity;
        rebind_symbols((struct rebinding *)rb, 1);
        
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

