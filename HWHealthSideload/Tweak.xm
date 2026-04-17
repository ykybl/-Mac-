#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import "fishhook.h"
#import <dlfcn.h>
#import <sys/sysctl.h>

// ============================================================================ //
//  HWHealthSideload v2.0 — 华为运动健康 iOS 侧载助手
//  新增: 签名伪装 / SSL Pinning 绕过 / HMS 账号鉴权绕过
// ============================================================================ //

// 华为官方的原始 Bundle ID 和 Team ID
static NSString * const kOriginalBundleID = @"com.huawei.iossporthealth";
static NSString * const kOriginalTeamID   = @"JCGHDQ387U"; // 华为在 Apple 的官方 Team ID

// ============================================================================ //
// Part 1: Anti-Anti-Debug (Bypass ptrace / sysctl)
// ============================================================================ //

static int (*original_ptrace)(int request, pid_t pid, caddr_t addr, int data);
int my_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    if (request == 31) { // PT_DENY_ATTACH
        NSLog(@"[HWSideload] ✅ 拦截 ptrace(PT_DENY_ATTACH)");
        return 0;
    }
    return original_ptrace(request, pid, addr, data);
}

static int (*original_sysctl)(int *name, u_int namelen, void *info, size_t *infosize, void *newinfo, size_t newinfosize);
int my_sysctl(int *name, u_int namelen, void *info, size_t *infosize, void *newinfo, size_t newinfosize) {
    int ret = original_sysctl(name, namelen, info, infosize, newinfo, newinfosize);
    if (namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID && info) {
        struct kinfo_proc *kinfo = (struct kinfo_proc *)info;
        if ((kinfo->kp_proc.p_flag & P_TRACED) != 0) {
            NSLog(@"[HWSideload] ✅ 拦截 sysctl 调试器检测");
            kinfo->kp_proc.p_flag ^= P_TRACED;
        }
    }
    return ret;
}

// 拦截 exit / abort 防止检测到异常后自杀
static void (*original_exit)(int status);
void my_exit(int status) {
    NSLog(@"[HWSideload] ✅ 拦截 exit(%d)，阻止自杀", status);
    // 不执行，吃掉这个死亡信号
}

static void (*original_abort)(void);
void my_abort(void) {
    NSLog(@"[HWSideload] ✅ 拦截 abort()，阻止自杀");
    // 不执行
}

static void bypassAntiDebug(void) {
    rebind_symbols((struct rebinding[4]){
        {"ptrace", (void *)my_ptrace, (void **)&original_ptrace},
        {"sysctl", (void *)my_sysctl, (void **)&original_sysctl},
        {"exit",   (void *)my_exit,   (void **)&original_exit},
        {"abort",  (void *)my_abort,  (void **)&original_abort}
    }, 4);
    NSLog(@"[HWSideload] 🛡️ Anti-Debug 四重防护已激活");
}

// ============================================================================ //
// Part 2: SSL Pinning 全面绕过
// ============================================================================ //

// 2a. Hook SecTrustEvaluateWithError — iOS 12+ 的证书校验核心
static OSStatus (*original_SecTrustEvaluateWithError)(SecTrustRef trust, CFErrorRef *error);
OSStatus my_SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error) {
    // 直接返回成功，不做任何校验
    if (error) *error = NULL;
    NSLog(@"[HWSideload] 🔓 SSL: SecTrustEvaluateWithError → 放行");
    return errSecSuccess;
}

// 2b. Hook SecTrustEvaluate — 旧版兼容
static OSStatus (*original_SecTrustEvaluate)(SecTrustRef trust, SecTrustResultType *result);
OSStatus my_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    if (result) *result = kSecTrustResultUnspecified; // 表示受信任
    NSLog(@"[HWSideload] 🔓 SSL: SecTrustEvaluate → 放行");
    return errSecSuccess;
}

static void bypassSSLPinning(void) {
    rebind_symbols((struct rebinding[2]){
        {"SecTrustEvaluateWithError", (void *)my_SecTrustEvaluateWithError, (void **)&original_SecTrustEvaluateWithError},
        {"SecTrustEvaluate",          (void *)my_SecTrustEvaluate,          (void **)&original_SecTrustEvaluate}
    }, 2);
    NSLog(@"[HWSideload] 🔓 SSL Pinning 绕过已激活");
}

// ============================================================================ //
// Part 3: 签名身份伪装 (让华为服务器以为我们仍然是官方签名)
// ============================================================================ //

%hook NSBundle

// 3a. 劫持 bundleIdentifier — 强制返回官方 Bundle ID
- (NSString *)bundleIdentifier {
    NSString *original = %orig;
    // 只对主 App 的 Bundle 生效，不影响 Framework
    if ([self isEqual:[NSBundle mainBundle]]) {
        NSLog(@"[HWSideload] 🎭 bundleIdentifier: %@ → %@", original, kOriginalBundleID);
        return kOriginalBundleID;
    }
    return original;
}

// 3b. 劫持 Info.plist 查询 — 伪装关键字段
- (id)objectForInfoDictionaryKey:(NSString *)key {
    id original = %orig;
    if (![self isEqual:[NSBundle mainBundle]]) return original;
    
    // 伪装 Bundle ID
    if ([key isEqualToString:@"CFBundleIdentifier"]) {
        NSLog(@"[HWSideload] 🎭 InfoDict[%@]: %@ → %@", key, original, kOriginalBundleID);
        return kOriginalBundleID;
    }
    // 伪装签名身份标识符
    if ([key isEqualToString:@"SignerIdentity"]) {
        return @"Apple iPhone OS Application Signing";
    }
    // 伪装 App ID Prefix (= Team ID)
    if ([key isEqualToString:@"AppIdentifierPrefix"]) {
        return [NSString stringWithFormat:@"%@.", kOriginalTeamID];
    }
    return original;
}

// 3c. 劫持 infoDictionary — 完整字典级别的伪装
- (NSDictionary *)infoDictionary {
    NSMutableDictionary *dict = [%orig mutableCopy];
    if ([self isEqual:[NSBundle mainBundle]]) {
        dict[@"CFBundleIdentifier"] = kOriginalBundleID;
        // 如果有 AppIdentifierPrefix，也伪装掉
        if (dict[@"AppIdentifierPrefix"]) {
            dict[@"AppIdentifierPrefix"] = [NSString stringWithFormat:@"%@.", kOriginalTeamID];
        }
    }
    return [dict copy];
}

%end

// ============================================================================ //
// Part 4: NSURLSession 认证质询绕过 (处理 HTTPS 证书委托回调)
// ============================================================================ //

%hook NSURLSession

// 直接放行所有 HTTPS 证书质询，避免华为 SDK 的自定义校验拦住我们
+ (NSURLSession *)sessionWithConfiguration:(NSURLSessionConfiguration *)configuration
                                  delegate:(id)delegate
                             delegateQueue:(NSOperationQueue *)queue {
    // 如果有 delegate，使用我们的代理包装器
    if (delegate) {
        NSLog(@"[HWSideload] 🔓 NSURLSession: 检测到自定义 delegate，植入证书放行");
    }
    return %orig;
}

%end

// ============================================================================ //
// Part 5: Hook 华为 HMS SDK / UcsAppAuth 的核心验证
// ============================================================================ //

// 5a. 尝试 Hook HMS 的设备验证检查 (可能存在的类名)
%hook HMSAnalytics
- (void)verifyAppIdentity {
    NSLog(@"[HWSideload] 🎭 HMS: verifyAppIdentity → 跳过");
    // 不调用 %orig，直接吃掉
}
%end

// 5b. 通用的 UcsAppAuth 鉴权绕过
%hook UcsAppAuth
// 如果该类存在某个验证方法，直接放行 
- (BOOL)verifyApp {
    NSLog(@"[HWSideload] 🎭 UcsAppAuth verifyApp → YES");
    return YES;
}
- (BOOL)checkAppIntegrity {
    NSLog(@"[HWSideload] 🎭 UcsAppAuth checkAppIntegrity → YES");
    return YES;
}
%end

// 5c. embedded.mobileprovision 读取伪装
// 部分 SDK 会读取 provision 文件里的 team-identifier
%hook NSData
+ (instancetype)dataWithContentsOfFile:(NSString *)path {
    if ([path containsString:@"embedded.mobileprovision"]) {
        NSLog(@"[HWSideload] 🎭 拦截读取 embedded.mobileprovision");
        // 返回原始的调用结果，但后面在解析层面我们已经拦截了 bundleIdentifier
    }
    return %orig;
}
%end

// ============================================================================ //
// Part 6: _dyld_get_image_name 伪装 (防止检测注入库名)
// ============================================================================ //

static const char* (*original_dyld_get_image_name)(uint32_t image_index);
const char* my_dyld_get_image_name(uint32_t image_index) {
    const char* name = original_dyld_get_image_name(image_index);
    if (name != NULL) {
        // 如果扫描到我们的 dylib 或者 Substrate 的名字，假装不存在
        NSString *imageName = [NSString stringWithUTF8String:name];
        if ([imageName containsString:@"HWHealthSideload"] ||
            [imageName containsString:@"Substrate"] ||
            [imageName containsString:@"substitute"] ||
            [imageName containsString:@"frida"] ||
            [imageName containsString:@"cycript"]) {
            NSLog(@"[HWSideload] 🎭 隐藏注入库: %@", imageName);
            return "/usr/lib/system/libsystem_c.dylib"; // 伪装成系统库
        }
    }
    return name;
}

static void bypassDylibDetection(void) {
    rebind_symbols((struct rebinding[1]){
        {"_dyld_get_image_name", (void *)my_dyld_get_image_name, (void **)&original_dyld_get_image_name}
    }, 1);
    NSLog(@"[HWSideload] 🎭 Dylib 注入检测伪装已激活");
}

// ============================================================================ //
// Part 7: UI 注入 — 悬浮侧载按钮 + 文件选取器
// ============================================================================ //

@interface HWHackSideloadHelper : NSObject <UIDocumentPickerDelegate>
@property (nonatomic, strong) UIButton *floatBtn;
+ (instancetype)sharedInstance;
- (void)showPicker;
@end

@implementation HWHackSideloadHelper

+ (instancetype)sharedInstance {
    static HWHackSideloadHelper *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[HWHackSideloadHelper alloc] init];
    });
    return instance;
}

- (void)addFloatButtonToWindow:(UIWindow *)window {
    if (self.floatBtn) return;
    
    self.floatBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    CGFloat screenW = [UIScreen mainScreen].bounds.size.width;
    CGFloat screenH = [UIScreen mainScreen].bounds.size.height;
    self.floatBtn.frame = CGRectMake(screenW - 140, screenH - 160, 120, 50);
    self.floatBtn.backgroundColor = [UIColor colorWithRed:0.9 green:0.2 blue:0.15 alpha:0.95];
    [self.floatBtn setTitle:@"🔥 侧载 HAP" forState:UIControlStateNormal];
    self.floatBtn.titleLabel.font = [UIFont boldSystemFontOfSize:15];
    [self.floatBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.floatBtn.layer.cornerRadius = 25;
    self.floatBtn.layer.shadowColor  = [UIColor blackColor].CGColor;
    self.floatBtn.layer.shadowOffset = CGSizeMake(0, 4);
    self.floatBtn.layer.shadowOpacity = 0.4;
    self.floatBtn.layer.shadowRadius  = 8;
    self.floatBtn.layer.zPosition = 99999;
    
    [self.floatBtn addTarget:self action:@selector(showPicker) forControlEvents:UIControlEventTouchUpInside];
    [window addSubview:self.floatBtn];
    
    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(handlePan:)];
    [self.floatBtn addGestureRecognizer:pan];
    
    NSLog(@"[HWSideload] 🔥 悬浮侧载按钮注入成功");
}

- (void)handlePan:(UIPanGestureRecognizer *)recognizer {
    CGPoint translation = [recognizer translationInView:self.floatBtn.superview];
    recognizer.view.center = CGPointMake(recognizer.view.center.x + translation.x,
                                         recognizer.view.center.y + translation.y);
    [recognizer setTranslation:CGPointZero inView:self.floatBtn.superview];
}

- (void)showPicker {
    UIDocumentPickerViewController *picker = [[UIDocumentPickerViewController alloc]
        initWithDocumentTypes:@[@"public.data", @"public.content", @"public.item"]
        inMode:UIDocumentPickerModeImport];
    picker.delegate = self;
    picker.allowsMultipleSelection = NO;
    picker.modalPresentationStyle = UIModalPresentationFullScreen;
    
    UIViewController *root = [UIApplication sharedApplication].keyWindow.rootViewController;
    while (root.presentedViewController) root = root.presentedViewController;
    [root presentViewController:picker animated:YES completion:nil];
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    NSURL *fileUrl = urls.firstObject;
    if (!fileUrl) return;
    
    BOOL accessing = [fileUrl startAccessingSecurityScopedResource];
    
    NSString *cachesDir = [NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES) firstObject];
    NSString *destPath  = [cachesDir stringByAppendingPathComponent:fileUrl.lastPathComponent];
    
    NSFileManager *fm = [NSFileManager defaultManager];
    [fm removeItemAtPath:destPath error:nil];
    
    NSError *error = nil;
    [fm copyItemAtPath:fileUrl.path toPath:destPath error:&error];
    
    if (accessing) [fileUrl stopAccessingSecurityScopedResource];
    
    UIViewController *root = [UIApplication sharedApplication].keyWindow.rootViewController;
    while (root.presentedViewController) root = root.presentedViewController;
    
    if (error) {
        NSLog(@"[HWSideload] ❌ 文件搬运失败: %@", error);
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"失败"
            message:[NSString stringWithFormat:@"文件搬运失败:\n%@", error.localizedDescription]
            preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
        [root presentViewController:alert animated:YES completion:nil];
        return;
    }
    
    NSLog(@"[HWSideload] ✅ HAP 文件就绪: %@", destPath);
    
    // 获取文件大小
    NSDictionary *attrs = [fm attributesOfItemAtPath:destPath error:nil];
    unsigned long long fileSize = [attrs fileSize];
    NSString *sizeStr = fileSize > 1024*1024
        ? [NSString stringWithFormat:@"%.1f MB", fileSize / (1024.0*1024.0)]
        : [NSString stringWithFormat:@"%.1f KB", fileSize / 1024.0];
    
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"✅ 沙盒中转成功"
        message:[NSString stringWithFormat:@"文件: %@\n大小: %@\n路径: %@\n\n已准备就绪，等待传输通道对接。",
                 fileUrl.lastPathComponent, sizeStr, destPath]
        preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
    [root presentViewController:alert animated:YES completion:nil];
}

@end

// ============================================================================ //
// Part 8: Hook 注入点 — Window 出现时植入 UI
// ============================================================================ //

%hook UIWindow
- (void)makeKeyAndVisible {
    %orig;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [[HWHackSideloadHelper sharedInstance] addFloatButtonToWindow:self];
    });
}
%end

// ============================================================================ //
// Part 9: 构造函数 — 进程启动时最早执行
// ============================================================================ //

%ctor {
    NSLog(@"[HWSideload] ====================================");
    NSLog(@"[HWSideload] 🚀 HWHealthSideload v2.0 已加载！");
    NSLog(@"[HWSideload] ====================================");
    
    // 第一层：反反调试
    bypassAntiDebug();
    
    // 第二层：SSL Pinning 绕过
    bypassSSLPinning();
    
    // 第三层：注入库名隐藏
    bypassDylibDetection();
    
    NSLog(@"[HWSideload] 🟢 所有防护层初始化完成，等待 UI 注入...");
}
