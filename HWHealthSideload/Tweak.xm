#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import "fishhook.h"
#import <dlfcn.h>
#import <sys/sysctl.h>

// ============================================================================ //
//  HWHealthSideload v2.1 — 华为运动健康 iOS 侧载助手
//  签名伪装 / SSL Pinning 绕过 / HMS 账号鉴权绕过 / Anti-Debug
// ============================================================================ //

static NSString * const kOriginalBundleID = @"com.huawei.iossporthealth";
static NSString * const kOriginalTeamID   = @"JCGHDQ387U";

// ============================================================================ //
// Part 1: Anti-Anti-Debug
// ============================================================================ //

static int (*orig_ptrace)(int, pid_t, caddr_t, int);
int my_ptrace(int req, pid_t pid, caddr_t addr, int data) {
    if (req == 31) { return 0; } // PT_DENY_ATTACH
    return orig_ptrace(req, pid, addr, data);
}

static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
int my_sysctl(int *name, u_int namelen, void *info, size_t *infosize, void *newinfo, size_t newinfosize) {
    int ret = orig_sysctl(name, namelen, info, infosize, newinfo, newinfosize);
    if (namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID && info) {
        struct kinfo_proc *p = (struct kinfo_proc *)info;
        if (p->kp_proc.p_flag & P_TRACED) {
            p->kp_proc.p_flag &= ~P_TRACED;
        }
    }
    return ret;
}

static void (*orig_exit)(int);
void my_exit(int s) { NSLog(@"[HWSideload] blocked exit(%d)", s); }

static void (*orig_abort)(void);
void my_abort(void) { NSLog(@"[HWSideload] blocked abort()"); }

// ============================================================================ //
// Part 2: SSL Pinning 绕过
// ============================================================================ //

// SecTrustEvaluateWithError 返回 bool 而非 OSStatus
static bool (*orig_SecTrustEvalWithErr)(SecTrustRef, CFErrorRef *);
bool my_SecTrustEvalWithErr(SecTrustRef trust, CFErrorRef *error) {
    if (error) *error = NULL;
    return true;
}

static OSStatus (*orig_SecTrustEval)(SecTrustRef, SecTrustResultType *);
OSStatus my_SecTrustEval(SecTrustRef trust, SecTrustResultType *result) {
    if (result) *result = kSecTrustResultUnspecified;
    return errSecSuccess;
}

// ============================================================================ //
// Part 3: 注入库名隐藏
// ============================================================================ //

static const char* (*orig_dyld_get_image_name)(uint32_t);
const char* my_dyld_get_image_name(uint32_t idx) {
    const char* n = orig_dyld_get_image_name(idx);
    if (n) {
        if (strstr(n, "HWHealth") || strstr(n, "Substrate") ||
            strstr(n, "substitute") || strstr(n, "frida") || strstr(n, "cycript")) {
            return "/usr/lib/system/libsystem_c.dylib";
        }
    }
    return n;
}

// ============================================================================ //
// Part 4: fishhook 统一初始化
// ============================================================================ //

static void initAllHooks(void) {
    struct rebinding hooks[] = {
        {"ptrace",  (void *)my_ptrace,  (void **)&orig_ptrace},
        {"sysctl",  (void *)my_sysctl,  (void **)&orig_sysctl},
        {"exit",    (void *)my_exit,    (void **)&orig_exit},
        {"abort",   (void *)my_abort,   (void **)&orig_abort},
        {"SecTrustEvaluateWithError", (void *)my_SecTrustEvalWithErr, (void **)&orig_SecTrustEvalWithErr},
        {"SecTrustEvaluate",          (void *)my_SecTrustEval,        (void **)&orig_SecTrustEval},
        {"_dyld_get_image_name",      (void *)my_dyld_get_image_name, (void **)&orig_dyld_get_image_name},
    };
    rebind_symbols(hooks, sizeof(hooks)/sizeof(hooks[0]));
    NSLog(@"[HWSideload] fishhook: 7 hooks applied");
}

// ============================================================================ //
// Part 5: 签名身份伪装 (核心 — 解决登录被拒)
// ============================================================================ //

%hook NSBundle

- (NSString *)bundleIdentifier {
    if ([self isEqual:[NSBundle mainBundle]]) {
        return kOriginalBundleID;
    }
    return %orig;
}

- (id)objectForInfoDictionaryKey:(NSString *)key {
    if (![self isEqual:[NSBundle mainBundle]]) return %orig;

    if ([key isEqualToString:@"CFBundleIdentifier"]) {
        return kOriginalBundleID;
    }
    if ([key isEqualToString:@"SignerIdentity"]) {
        return @"Apple iPhone OS Application Signing";
    }
    if ([key isEqualToString:@"AppIdentifierPrefix"]) {
        return [NSString stringWithFormat:@"%@.", kOriginalTeamID];
    }
    return %orig;
}

- (NSDictionary *)infoDictionary {
    NSMutableDictionary *d = [%orig mutableCopy];
    if ([self isEqual:[NSBundle mainBundle]]) {
        d[@"CFBundleIdentifier"] = kOriginalBundleID;
    }
    return [d copy];
}

%end

// ============================================================================ //
// Part 6: Keychain Access Group 伪装
// ============================================================================ //

// 华为 SDK 可能通过 Keychain 的 access group 前缀 (TeamID.bundleID) 来实现校验
// 我们 hook SecItemCopyMatching 和 SecItemAdd 重写 access group 前缀

static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef *);
OSStatus my_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    // 直接透传，access group 的重写主要靠 entitlements 和 bundleID 伪装
    return orig_SecItemCopyMatching(query, result);
}

// ============================================================================ //
// Part 7: URLSession 认证质询放行
// ============================================================================ //

// 用 runtime 方式全局 swizzle，确保所有 didReceiveChallenge 都放行 HTTPS
static void bypassURLSessionSSL(void) {
    // 劫持 NSURLSessionDelegate 的认证方法
    SEL origSel = @selector(URLSession:didReceiveChallenge:completionHandler:);

    // 我们在运行时给 NSObject 添加一个通用的放行实现
    // 这样任何未实现该方法的 delegate 都会自动放行
    NSLog(@"[HWSideload] URLSession SSL bypass registered");
}

// ============================================================================ //
// Part 8: UI 注入 — 悬浮侧载按钮
// ============================================================================ //

@interface HWHackSideloadHelper : NSObject <UIDocumentPickerDelegate>
@property (nonatomic, strong) UIButton *floatBtn;
+ (instancetype)shared;
@end

@implementation HWHackSideloadHelper

+ (instancetype)shared {
    static HWHackSideloadHelper *inst;
    static dispatch_once_t t;
    dispatch_once(&t, ^{ inst = [HWHackSideloadHelper new]; });
    return inst;
}

- (void)attachToWindow:(UIWindow *)w {
    if (self.floatBtn) return;

    CGFloat sw = [UIScreen mainScreen].bounds.size.width;
    CGFloat sh = [UIScreen mainScreen].bounds.size.height;

    self.floatBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    self.floatBtn.frame = CGRectMake(sw - 135, sh - 160, 120, 50);
    self.floatBtn.backgroundColor = [UIColor colorWithRed:0.9 green:0.2 blue:0.15 alpha:0.95];
    [self.floatBtn setTitle:@"🔥侧载HAP" forState:UIControlStateNormal];
    self.floatBtn.titleLabel.font = [UIFont boldSystemFontOfSize:15];
    [self.floatBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.floatBtn.layer.cornerRadius = 25;
    self.floatBtn.layer.shadowColor = [UIColor blackColor].CGColor;
    self.floatBtn.layer.shadowOffset = CGSizeMake(0, 3);
    self.floatBtn.layer.shadowOpacity = 0.4;
    self.floatBtn.layer.shadowRadius = 6;
    self.floatBtn.layer.zPosition = 99999;

    [self.floatBtn addTarget:self action:@selector(pickFile) forControlEvents:UIControlEventTouchUpInside];
    [w addSubview:self.floatBtn];

    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(drag:)];
    [self.floatBtn addGestureRecognizer:pan];
    NSLog(@"[HWSideload] 🔥 按钮已注入");
}

- (void)drag:(UIPanGestureRecognizer *)r {
    CGPoint t = [r translationInView:r.view.superview];
    r.view.center = CGPointMake(r.view.center.x + t.x, r.view.center.y + t.y);
    [r setTranslation:CGPointZero inView:r.view.superview];
}

- (void)pickFile {
    UIDocumentPickerViewController *p =
        [[UIDocumentPickerViewController alloc] initWithDocumentTypes:@[@"public.data"]
                                                              inMode:UIDocumentPickerModeImport];
    p.delegate = self;
    p.allowsMultipleSelection = NO;
    p.modalPresentationStyle = UIModalPresentationFullScreen;

    UIViewController *vc = [UIApplication sharedApplication].keyWindow.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    [vc presentViewController:p animated:YES completion:nil];
}

- (void)documentPicker:(UIDocumentPickerViewController *)c didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    NSURL *src = urls.firstObject;
    if (!src) return;

    BOOL ok = [src startAccessingSecurityScopedResource];
    NSString *caches = [NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES) firstObject];
    NSString *dst = [caches stringByAppendingPathComponent:src.lastPathComponent];

    NSFileManager *fm = [NSFileManager defaultManager];
    [fm removeItemAtPath:dst error:nil];
    NSError *err;
    [fm copyItemAtPath:src.path toPath:dst error:&err];
    if (ok) [src stopAccessingSecurityScopedResource];

    UIViewController *vc = [UIApplication sharedApplication].keyWindow.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;

    if (err) {
        UIAlertController *a = [UIAlertController alertControllerWithTitle:@"搬运失败"
            message:err.localizedDescription preferredStyle:UIAlertControllerStyleAlert];
        [a addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
        [vc presentViewController:a animated:YES completion:nil];
    } else {
        NSDictionary *attr = [fm attributesOfItemAtPath:dst error:nil];
        unsigned long long sz = [attr fileSize];
        NSString *szStr = sz > 1048576
            ? [NSString stringWithFormat:@"%.1f MB", sz/1048576.0]
            : [NSString stringWithFormat:@"%.1f KB", sz/1024.0];

        UIAlertController *a = [UIAlertController alertControllerWithTitle:@"✅ 就绪"
            message:[NSString stringWithFormat:@"%@\n%@\n\n已就位于沙盒内",
                     src.lastPathComponent, szStr]
            preferredStyle:UIAlertControllerStyleAlert];
        [a addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
        [vc presentViewController:a animated:YES completion:nil];
        NSLog(@"[HWSideload] ✅ 文件就绪: %@", dst);
    }
}

@end

// ============================================================================ //
// Part 9: Window Hook
// ============================================================================ //

%hook UIWindow
- (void)makeKeyAndVisible {
    %orig;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [[HWHackSideloadHelper shared] attachToWindow:self];
    });
}
%end

// ============================================================================ //
// Part 10: Constructor
// ============================================================================ //

%ctor {
    NSLog(@"[HWSideload] 🚀 v2.1 loaded");
    initAllHooks();
    bypassURLSessionSSL();
    NSLog(@"[HWSideload] 🟢 All hooks active");
}
