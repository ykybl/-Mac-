#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import "fishhook.h"
#import <sys/sysctl.h>

// ============================================================================
//  HWHealthSideload v3.0 — 极简稳定版
//  只保留: Bundle ID 伪装 + 反调试 + 悬浮按钮
//  目标: 100% 编译通过 + 解决"受限业务服务范围"登录拒绝
// ============================================================================

// ============================================================================
// Part 1: Anti-Debug (fishhook)
// ============================================================================

static int (*orig_ptrace)(int, pid_t, caddr_t, int);
static int my_ptrace(int req, pid_t pid, caddr_t addr, int data) {
    if (req == 31) { return 0; }
    return orig_ptrace(req, pid, addr, data);
}

static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int my_sysctl(int *name, u_int namelen, void *info, size_t *infosize, void *newinfo, size_t newinfosize) {
    int ret = orig_sysctl(name, namelen, info, infosize, newinfo, newinfosize);
    if (namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID && info) {
        struct kinfo_proc *p = (struct kinfo_proc *)info;
        if (p->kp_proc.p_flag & P_TRACED) {
            p->kp_proc.p_flag &= ~P_TRACED;
        }
    }
    return ret;
}

// ============================================================================
// Part 2: Bundle ID 伪装 (Logos %hook — 解决登录被拒的核心)
// ============================================================================

%hook NSBundle

- (NSString *)bundleIdentifier {
    if ([self isEqual:[NSBundle mainBundle]]) {
        return @"com.huawei.iossporthealth";
    }
    return %orig;
}

- (id)objectForInfoDictionaryKey:(NSString *)key {
    if ([self isEqual:[NSBundle mainBundle]]) {
        if ([key isEqualToString:@"CFBundleIdentifier"]) {
            return @"com.huawei.iossporthealth";
        }
    }
    return %orig;
}

- (NSDictionary *)infoDictionary {
    NSMutableDictionary *d = [%orig mutableCopy];
    if ([self isEqual:[NSBundle mainBundle]]) {
        d[@"CFBundleIdentifier"] = @"com.huawei.iossporthealth";
    }
    return [d copy];
}

%end

// ============================================================================
// Part 3: 悬浮侧载按钮 + 文件选取
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
    [self.btn setTitle:@"侧载HAP" forState:UIControlStateNormal];
    self.btn.titleLabel.font = [UIFont boldSystemFontOfSize:15];
    [self.btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.btn.layer.cornerRadius = 25;
    self.btn.layer.shadowColor = [UIColor blackColor].CGColor;
    self.btn.layer.shadowOffset = CGSizeMake(0, 3);
    self.btn.layer.shadowOpacity = 0.4;
    self.btn.layer.zPosition = 99999;

    [self.btn addTarget:self action:@selector(pick) forControlEvents:UIControlEventTouchUpInside];
    [w addSubview:self.btn];

    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(drag:)];
    [self.btn addGestureRecognizer:pan];
}

- (void)drag:(UIPanGestureRecognizer *)r {
    CGPoint t = [r translationInView:r.view.superview];
    r.view.center = CGPointMake(r.view.center.x + t.x, r.view.center.y + t.y);
    [r setTranslation:CGPointZero inView:r.view.superview];
}

- (void)pick {
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

    NSString *msg = err
        ? [NSString stringWithFormat:@"失败: %@", err.localizedDescription]
        : [NSString stringWithFormat:@"文件已就绪:\n%@", dst];

    UIAlertController *a = [UIAlertController alertControllerWithTitle:(err ? @"❌" : @"✅")
        message:msg preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
    [vc presentViewController:a animated:YES completion:nil];
}

@end

// ============================================================================
// Part 4: Window Hook — 植入 UI
// ============================================================================

%hook UIWindow
- (void)makeKeyAndVisible {
    %orig;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [[HWSideloadUI shared] attach:self];
    });
}
%end

// ============================================================================
// Part 5: Constructor
// ============================================================================

%ctor {
    NSLog(@"[HWSideload] v3.0 loaded");
    struct rebinding hooks[] = {
        {"ptrace", (void *)my_ptrace, (void **)&orig_ptrace},
        {"sysctl", (void *)my_sysctl, (void **)&orig_sysctl},
    };
    rebind_symbols(hooks, 2);
    NSLog(@"[HWSideload] hooks active");
}
