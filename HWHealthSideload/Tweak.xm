#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import "fishhook.h"
#import <sys/sysctl.h>

// ============================================================================
//  HWHealthSideload v4.2
//  修复: 移除 open() Hook (导致闪退) + 修复底部导航栏消失
// ============================================================================

static NSString *g_hapPath = nil;
static BOOL g_intercept = NO;

// ============================================================================
// Part 1: Anti-Debug
// ============================================================================

static int (*orig_ptrace)(int, pid_t, caddr_t, int);
static int my_ptrace(int req, pid_t pid, caddr_t addr, int data) {
    if (req == 31) return 0;
    return orig_ptrace(req, pid, addr, data);
}

static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int my_sysctl(int *name, u_int namelen, void *info, size_t *infosize, void *newinfo, size_t newinfosize) {
    int ret = orig_sysctl(name, namelen, info, infosize, newinfo, newinfosize);
    if (namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC &&
        name[2] == KERN_PROC_PID && info) {
        struct kinfo_proc *p = (struct kinfo_proc *)info;
        if (p->kp_proc.p_flag & P_TRACED)
            p->kp_proc.p_flag &= ~P_TRACED;
    }
    return ret;
}

// ============================================================================
// Part 2: Bundle ID
// ============================================================================

%hook NSBundle
- (NSString *)bundleIdentifier {
    if ([self isEqual:[NSBundle mainBundle]])
        return @"com.huawei.iossporthealth";
    return %orig;
}
- (id)objectForInfoDictionaryKey:(NSString *)key {
    if ([self isEqual:[NSBundle mainBundle]] &&
        [key isEqualToString:@"CFBundleIdentifier"])
        return @"com.huawei.iossporthealth";
    return %orig;
}
%end

// ============================================================================
// Part 3: NSFileManager 拦截
// ============================================================================

%hook NSFileManager

- (BOOL)copyItemAtPath:(NSString *)src toPath:(NSString *)dst error:(NSError **)err {
    if (g_intercept && g_hapPath &&
        [[src pathExtension] caseInsensitiveCompare:@"hap"] == NSOrderedSame &&
        ![src isEqualToString:g_hapPath]) {
        NSLog(@"[HWSideload] INTERCEPT copyItemAtPath: %@ -> %@", src, g_hapPath);
        return %orig(g_hapPath, dst, err);
    }
    return %orig;
}

- (BOOL)copyItemAtURL:(NSURL *)srcU toURL:(NSURL *)dstU error:(NSError **)err {
    if (g_intercept && g_hapPath &&
        [[srcU pathExtension] caseInsensitiveCompare:@"hap"] == NSOrderedSame &&
        ![srcU.path isEqualToString:g_hapPath]) {
        NSLog(@"[HWSideload] INTERCEPT copyItemAtURL: %@ -> %@", srcU.path, g_hapPath);
        NSURL *u = [NSURL fileURLWithPath:g_hapPath];
        return %orig(u, dstU, err);
    }
    return %orig;
}

- (BOOL)moveItemAtPath:(NSString *)src toPath:(NSString *)dst error:(NSError **)err {
    if (g_intercept && g_hapPath &&
        [[src pathExtension] caseInsensitiveCompare:@"hap"] == NSOrderedSame &&
        ![src isEqualToString:g_hapPath]) {
        NSLog(@"[HWSideload] INTERCEPT moveItemAtPath: %@ -> %@", src, g_hapPath);
        [self removeItemAtPath:dst error:nil];
        return [self copyItemAtPath:g_hapPath toPath:dst error:err];
    }
    return %orig;
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
    [self.btn setTitle:@"HAP" forState:UIControlStateNormal];
    self.btn.titleLabel.font = [UIFont boldSystemFontOfSize:15];
    [self.btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.btn.layer.cornerRadius = 25;
    self.btn.layer.shadowColor = [UIColor blackColor].CGColor;
    self.btn.layer.shadowOffset = CGSizeMake(0, 3);
    self.btn.layer.shadowOpacity = 0.4;
    self.btn.layer.zPosition = 99999;

    [self.btn addTarget:self action:@selector(menu) forControlEvents:UIControlEventTouchUpInside];
    [w addSubview:self.btn];

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
    NSString *st = g_hapPath
        ? [NSString stringWithFormat:@"File: %@\nIntercept: %@",
           [g_hapPath lastPathComponent], g_intercept ? @"ON" : @"OFF"]
        : @"No file selected";

    // 使用 Alert 样式而非 ActionSheet，避免干扰 TabBar
    UIAlertController *m = [UIAlertController
        alertControllerWithTitle:@"HAP Sideload"
        message:st preferredStyle:UIAlertControllerStyleAlert];

    [m addAction:[UIAlertAction actionWithTitle:@"Select .hap file"
        style:UIAlertActionStyleDefault handler:^(id a) {
        [self pickFile];
    }]];

    if (g_hapPath) {
        NSString *title = g_intercept ? @"Turn OFF intercept" : @"Turn ON intercept";
        [m addAction:[UIAlertAction actionWithTitle:title
            style:UIAlertActionStyleDefault handler:^(id a) {
            g_intercept = !g_intercept;
            [self.btn setTitle:(g_intercept ? @"ON" : @"HAP")
                      forState:UIControlStateNormal];
            self.btn.backgroundColor = g_intercept
                ? [UIColor colorWithRed:0.2 green:0.8 blue:0.3 alpha:0.95]
                : [UIColor colorWithRed:0.9 green:0.2 blue:0.15 alpha:0.95];
            NSString *msg = g_intercept
                ? @"Intercept ON.\nGo to app market and install any watch app.\nYour HAP will be sent instead."
                : @"Intercept OFF.";
            [self alert:@"Status" msg:msg];
        }]];
    }

    [m addAction:[UIAlertAction actionWithTitle:@"Scan classes"
        style:UIAlertActionStyleDefault handler:^(id a) {
        NSString *r = searchClasses(@[@"Market", @"Install", @"Hap",
            @"Transfer", @"Download", @"AppStore"]);
        NSLog(@"[HWSideload]\n%@", r);
        [self alert:@"Scan result" msg:r];
    }]];

    [m addAction:[UIAlertAction actionWithTitle:@"Cancel"
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
        NSDictionary *at = [fm attributesOfItemAtPath:dst error:nil];
        unsigned long long sz = [at fileSize];
        [self alert:@"Ready"
               msg:[NSString stringWithFormat:
                    @"%@ (%.1f MB)\n\n"
                    @"Next:\n"
                    @"1. Tap button > Turn ON intercept\n"
                    @"2. Go to watch app market\n"
                    @"3. Install any app\n"
                    @"4. Watch receives YOUR file",
                    [dst lastPathComponent], sz/1048576.0]];
    } else {
        [self alert:@"Error" msg:err.localizedDescription];
    }
}

- (void)alert:(NSString *)t msg:(NSString *)m {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:t
        message:m preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"OK"
        style:UIAlertActionStyleDefault handler:nil]];
    UIViewController *vc = [UIApplication sharedApplication].keyWindow.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    [vc presentViewController:a animated:YES completion:nil];
}

@end

// ============================================================================
// Part 6: Window Hook
// ============================================================================

%hook UIWindow
- (void)makeKeyAndVisible {
    %orig;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)),
        dispatch_get_main_queue(), ^{
        [[HWSideloadUI shared] attach:self];
    });
}
%end

// ============================================================================
// Part 7: Constructor — 注意: 不再 Hook open()
// ============================================================================

%ctor {
    NSLog(@"[HWSideload] v4.2 loaded");
    struct rebinding h[] = {
        {"ptrace", (void *)my_ptrace, (void **)&orig_ptrace},
        {"sysctl", (void *)my_sysctl, (void **)&orig_sysctl},
    };
    rebind_symbols(h, 2);
    NSLog(@"[HWSideload] hooks active (ptrace+sysctl only)");
}
