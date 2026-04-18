#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import "fishhook.h"
#import <sys/sysctl.h>

// ============================================================================
//  HWHealthSideload v4.1 — 编译安全版
//  只保留 100% 能编译通过的 Hook + 应用市场劫持逻辑
// ============================================================================

static NSString *g_hapPath = nil;
static BOOL g_intercept = NO;

// ============================================================================
// Part 1: Anti-Debug (fishhook)
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
// Part 2: Bundle ID 伪装
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
// Part 3: NSFileManager 拦截 — 替换 HAP 文件复制
// ============================================================================

%hook NSFileManager

- (BOOL)copyItemAtPath:(NSString *)src toPath:(NSString *)dst error:(NSError **)err {
    if (g_intercept && g_hapPath &&
        [[src pathExtension] caseInsensitiveCompare:@"hap"] == NSOrderedSame &&
        ![src isEqualToString:g_hapPath]) {
        NSLog(@"[HWSideload] 🔀 拦截复制: %@ → 替换为 %@", src, g_hapPath);
        return %orig(g_hapPath, dst, err);
    }
    return %orig;
}

- (BOOL)copyItemAtURL:(NSURL *)srcU toURL:(NSURL *)dstU error:(NSError **)err {
    if (g_intercept && g_hapPath &&
        [[srcU pathExtension] caseInsensitiveCompare:@"hap"] == NSOrderedSame &&
        ![srcU.path isEqualToString:g_hapPath]) {
        NSLog(@"[HWSideload] 🔀 URL拦截: %@ → %@", srcU.path, g_hapPath);
        NSURL *u = [NSURL fileURLWithPath:g_hapPath];
        return %orig(u, dstU, err);
    }
    return %orig;
}

// 该方法用于移动文件，应用市场也可能用
- (BOOL)moveItemAtPath:(NSString *)src toPath:(NSString *)dst error:(NSError **)err {
    if (g_intercept && g_hapPath &&
        [[src pathExtension] caseInsensitiveCompare:@"hap"] == NSOrderedSame &&
        ![src isEqualToString:g_hapPath]) {
        NSLog(@"[HWSideload] 🔀 移动拦截: 先复制我们的文件到 %@", dst);
        // 改用复制（因为源文件是我们不想动的）
        [self removeItemAtPath:dst error:nil];
        return [self copyItemAtPath:g_hapPath toPath:dst error:err];
    }
    return %orig;
}

%end

// ============================================================================
// Part 4: 监控所有文件写入 — 用 fishhook 拦截 C 层 open()
// 当应用打开 .hap 文件读取时，重定向到我们的文件
// ============================================================================

static int (*orig_open)(const char *, int, ...);
static int my_open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }

    // 只在读取模式下拦截 .hap 文件
    if (g_intercept && g_hapPath && path != NULL) {
        size_t len = strlen(path);
        if (len > 4 && strcasecmp(path + len - 4, ".hap") == 0) {
            // 不拦截我们自己的文件
            if (strcmp(path, [g_hapPath UTF8String]) != 0) {
                NSLog(@"[HWSideload] 📂 open() 拦截: %s → %s", path, [g_hapPath UTF8String]);
                path = [g_hapPath UTF8String];
            }
        }
    }

    if (flags & O_CREAT) {
        return orig_open(path, flags, mode);
    }
    return orig_open(path, flags);
}

// ============================================================================
// Part 5: 运行时探测
// ============================================================================

static NSString *searchClasses(NSArray *keywords) {
    NSMutableString *r = [NSMutableString string];
    int n = objc_getClassList(NULL, 0);
    Class *cls = (Class *)malloc(sizeof(Class) * n);
    objc_getClassList(cls, n);

    for (NSString *kw in keywords) {
        int f = 0;
        [r appendFormat:@"\n─ \"%@\" ─\n", kw];
        for (int i = 0; i < n; i++) {
            NSString *name = NSStringFromClass(cls[i]);
            if ([name localizedCaseInsensitiveContainsString:kw]) {
                [r appendFormat:@"  %@\n", name];
                if (++f >= 15) { [r appendString:@"  ...\n"]; break; }
            }
        }
        if (!f) [r appendString:@"  (无)\n"];
    }
    free(cls);
    return r;
}

// ============================================================================
// Part 6: UI
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
        ? [NSString stringWithFormat:@"已装弹: %@\n拦截: %@",
           [g_hapPath lastPathComponent], g_intercept ? @"🟢开" : @"🔴关"]
        : @"尚未选择文件";

    UIAlertController *m = [UIAlertController
        alertControllerWithTitle:@"🔥 HAP 侧载"
        message:st preferredStyle:UIAlertControllerStyleActionSheet];

    [m addAction:[UIAlertAction actionWithTitle:@"📁 选择 .hap 文件"
        style:UIAlertActionStyleDefault handler:^(id _) {
        [self pickFile];
    }]];

    if (g_hapPath) {
        NSString *t = g_intercept
            ? @"🔴 关闭拦截"
            : @"🟢 开启拦截（然后去市场安装任意应用）";
        [m addAction:[UIAlertAction actionWithTitle:t
            style:UIAlertActionStyleDefault handler:^(id _) {
            g_intercept = !g_intercept;
            [self.btn setTitle:(g_intercept ? @"🟢拦截中" : @"侧载HAP")
                      forState:UIControlStateNormal];
            self.btn.backgroundColor = g_intercept
                ? [UIColor colorWithRed:0.2 green:0.8 blue:0.3 alpha:0.95]
                : [UIColor colorWithRed:0.9 green:0.2 blue:0.15 alpha:0.95];
            NSString *msg = g_intercept
                ? @"✅ 拦截已开启！\n\n按钮已变绿。\n现在去应用市场，点任意一款应用的「安装」按钮。\n系统会自动替换为你的 HAP 文件。"
                : @"拦截已关闭。";
            [self alert:@"状态" msg:msg];
        }]];
    }

    [m addAction:[UIAlertAction actionWithTitle:@"🔍 探测相关类"
        style:UIAlertActionStyleDefault handler:^(id _) {
        NSString *r = searchClasses(@[@"Market", @"Install", @"Hap",
            @"Transfer", @"Download", @"AppStore"]);
        NSLog(@"[HWSideload]\n%@", r);
        [self alert:@"探测结果" msg:r];
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
    p.modalPresentationStyle = UIModalPresentationFullScreen;
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
        [self alert:@"✅ 装弹成功"
               msg:[NSString stringWithFormat:
                    @"%@  (%.1f MB)\n\n"
                    @"下一步:\n"
                    @"1. 点按钮 → 开启拦截\n"
                    @"2. 去应用市场安装任意应用\n"
                    @"3. 手表实际收到的是你的文件",
                    [dst lastPathComponent], sz/1048576.0]];
    } else {
        [self alert:@"❌" msg:err.localizedDescription];
    }
}

- (void)alert:(NSString *)t msg:(NSString *)m {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:t
        message:m preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"好"
        style:UIAlertActionStyleDefault handler:nil]];
    UIViewController *vc = [UIApplication sharedApplication].keyWindow.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    [vc presentViewController:a animated:YES completion:nil];
}

@end

// ============================================================================
// Part 7: Window Hook
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
// Part 8: Constructor
// ============================================================================

%ctor {
    NSLog(@"[HWSideload] v4.1 loaded");
    struct rebinding h[] = {
        {"ptrace", (void *)my_ptrace, (void **)&orig_ptrace},
        {"sysctl", (void *)my_sysctl, (void **)&orig_sysctl},
        {"open",   (void *)my_open,   (void **)&orig_open},
    };
    rebind_symbols(h, 3);
    NSLog(@"[HWSideload] hooks: ptrace+sysctl+open active");
}
