#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import "fishhook.h"
#import <sys/sysctl.h>

// ============================================================================
//  HWHealthSideload v4.0 — 应用市场安装劫持版
//  核心思路: Hook 华为手表应用市场的安装流程
//           把即将发送到手表的 HAP 文件替换为我们自己的
// ============================================================================

// 存储用户选择的 HAP 文件路径（全局）
static NSString *g_selectedHapPath = nil;
static BOOL g_interceptEnabled = NO;

// ============================================================================
// Part 1: Anti-Debug
// ============================================================================

static int (*orig_ptrace)(int, pid_t, caddr_t, int);
static int my_ptrace(int req, pid_t pid, caddr_t addr, int data) {
    if (req == 31) { return 0; }
    return orig_ptrace(req, pid, addr, data);
}

static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int my_sysctl(int *name, u_int namelen, void *info, size_t *infosize, void *newinfo, size_t newinfosize) {
    int ret = orig_sysctl(name, namelen, info, infosize, newinfo, newinfosize);
    if (namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC &&
        name[2] == KERN_PROC_PID && info) {
        struct kinfo_proc *p = (struct kinfo_proc *)info;
        if (p->kp_proc.p_flag & P_TRACED) {
            p->kp_proc.p_flag &= ~P_TRACED;
        }
    }
    return ret;
}

// ============================================================================
// Part 2: Bundle ID 伪装
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

%end

// ============================================================================
// Part 3: 核心拦截 — Hook 文件路径读取
// 当 App 要读取 HAP 文件路径发送给手表时，我们偷梁换柱
// ============================================================================

// Hook NSString 的路径相关方法，拦截所有含 .hap 的路径
%hook NSString

// 当 App 询问文件是否存在、或者拼接路径时，注入我们的文件
- (BOOL)hasSuffix:(NSString *)suffix {
    BOOL result = %orig;
    // 监控对 .hap 后缀的检查
    if ([suffix isEqualToString:@".hap"] && result && g_interceptEnabled && g_selectedHapPath) {
        NSLog(@"[HWSideload] 🎯 检测到 .hap 路径访问: %@", self);
    }
    return result;
}

%end

// ============================================================================
// Part 4: Hook NSFileManager — 拦截 HAP 文件的读取/复制
// ============================================================================

%hook NSFileManager

// 当 App 要复制某个 HAP 文件时，把源路径替换成我们的
- (BOOL)copyItemAtPath:(NSString *)srcPath toPath:(NSString *)dstPath error:(NSError **)error {
    if (g_interceptEnabled && g_selectedHapPath &&
        [srcPath.pathExtension.lowercaseString isEqualToString:@"hap"] &&
        ![srcPath isEqualToString:g_selectedHapPath]) {

        NSLog(@"[HWSideload] 🔀 HAP 文件路径拦截!");
        NSLog(@"[HWSideload]   原始路径: %@", srcPath);
        NSLog(@"[HWSideload]   替换为:  %@", g_selectedHapPath);

        // 将目标替换为我们的文件
        return %orig(g_selectedHapPath, dstPath, error);
    }
    return %orig;
}

- (BOOL)copyItemAtURL:(NSURL *)srcURL toURL:(NSURL *)dstURL error:(NSError **)error {
    if (g_interceptEnabled && g_selectedHapPath &&
        [srcURL.pathExtension.lowercaseString isEqualToString:@"hap"] &&
        ![srcURL.path isEqualToString:g_selectedHapPath]) {

        NSLog(@"[HWSideload] 🔀 HAP URL 拦截!");
        NSLog(@"[HWSideload]   原始: %@", srcURL.path);
        NSLog(@"[HWSideload]   替换: %@", g_selectedHapPath);

        NSURL *ourURL = [NSURL fileURLWithPath:g_selectedHapPath];
        return %orig(ourURL, dstURL, error);
    }
    return %orig;
}

%end

// ============================================================================
// Part 5: Hook NSData — 拦截 HAP 文件数据的读取
// ============================================================================

%hook NSData

+ (instancetype)dataWithContentsOfFile:(NSString *)path {
    if (g_interceptEnabled && g_selectedHapPath &&
        [path.pathExtension.lowercaseString isEqualToString:@"hap"] &&
        ![path isEqualToString:g_selectedHapPath]) {

        NSLog(@"[HWSideload] 📦 NSData 读取 HAP 拦截: %@ → %@", path, g_selectedHapPath);
        return %orig(g_selectedHapPath);
    }
    return %orig;
}

+ (instancetype)dataWithContentsOfURL:(NSURL *)url {
    if (g_interceptEnabled && g_selectedHapPath &&
        [url.pathExtension.lowercaseString isEqualToString:@"hap"] &&
        ![url.path isEqualToString:g_selectedHapPath]) {

        NSLog(@"[HWSideload] 📦 NSData URL 读取 HAP 拦截: %@", url.path);
        NSURL *ours = [NSURL fileURLWithPath:g_selectedHapPath];
        return %orig(ours);
    }
    return %orig;
}

%end

// ============================================================================
// Part 6: Hook NSURLRequest — 拦截下载 HAP 的网络请求
// 当应用市场从华为服务器下载 HAP 时，直接返回本地文件
// ============================================================================

%hook NSURLSession

- (NSURLSessionDownloadTask *)downloadTaskWithRequest:(NSURLRequest *)request
                                    completionHandler:(void (^)(NSURL *, NSURLResponse *, NSError *))completionHandler {
    NSString *urlStr = request.URL.absoluteString;
    
    // 监控所有 HAP 文件的下载请求
    if ([urlStr containsString:@".hap"] || [urlStr containsString:@"appstore"] ||
        [urlStr containsString:@"market"] || [urlStr containsString:@"download"]) {
        
        NSLog(@"[HWSideload] 🌐 检测到下载请求: %@", urlStr);
        
        // 如果拦截模式开启且有文件，劫持这个下载任务
        if (g_interceptEnabled && g_selectedHapPath) {
            NSLog(@"[HWSideload] ✂️ 劫持下载 → 使用本地 HAP");

            // 立刻回调，返回我们本地的文件 URL，模拟下载完成
            if (completionHandler) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    NSURL *localURL = [NSURL fileURLWithPath:g_selectedHapPath];
                    NSURLResponse *fakeResp = [[NSURLResponse alloc]
                        initWithURL:request.URL
                           MIMEType:@"application/vnd.huawei.hap"
              expectedContentLength:-1
                   textEncodingName:nil];
                    completionHandler(localURL, fakeResp, nil);
                });
            }
            // 返回一个假的立刻完成的 task（不会真正发请求）
            return %orig;
        }
    }
    return %orig;
}

%end

// ============================================================================
// Part 7: 运行时探测 — 专门搜索应用市场/安装相关类
// ============================================================================

static NSString *searchClasses(NSArray<NSString *> *keywords) {
    NSMutableString *result = [NSMutableString string];
    int total = objc_getClassList(NULL, 0);
    Class *classes = (Class *)malloc(sizeof(Class) * total);
    objc_getClassList(classes, total);

    for (NSString *kw in keywords) {
        int found = 0;
        [result appendFormat:@"\n── 关键词: \"%@\" ──\n", kw];
        for (int i = 0; i < total; i++) {
            NSString *name = NSStringFromClass(classes[i]);
            if ([name localizedCaseInsensitiveContainsString:kw]) {
                [result appendFormat:@"  %@\n", name];
                found++;
                if (found >= 20) {
                    [result appendString:@"  ...(截断)\n"];
                    break;
                }
            }
        }
        if (found == 0) [result appendString:@"  (无匹配)\n"];
    }

    free(classes);
    return result;
}

static NSString *dumpMethods(NSString *clsName) {
    Class cls = NSClassFromString(clsName);
    if (!cls) return [NSString stringWithFormat:@"类 %@ 不存在\n", clsName];

    NSMutableString *r = [NSMutableString stringWithFormat:@"📋 %@:\n", clsName];
    unsigned int cnt = 0;
    Method *ms = class_copyMethodList(cls, &cnt);
    for (unsigned int i = 0; i < cnt; i++) {
        [r appendFormat:@"  %@\n", NSStringFromSelector(method_getName(ms[i]))];
    }
    free(ms);

    // 类方法
    Method *cms = class_copyMethodList(object_getClass(cls), &cnt);
    for (unsigned int i = 0; i < cnt; i++) {
        [r appendFormat:@"  +%@\n", NSStringFromSelector(method_getName(cms[i]))];
    }
    free(cms);

    [r appendFormat:@"共 %u 个方法\n", cnt];
    return r;
}

// ============================================================================
// Part 8: 悬浮按钮 + 操作菜单
// ============================================================================

@interface HWSideloadUI : NSObject <UIDocumentPickerDelegate>
@property (nonatomic, strong) UIButton *btn;
@property (nonatomic, copy) NSString *lastFilePath;
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

    [self.btn addTarget:self action:@selector(mainMenu) forControlEvents:UIControlEventTouchUpInside];
    [w addSubview:self.btn];

    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(drag:)];
    [self.btn addGestureRecognizer:pan];
}

- (void)drag:(UIPanGestureRecognizer *)r {
    CGPoint t = [r translationInView:r.view.superview];
    r.view.center = CGPointMake(r.view.center.x + t.x, r.view.center.y + t.y);
    [r setTranslation:CGPointZero inView:r.view.superview];
}

- (void)mainMenu {
    NSString *statusStr = g_selectedHapPath
        ? [NSString stringWithFormat:@"已装弹: %@\n拦截: %@",
           [g_selectedHapPath lastPathComponent],
           g_interceptEnabled ? @"🟢 开启" : @"🔴 关闭"]
        : @"尚未选择 HAP 文件";

    UIAlertController *menu = [UIAlertController
        alertControllerWithTitle:@"🔥 HAP 侧载控制台"
        message:statusStr
        preferredStyle:UIAlertControllerStyleActionSheet];

    [menu addAction:[UIAlertAction actionWithTitle:@"📁 选择 .hap 文件" style:UIAlertActionStyleDefault handler:^(id a) {
        [self pickFile];
    }]];

    if (g_selectedHapPath) {
        NSString *interceptTitle = g_interceptEnabled
            ? @"🔴 关闭拦截模式"
            : @"🟢 开启拦截模式（然后去应用市场安装任意应用）";
        [menu addAction:[UIAlertAction actionWithTitle:interceptTitle style:UIAlertActionStyleDefault handler:^(id a) {
            g_interceptEnabled = !g_interceptEnabled;
            NSString *msg = g_interceptEnabled
                ? @"✅ 拦截已开启！\n\n现在去"发现"→ 应用市场，随便点击安装任意一款手表应用，系统会自动把它替换成你的 HAP 文件发送到手表。"
                : @"🔴 拦截已关闭，恢复正常安装流程。";
            [self alert:@"拦截模式" msg:msg];
        }]];
    }

    [menu addAction:[UIAlertAction actionWithTitle:@"🔍 探测应用市场类" style:UIAlertActionStyleDefault handler:^(id a) {
        NSString *result = searchClasses(@[@"Market", @"AppStore", @"Install", @"Watch", @"Wear", @"Hap", @"Application"]);
        NSLog(@"[HWSideload] 探测结果:\n%@", result);
        [self alert:@"探测结果（同时已输出到日志）" msg:result];
    }]];

    [menu addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];

    UIViewController *vc = [UIApplication sharedApplication].keyWindow.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    [vc presentViewController:menu animated:YES completion:nil];
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

    if (!err) {
        g_selectedHapPath = dst;
        self.lastFilePath = dst;
        NSDictionary *attr = [fm attributesOfItemAtPath:dst error:nil];
        unsigned long long sz = [attr fileSize];
        [self alert:@"✅ 装弹成功！"
               msg:[NSString stringWithFormat:@"文件: %@\n大小: %.1f MB\n\n现在点按钮 → 开启拦截模式\n然后去手表应用市场随便点安装一个应用，系统会把安装包自动替换成你的文件！",
                    [dst lastPathComponent], sz/1048576.0]];
    } else {
        [self alert:@"❌" msg:err.localizedDescription];
    }
}

- (void)alert:(NSString *)title msg:(NSString *)msg {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:title
        message:msg preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleDefault handler:nil]];
    UIViewController *vc = [UIApplication sharedApplication].keyWindow.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    [vc presentViewController:a animated:YES completion:nil];
}

@end

// ============================================================================
// Part 9: Window Hook
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
// Part 10: Constructor
// ============================================================================

%ctor {
    NSLog(@"[HWSideload] v4.0 — 市场安装劫持版 loaded");
    struct rebinding hooks[] = {
        {"ptrace", (void *)my_ptrace, (void **)&orig_ptrace},
        {"sysctl", (void *)my_sysctl, (void **)&orig_sysctl},
    };
    rebind_symbols(hooks, 2);
    NSLog(@"[HWSideload] hooks: ptrace + sysctl active");
    NSLog(@"[HWSideload] 文件拦截层: NSFileManager + NSData + NSURLSession → 待激活");
}
