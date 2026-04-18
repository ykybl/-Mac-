#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <fishhook.h>
#import <Security/Security.h>

#pragma clang diagnostic ignored "-Wunused-function"
#pragma clang diagnostic ignored "-Wunused-variable"

static NSString *g_hapPath = nil;
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
        if (g_logs.count > 150) [g_logs removeObjectAtIndex:0];
    });
}

// ============================================================================
// Part 1: 环境检测绕过
// ============================================================================

typedef OSStatus (*SecCodeCheckValidity_func)(void *code, uint32_t flags, void *req);
static SecCodeCheckValidity_func orig_SecCodeCheckValidity;
static OSStatus my_SecCodeCheckValidity(void *code, uint32_t flags, void *req) {
    return 0; // errSecSuccess
}

typedef OSStatus (*SecCodeCopySelf_func)(uint32_t flags, void **selfCode);
static SecCodeCopySelf_func orig_SecCodeCopySelf;
static OSStatus my_SecCodeCopySelf(uint32_t flags, void **selfCode) {
    orig_SecCodeCopySelf(flags, selfCode);
    return 0; // errSecSuccess
}

// ============================================================================
// Part 2: Bundle ID 伪装
// ============================================================================

%hook NSBundle

- (NSString *)bundleIdentifier {
    NSString *orig = %orig;
    if ([orig containsString:@"huawei"] || [orig containsString:@"health"] || [orig containsString:@"HWHealthSideload"]) {
        void *r = __builtin_return_address(0);
        Dl_info info;
        if (dladdr(r, &info)) {
            NSString *img = [NSString stringWithUTF8String:info.dli_fname];
            if ([img containsString:@"HuaweiHealth"]) {
                return @"com.huawei.iossporthealth";
            }
        }
    }
    return orig;
}

%end

// ============================================================================
// Part 3: NSFileManager & NSData & NSURLSession 拦截
// ============================================================================

%hook NSFileManager

- (BOOL)copyItemAtPath:(NSString *)src toPath:(NSString *)dst error:(NSError **)err {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"Copy(P): %@ -> %@", src.lastPathComponent, dst.lastPathComponent]); }
    if (g_intercept && g_hapPath && [[src pathExtension] caseInsensitiveCompare:@"hap"] == NSOrderedSame && ![src isEqualToString:g_hapPath]) {
        HWSLog(@"💥 劫持 copyItemAtPath!");
        return %orig(g_hapPath, dst, err);
    }
    return %orig;
}

- (BOOL)copyItemAtURL:(NSURL *)srcU toURL:(NSURL *)dstU error:(NSError **)err {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"Copy(U): %@ -> %@", srcU.lastPathComponent, dstU.lastPathComponent]); }
    if (g_intercept && g_hapPath && [[srcU.path pathExtension] caseInsensitiveCompare:@"hap"] == NSOrderedSame && ![srcU.path isEqualToString:g_hapPath]) {
        HWSLog(@"💥 劫持 copyItemAtURL!");
        return %orig([NSURL fileURLWithPath:g_hapPath], dstU, err);
    }
    return %orig;
}

- (BOOL)moveItemAtPath:(NSString *)src toPath:(NSString *)dst error:(NSError **)err {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"Move(P): %@ -> %@", src.lastPathComponent, dst.lastPathComponent]); }
    if (g_intercept && g_hapPath && [[src pathExtension] caseInsensitiveCompare:@"hap"] == NSOrderedSame && ![src isEqualToString:g_hapPath]) {
        HWSLog(@"💥 劫持 moveItemAtPath!");
        [self removeItemAtPath:dst error:nil];
        return [self copyItemAtPath:g_hapPath toPath:dst error:err];
    }
    return %orig;
}

- (BOOL)moveItemAtURL:(NSURL *)srcU toURL:(NSURL *)dstU error:(NSError **)err {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"Move(U): %@ -> %@", srcU.lastPathComponent, dstU.lastPathComponent]); }
    if (g_intercept && g_hapPath && [[srcU.path pathExtension] caseInsensitiveCompare:@"hap"] == NSOrderedSame && ![srcU.path isEqualToString:g_hapPath]) {
        HWSLog(@"💥 劫持 moveItemAtURL!");
        [self removeItemAtURL:dstU error:nil];
        return [self copyItemAtURL:[NSURL fileURLWithPath:g_hapPath] toURL:dstU error:err];
    }
    return %orig;
}

%end

%hook NSData

- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)useAuxiliaryFile {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"WriteFile: %@", path.lastPathComponent]); }
    if (g_intercept && g_hapPath && [[path pathExtension] caseInsensitiveCompare:@"hap"] == NSOrderedSame && ![path isEqualToString:g_hapPath]) {
        HWSLog(@"💥 劫持 NSData writeToFile!");
        NSFileManager *fm = [NSFileManager defaultManager];
        [fm removeItemAtPath:path error:nil];
        return [fm copyItemAtPath:g_hapPath toPath:path error:nil];
    }
    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url atomically:(BOOL)atomically {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"WriteURL: %@", url.lastPathComponent]); }
    if (g_intercept && g_hapPath && [[url.path pathExtension] caseInsensitiveCompare:@"hap"] == NSOrderedSame && ![url.path isEqualToString:g_hapPath]) {
        HWSLog(@"💥 劫持 NSData writeToURL!");
        NSFileManager *fm = [NSFileManager defaultManager];
        [fm removeItemAtURL:url error:nil];
        return [fm copyItemAtURL:[NSURL fileURLWithPath:g_hapPath] toURL:url error:nil];
    }
    return %orig;
}

+ (instancetype)dataWithContentsOfFile:(NSString *)path {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"Data ReadFile: %@", path.lastPathComponent]); }
    if (g_intercept && g_hapPath && [[path pathExtension] caseInsensitiveCompare:@"hap"] == NSOrderedSame && ![path isEqualToString:g_hapPath]) {
        HWSLog(@"💥 劫持 Data ReadFile!");
        return %orig(g_hapPath);
    }
    return %orig;
}

+ (instancetype)dataWithContentsOfURL:(NSURL *)url {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"Data ReadURL: %@", url.lastPathComponent]); }
    if (g_intercept && g_hapPath && [[url.path pathExtension] caseInsensitiveCompare:@"hap"] == NSOrderedSame && ![url.path isEqualToString:g_hapPath]) {
        HWSLog(@"💥 劫持 Data ReadURL!");
        return %orig([NSURL fileURLWithPath:g_hapPath]);
    }
    return %orig;
}

- (instancetype)initWithContentsOfFile:(NSString *)path options:(NSDataReadingOptions)readOptionsMask error:(NSError **)errorPtr {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"Init ReadFile: %@", path.lastPathComponent]); }
    if (g_intercept && g_hapPath && [[path pathExtension] caseInsensitiveCompare:@"hap"] == NSOrderedSame && ![path isEqualToString:g_hapPath]) {
        HWSLog(@"💥 劫持 Init ReadFile!");
        return %orig(g_hapPath, readOptionsMask, errorPtr);
    }
    return %orig;
}

- (instancetype)initWithContentsOfURL:(NSURL *)url options:(NSDataReadingOptions)readOptionsMask error:(NSError **)errorPtr {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"Init ReadURL: %@", url.lastPathComponent]); }
    if (g_intercept && g_hapPath && [[url.path pathExtension] caseInsensitiveCompare:@"hap"] == NSOrderedSame && ![url.path isEqualToString:g_hapPath]) {
        HWSLog(@"💥 劫持 Init ReadURL!");
        return %orig([NSURL fileURLWithPath:g_hapPath], readOptionsMask, errorPtr);
    }
    return %orig;
}

%end

%hook NSURLSession

- (NSURLSessionDownloadTask *)downloadTaskWithRequest:(NSURLRequest *)request {
    if (g_intercept) {
        NSString *u = request.URL.absoluteString;
        HWSLog([NSString stringWithFormat:@"NET Req: %@", request.URL.lastPathComponent]);
        
        if (g_hapPath && ([u containsString:@".hap"] || [u containsString:@"pkg"])) {
            HWSLog(@"💥 自动替换网络请求 (Request)为本地 HAP!");
            NSMutableURLRequest *newReq = [request mutableCopy];
            newReq.URL = [NSURL fileURLWithPath:g_hapPath];
            return %orig(newReq);
        }
    }
    return %orig;
}

- (NSURLSessionDownloadTask *)downloadTaskWithURL:(NSURL *)url {
    if (g_intercept) {
        NSString *u = url.absoluteString;
        HWSLog([NSString stringWithFormat:@"NET URL: %@", url.lastPathComponent]);
        
        if (g_hapPath && ([u containsString:@".hap"] || [u containsString:@"pkg"])) {
            HWSLog(@"💥 自动替换网络请求 (URL)为本地 HAP!");
            return %orig([NSURL fileURLWithPath:g_hapPath]);
        }
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
    NSString *st = g_hapPath
        ? [NSString stringWithFormat:@"文件: %@\n劫持: %@",
           [g_hapPath lastPathComponent], g_intercept ? @"已开启" : @"已关闭"]
        : @"未选择文件";

    // 使用 Alert 样式而非 ActionSheet，避免干扰 TabBar
    UIAlertController *m = [UIAlertController
        alertControllerWithTitle:@"HAP 侧载"
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
                ? @"劫持已开启。\n前往手表应用市场安装任意应用，\n您的 HAP 文件将被系统替换发送至手表。"
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
        NSDictionary *at = [fm attributesOfItemAtPath:dst error:nil];
        unsigned long long sz = [at fileSize];
        [self alert:@"准备就绪"
               msg:[NSString stringWithFormat:
                    @"%@ (%.1f MB)\n\n"
                    @"下一步:\n"
                    @"1. 点击侧载按钮 > 开启劫持\n"
                    @"2. 进入手表应用市场\n"
                    @"3. 安装任意应用\n"
                    @"4. 手表将接收您的文件",
                    [dst lastPathComponent], sz/1048576.0]];
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
    dispatch_async(dispatch_get_main_queue(), ^{
        struct rebinding rb[2];
        rb[0].name = "SecCodeCheckValidity";
        rb[0].replacement = (void *)my_SecCodeCheckValidity;
        rb[0].replaced = (void **)&orig_SecCodeCheckValidity;

        rb[1].name = "SecCodeCopySelf";
        rb[1].replacement = (void *)my_SecCodeCopySelf;
        rb[1].replaced = (void **)&orig_SecCodeCopySelf;

        rebind_symbols((struct rebinding *)rb, 2);

        CFNotificationCenterAddObserver(CFNotificationCenterGetLocalCenter(), NULL,
            appDidBecomeActive, (CFStringRef)UIApplicationDidBecomeActiveNotification, NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
    });
}
