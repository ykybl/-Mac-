#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <objc/runtime.h>

// ============================================================
// 全局状态
// ============================================================
static BOOL     g_intercept = NO;
static NSString *g_hapPath  = nil;

// ============================================================
// 日志工具
// ============================================================
static void HWSLog(NSString *msg) {
    if (!msg) return;
    NSLog(@"[HWHealthSideload] %@", msg);
    NSString *logFile = [NSTemporaryDirectory() stringByAppendingPathComponent:@"HWHealthSideload.log"];
    NSDateFormatter *df = [NSDateFormatter new];
    [df setDateFormat:@"[aah:mm:ss.SSS] "];
    NSString *line = [[df stringFromDate:[NSDate date]] stringByAppendingFormat:@"%@\n", msg];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:logFile];
    if (fh) {
        [fh seekToEndOfFile];
        [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
        [fh closeFile];
    } else {
        [line writeToFile:logFile atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
}

// ============================================================
// 工具：判断目标路径是否是需要劫持的 .bin 文件
// ============================================================
static BOOL isTargetBin(NSString *path) {
    if (!path) return NO;
    return [path.lowercaseString containsString:@".bin"];
}

// ============================================================
// Hook NSFileManager —— 拦截物理文件 复制/移动
// ============================================================
%hook NSFileManager

// copy 路径版：把目标 .bin 替换为 .hap
- (BOOL)copyItemAtPath:(NSString *)src toPath:(NSString *)dst error:(NSError **)err {
    if (g_intercept && g_hapPath && isTargetBin(dst) && ![dst isEqualToString:g_hapPath]) {
        HWSLog([NSString stringWithFormat:@"💥 [Copy(P)] %@ -> .hap", dst.lastPathComponent]);
        return %orig(g_hapPath, dst, err);
    }
    return %orig;
}

// copy URL版
- (BOOL)copyItemAtURL:(NSURL *)srcU toURL:(NSURL *)dstU error:(NSError **)err {
    if (g_intercept && g_hapPath && isTargetBin(dstU.path) && ![dstU.path isEqualToString:g_hapPath]) {
        HWSLog([NSString stringWithFormat:@"💥 [Copy(U)] %@ -> .hap", dstU.lastPathComponent]);
        return %orig([NSURL fileURLWithPath:g_hapPath], dstU, err);
    }
    return %orig;
}

// move 路径版：先删目标，再从 .hap 复制过去
- (BOOL)moveItemAtPath:(NSString *)src toPath:(NSString *)dst error:(NSError **)err {
    if (g_intercept && g_hapPath && isTargetBin(dst) && ![dst isEqualToString:g_hapPath]) {
        HWSLog([NSString stringWithFormat:@"💥 [Move(P)] %@ -> .hap", dst.lastPathComponent]);
        [self removeItemAtPath:dst error:nil];
        return [self copyItemAtPath:g_hapPath toPath:dst error:err];
    }
    return %orig;
}

// move URL版（最常触发的主路径）
- (BOOL)moveItemAtURL:(NSURL *)srcU toURL:(NSURL *)dstU error:(NSError **)err {
    if (g_intercept && g_hapPath && isTargetBin(dstU.path) && ![dstU.path isEqualToString:g_hapPath]) {
        HWSLog([NSString stringWithFormat:@"💥 [Move(U)] %@ -> .hap (%lld bytes)",
                dstU.lastPathComponent,
                (long long)[[[NSFileManager defaultManager] attributesOfItemAtPath:g_hapPath error:nil] fileSize]]);
        [self removeItemAtURL:dstU error:nil];
        return [self copyItemAtURL:[NSURL fileURLWithPath:g_hapPath] toURL:dstU error:err];
    }
    return %orig;
}

%end

// ============================================================
// Hook NSData —— 拦截内存数据的物理写入
// Bug 修复：原版错误地把 .bin 数据写回 .hap 路径，污染源文件
// ============================================================
%hook NSData

- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)useAuxiliaryFile {
    if (g_intercept && g_hapPath && isTargetBin(path) && ![path isEqualToString:g_hapPath]) {
        HWSLog([NSString stringWithFormat:@"💥 [WriteFile] %@ -> .hap", path.lastPathComponent]);
        // ✅ 正确：加载 .hap 数据，写入目标 .bin 路径（而非把 .bin 写入 .hap）
        NSData *hapData = [NSData dataWithContentsOfFile:g_hapPath];
        if (hapData) return [hapData writeToFile:path atomically:useAuxiliaryFile];
    }
    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url atomically:(BOOL)atomically {
    if (g_intercept && g_hapPath && isTargetBin(url.path) && ![url.path isEqualToString:g_hapPath]) {
        HWSLog([NSString stringWithFormat:@"💥 [WriteURL] %@ -> .hap", url.lastPathComponent]);
        NSFileManager *fm = [NSFileManager defaultManager];
        [fm removeItemAtURL:url error:nil];
        return [fm copyItemAtURL:[NSURL fileURLWithPath:g_hapPath] toURL:url error:nil];
    }
    return %orig;
}

%end

// ============================================================
// 全局 DocumentPicker delegate —— 解决 delegate 绑在随机 VC 上的隐患
// ============================================================
@interface HWSDocPickerDelegate : NSObject <UIDocumentPickerDelegate>
+ (instancetype)shared;
@end

@implementation HWSDocPickerDelegate
+ (instancetype)shared {
    static HWSDocPickerDelegate *s = nil;
    static dispatch_once_t t;
    dispatch_once(&t, ^{ s = [self new]; });
    return s;
}
- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    if (urls.count == 0) return;
    NSURL *url = urls.firstObject;
    // 如果 App 是沙箱临时授权，需要先拷贝到我们的 Temp 目录
    NSString *dst = [NSTemporaryDirectory() stringByAppendingPathComponent:url.lastPathComponent];
    [[NSFileManager defaultManager] removeItemAtPath:dst error:nil];
    NSError *err = nil;
    if ([url startAccessingSecurityScopedResource]) {
        [[NSFileManager defaultManager] copyItemAtURL:url toURL:[NSURL fileURLWithPath:dst] error:&err];
        [url stopAccessingSecurityScopedResource];
    }
    g_hapPath   = err ? url.path : dst;
    g_intercept = YES;
    HWSLog([NSString stringWithFormat:@"[UI] 已挂载外挂包: %@ (%lld bytes)",
            g_hapPath.lastPathComponent,
            (long long)[[[NSFileManager defaultManager] attributesOfItemAtPath:g_hapPath error:nil] fileSize]]);
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *ac = [UIAlertController
            alertControllerWithTitle:@"✅ 挂载成功"
            message:[NSString stringWithFormat:@"包: %@\n劫持已开启，点击市场应用的安装即可替换！", g_hapPath.lastPathComponent]
            preferredStyle:UIAlertControllerStyleAlert];
        [ac addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [[UIApplication sharedApplication].keyWindow.rootViewController presentViewController:ac animated:YES completion:nil];
    });
}
- (void)documentPickerWasCancelled:(UIDocumentPickerViewController *)controller {}
@end

// ============================================================
// 悬浮按钮工具函数（全局，不依赖 VC self）
// ============================================================
static void hws_showDocPicker(void) {
    UIDocumentPickerViewController *dp = [[UIDocumentPickerViewController alloc]
        initWithDocumentTypes:@[@"public.data"] inMode:UIDocumentPickerModeImport];
    dp.delegate = [HWSDocPickerDelegate shared];
    UIViewController *root = [UIApplication sharedApplication].keyWindow.rootViewController;
    while (root.presentedViewController) root = root.presentedViewController;
    [root presentViewController:dp animated:YES completion:nil];
}

static void hws_showMenu(void) {
    NSString *statusStr = g_intercept ? @"🟢 开启" : @"🔴 关闭";
    NSString *hapStr    = g_hapPath ? [NSString stringWithFormat:@"%@ (%lld KB)",
                                       g_hapPath.lastPathComponent,
                                       (long long)[[[NSFileManager defaultManager] attributesOfItemAtPath:g_hapPath error:nil] fileSize] / 1024]
                                    : @"未选择";
    UIAlertController *ac = [UIAlertController
        alertControllerWithTitle:@"侧载管理 v4.32"
        message:[NSString stringWithFormat:@"劫持状态: %@\n当前包: %@", statusStr, hapStr]
        preferredStyle:UIAlertControllerStyleAlert];

    NSString *toggleTitle = g_intercept ? @"🚫 关闭劫持" : @"✅ 开启劫持";
    [ac addAction:[UIAlertAction actionWithTitle:toggleTitle style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        g_intercept = !g_intercept;
        HWSLog([NSString stringWithFormat:@"[UI] 劫持已%@", g_intercept ? @"开启" : @"关闭"]);
    }]];

    [ac addAction:[UIAlertAction actionWithTitle:@"📂 选取 .hap 包" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        hws_showDocPicker();
    }]];

    [ac addAction:[UIAlertAction actionWithTitle:@"🗑 清空日志" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *a) {
        NSString *logFile = [NSTemporaryDirectory() stringByAppendingPathComponent:@"HWHealthSideload.log"];
        [[NSFileManager defaultManager] removeItemAtPath:logFile error:nil];
    }]];

    [ac addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];

    UIViewController *root = [UIApplication sharedApplication].keyWindow.rootViewController;
    while (root.presentedViewController) root = root.presentedViewController;
    [root presentViewController:ac animated:YES completion:nil];
}

// ============================================================
// Hook UIViewController —— 注入悬浮按钮（弱引用，避免悬空崩溃）
// ============================================================
%hook UIViewController

- (void)viewDidLoad {
    %orig;
    // 只在符合华为相关界面时触发，且全局只初始化一次
    NSString *cls = NSStringFromClass(self.class);
    if (!([cls containsString:@"Device"] || [cls containsString:@"Watch"] || [cls containsString:@"Main"])) return;

    static dispatch_once_t once;
    dispatch_once(&once, ^{
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            UIWindow *win = [UIApplication sharedApplication].keyWindow;
            if (!win) return;

            UIButton *btn = [UIButton buttonWithType:UIButtonTypeCustom];
            btn.frame = CGRectMake(12, 110, 56, 56);
            btn.backgroundColor = [UIColor colorWithRed:0.1 green:0.6 blue:1.0 alpha:0.85];
            btn.layer.cornerRadius = 28;
            btn.layer.shadowColor  = [UIColor blackColor].CGColor;
            btn.layer.shadowOpacity = 0.4;
            btn.layer.shadowRadius  = 6;
            btn.layer.shadowOffset  = CGSizeMake(0, 3);
            [btn setTitle:@"⚡️" forState:UIControlStateNormal];
            btn.titleLabel.font = [UIFont systemFontOfSize:22];

            // ✅ 修复：使用 block 回调而非 target-action 绑定 self，避免 VC 被回收后崩溃
            [btn addTarget:[HWSDocPickerDelegate shared]
                    action:@selector(hws_btnTapped)
          forControlEvents:UIControlEventTouchUpInside];

            // 注册 tap 响应
            class_addMethod([HWSDocPickerDelegate class], @selector(hws_btnTapped), imp_implementationWithBlock(^{
                hws_showMenu();
            }), "v@:");

            // 拖动
            UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:[HWSDocPickerDelegate shared] action:@selector(hws_drag:)];
            class_addMethod([HWSDocPickerDelegate class], @selector(hws_drag:), imp_implementationWithBlock(^(id _self, UIPanGestureRecognizer *g){
                UIView *v = g.view;
                CGPoint p = [g locationInView:v.superview];
                v.center = p;
            }), "v@:@");
            [btn addGestureRecognizer:pan];

            [win addSubview:btn];
        });
    });
}

%end