#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>

static BOOL g_intercept = NO;
static NSString *g_hapPath = nil;

static void HWSLog(NSString *msg) {
    if (!msg) return;
    NSLog(@"[HWHealthSideload] %@", msg);
    
    NSString *logFile = [NSTemporaryDirectory() stringByAppendingPathComponent:@"HWHealthSideload.log"];
    NSDateFormatter *df = [[NSDateFormatter alloc] init];
    [df setDateFormat:@"[aah:mm:ss.SSS] "];
    NSString *tb = [df stringFromDate:[NSDate date]];
    
    NSString *writeStr = [NSString stringWithFormat:@"%@%@\n", tb, msg];
    
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:logFile];
    if (fh) {
        [fh seekToEndOfFile];
        [fh writeData:[writeStr dataUsingEncoding:NSUTF8StringEncoding]];
        [fh closeFile];
    } else {
        [writeStr writeToFile:logFile atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
}

static BOOL isTargetExt(NSString *path) {
    if (!path) return NO;
    NSString *low = path.lowercaseString;
    return [low containsString:@".bin"];
}

// NSJSONSerialization hook 已移除 —— 该 hook 会拦截所有 JSON 解析包括登录接口，导致账号服务异常

%hook NSFileManager

- (BOOL)copyItemAtPath:(NSString *)src toPath:(NSString *)dst error:(NSError **)err {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"Copy(P): %@ -> %@", src.lastPathComponent, dst.lastPathComponent]); }
    if (g_intercept && g_hapPath && isTargetExt(dst) && ![dst isEqualToString:g_hapPath]) {
        HWSLog(@"💥 劫持物理文件写入 copyItemAtPath!");
        return %orig(g_hapPath, dst, err);
    }
    return %orig;
}

- (BOOL)copyItemAtURL:(NSURL *)srcU toURL:(NSURL *)dstU error:(NSError **)err {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"Copy(U): %@ -> %@", srcU.lastPathComponent, dstU.lastPathComponent]); }
    if (g_intercept && g_hapPath && isTargetExt(dstU.path) && ![dstU.path isEqualToString:g_hapPath]) {
        HWSLog(@"💥 劫持物理文件写入 copyItemAtURL!");
        return %orig([NSURL fileURLWithPath:g_hapPath], dstU, err);
    }
    return %orig;
}

- (BOOL)moveItemAtPath:(NSString *)src toPath:(NSString *)dst error:(NSError **)err {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"Move(P): %@ -> %@", src.lastPathComponent, dst.lastPathComponent]); }
    if (g_intercept && g_hapPath && isTargetExt(dst) && ![dst isEqualToString:g_hapPath]) {
        HWSLog(@"💥 劫持物理文件写入 moveItemAtPath!");
        [self removeItemAtPath:dst error:nil];
        return [self copyItemAtPath:g_hapPath toPath:dst error:err];
    }
    return %orig;
}

- (BOOL)moveItemAtURL:(NSURL *)srcU toURL:(NSURL *)dstU error:(NSError **)err {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"Move(U): %@ -> %@", srcU.lastPathComponent, dstU.lastPathComponent]); }
    if (g_intercept && g_hapPath && isTargetExt(dstU.path) && ![dstU.path isEqualToString:g_hapPath]) {
        HWSLog(@"💥 劫持物理文件写入 moveItemAtURL!");
        [self removeItemAtURL:dstU error:nil];
        return [self copyItemAtURL:[NSURL fileURLWithPath:g_hapPath] toURL:dstU error:err];
    }
    return %orig;
}

%end

%hook NSData

- (BOOL)writeToFile:(NSString *)path atomically:(BOOL)useAuxiliaryFile {
    if (g_intercept && isTargetExt(path)) { HWSLog([NSString stringWithFormat:@"WriteFile: %@", path.lastPathComponent]); }
    if (g_intercept && g_hapPath && isTargetExt(path) && ![path isEqualToString:g_hapPath]) {
        HWSLog(@"💥 劫持物理文件写入 NSData writeToFile!");
        NSData *hapData = [NSData dataWithContentsOfFile:g_hapPath];
        if (hapData) return %orig(g_hapPath, useAuxiliaryFile);
    }
    return %orig;
}

- (BOOL)writeToURL:(NSURL *)url atomically:(BOOL)atomically {
    if (g_intercept) { HWSLog([NSString stringWithFormat:@"WriteURL: %@", url.lastPathComponent]); }
    if (g_intercept && g_hapPath && isTargetExt(url.path) && ![url.path isEqualToString:g_hapPath]) {
        HWSLog(@"💥 劫持物理文件写入 NSData writeToURL!");
        NSFileManager *fm = [NSFileManager defaultManager];
        [fm removeItemAtURL:url error:nil];
        return [fm copyItemAtURL:[NSURL fileURLWithPath:g_hapPath] toURL:url error:nil];
    }
    return %orig;
}

%end

// ============================================================================
// Core UI Injection
// ============================================================================
@interface UIViewController (HWSSideload)
- (void)hws_showMenu;
- (void)hws_drag:(UIPanGestureRecognizer *)pan;
@end

%hook UIViewController

- (void)viewDidLoad {
    %orig;
    NSString *clsName = NSStringFromClass([self class]);
    if ([clsName containsString:@"Device"] || [clsName containsString:@"Watch"] || [clsName containsString:@"Main"]) {
        static dispatch_once_t onceToken;
        dispatch_once(&onceToken, ^{
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                UIWindow *window = [UIApplication sharedApplication].keyWindow;
                if (!window) return;
                
                UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
                btn.frame = CGRectMake(10, 100, 60, 60);
                btn.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.7];
                btn.layer.cornerRadius = 30;
                [btn setTitle:@"侧载" forState:UIControlStateNormal];
                [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
                [btn addTarget:self action:@selector(hws_showMenu) forControlEvents:UIControlEventTouchUpInside];
                
                UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(hws_drag:)];
                [btn addGestureRecognizer:pan];
                
                [window addSubview:btn];
            });
        });
    }
}

%new
- (void)hws_drag:(UIPanGestureRecognizer *)pan {
    UIView *btn = pan.view;
    CGPoint p = [pan locationInView:btn.superview];
    btn.center = p;
}

%new
- (void)hws_showMenu {
    UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"侧载管理 (v4.31 物理替换版)" 
                                                                message:[NSString stringWithFormat:@"状态: %@\n当前包: %@", g_intercept ? @"开启" : @"关闭", g_hapPath ? g_hapPath.lastPathComponent : @"未选择"] 
                                                         preferredStyle:UIAlertControllerStyleAlert];
    
    [ac addAction:[UIAlertAction actionWithTitle:g_intercept ? @"🚫 关闭劫持" : @"✅ 开启劫持" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        g_intercept = !g_intercept;
        [self hws_showMenu]; // Refresh UI
    }]];
    
    [ac addAction:[UIAlertAction actionWithTitle:@"📂 选取 .hap" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        UIDocumentPickerViewController *dp = [[UIDocumentPickerViewController alloc] initWithDocumentTypes:@[@"public.data"] inMode:UIDocumentPickerModeImport];
        dp.delegate = (id<UIDocumentPickerDelegate>)self;
        [[UIApplication sharedApplication].keyWindow.rootViewController presentViewController:dp animated:YES completion:nil];
    }]];
    
    [ac addAction:[UIAlertAction actionWithTitle:@"清空日志" style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
        NSString *logFile = [NSTemporaryDirectory() stringByAppendingPathComponent:@"HWHealthSideload.log"];
        [[NSFileManager defaultManager] removeItemAtPath:logFile error:nil];
    }]];
    
    [ac addAction:[UIAlertAction actionWithTitle:@"关闭" style:UIAlertActionStyleCancel handler:nil]];
    
    [[UIApplication sharedApplication].keyWindow.rootViewController presentViewController:ac animated:YES completion:nil];
}

%new
- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    if (urls.count > 0) {
        g_hapPath = urls.firstObject.path;
        g_intercept = YES;
        HWSLog([NSString stringWithFormat:@"[UI] 已加载自定义包: %@", g_hapPath]);
        
        UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"成功" message:[NSString stringWithFormat:@"已挂载: %@\n全局劫持已开启，现在可以直接点击市场中的安装！", g_hapPath.lastPathComponent] preferredStyle:UIAlertControllerStyleAlert];
        [ac addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
        [[UIApplication sharedApplication].keyWindow.rootViewController presentViewController:ac animated:YES completion:nil];
    }
}
%end