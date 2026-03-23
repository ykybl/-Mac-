#import <UIKit/UIKit.h>
#import "fishhook.h"
#import <dlfcn.h>
#import <sys/sysctl.h>

// -------------------------------------------------------------------------------- //
// Part 1: Anti-Anti-Debug (Bypass ptrace and sysctl)
// -------------------------------------------------------------------------------- //

static int (*original_ptrace)(int request, pid_t pid, caddr_t addr, int data);

int my_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    if (request == 31) { // PT_DENY_ATTACH
        NSLog(@"[HWHealthSideload] Blocked ptrace(PT_DENY_ATTACH)");
        return 0;
    }
    return original_ptrace(request, pid, addr, data);
}

static int (*original_sysctl)(int * name, u_int namelen, void * info, size_t * infosize, void * newinfo, size_t newinfosize);

int my_sysctl(int * name, u_int namelen, void * info, size_t * infosize, void * newinfo, size_t newinfosize) {
    int ret = original_sysctl(name, namelen, info, infosize, newinfo, newinfosize);
    if (namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID && info) {
        struct kinfo_proc *kinfo = (struct kinfo_proc *)info;
        if ((kinfo->kp_proc.p_flag & P_TRACED) != 0) {
            NSLog(@"[HWHealthSideload] Blocked sysctl debugger check");
            kinfo->kp_proc.p_flag ^= P_TRACED; // Clear the flag
        }
    }
    return ret;
}

static void bypassAntiDebug() {
    rebind_symbols((struct rebinding[2]){
        {"ptrace", (void *)my_ptrace, (void **)&original_ptrace},
        {"sysctl", (void *)my_sysctl, (void **)&original_sysctl}
    }, 2);
    NSLog(@"[HWHealthSideload] Anti-Debug bypassed with fishhook!");
}

// -------------------------------------------------------------------------------- //
// Part 2: UI Injection & Sideload Handling
// -------------------------------------------------------------------------------- //

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
    // 右下角悬浮按钮
    CGFloat screenWidth = [UIScreen mainScreen].bounds.size.width;
    CGFloat screenHeight = [UIScreen mainScreen].bounds.size.height;
    self.floatBtn.frame = CGRectMake(screenWidth - 140, screenHeight - 150, 120, 50);
    self.floatBtn.backgroundColor = [UIColor systemRedColor];
    [self.floatBtn setTitle:@"🔥 侧载 HAP" forState:UIControlStateNormal];
    self.floatBtn.titleLabel.font = [UIFont boldSystemFontOfSize:16];
    [self.floatBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.floatBtn.layer.cornerRadius = 25;
    
    // 增加阴影，更明显
    self.floatBtn.layer.shadowColor = [UIColor blackColor].CGColor;
    self.floatBtn.layer.shadowOffset = CGSizeMake(0, 4);
    self.floatBtn.layer.shadowOpacity = 0.3;
    self.floatBtn.layer.zPosition = 9999;
    
    [self.floatBtn addTarget:self action:@selector(showPicker) forControlEvents:UIControlEventTouchUpInside];
    [window addSubview:self.floatBtn];
    
    // 增加拖拽功能
    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(handlePan:)];
    [self.floatBtn addGestureRecognizer:pan];
}

- (void)handlePan:(UIPanGestureRecognizer *)recognizer {
    CGPoint translation = [recognizer translationInView:self.floatBtn.superview];
    recognizer.view.center = CGPointMake(recognizer.view.center.x + translation.x,
                                         recognizer.view.center.y + translation.y);
    [recognizer setTranslation:CGPointZero inView:self.floatBtn.superview];
}

- (void)showPicker {
    UIDocumentPickerViewController *picker = [[UIDocumentPickerViewController alloc] initWithDocumentTypes:@[@"public.data", @"public.content", @"public.item"] inMode:UIDocumentPickerModeImport];
    picker.delegate = self;
    picker.allowsMultipleSelection = NO;
    picker.modalPresentationStyle = UIModalPresentationFullScreen;
    
    UIViewController *root = [UIApplication sharedApplication].keyWindow.rootViewController;
    while (root.presentedViewController) {
        root = root.presentedViewController;
    }
    [root presentViewController:picker animated:YES completion:nil];
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    NSURL *fileUrl = urls.firstObject;
    if (!fileUrl) return;
    
    BOOL accessing = [fileUrl startAccessingSecurityScopedResource];
    
    NSString *cachesDir = [NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES) firstObject];
    NSString *destPath = [cachesDir stringByAppendingPathComponent:fileUrl.lastPathComponent];
    
    NSFileManager *fm = [NSFileManager defaultManager];
    if ([fm fileExistsAtPath:destPath]) {
        [fm removeItemAtPath:destPath error:nil];
    }
    
    NSError *error = nil;
    [fm copyItemAtPath:fileUrl.path toPath:destPath error:&error];
    
    if (accessing) {
        [fileUrl stopAccessingSecurityScopedResource];
    }
    
    if (error) {
        NSLog(@"[HWHealthSideload] ❌ 搬运文件失败: %@", error);
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"失败" message:[NSString stringWithFormat:@"文件搬运失败: %@", error.localizedDescription] preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:nil]];
        [[[[UIApplication sharedApplication] keyWindow] rootViewController] presentViewController:alert animated:YES completion:nil];
        return;
    }
    
    NSLog(@"[HWHealthSideload] ✅ 文件成功中转至沙盒: %@", destPath);
    
    // ----------------------------------------------------- //
    // 调用官方底层 WiFi 发包接口
    // ----------------------------------------------------- //
    Class transferMgrClass = NSClassFromString(@"HuaweiWear.SHDWiFiTransferManager");
    if (transferMgrClass) {
        NSLog(@"[HWHealthSideload] 成功反射获取类: %@", transferMgrClass);
        // 这里需要后续根据 Frida 得到的单例调用方法来填充。
        // 目前先做个弹窗提示成功搬运！
        
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"沙盒中转成功" message:[NSString stringWithFormat:@"HAP 包已就绪:\n%@\n\n准备调用 SHDWiFiTransferManager...\n等待 Frida 参数验证完成后补全后续发包代码。", destPath] preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"去发包" style:UIAlertActionStyleDefault handler:nil]];
        
        UIViewController *root = [UIApplication sharedApplication].keyWindow.rootViewController;
        while (root.presentedViewController) {
            root = root.presentedViewController;
        }
        [root presentViewController:alert animated:YES completion:nil];
    } else {
        NSLog(@"[HWHealthSideload] ❌ 警告: 找不到 HuaweiWear.SHDWiFiTransferManager 类！");
    }
}

@end

// -------------------------------------------------------------------------------- //
// Part 3: Hook 注入点
// -------------------------------------------------------------------------------- //
%hook UIWindow

- (void)makeKeyAndVisible {
    %orig;
    [[HWHackSideloadHelper sharedInstance] addFloatButtonToWindow:self];
}

%end

// 进程启动初始化
%ctor {
    NSLog(@"[HWHealthSideload] 🚀 Tweak Loaded into Huawei Health.");
    bypassAntiDebug();
}
