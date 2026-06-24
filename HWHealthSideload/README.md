# HWHealthSideload — 华为手表 HarmonyOS 应用侧加载工具

> **项目目标**：通过 Theos Tweak 注入 Huawei Health iOS App，绕过手机端和手表端的签名验证，实现向 HarmonyOS 手表侧加载自签名 `.hap` 应用。

---

## 一、项目概述

### 1.1 核心问题

华为手表应用只能通过官方华为应用市场安装。本项目通过在 iOS 端的 Huawei Health App 中注入 Tweak，劫持应用市场的安装流程：当用户在市场中点击"安装"某个应用时，实际传输到手表的是用户事先选定的自定义 `.hap` 文件。

### 1.2 工作原理（简要流程）

```
用户选择 .hap 文件 → 开启劫持 → 在应用市场点击安装任意应用
    ↓
手机端下载官方 .bin 文件 → [Tweak 拦截] → 替换为用户的 .hap
    ↓
通过 WiFi P2P 传输到手表 → [Tweak 伪装校验和/签名/大小]
    ↓
手表安装（需绕过手表端 DRM 校验）
```

### 1.3 当前版本与状态

- **Tweak 版本**：v4.54（探针增强版）
- **UI 版本**：v4.53
- **包名**：`com.geeker.hwhealthsideload`
- **目标进程**：`HuaweiWear`（即 Huawei Health App）
- **目标 Bundle ID**：`com.huawei.iossporthealth`
- **当前状态**：数据传输流程已打通，手表端 DRM 签名校验仍在攻克中

---

## 二、项目结构

```
HuaweiHealth_iOS_Mod/
├── HWHealthSideload/          ← Tweak 主目录
│   ├── Tweak.xm               ← 核心代码（1344 行，Objective-C + Logos 语法）
│   ├── Makefile                ← Theos 编译配置
│   ├── control                 ← Debian 包元数据
│   ├── HWHealthSideload.plist  ← 注入过滤器（仅注入 com.huawei.iossporthealth）
│   ├── fishhook.c / .h         ← Facebook fishhook 库（用于 Hook C 函数）
│   ├── Bug.md / Bug_Ai.md      ← Bug 追踪（子目录级）
│   ├── Task.md / Task_Ai.md    ← 任务追踪（子目录级）
│   └── .github/                ← GitHub 配置
├── Bug.md / Bug_Ai.md          ← Bug 追踪（项目级）
├── Task.md / Task_Ai.md        ← 任务追踪（项目级）
├── Test.md                     ← 早期研究笔记与攻击策略文档（~610 行）
└── 归档/                       ← 历史版本归档
```

### 2.1 编译配置（Makefile）

```makefile
TARGET := iphone:clang:latest:14.0
INSTALL_TARGET_PROCESSES = HuaweiWear
ARCHS = arm64

TWEAK_NAME = HWHealthSideload
HWHealthSideload_FILES = Tweak.xm fishhook.c
HWHealthSideload_CFLAGS = -fobjc-arc -Wno-deprecated-declarations
HWHealthSideload_FRAMEWORKS = UIKit Foundation Security
```

### 2.2 注入过滤器（plist）

仅注入 Bundle ID 为 `com.huawei.iossporthealth` 的进程。

---

## 三、代码架构（Tweak.xm）

整个 Tweak 按功能分为 6 个 Part，外加一个 `%group SideloadHooks`。

### 3.1 Part 0：日志系统

| 组件 | 说明 |
|------|------|
| `HWSLog(msg)` | 全局日志函数，带时间戳（`HH:mm:ss.SSS`） |
| `g_logs` | `NSMutableArray` 环形缓冲，上限 5000 条 |
| 日志导出 | 通过 UI 按钮复制最新 300 条到剪贴板 |

### 3.2 Part 0.5：工具函数

| 函数 | 说明 |
|------|------|
| `fileSHA256(path)` | 计算文件 SHA-256 |
| `fileMD5(path)` | 计算文件 MD5 |
| `fileSHA1(path)` | 计算文件 SHA-1 |

### 3.3 Part 1：环境检测绕过（fishhook）

通过 fishhook 在 `%ctor` 中绑定，拦截 Security 框架的 C 函数：

| Hook 目标 | 作用 |
|-----------|------|
| `SecCodeCheckValidity` | 强制返回 `errSecSuccess`，绕过代码签名校验 |
| `SecTrustEvaluate` | 强制 `*result = kSecTrustResultProceed`，绕过旧版证书验证 |
| `SecTrustEvaluateWithError` | 强制返回 `YES` + `*error = NULL`，绕过新版证书验证 |

### 3.4 Part 2：网络层 Bundle ID 注入

所有发往外部的 HTTP 请求中，将实际 Bundle ID 替换为官方 `com.huawei.iossporthealth`，欺骗服务器鉴权。

| Hook 目标 | 覆盖范围 |
|-----------|---------|
| `NSMutableURLRequest initWithURL:` | URL 替换 |
| `NSMutableURLRequest setURL:` | URL Setter 替换 |
| `setValue:forHTTPHeaderField:` | 请求头替换 |
| `addValue:forHTTPHeaderField:` | 请求头追加替换 |
| `setAllHTTPHeaderFields:` | 全量请求头替换 |
| `setHTTPBody:` | 请求体替换（<64KB 的 UTF-8 文本） |

**核心函数**：`sanitizeString(str)` — 安全替换字符串中的 Bundle ID。

### 3.5 Part 3：文件系统拦截层

| Hook 目标 | 作用 |
|-----------|------|
| `NSFileManager copyItemAtPath:` / `copyItemAtURL:` | 监控文件复制 |
| `NSFileManager moveItemAtPath:` / `moveItemAtURL:` | 监控文件移动 + 触发全宇宙扫描 |
| `NSData writeToFile:` | 劫持 `.hap/.pkg/.bin` 写入，替换为自定义 HAP |
| `NSData dataWithContentsOfFile:` / `dataWithContentsOfURL:` | 劫持文件读取 |
| `NSData initWithContentsOfURL:options:error:` | 劫持初始化读取 |
| `NSFileManager attributesOfItemAtPath:` | 伪装文件大小（.bin → HAP 大小） |
| `NSFileHandle fileHandleForReadingAtPath:` | 底层流替换 |
| `NSInputStream inputStreamWithFileAtPath:` / `initWithFileAtPath:` | 输入流替换 |

**判断函数**：`isTargetExt(path)` — 路径中包含 `.hap`、`.pkg` 或 `.bin` 即为目标。

### 3.6 Part 3.5：动态传输 Hook（`%group SideloadHooks`）

这是侧加载的**核心数据替换层**，运行时动态绑定华为内部类。

#### 关键 Hook 类

| 类名 | 方法 | 作用 |
|------|------|------|
| `SHDWiFiCommandSend` | `+sendNotifiDeviceStartTransferFileWithFileInfo:` | 拦截传输启动指令 |
| `SHDWiFiCommandSend` | `+sendNotifiDeviceTransferFileInfoWithFileInfo:` | 拦截传输文件信息 |
| `SHDWiFiCommandSend` | `+sendTransferFileInfo:` | 拦截传输信息 |
| `SHDWiFiTransferManager` | `-transferFileInfo:callback:` | 拦截传输回调 |
| `SHWatchAppStoreManager` | `-pushFileProgress:` | 监控推送进度 |
| `WSSCommonFileMgr` | `-sendFileContentToDeviceWithDataInfo:` | 监控数据分包发送 |
| `WSSCommonFileMgr` | `-sendFileCheckMode:fileid:offsetSize:` | 监控校验模式（⚠️ **不得修改 checkMode！手表需要 mode=3**） |
| `WSSCommonFileMgr` | `-recevicedPushFileData:commondID:deviceIdentify:` | 监控手表返回数据 |
| `WSSCommonFileMgr` | `-sendFileTransferNegotiate:errorCode:` | 监控协商结果 |
| `WSSCommonFileMgr` | `-finishPushFileWithType:` | **传输完成后立即关闭 `g_intercept`**（v4.53 关键修复） |
| `WSSCommonFileMgrSendUtil` | `+sendFileContentToDeviceWithDataInfo:fileData:deviceInfo:selectIndexArray:negotiate:` | **核心数据替换点**（v4.54） |
| `WSSCommonFileMgrSendUtil` | `+sendFileCheckMode:deviceInfo:fileInfo:fileid:offsetSize:` | 校验模式（直接放行） |
| `WSSCommonFileMgrSendUtil` | `+sendFileTransferNegotiate:deviceInfo:errorCode:` | 协商回调 |
| `NSNotificationCenter` | `-postNotificationName:object:userInfo:` | 拦截 `notif_pushfile_update_status` 通知 |

#### 核心数据替换逻辑（`WSSCommonFileMgrSendUtil`）

```
第一包到达时：
  1. 完整 dump dataInfo / negotiate / deviceInfo / selectIndexArray 的属性
  2. 自动发现 offset 字段名（探针）
  3. 记录块大小 g_hapChunkSize
  4. 打印 fileData 前 128 字节 HEX

后续每包：
  1. 从 dataInfo 获取 offset（或用块序号推算）
  2. 从 g_hapFileHandle 对应偏移读取相同大小的数据
  3. 如果最后一块不足，用 0x00 补齐
  4. 调用 %orig 传入替换后的数据
```

#### 辅助函数

| 函数 | 作用 |
|------|------|
| `dumpObjectProperties(obj, tag)` | 反射 dump 对象的所有 `@property` |
| `replacePathAndSizeInFileInfo(info)` | 动态替换 FileInfo 中的路径、大小、校验和、Bundle ID |

### 3.7 JSON 安装指令劫持

| Hook 目标 | 作用 |
|-----------|------|
| `NSJSONSerialization JSONObjectWithData:options:error:` | 拦截 JSON 解析，精准命中安装指令 |

**匹配条件**：字典中同时包含 `packageName`/`package` 和 `hashValue`/`hash`/`sha256`/`digest`。

**递归替换字段**：

| 字段 | 替换值 |
|------|--------|
| `size` / `filesize` / `apksize` / `appsize` | HAP 文件实际大小 |
| `hash` / `sha256` / `digest` / `hashvalue` | 根据长度自动选择 MD5(32) / SHA1(40) / SHA256(64) |
| `package` / `packagename` / `bundle` | 用户设定的 `g_hapBundleID` |
| `installType` | 强制改为 `1`（开发者/更新模式） |
| `sign` / `signature` / `cert` | 清空（`""`） |

**重入保护**：`g_jsonHookActive` 标志防止 Hook 内 JSON 序列化递归。

### 3.8 NSURLSession 探针

拦截 `dataTaskWithRequest:completionHandler:`，捕获包含 `appgallery`/`watchapp`/`install`/`download` 等关键词的 API 响应，打印前 2000 字符用于协议分析。

### 3.9 Part 4：运行时探测

| 函数 | 作用 |
|------|------|
| `searchClasses(keywords)` | 按关键词搜索 ObjC 运行时所有类 |
| `dumpTargetClasses()` | Dump 预定义目标类的全部实例方法和类方法 |

**预定义目标类**：
- `HuaweiWear.SHWatchAppStoreManager`
- `SHSports.SHNDownloader`
- `HuaweiWear.SHHapVersionRequest`
- `WatchFaceSDK.WFTrialThemesInstallObserver`
- `HuaweiWear.SHWatchAppStoreSetModel`
- `AppProtection.APAppInstallationManager`
- `SHSports.RoadNetworkGaoDeDownloader`

### 3.10 Part 5：UI 系统

`HWSideloadUI` 单例提供浮动按钮和操作菜单：

| 功能 | 说明 |
|------|------|
| 浮动按钮 | 红色圆角按钮，支持拖拽，标题随状态切换（"侧载"/"开启"） |
| 选择 .hap 文件 | `UIDocumentPickerViewController`，复制到 Caches 目录 |
| 输入 Bundle ID | 用户可指定自定义包名（可选） |
| 开启/关闭劫持 | 切换 `g_intercept`，开启时清空日志缓冲 |
| 查看日志 | 复制最新 300 条日志到剪贴板 |

### 3.11 Part 6：初始化（`%ctor`）

```
1. 保存真实 Bundle ID（g_realBundleId）
2. %init(_ungrouped) — 初始化所有非分组 Hook
3. 在主队列中：
   a. fishhook 绑定 SecCodeCheckValidity + SecTrustEvaluate + SecTrustEvaluateWithError
   b. 注册 UIApplicationDidBecomeActiveNotification → 附加 UI
   c. 动态获取 SHDWiFiTransferManager / SHWatchAppStoreManager / SHDWiFiCommandSend 类句柄
   d. %init(SideloadHooks) — 初始化分组 Hook（传入动态类）
```

---

## 四、全局变量速查

| 变量 | 类型 | 作用 |
|------|------|------|
| `g_hapPath` | `NSString *` | 用户选择的 HAP 文件路径（Caches 目录副本） |
| `g_hapBundleID` | `NSString *` | 用户指定的自定义 Bundle ID |
| `g_hapChecksum` | `NSString *` | HAP 的 SHA-256 |
| `g_hapMD5` | `NSString *` | HAP 的 MD5 |
| `g_hapSHA1` | `NSString *` | HAP 的 SHA-1 |
| `g_intercept` | `BOOL` | 劫持总开关 |
| `g_hapFileHandle` | `NSFileHandle *` | HAP 文件的读取句柄（用于分块替换） |
| `g_hapFileSize` | `long long` | HAP 文件大小 |
| `g_hapChunkSize` | `NSInteger` | 从第一包探针获取的块大小 |
| `g_hapOffsetKey` | `NSString *` | 探针自动发现的 offset 属性名 |
| `g_realBundleId` | `NSString *` | 应用的真实 Bundle ID（用于网络层替换） |
| `g_logs` | `NSMutableArray *` | 日志环形缓冲 |
| `g_jsonHookActive` | `BOOL` | JSON Hook 重入保护锁 |
| `g_utilChunkCount` | `NSInteger` | 数据块计数器 |

---

## 五、版本历史

| 版本 | 关键变更 |
|------|---------|
| v4.18 | 确认 `alisec_crypto_dec` 在读取 `.bin` 时解密失败 |
| v4.19 | 实现全宇宙方法扫描器，定位到 `SHDWiFiTransferManager` |
| v4.20 | 深度 Hook `transferFileInfo:` 获取协议对象结构 |
| v4.53 | **关键修复**：传输完成后立即关闭 `g_intercept`，防止后续系统文件（如腾讯通知图标包 `ab08691c_comtencentxin_1.bin`）被错误替换 |
| v4.54 | 探针增强：第一包完整协议分析、自动发现 offset 字段、分块数据替换逻辑 |

---

## 六、已知 Bug 与当前状态

### 6.1 项目级 Bug

| ID | 模块 | 问题 | 状态 |
|:---|:-----|:-----|:----:|
| 001 | 侧载劫持 | 开启劫持后安装的仍是原版软件 | 🟡 待验证 |
| 002 | 环境检测绕过 | 提示业务受限制（Bundle ID 验证失败） | 🟡 待验证 |
| 003 | 稳定性 | 应用启动闪退且底部功能栏消失 | 🟡 待验证 |

### 6.2 子目录级 Bug

| ID | 模块 | 问题 | 状态 |
|:---|:-----|:-----|:----:|
| 001 | DRM | `alisec_crypto_dec` 校验失败导致流程中断 | 🟡 待验证 |
| 002 | 传输层 | 需要在校验后、传输前找到 Hook 点进行数据注入 | 🟡 处理中 |

### 6.3 技术细节

- **Bug-001（劫持失败）**：`moveItemAtURL:` 和 `writeToFile:` 钩子失效。已加入 `NSData init` 读取拦截和 `NSURLSession` 底层劫持。
- **Bug-002（业务受限）**：`NSBundle bundleIdentifier` 伪装钩子误加 `if (g_intercept)` 条件，导致启动时华为 SDK 鉴权失败。已移除前置条件。
- **Bug-003（闪退）**：`SecCodeCopySelf` 钩子返回 0 但未保证指针赋值；`infoDictionary` 全量 Mock 丢失系统元数据。已移除 `SecCodeCopySelf`，改用 `dladdr` + 精准伪装 `CFBundleIdentifier`。

---

## 七、任务看板

### 已完成

| ID | 模块 | 功能 |
|:---|:-----|:-----|
| T001 | 基础框架 | 侧载开关 UI 与日志系统 |
| T002 | 网络层 | 绕过 Bundle ID 鉴权限制 |

### 进行中

| ID | 模块 | 功能 | 优先级 |
|:---|:-----|:-----|:------:|
| T003 | 运行时分析 | 定位最终传输接口（WiFi/BLE） | 高 |

### 待处理

| ID | 模块 | 功能 | 优先级 |
|:---|:-----|:-----|:------:|
| T004 | 协议层 | 拦截并替换蓝牙/WiFi P2P 传输数据流 | 高 |
| T005 | 协议层 | 破解 HRP/LMT 协议中的文件包头校验 | 中 |

---

## 八、开发环境与构建

### 8.1 环境要求

- **Theos**：最新版（[theos/theos](https://github.com/theos/theos)）
- **目标 SDK**：iOS 14.0+
- **架构**：arm64
- **依赖**：`mobilesubstrate`

### 8.2 构建命令

```bash
cd HWHealthSideload
make clean && make package
```

### 8.3 安装方式

使用 nb全能助手（或类似工具）将生成的 `.deb` 注入到已砸壳的 Huawei Health IPA 中，重签名后安装。

---

## 九、关键注意事项（接手必读）

### ⚠️ 绝对不能做的事

1. **不要修改 `sendFileCheckMode:` 的 `checkMode` 参数**
   - 手表需要 `mode=3`，改为 0 会导致 `errorCode=140001`
   
2. **不要在 `finishPushFileWithType:` 之后保持 `g_intercept = YES`**
   - 传输完成后手表会立即请求其他系统文件（如腾讯通知图标包），如果不关闭会导致这些文件也被替换，安装必然失败

3. **不要在 `NSJSONSerialization` Hook 内部再调用 JSON 序列化**
   - 会导致无限递归，必须使用 `g_jsonHookActive` 重入锁

4. **不要对所有 JSON 都执行替换**
   - 必须用 `isInstallCommandDict()` + `containsInstallCommand()` 精准匹配安装指令

### ✅ 核心开发策略

1. **当前策略**：依赖底层 Hook 进行摸索。如果劫持未生效，用户可在应用内通过按钮将日志导出到剪贴板，用以针对性开发。
2. **日志驱动**：所有关键路径都有 `HWSLog()` 埋点，通过日志分析华为内部协议结构。
3. **探针优先**：v4.54 的第一包探针会自动 dump 所有协议对象属性、自动发现 offset 字段名，无需硬编码。

### 🔑 已知的华为内部类与协议

| 类/组件 | 用途 |
|---------|------|
| `SHDWiFiTransferManager` | WiFi P2P 传输管理器 |
| `SHDWiFiCommandSend` | WiFi 指令发送 |
| `SHWatchAppStoreManager` | 手表应用市场管理 |
| `WSSCommonFileMgr` | 通用文件管理器（含传输协商） |
| `WSSCommonFileMgrSendUtil` | 文件发送工具类（含数据块发送） |
| `AliSec_Crypto` | 阿里安全加密库（位于 `HuaweiWear.framework`） |
| `notif_pushfile_update_status` | 文件推送状态通知名 |

---

## 十、早期研究记录

`Test.md`（610 行）包含了项目初期的完整攻防策略分析，涵盖：

1. **华为 App 环境安全检测机制分析**（签名校验、Bundle ID 校验、动态库注入检测、反调试、文件系统检查）
2. **六大攻击点详细代码模板**（SecCode、ptrace/sysctl、_dyld 隐藏、Bundle ID 伪装、文件系统隐藏、网络调试）
3. **dylib_dobby_hook 框架集成方案**
4. **最小化测试路线**
5. **完整的 `HuaweiHealthHack.m` 模板**（基于 Dobby 框架）

---

## 十一、协作约定

- 所有文档、注释、提交信息使用**简体中文**
- Bug 追踪使用 `Bug.md`（面向用户）+ `Bug_Ai.md`（面向技术），状态标记：🔴 待处理 / 🟡 处理中 / 🟢 已处理
- 任务追踪使用 `Task.md` + `Task_Ai.md`
- AI 不得自行将 Bug 标记为已解决（🟢），必须等待用户确认
- 修改代码后必须重新编译验证
