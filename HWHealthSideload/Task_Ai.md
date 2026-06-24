# Huawei Health iOS Sideloading AI Data

## 🚀 架构设计
- **注入方式**: 通过 Theos 开发的 Dylib 注入 `HuaweiWear` 进程。
- **劫持点**: 
    1. `NSMutableURLRequest` (鉴权欺骗)
    2. `NSFileManager`/`NSData` (文件系统拦截)
    3. `SHDWiFiTransferManager` (待验证，P2P 传输层)

## 🔗 数据关联
- **Bundle ID**: `com.huawei.iossporthealth` (官方固定值)
- **校验库**: `AliSec_Crypto` (位于 `HuaweiWear.framework`)

## 📝 实现细节与记录
- **v4.18**: 确认了 `alisec_crypto_dec` 在读取 `.bin` 时的解密失败。
- **v4.19**: 实现了全宇宙方法扫描器，定位到了 `SHDWiFiTransferManager`。
- **v4.20 计划**: 深度 Hook `transferFileInfo:` 获取协议对象结构。
