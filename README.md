# Luna

在 iOS 应用内部解压、检查并准备运行第三方应用的容器。

> **先读这一段。** Luna 无法上架 App Store —— 它违反审核指南 2.5.2（下载并执行代码）。
> 它只能以「开源源码 + CI 产出的未签名 IPA」形式存在，由你自己侧载到自己的设备。
> 容器内的所有应用与 Luna 共享同一进程、同一 UID，Luna **无法**验证第三方 IPA 的真实性。
> 请只导入你自己信任的来源。完整披露见 [SECURITY.md](SECURITY.md)。

---

## 这是什么

Luna 是一个**应用启动器**，不是模拟器，也不是虚拟机。它做的是：

1. 把一个 `.ipa` 解压到 Luna 自己的沙盒目录（**不安装到系统**）
2. 解析里面 `.app` 的 `Info.plist` 与 Mach-O 二进制
3. 完成加载一个非可执行映像所需的二进制改写
4. 在应用内的浮层窗口中承载会话

因为 guest 从未注册到系统，它们不占用 App ID，也不受「免费 Apple ID 只能装 3 个应用」的限制——
一个 Luna 可以装任意多个。

## 为什么需要二进制改写

iOS 不允许应用加载别人的可执行文件。`dlopen()` 会直接拒绝 `MH_EXECUTE` 类型的映像，
这是内核层面的规则，没有通融余地。唯一能走通的路是把 guest 变成**动态库**再加载：

| 步骤 | 操作 | 原因 |
|---|---|---|
| 1 | 注入 `LC_LOAD_DYLIB` | 让 dyld 在映射 guest 时先跑我们的装载代码 |
| 2 | `__PAGEZERO` 段 `vmaddr → 0xFFFFC000`、`vmsize → 0x4000` | guest 预留的零页会与 Luna 自己的地址空间冲突，缩成一个 16 KB 保护页避让 |
| 3 | `filetype` 从 `MH_EXECUTE` 改为 `MH_DYLIB` | `dlopen()` 只接受后者 |

这三步都在 `Core/MachO/MachOPatcher.swift` 里，全部基于公开的 Mach-O 格式规范，
只操作 Luna 沙盒内的一份副本，不碰原始 IPA。

**还需要什么：** 把改写后的映像真正映射进内存，需要「可写且可执行」的内存页，
也就是 JIT 权限。App Store 分发的应用永远拿不到这个权限。
`Core/Loader/GuestLoader.swift` 里的能力探测会实际尝试 `mmap` + `mprotect`，
失败时如实告诉你原因，而不是崩掉。

## 现在能跑通什么

| 能力 | 状态 |
|---|---|
| IPA 导入（自研 ZIP 解析，含 Zip-Slip 防护） | 可用 |
| Bundle 检查（Bundle ID、版本、加密状态、Entitlements、最低系统版本） | 可用 |
| Mach-O 解析（fat/thin、load commands、段、依赖库） | 可用 |
| 二进制改写（三步全流程） | 可用 |
| Keychain 组分配（128 组，按 Bundle ID 确定性分配） | 可用 |
| 应用内浮层虚拟窗口 | 可用 |
| 容器管理与存储统计 | 可用 |
| 损坏 IPA 的静默失败防护 | 可用 |
| **代码映射（`dlopen` + entry point 跳转）** | **需要 JIT，未满足前置条件时停在预览模式** |

预览模式不是占位符。它会真实执行解压、检查、改写全流程，并把真实的修补报告
（文件类型变化、`__PAGEZERO` 前后值、注入路径）展示出来。
唯一省略的是最后一步映射。

## 构建

本地需要 macOS + Xcode 16：

```bash
xcodebuild archive \
  -project Luna.xcodeproj \
  -scheme Luna \
  -configuration Release \
  -destination 'generic/platform=iOS' \
  -archivePath build/Luna.xcarchive \
  CODE_SIGNING_ALLOWED=NO CODE_SIGN_IDENTITY="" DEVELOPMENT_TEAM=""
```

或者直接推到 GitHub，让 Actions 出包。工作流会：

1. 校验工程结构完整、每个 `.swift` 文件都在 Sources 编译阶段里
2. 检查没有误提交的证书或 Team ID
3. 用 `CODE_SIGNING_ALLOWED=NO` 构建
4. 校验产物是 arm64、验证 entitlement 数量
5. 打成未签名 IPA 并发布到 `nightly` release

产物在 Actions 的 **Artifacts** 里，或在 [nightly release](../../releases/tag/nightly)。

## 安装

未签名 IPA 需要你自己签名。可选的路径和各自的代价：

| 方式 | 前置条件 | 说明 |
|---|---|---|
| **TrollStore** | 设备有 CoreTrust 漏洞（大致 iOS 14–17.0） | 永久签名不过期，**也是唯一能解锁 JIT 的路径** |
| **SideStore / AltStore** | 需要电脑装一次 | 免费 Apple ID，7 天过期，需续签 |
| **Sideloadly / iLoader** | 需要电脑 | 最快的一次性安装 |
| **付费开发者证书** | $99/年 | 1 年有效期 |

要让**运行时加载**真正工作，签名必须带 `get-task-allow`（即 JIT 权限）。
免费和付费的**发布**证书都拿不到这个权限——所以现实中只有 TrollStore
或调试签名的发展构建能解锁它。没有 JIT 时 Luna 依然完整可用，只是停在预览模式。

## 工程结构

```
Luna/
├── Luna/
│   ├── App/                     应用入口、Tab 路由
│   ├── Core/
│   │   ├── MachO/               二进制解析与改写引擎
│   │   │   ├── MachODefines.swift     Mach-O 常量与字节读取
│   │   │   ├── MachOImage.swift       只读分析：fat/thin、load commands、段
│   │   │   └── MachOPatcher.swift     三步改写引擎
│   │   ├── Container/           容器层
│   │   │   ├── IPAArchive.swift       自研 ZIP 解析与安全解压
│   │   │   ├── BundleInspector.swift  Info.plist / Mach-O 检查
│   │   │   ├── GuestApp.swift         数据模型与磁盘布局
│   │   │   └── GuestStore.swift       清单管理与导入流水线
│   │   ├── Loader/
│   │   │   └── GuestLoader.swift      加载协议、能力探测、预览/运行时两个实现
│   │   └── Security/
│   │       ├── KeychainGroupAllocator.swift
│   │       └── SHA256.swift
│   └── Features/
│       ├── AppLibrary/          应用列表与详情
│       ├── ContainerWindow/     浮层虚拟窗口、会话协调、诊断页
│       └── Settings/            存储统计、合规说明
├── .github/workflows/build-ipa.yml
└── docs/
    ├── ARCHITECTURE.md          架构与数据流
    ├── LOADER.md                加载链路的剩余工作
    └── ACKNOWLEDGEMENTS.md      技术致谢
```

## 已知限制

这些不是待办事项，是架构的固有边界：

- **guest 之间没有沙盒隔离。** 所有 guest 在同一进程内运行，一个 guest 能读另一个 guest 的数据。
- **Entitlements 不传递。** guest 声明的推送、HealthKit、通用链接等能力全部失效。
- **App 权限全局共享。** 相机/相册/麦克风授权对整个进程生效。
- **扩展不支持。** guest 的 App Extension 无法注册。
- **一次一个会话。** 同时只能运行一个 guest。
- **arm64e 未验证。** 建议使用 arm64 二进制。
- **加密二进制无法加载。** 从 App Store 抓的原包，`__TEXT` 段是加密的，用不了。

## 许可

Apache-2.0。致谢见 [docs/ACKNOWLEDGEMENTS.md](docs/ACKNOWLEDGEMENTS.md)。
