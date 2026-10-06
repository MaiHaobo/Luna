# 架构

## 数据流

```
                    ┌──────────────┐
   .ipa  ──────────►│  staging/    │  复制进沙盒（原 URL 往往是
   (Files/分享/      └──────┬───────┘  另一个 app 的 security-scoped
    AirDrop)               │           bookmark，返回后即失效）
                           ▼
                    ┌──────────────┐
                    │ IPAArchive   │  自研 ZIP 解析
                    │  .extract()  │  · 校验每个条目路径，防 Zip-Slip
                    └──────┬───────┘  · stored / deflate 两种压缩
                           │          · 逐文件写出，不整包驻留内存
                           ▼
                    ┌──────────────┐
                    │ BundleInspec │  读 Info.plist + Mach-O
                    │    tor       │  · Bundle ID / 版本 / 最低系统
                    └──────┬───────┘  · 加密状态（LC_ENCRYPTION_INFO）
                           │          · Entitlements 声明的能力
                           ▼
                    ┌──────────────┐
                    │ GuestStore   │  写入 manifest（guests.json）
                    │   .import()  │  分配 Keychain 组索引
                    └──────┬───────┘  记录可执行文件 SHA-256
                           │
        ┌──────────────────┴──────────────────┐
        ▼                                     ▼
┌──────────────┐                     ┌──────────────┐
│ GuestData/   │                     │ Patched/     │
│  <uuid>/     │                     │  <uuid>/     │
│    X.app/    │                     │    X（已改写）│
│  data-<uuid>/│                     └──────────────┘
│   （可写）    │                      Derived data
└──────────────┘                      （排除备份）
  排除备份？否 —— guest 数据不可再生
```

## 分层与依赖方向

```
Features/          视图层。只依赖 Core 的公开接口。
  AppLibrary
  ContainerWindow
  Settings
      │
      ▼
Core/              无 UI 依赖，可在任意平台单测。
  Container   ──► MachO
  Loader      ──► MachO, Security
  Security    ──► （无依赖）
  MachO       ──► （无依赖）
```

`Core/MachO` 完全没有 `UIKit` 依赖。它只处理 `Data`，所以同一个模块
既能在 iOS 上跑，也能在 macOS 的测试目标里跑对拍验证。

## 关键设计决策

### 为什么自研 ZIP 而不是用依赖

`IPAArchive` 手写了 ZIP 中央目录解析与 DEFLATE 解压。三个理由：

1. **安全。** 从不可信来源解压归档是经典攻击面。自己写才能保证
   路径校验发生在**写出第一个字节之前**，而不是依赖第三方库的默认行为。
2. **可构建性。** CI runner 没有网络保证。零 SPM 依赖意味着构建不会因为
   拉不到包而失败。
3. **可测试性。** 同一份代码在 macOS 上跑单测，行为与设备上一致。

### 为什么加载是一个协议

加载 guest 是整个项目最脆弱的部分，依赖 dyld 的内部符号布局
（`dyld4::APIs::_NSGetExecutablePath`），Apple 在版本之间改过。
如果让这种脆弱性渗进每个视图，整个工程会变成一堆 `if canJIT` 分支。

所以加载面被压缩成一个协议 `GuestLoader`，两个实现：

- `PreviewLoader` —— 只用公开 API，永远可用。它真实执行解压、检查、改写全流程，
  只是不映射代码。
- `RuntimeLoader` —— 真实 `dlopen` 路径，被能力探测硬门控。

视图只问 `LoaderRegistry.active` 要一个加载器，自己不做能力判断。
运行时不可用时自动降级，并把**具体是哪个前置条件不满足**告诉用户。

### 能力探测是真的在探测

`LoaderCapabilities.probe()` 不是读版本号猜的：

- 实际 `mmap` 一页，尝试 `mprotect` 加上 `PROT_EXEC`，再 `munmap`。
  App Store 构建下这个调用会以 `EPERM` 失败。
- 用 `sysctl(KERN_PROC)` 读 `P_TRACED` 判断是否被调试。
- 检查 `/var/jb` 等路径的可写性判断特权环境。

这意味着诊断页显示的是**事实**，而不是对系统版本的推测。

### 为什么虚拟窗口用独立 UIWindow

guest 会话需要一个「像设备一样」的区域：自己的坐标系、自己的外观、
自己的关闭语义。如果做成子视图控制器嵌在主层级里，guest 自己的
`presentViewController` 会落进 Luna 的导航栈，Luna 的导航栏会盖在上面。

独立 `UIWindow` 给出干净的边界：关闭窗口就等于拆掉整个会话，一步到位。
全部使用公开 API。

### 为什么 patched 产物放在 Application Support

`GuestData/` 在 Documents 下，**不**排除备份 —— guest 的数据不可再生，
用户会期望它被备份。

`Patched/` 放在 Application Support 并排除备份 —— 它是派生产物，
随时可以从原 bundle 重新生成，没有备份价值，占了备份配额反而有害。

## 磁盘布局

```
Documents/Luna/
├── guests.json              清单
├── Staging/                 导入中转，导入完成后清理
├── GuestData/
│   ├── <uuid>/              guest bundle（只读）
│   └── data-<uuid>/         guest 可写数据
└── Logs/                    会话日志

Library/Application Support/Luna/Patched/
└── <uuid>/                  改写后的二进制（排除备份）
```

`guest.json` 里存的是**相对目录名**而不是绝对路径。
Luna 的容器路径在每次重装、每次系统更新后都会变，
存绝对路径会让所有记录失效。

## 启动流程

```
用户点击运行
    │
    ▼
GuestStore 校验 trustAcknowledged ──否──► 打开信任确认页
    │是
    ▼
LoaderRegistry.active 选加载器
    │
    ├─ RuntimeLoader 可用 ──► 创建会话、映射镜像、跳 entry point
    │
    └─ 否则 ──► PreviewLoader
                  │
                  ├─ 校验可执行文件存在
                  ├─ 校验非加密二进制
                  ├─ MachOPatcher.patch() ──► 生成修补报告
                  └─ onPresent 回调
                          │
                          ▼
                  SessionCoordinator 建 ContainerWindow
                  写入 lastLaunchedAt、patchSummary
                  检测到降级时，把阻断原因逐条写进会话日志
```
