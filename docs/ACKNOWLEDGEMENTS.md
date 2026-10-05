# 致谢

Luna 的实现在相当程度上立足于开源社区在「应用内加载」这个领域的公开积累。
以下项目贡献了关键技术思路，在此明确致谢。

## LiveContainer

**https://github.com/LiveContainer/LiveContainer** — Apache-2.0

Luna 最重要的技术参照。本文档中描述的整个加载思路——把 guest 二进制的
`filetype` 从 `MH_EXECUTE` 改写为 `MH_DYLIB`、重定位 `__PAGEZERO` 段、
注入 `LC_LOAD_DYLIB`、重绑 `_NSGetExecutablePath` 与 `NSBundle.mainBundle`、
最后 `dlopen` 并跳转 entry point——是 LiveContainer 团队在公开代码与文档中
系统化建立起来的。

Luna 具体借鉴的要点：

- 三步二进制改写的**目标值**（`__PAGEZERO` 的 `0xFFFFC000` / `0x4000`、
  `MH_DYLIB` 改写位置）
- 用多种子 Keychain 访问组做半隔离的思路（128 组的数量选择也来自此处）
- guest 应用共享宿主权限与 Entitlements 这一限制的完整表述
- 多任务虚拟窗口的产品形态

Luna 没有复制 LiveContainer 的代码。两者的实现是独立编写的：
Luna 采用了不同的模块划分、自研的 ZIP 解析与 SHA-256、
基于能力探测而非版本判断的加载器选择机制，以及不同的 UI 架构。
但设计思路上受益于 LiveContainer 的公开工作，这一点应当明确记录。

## litehook

**https://github.com/opa334/litehook** — MIT

轻量级函数重绑库，用于在运行时替换 `_NSGetExecutablePath` 等符号。
Luna 的 loader shim（见 `docs/LOADER.md`）计划使用同类机制。
`litehook` 在 arm64e 与共享缓存处理上的实践提供了重要参考。

## ZSign

**https://github.com/zhlynn/zsign** — MIT

跨平台 IPA 签名的 C++ 实现。当 JIT 不可用时，guest 二进制需要用宿主的
证书重新签名才能通过 Library Validation，ZSign 是这个环节的成熟方案。
LiveContainer 使用的是 Feather 维护的分支
（**https://github.com/khcrysalis/Feather**），其中包含针对容器场景的改动。

## 相关阅读

- **xpn — "Restoring Dyld Memory Loading"**
  https://blog.xpnsec.com/restoring-dyld-memory-loading/
  解释了 dyld 内存加载的机制，以及为什么 `MH_DYLIB` 改写能绕过
  Library Validation。

- **LinusHenze — CFastFind** (MIT)
  在 Mach-O 映像的内存中快速定位字节序列，用于定位需要 patch 的结构。

- **SideStore** — https://github.com/SideStore/SideStore
  设备端侧载与续签的实现，其 `minimuxer`（usbmuxd 的 iOS 重实现）
  与 Anisette 服务的用法对理解侧载生态很有帮助。

## Apple 文档

- `Mach-O Programming Topics` — 二进制格式规范
- `App Review Guidelines` 4.7 与 2.5.2 — 决定了 Luna 能做与不能做的边界

---

## 关于本项目的定位

上面这些项目共同积累的知识，本质上是**平台安全机制的对抗性研究**。
Luna 面向的是学习与实验场景，不是分发平台。

如果你在这个领域继续做研究，请同样遵守：
只在自己的设备上、只对你依法有权使用的软件、只用于安全研究与学习。

并请把发现的风险**公开写出来**——本节提到的每一份文档之所以有价值，
都是因为作者选择了公开而不是保留。
