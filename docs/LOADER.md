# 加载链路：已完成部分与剩余工作

这份文档说明「在 Luna 里真正跑起一个 guest」还差什么，以及为什么差这些。

## 已完成

### 1. 二进制改写引擎（`Core/MachO/MachOPatcher.swift`）

三个改写全部实现并可直接调用：

```
patch(sourceURL:outputURL:loaderPath:)
  ├─ rewriteFileType()      MH_EXECUTE(0x2) → MH_DYLIB(0x6)   头部偏移 +12
  ├─ relocatePageZero()     vmaddr → 0xFFFFC000                命令偏移 +24
  │                         vmsize → 0x4000                    命令偏移 +32
  └─ injectLoadDylib()      在 load command 区尾部零填充里
                            写入 dylib_command，回填 ncmds +1、
                            sizeofcmds += 新命令长度
```

注入前会校验零填充确实是零、且长度足够，否则抛
`MachOError.noRoomForLoadCommand`，而不是覆盖掉第一个 section。

### 2. 能力探测（`Core/Loader/GuestLoader.swift`）

`LoaderCapabilities.probe()` 实际尝试申请可写可执行内存，这是 JIT 权限的真实检验，
不是版本号推测。

### 3. 加载抽象与降级路径

`GuestLoader` 协议 + `PreviewLoader` / `RuntimeLoader` 两个实现 + `LoaderRegistry` 选择。
运行时不可用时自动降级，并把阻断原因逐条展示。

### 4. 端到端可观测

会话日志、诊断页、修补报告——每一层都能看到自己发生了什么。

## 剩余工作

### 步骤 1：装载 Shim（`LunaLoaderShim.dylib`）

需要在 `Core/Signing/` 下新增一个 dylib 目标，被注入的 `LC_LOAD_DYLIB`
指向它。它要做四件事：

```c
// 伪代码，实际是 dyld 回调 + 符号重绑
__attribute__((constructor))
static void luna_shim_init(void) {
    // 1. 重绑 _NSGetExecutablePath，让它返回 guest 的路径
    //    这样 guest 拿到的「我的可执行文件在哪」是它自己
    // 2. 覆盖 NSBundle.mainBundle 为 guest 的 bundle
    //    否则 guest 找不到自己的资源
    // 3. 找到 guest 的 entry point 并跳转
    //    guest 的 entry 会调用 UIApplicationMain，像正常 app 一样起来
    // 4. 处理 Keychain 组切换（切到 KeychainGroupAllocator 分配的组）
}
```

第 1 步和第 2 步需要在 dyld 完成重定位之后、guest 的 `+load` 之前执行。
时机靠 `__attribute__((constructor))` 的优先级控制。

**为什么这一步没做：** 它必须与真实的 `dlopen` 流程配合调试，而后者需要
JIT 环境。在没有真机 JIT 的条件下写出来的 shim 无法验证，交付一份未经验证
的私有 API 调用序列比交付一份明确的 TODO 更糟。

### 步骤 2：进程加载

在 `RuntimeLoader.launch()` 里替换当前的 `throw`：

```swift
func launch(_ guest: GuestApp) throws {
    guard isAvailable else { throw LoaderError.runtimeUnavailable(...) }

    // a. 确保二进制已改写
    let patched = guest.patchedExecutableURL
    guard FileManager.default.fileExists(atPath: patched.path) else {
        throw LoaderError.patchFailed("尚未改写")
    }

    // b. dlopen。RTLD_NOW 让符号解析错误立刻暴露，
    //    而不是留到调用时才崩。
    guard let handle = dlopen(patched.path, RTLD_NOW) else {
        throw LoaderError.runtimeUnavailable(String(cString: dlerror()))
    }

    // c. shim 的 constructor 会接管，跳到 guest entry point。
    //    控制权不会回到这里。
}
```

### 步骤 3：验证清单

在真机上跑通需要逐项确认：

| 检查项 | 方法 |
|---|---|
| 改写后 `filetype` 真的是 6 | `otool -hv <patched>` |
| `__PAGEZERO` 值正确 | `otool -l <patched>` 看 `vmaddr`/`vmsize` |
| 注入的 `LC_LOAD_DYLIB` 存在且路径正确 | `otool -l <patched>` 看 `LC_LOAD_DYLIB` |
| shim 能被 dyld 找到 | 确认路径是 `@executable_path/Frameworks/...` 且文件已打包 |
| `_NSGetExecutablePath` 重绑生效 | guest 内打日志看返回路径 |
| `NSBundle.mainBundle` 指向 guest | guest 内读 `bundlePath` |
| entry point 跳转正确 | 用 `lldb` 断在 guest 的入口 |

### 步骤 4：签名桥接（可选但推荐）

没有 JIT 时，guest 必须用 Luna 的证书重新签名才能通过 Library Validation。
这需要把 ZSign（或等价实现）作为 C++ 目标接进来。
`Core/Signing/` 目录已预留。

## 已知会失败的场景

| 场景 | 原因 |
|---|---|
| App Store 抓的原包 | `__TEXT` 段加密，映射后第一条指令就 fault |
| 带 App Extension 的 app | 扩展无法注册，主包可能因此拒绝启动 |
| 依赖 `get-task-allow` 的 app | 调试类工具在重签名后失去该 entitlement |
| arm64e 二进制 | 指针认证机制未验证 |
| iOS 26+ 无 JIT 环境 | 平台层面禁止可执行内存 |

## 开发顺序建议

1. 先用**自己编译的 hello-world iOS app** 做 guest，不要一上来就试真实应用
2. 在 TrollStore 环境（或有 JIT 的调试构建）下验证改写后的二进制能被 `dlopen`
3. 再加 shim，先只做 `_NSGetExecutablePath` 重绑，跑通再加重绑 `NSBundle`
4. 最后接真实应用，逐个处理兼容性问题

第 1 步可以在没有 JIT 的普通设备上完成 —— 改写本身不需要 JIT，
只有映射需要。所以**改写引擎可以先独立验证**，这正是能力探测和预览模式
存在的意义。
