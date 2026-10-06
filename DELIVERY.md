# Luna — 液态玻璃迁移完成

仓库：**https://github.com/MaiHaobo/Luna**
产物：**https://github.com/MaiHaobo/Luna/releases/tag/nightly**

---

## 这一轮做了什么

把界面从自定义的「模拟玻璃」改成 iOS 26 的原生 Liquid Glass，
并且把最低系统从 iOS 17 提到 iOS 26。

### 两个决策（你确认的）

**1. 只支持 iOS 26+，不做降级分支**

部署目标直接提到 26.0，`glassEffect` 当普通 API 用，不写 `#available`。
代价是放弃 iOS 17–25。以后若要下探，只改 `Luna/Support/LunaGlass.swift` 一个文件。

**2. 玻璃只上导航层，内容层保持不透明**

你最初选「全应用重做」，在追问后改为**严格遵循官方规范**。
原因不是保守而是可读性：玻璃会**采样背景**，铺在列表行上会让文字
随背后内容滚动而明暗抖动。Apple HIG 明确不建议在内容层使用。

| 位置 | 处理 |
| --- | --- |
| 容器窗口卡片 | ✅ 深色玻璃 |
| 导入进度横幅 | ✅ 玻璃 |
| 标签栏 / 导航栏 / Sheet | ✅ 系统自动，无需改 |
| 列表行、设置项、诊断项 | ❌ 保持不透明 |
| 访客画布（纯黑） | ❌ 保持不透明 |

---

## 三个阶段的 CI 结果

分三阶段不是为了渐进上线，是为了**隔离故障**——刚跳到全新 SDK，
同时改视图会让「API 写错了」和「视图改错了」混在同一个报错里。

| 阶段 | 内容 | 目的 | CI |
| --- | --- | --- | --- |
| 1 | 部署目标 → 26.0，runner → `macos-26` | 旧代码能否在新 SDK 编译 | ✅ run #6 |
| 2 | 新增 `LunaGlass.swift`，接线 pbxproj，**无人调用** | 单独验证 API 签名 | ✅ run #8 |
| 3 | 改写两个视图 | 应用材质 | ✅ run #9 |
| 合并 | `main` 分支自动发布 | 产出 IPA | ✅ run #10 |

阶段 2 是关键设计：空跑一次编译，把「这个 API 是不是这么写」单独问出来。
它绿了，阶段 3 的任何报错就一定是视图的问题。

---

## 验证过的 API（来自 Apple 官方文档，非推断）

```swift
nonisolated func glassEffect(
    _ glass: Glass = .regular,
    in shape: some Shape = DefaultGlassEffectShape()
) -> some View                    // iOS 26.0+
```

- `Glass`：`.regular` / `.clear` / `.identity`
- `Glass.tint(Color?)` —— 参数是**可选** `Color?`
- `Glass.interactive(Bool)`
- `Shape`：`.capsule`、`.circle`、`.rect(cornerRadius:style:)`

**顺序规则**：`glassEffect` 必须在其他外观修饰符**之后**。
顺序反了的现象是圆角跑进内容里，而不是报错。

---

## 踩到的两个坑（都写进注释了）

**1. 不透明底必须删掉，不是改成半透明**

玻璃靠采样背景工作。背景被不透明色盖住时，**玻璃会渲染成一块平的灰方块**。
原本的 `secondarySystemBackground` 填充因此必须移除。`clipShape` 同理删除——
`glassEffect` 自己按圆角裁剪，再裁一次会切掉材质的高光边。

**2. 动态色在深色玻璃上会失效**

删掉不透明底后，标题栏/状态栏/日志面板下面不再是「系统背景色」
而是「深色玻璃」，于是 `.primary` / `.secondary` 这些**随外观解析**的
动态色在浅色模式下解析成接近黑色，压在深色玻璃上看不清。

这些位置的文字改成显式白色，按层级递减透明度。
`GuestCanvas` 内部**一字未改**——它本身叠在纯黑矩形上，行为不变。

---

## 产物核对

下载自 nightly Release 的 `Luna-unsigned.ipa`（227,646 字节）：

| 字段 | 值 |
| --- | --- |
| `MinimumOSVersion` | **26.0** ✅（此前 17.0） |
| `DTSDKName` | **iphoneos26.5** |
| `DTPlatformVersion` | 26.5 |
| Bundle ID | `com.luna.container` |
| Mach-O | arm64 `MH_EXECUTE`，43 条 load command |
| sha256 | `408f13c84c33f60ea37edc4cb79b8e744d5d3db92880e92d730149f77c7f696f` |

CI 用 Xcode **26.6**（`macos-26` runner）编译，16/16 步全过。

---

## 遗留事项

**请立即吊销那个 PAT。** `ghp_...cLA1` 在对话里以明文出现过，
它带有 `repo`、`workflow`、`delete_repo` 等权限。
去 https://github.com/settings/tokens 撤销后重新生成。

**`github.com` 间歇性不可达。** 本轮推送有多次 `git push` 静默失败
（TCP 通但数据传输被丢弃），改用 `api_push.py` 走 `api.github.com` 成功。
该脚本的路径重建 tree，会产生**内容相同、SHA 不同**的提交，
导致下一次 `git push` 报 `refusing to merge unrelated histories`。
处理办法已写进 `docs/PUSH_BLOCKED.md`。
