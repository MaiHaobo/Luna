# Liquid Glass 迁移记录

> 最低系统：**iOS 26.0**（`IPHONEOS_DEPLOYMENT_TARGET = 26.0`）
> CI runner：`macos-26`，实测 Xcode **26.6**
> 状态：✅ 三个阶段的 CI 全部通过

---

## 决策

### 只支持 iOS 26+，不做降级分支

Luna 的目标设备本来就明确，为一个不存在的旧系统维护一套
`#available` 分支只会让每个视图都长出两块代码。部署目标直接提到 26.0，
`glassEffect` 当作普通 API 使用。

代价是放弃 iOS 17–25。如果以后要下探，`LunaGlass.swift` 是唯一需要改的地方。

### 玻璃只上「导航层」，内容层保持不透明

用户最初选的是「全应用重做」，在追问「列表行、设置项要不要也玻璃化」后
改为**严格遵循官方规范**：材质属于浮在内容之上的层，不属于内容本身。

原因是可读性，不是保守。玻璃**采样背景**——把它铺在列表行上，
行与行之间的文字会随着背后内容滚动而明暗抖动。Apple 的 HIG 就明确
不建议在内容层使用。

所以最终：

| 位置 | 处理 |
| --- | --- |
| `ContainerWindowRootView` 卡片 | ✅ 深色玻璃 |
| `AppLibraryView` 导入横幅 | ✅ 玻璃 |
| `TabView` / 导航栏 | ✅ 系统自动处理，无需改动 |
| Sheet | ✅ 系统自动处理 |
| 列表行、设置项、诊断项 | ❌ 保持不透明 |
| 访客画布（纯黑） | ❌ 保持不透明，它是内容 |

---

## 三个阶段的划分

分阶段不是为了渐进式上线，是为了**隔离故障**。当时刚把部署目标跳到
一个全新的 SDK，同时改视图会让「API 签名写错了」和「视图改错了」
混在同一个编译错误里。

| 阶段 | 内容 | 目的 | CI |
| --- | --- | --- | --- |
| 1 | 部署目标 → 26.0，runner → `macos-26` | 确认旧代码能在新 SDK 上编译 | ✅ #6 |
| 2 | 新增 `LunaGlass.swift`，接线 pbxproj，**无人调用** | 确认 API 签名正确 | ✅ #8 |
| 3 | 改写两个视图 | 应用材质 | ✅ #9 |

阶段 2 是关键设计：空跑一次编译，把「这个 API 是不是这么写」单独问出来。
它绿了，阶段 3 的任何报错就一定是视图的问题。

---

## 验证过的 API 签名

来自 Apple 官方文档，不是推断：

```swift
nonisolated func glassEffect(
    _ glass: Glass = .regular,
    in shape: some Shape = DefaultGlassEffectShape()
) -> some View                    // iOS 26.0+
```

- `Glass`：`.regular` / `.clear` / `.identity`
- `Glass.tint(Color?)` —— 参数是**可选**的 `Color?`
- `Glass.interactive(Bool)` —— 参数是 `Bool`
- `Shape`：`.capsule`、`.circle`、`.rect(cornerRadius:style:)`
- `GlassButtonStyle` 通过 `.buttonStyle(.glass)` 构造

### 应用顺序

`glassEffect` 必须在**其他影响外观的修饰符之后**：

```swift
content
    .padding(16)              // 在玻璃之内 → 被吸收
    .lunaGlassCard()          // 材质
    .padding(12)              // 在玻璃之外 → 玻璃被内缩
```

顺序反了的现象是圆角跑到内容里面去，而不是报错。

---

## 关键实现细节

### `LunaGlass.swift` 用 `extension View` 而非 `ViewModifier`

`ViewModifier` 需要一个新的 `struct`。而 `tools/swift_sanity.py` 有
跨文件重名类型的检查，`struct` 会被检查、`extension` 不会被检查。
用 extension 是让那个检查保持有价值的唯一方式——它应该拦住真正的重名，
不该被一个约定俗成的辅助类型触发。

另外这两个辅助函数**不转发泛型 `Shape`**。手写

```swift
func glass<S: Shape>(in shape: S) -> some View
```

很容易和 SDK 自身的约束（`Shape` 同时满足 `Sendable` 和 `Animatable`）
错配，而错配只会在 macOS CI 上暴露。两个固定形状覆盖了全部调用点。

### 深色着色：`overlayScrim`

浮动窗口上有纯黑画布和白色 chrome。普通玻璃会采样到窗口**背后**的
应用界面，产生一块浅色表面，白字压不上去。所以用
`.regular.tint(.black.opacity(0.30))`。

### 不透明底必须删掉

这是最容易漏的一步。玻璃靠采样背景工作，**背景被不透明色盖住时
玻璃会渲染成一块平的灰方块**。所以 `secondarySystemBackground` 填充
必须删——不是「顺手改成半透明」，是必须移除。

`clipShape` 同理删除：`glassEffect` 自己按圆角裁剪，
再裁一次会把材质的高光边切掉。

### 连带修复：动态色在深色玻璃上会失效

删掉不透明底之后，标题栏、状态栏、日志面板下面不再是「系统背景色」
而是「深色玻璃」，于是 `.primary` / `.secondary` 这些**随外观解析**的
动态色会出问题：浅色模式下它们解析成接近黑色，压在深色玻璃上看不清。

这些位置的文字因此改成显式的白色，按层级递减透明度：

| 位置 | 颜色 |
| --- | --- |
| 标题 | `.white` |
| 副标题 | `.white.opacity(0.6)` |
| 指标标题 | `.white.opacity(0.5)` |
| 指标值 | `.white.opacity(0.85)` |
| 日志正文 | `.white.opacity(0.72)` |
| 错误正文 | `.white.opacity(0.7)` |

日志面板的背景同时从 `black.opacity(0.85)` 降到
`LunaGlassPalette.codePane`（0.35）——它现在是半透明层，不是实心板。

**`GuestCanvas` 内部一字未改。** 它本身叠在纯黑矩形上，
`.secondary` 在那里行为不变。

---

## 排查过但确认无需改动的 API

部署目标跳到 26 之后，逐个审计了 iOS 26 移除的 API：

| API | 状态 |
| --- | --- |
| `NavigationView` | 未使用 |
| `foregroundColor` | 未使用 |
| `navigationBarItems` | 未使用 |
| `keyWindow` | 未使用 |
| `UIScreen.main` | 未使用 |

`LunaApp.swift` 的 `TabView` + `.tabItem` 不动——iOS 26 的标签栏
会自动应用玻璃，手动加一层反而会叠出两层材质。

`ContainerWindow.swift` 不动：`backgroundColor = .clear` 和
`host.view.backgroundColor = .clear` 正是玻璃能采样的**前提**，
已经是正确的。
