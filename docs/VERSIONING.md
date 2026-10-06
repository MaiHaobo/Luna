# 版本号与产物命名

## 规则

**产物文件名带上版本号：`Luna-<版本>-unsigned.ipa`**

```
Luna-1.0.1-unsigned.ipa
```

同时发布一份不带版本号的 `Luna-unsigned.ipa`，保持稳定 URL——
AltStore / SideStore 的源，以及任何已经指向这个路径的脚本，都不需要改。

## 版本号写在哪

**只有一个地方：`Luna.xcodeproj/project.pbxproj`**

```
MARKETING_VERSION = 1.0.1;
```

这个值有两处（Debug 和 Release 各一），**改的时候两个都要改**。
它经 `Info.plist` 的 `$(MARKETING_VERSION)` 进入 bundle 的
`CFBundleShortVersionString`，工作流再从构建好的 bundle 里读回来命名文件。

工作流里**不重复写版本号**。这是刻意的：如果两处各写一份，
它们迟早会不一致，而一个标错版本号的文件比一个没标版本号的文件更糟。

## 怎么升版本

1. 改 `project.pbxproj` 里两处 `MARKETING_VERSION`
2. 提交、推送到 `main`
3. CI 自动构建，产物名自动带上新版本号，Release 自动更新

不需要改工作流，不需要打 tag。

> 如果你希望「打 tag 自动定版本」，那是另一套做法（tag 触发 + 从 tag 名取版本），
> 当前没有启用。

### 当前的版本序列

| 版本 | 说明 |
| --- | --- |
| （无） | 早期构建，产物名统一是 `Luna-unsigned.ipa`，无法区分 |
| **1.0.1** | 起用版本化命名的第一个版本 |

`CURRENT_PROJECT_VERSION`（build 号）保持为 `1`，目前不参与命名。

## 命名规则的取舍

**为什么用纯 `1.0.1` 而不是 `1.0.1+build12`**

版本号由人决定，构建次数不参与。同一个版本号可能对应多次构建
（比如改了 CI 配置重新跑），文件名会重复——但 Release 资产是
`--clobber` 覆盖的，永远只有最新一份，所以重复不影响使用。

代价是：**无法从文件名区分同一版本的不同构建**。
如果以后需要（比如要对比两次构建的产物），把 CI 运行号加进去即可。

**为什么保留稳定名**

滚动 Release 的价值就是「最新构建永远在同一个 URL」。
去掉稳定名会让所有下游引用失效。

## 发布到哪儿

每次 `main` 分支的 push 都会更新 `nightly` 这个 Release
（标记为 prerelease，不占正式版本号）：

https://github.com/MaiHaobo/Luna/releases/tag/nightly

包含三个资产：

| 资产 | 用途 |
| --- | --- |
| `Luna-1.0.1-unsigned.ipa` | 带版本号，给人下载 |
| `Luna-unsigned.ipa` | 稳定 URL，给工具引用 |
| `INSTALL.md` | 安装说明，标题里带版本号 |

其他分支的构建（`workflow_dispatch`）只上传 Artifact，不发布 Release。

## 改工作流时的两个坑

### `GITHUB_ENV` 的名称大小写敏感

写入时用什么名字，读取时就得用什么名字：

```bash
# Package IPA 步骤
echo "ipa_name=${IPA}" >> "$GITHUB_ENV"     # 写 ipa_name

# 后续步骤
"build/${ipa_name}"                         # 必须也是小写
```

写成 `${IPA}` 不会得到空字符串，而是 **`unbound variable` 直接失败**
（因为那些步骤开了 `set -u`）。这个坑真实发生过一次：打包成功了，
发布步骤挂掉，因为包装步骤写的是小写、发布步骤读的是大写。

**约定：所有跨步骤变量一律小写**，大写只用于步骤内部的临时 shell 变量。

### 没开 `set -u` 的步骤会静默出错

更要命的是同一类错误的另一种表现。`Write install instructions`
原本没声明 `set -euo pipefail`，于是 `${VERSION}` 这类未绑定变量
**悄悄展开成空字符串**，步骤显示成功，但生成的文件是：

```markdown
# Installing Luna              ← 版本号是空的

`-unsigned.ipa` has **no signature**.   ← 文件名也是空的
```

比崩溃更糟，因为不会有人注意到。

**约定：每个 `run:` 步骤开头都写 `set -euo pipefail`**，让这类笔误
立刻失败。唯一的例外是你确实需要容忍某个命令失败（用 `|| true` 显式标注）。

