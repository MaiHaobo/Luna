# 推送到 GitHub —— 已完成

> **状态：✅ 已解决（2026-10-06）**
> 仓库：https://github.com/MaiHaobo/Luna
> 分支：`main`、`liquid-glass`

这份文档原本用于记录「推不上去」的阻塞。阻塞已解除，保留下来是因为排查过程本身有价值——
如果你以后遇到类似的「API 能读不能写」，这里的诊断路径可以直接复用。

---

## 最终是怎么解决的

由仓库所有者提供一个带 `repo` 权限的 Classic PAT，替换掉原连接器 token。

原连接器 token 是 App 安装令牌（`ghu_` 前缀），实测**完全只读**，见下节。
换成 PAT 后，建仓和推送都是一次成功。

---

## 原始阻塞的实测证据

| 探测项 | 结果 | 含义 |
| --- | --- | --- |
| `GET /user` | `200`，`login = MaiHaobo` | 凭据有效，身份正确 |
| `x-oauth-scopes` 响应头 | **空** | App 安装令牌，不带 classic scope |
| `POST /user/repos`（建仓） | **`403 Resource not accessible by integration`** | 无建仓权限 |
| `POST /git/refs`（建分支） | **`403`** | 对已有仓库也无写权限 |
| `POST /git/blobs`（传对象） | **`403`** | 同上 |
| `GET /repos/.../contents/`（读） | `200` | 读权限正常 |

### 一个容易踩的坑

`GET /repos` 返回的 `permissions.push = true` 是**误导性的**。
它描述的是**你自己的账号**对该仓库的权限，而不是**这个 App 被授予**的权限。
真正决定成败的是 App 安装时的细粒度授权。看到 `push=true` 就以为能推，会白折腾很久。

最直接的判据是 `git-receive-pack` 端点：

```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: token $GITHUB_TOKEN" \
  -H "User-Agent: git/2.40" \
  "https://github.com/OWNER/REPO.git/info/refs?service=git-receive-pack"
```

- `200` → 有写权限
- `401 invalid credentials` → token 是只读的（就是这里的情况）

这比 dry-run `git push` 可靠得多——dry-run 在无写权限时会**静默挂起**而不是报错。

---

## 网络问题（已自愈）

阻塞初期 `github.com:443` 的 TCP 握手能完成，但 `git ls-remote` 返回**空**，
说明 TLS 之后的数据被中间代理丢弃了。`api.github.com` 同网段却完全正常。

第二天复测时 git 协议已恢复正常，`info/refs` 返回了标准的
`application/x-git-upload-pack-advertisement`。所以网络问题是**暂时的**，
不是环境的结构性限制。

---

## 推送方式

优先用标准 `git push`：

```bash
git remote add origin "https://oauth2:${GITHUB_TOKEN}@github.com/MaiHaobo/Luna.git"
git push -u origin main
```

### 备用通道：`tools/api_push.py`

当 `github.com:443` 被阻断时（症状见上节），改用这个脚本。它走
`api.github.com` 的 Git Data API（blob → tree → commit → ref）重建一次推送。
已实际投产三次。

```bash
LUNA_BRANCH=liquid-glass GITHUB_TOKEN=... python3 tools/api_push.py
```

**两个必须知道的坑：**

1. **变量名是 `LUNA_BRANCH`，不是 `GITHUB_BRANCH`。**
   传错名字不会报错——脚本会静默回落到默认值 `main`，
   把分支上的改动推到 `main` 去。第一次就踩了这个。

2. **它会产生一个内容相同、SHA 不同的提交。**
   因为 tree 是从工作目录重建的，不是从 git 对象库导出的，
   所以远端提交与本地提交没有共同的父提交。表现是下一次
   `git push` 被拒（non-fast-forward），且
   `git merge` 报 `refusing to merge unrelated histories`。
   处理办法：

   ```bash
   git fetch origin <branch>:refs/remotes/tmp/x
   git diff --stat refs/remotes/tmp/x HEAD   # 确认为空，即内容一致
   git merge --no-ff --allow-unrelated-histories -X ours <sha>
   ```

   `-X ours` 保留本地这条有真实提交信息的历史链。

   规范做法是网络恢复后**优先 `git push`**，
   让 API 通道只作为应急手段，避免历史反复分叉。
