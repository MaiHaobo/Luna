# 推送到 GitHub —— 当前阻塞与解法

Luna 项目已完成并在本地提交（`e7fdf9e`，36 个文件），但**代码还没到你的 GitHub 上**。
这份文档说明卡在哪、为什么、以及你花 30 秒能怎么解开。

---

## 一句话结论

> 授权给这个会话的 GitHub 凭据是**只读**的：它能读你的仓库，但**不能建仓库、不能推代码**。
> 这不是 Luna 项目的问题，是连接器授权范围的问题。

---

## 实测证据

| 探测项 | 结果 | 含义 |
| --- | --- | --- |
| `GET /user` | `200`，`login = MaiHaobo` | 凭据有效，身份正确 |
| `x-oauth-scopes` 响应头 | **空** | 这是 App 安装令牌（`ghu_` 前缀），不带 classic scope |
| `POST /user/repos`（建仓） | **`403 Resource not accessible by integration`** | 无建仓权限 |
| `POST /git/refs`（建分支，测写权限） | **`403 Resource not accessible by integration`** | **对已有仓库也无写权限** |
| `GET /repos/.../contents/`（读） | `200` | 读权限正常 |
| `git ls-remote https://github.com/...` | TCP 连通，但**返回空** | git 协议主机被中间层拦掉了 |

关键在第四行：`GET /repos` 返回的 `permissions.push = true` 是**误导性的**。
它描述的是你自己账号对该仓库的权限，而不是**这个 App 被授予**的权限。
真正决定成败的是 App 安装时的细粒度授权，而它只给了 `Contents: Read`。

所以：

- **走 `git push`** → 网络不通（`github.com` 的 git 端点无响应）
- **走 REST API** → 网络通，但权限不足（403）

两条路各自被不同的东西堵住，合起来就是「推不上去」。

---

## 解法（二选一，都很快）

### 方案 A：重新授权连接器，勾上写权限 ⭐ 推荐

1. 打开 GitHub → **Settings → Applications → Installed GitHub Apps**
2. 找到本会话使用的那个 App，点 **Configure**
3. 把 **Repository permissions** 里的两项提到写：
   - **Contents** → `Read and write` （推代码必备）
   - **Administration** → `Read and write` （建仓库必备）
4. 保存，回到会话里说一声「好了」

改完之后我一条命令就能完成：建仓 → 推送 → 触发 Actions 出 `Luna-unsigned.ipa`。

> 如果你不想给 `Administration` 权限，那就用方案 B，或者你自己在网页上点一下建空仓库。

### 方案 B：你手动建一个空仓库

1. 打开 https://github.com/new
2. 仓库名填 **`Luna`**
3. **不要**勾选 `Add a README file`、`.gitignore`、`license`（必须留空，否则要处理冲突）
4. 创建完告诉我

只要仓库存在 + `Contents` 有写权限，我就能用 `tools/api_push.py` 推上去
（这条路径走 `api.github.com`，网络是通的，已验证）。

---

## 建好之后我会做什么

```bash
GITHUB_TOKEN=*** LUNA_REPO=MaiHaobo/Luna LUNA_BRANCH=main \
  python3 tools/api_push.py /workspace/Luna
```

推送成功后，`.github/workflows/build-ipa.yml` 会自动跑（`macos-15` + `xcodebuild`），
产出 **`Luna-unsigned.ipa`**，并发布到 `nightly` Release。你从 Release 页面下载安装即可。

---

## 附：为什么不用 `git push`

`github.com:443` 在这个沙箱里 TCP 三次握手能完成，但 `git ls-remote` 返回**空**——
说明 TLS 之后的数据被中间代理丢弃了。`ssh.github.com:443` 虽然也通，但没有可用的 SSH 私钥。

`api.github.com` 走的是同一个 C 段（`20.205.243.0/24`）却完全正常，所以
`tools/api_push.py` 用 REST 的 Git Data API（blob → tree → commit → ref）重建一次推送。
代价是每个文件一个请求，36 个文件大约 40 秒，可以接受。
