# FlexConnect

FlexConnect 2.0 是一个可选择 AnyConnect 或 aTrust 的 VPN 客户端，提供守护进程、桌面托盘和命令行接口，面向 Windows、Linux 和 macOS。

## 组件

- `flexconnectd`：本地守护进程，负责连接管理、状态维护和 API 服务
- `flextray`：桌面托盘入口，展示状态并提供常用操作
- `flexconnect`：命令行客户端，适合脚本和日常运维
- `client/local`：类型化本地 API 客户端
- `internal/vpn/anyconnect`：内建 AnyConnect 后端
- `internal/vpn/atrust`：通过 GeekTrust 库连接 aTrust，由 FlexConnect 管理系统 TUN、路由和 DNS

## 能力

- 管理多个 Profile
- 发起和断开 VPN 连接
- 应用服务器路由与本地路由策略
- 提供本地 SOCKS5 代理；代理连接与域名解析只走已连接的 VPN 隧道
- 导出诊断信息
- 通过 `flexconnect netcheck` 执行不创建系统 TUN 的 CSTP/DTLS 连接探查和 VPN 流量测速
- 通过命令行完成 Profile 管理与路由配置

## 快速开始

### 启动守护进程和托盘

```bash
go run ./cmd/flexconnectd
go run ./cmd/flextray
```

### 常用 CLI

```bash
flexconnect status
flexconnect up
flexconnect down
flexconnect profile list
```

### 首次使用

1. 启动 `flexconnectd`
2. 运行 `flexconnect login` 并在终端中安全输入连接信息
3. 创建或选择一个 Profile
4. 输入服务器、用户名和密码并连接

aTrust 的部署兼容行为由每个 Profile 显式配置，默认关闭。使用 `--atrust-compatibility-file` 导入 JSON，格式和开关说明见 [aTrust 部署兼容配置](docs/atrust-compatibility.md)。

aTrust 使用已注册的 Passkey keystore。先启动守护进程，再用
`profile add --provider atrust --auth-method ecnu_passkey --keystore <file>`
导入凭据。导入后请勿让其他程序并发使用源 keystore；源文件不会被自动删除。

连接成功后，CLI 与托盘会显示当前状态、VPN 地址、DNS 和路由摘要。

## 命令示例

```bash
flexconnect login --server https://vpn.example.com --user alice --password-file ./secrets/flexconnect_password --name corp
flexconnect up -p corp
flexconnect down
flexconnect diag diag.json
flexconnect netcheck --env-file .env
flexconnect proxy status
flexconnect proxy enable 127.0.0.1:1080
flexconnect proxy disable
flexconnect profile add --scope machine --password-file ./secrets/flexconnect_password unattended https://vpn.example.com machine-user
flexconnect profile add --provider atrust --auth-method ecnu_passkey --keystore ./ecnu.keystore campus https://vpn.ecnu.edu.cn
flexconnect up -p campus
flexconnect control-mode machine -p unattended
flexconnect control-mode user
flexconnect logs
```

## 连接诊断

`flexconnect netcheck` 是独立于守护进程的连接级探查入口。它从指定 dotenv 文件读取
`ENDPOINT`、`USERNAME`、`PASSWORD` 和可选的 `GROUP`，建立 CSTP/DTLS 链路，在用户态
网络栈中执行受限下载测速，不创建系统 TUN、不修改系统路由或 DNS，并输出实际本地/远端
socket、底层网卡、VPN 地址、MTU、DPD、DTLS 和测速帧统计。测速目标可通过
`--speedtest-url` 覆盖；使用 `--no-speedtest` 只检查连接稳定性。输出不包含密码、Cookie、
令牌或数据包内容。

```bash
flexconnect netcheck --env-file .env
flexconnect netcheck --env-file .env --speedtest-url https://speed.example/download?bytes=4194304
flexconnect netcheck --env-file .env --no-speedtest --json
```

守护进程只在运行期间保留有界的近期连接历史。`flexconnect watch` 以
NDJSON 输出 `connection_lost`、`reconnect_scheduled`、`reconnect_attempt`、
`reconnected`、`reconnect_failed` 和 `reconnect_exhausted` 等生命周期事件；自动重连
每轮最多尝试 3 次，用尽后进入可观测的 `Error` 状态，不再定时重试；网络恢复、路径变化或
Windows 唤醒/解锁后，仍有连接意图的瞬时故障会开启新一轮重试。休眠或物理网络不可用时
会暂停并取消正在进行的自动连接尝试。认证等非瞬时故障需要用户手动重试。`flexconnect diag`
会同时包含这些事件、最后一次传输/关闭原因以及当前重连快照。

主动断开会被记录为人为操作，不会触发异常断线重连通知。非主动断开及重连进度会由托盘
通过系统通知提示；平台通知服务不可用时，错误会进入托盘日志，不会改变 VPN 状态。

非交互场景只接受 `--password-file` 或 `--password-stdin`。FlexConnect 不接受命令行
明文密码，因为进程参数和 shell 历史可能泄露凭据。

托盘菜单操作、诊断复制和 watch 通道错误会弹出可去重的桌面错误提示，并同时写入托盘日志。
如果 `flextray` 启动时无法连接守护进程，会先弹出错误提示，然后退出。

SOCKS5 代理是 VPN-only：启用后只支持 TCP CONNECT 和 IPv4 目标，域名通过 VPN DNS 解析，无法确认走 VPN 时会拒绝连接，不会回退到本机网络。当前不支持 UDP ASSOC、BIND 或 IPv6 代理目标。

## Docker 部署

Docker 镜像运行 `flexconnectd`，通过环境变量按名称创建或更新 machine Profile，ID 由 daemon 随机生成。容器内需要 Linux TUN 能力；容器内 SOCKS5 可监听 `0.0.0.0:1080`，Compose 默认只映射到宿主机 `127.0.0.1:1080`。

```bash
docker build -t flexconnect:local .
docker run --rm \
  --cap-add NET_ADMIN \
  --device /dev/net/tun \
  -p 127.0.0.1:1080:1080 \
  -e FLEXCONNECT_SERVER=https://vpn.example.com \
  -e FLEXCONNECT_USERNAME=alice \
  -e FLEXCONNECT_PASSWORD='<password>' \
  flexconnect:local
```

推荐用 Compose 和 Docker secret 注入密码：

```bash
mkdir -p secrets
printf '%s\n' '<password>' > secrets/flexconnect_password
FLEXCONNECT_SERVER=https://vpn.example.com FLEXCONNECT_USERNAME=alice docker compose -f docker-compose.example.yml up --build
```

缺少必填环境变量、密码文件不可读或 machine Profile 持久化失败会直接非零退出。连接失败会保留 machine 锁并通过 `/v3/ready`、status、diagnostics 和 watch 暴露；只有明确分类为瞬态的错误才执行最多 3 次重连。管理员必须显式退出 machine 模式才能解除锁定。

管理员手动管理 unattended 模式时，先用 `profile add --scope machine` 创建 machine Profile，
再执行 `control-mode machine`。`control-mode` 会返回异步 operation；终态通过 watch 发布并在
发布后从 operation 查询表移除。即使 daemon 因 machine 连接失败而 not ready，`status`、`diag`、
`watch`、`down` 和 `control-mode user` 仍可用于诊断或恢复。

### 发布到 GitHub Packages

仓库中的 `Docker Release` 工作流会在推送 `v*` tag 时将镜像发布到 `ghcr.io`，并自动打上 `v` 去掉前缀后的版本标签（如 `1.3.4`）以及 `<major>`、`<major>.<minor>`。

从 GHCR 发布镜像（可选）：

```bash
docker login ghcr.io
IMAGE=ghcr.io/<OWNER>/flexconnect
VERSION=<VERSION>

docker build -t "${IMAGE}:${VERSION}" .
docker push "${IMAGE}:${VERSION}"
docker tag "${IMAGE}:${VERSION}" "${IMAGE}:latest"
docker push "${IMAGE}:latest"
```

从 GHCR 拉取镜像：

```bash
docker pull ghcr.io/<OWNER>/flexconnect:<VERSION>
```

### 守护进程密码存储

Linux daemon 默认独立持久化密码，不依赖桌面登录会话或 Secret Service。
密码以明文保存在 `--state` 文件所在目录的 `secrets.json`；目录权限为 `0700`，
文件权限为 `0600`，打包的系统服务由 root 持有。Profile 状态仍只保存 `secret_ref`。
这不提供磁盘加密；需要静态加密时应使用加密磁盘或显式配置可用的钥匙串。
Windows/macOS 继续默认使用系统钥匙串，Docker 继续默认使用 `memory`。

升级前使用 Linux 钥匙串的用户可设置 `FLEXCONNECT_SECRET_STORE=keyring` 保持原后端；
切换到文件存储后须重新录入密码，不会自动迁移桌面或 root 钥匙串里的凭据。
显式 `keyring` 模式失败时仍直接报错，不会自动降级。

### 环境变量

| 变量 | 说明 |
| --- | --- |
| `FLEXCONNECT_SOCKET` | daemon 本地 Unix socket，镜像默认 `/run/flexconnect/flexconnect.sock` |
| `FLEXCONNECT_STATE` | 状态文件路径，镜像默认 `/var/lib/flexconnect/state.json` |
| `FLEXCONNECT_VERBOSE` | `true` 时启用 debug 日志 |
| `FLEXCONNECT_SECRET_STORE` | Linux 默认 `file`；Windows/macOS 默认 `keyring`（不可用时启动失败）；可显式选择 `keyring`、`file`、`memory`；镜像默认 `memory` |
| `FLEXCONNECT_CONNECT_ON_START` | `true` 时启动即 upsert Profile 并连接；镜像默认 `true` |
| `FLEXCONNECT_CONNECT_TIMEOUT` | 启动连接超时，例如 `45s`、`2m` |
| `FLEXCONNECT_PROFILE_NAME` | 启动 machine Profile 的稳定名称，镜像默认 `docker`；ID 由 daemon 生成 |
| `FLEXCONNECT_SERVER` | AnyConnect 服务器 URL，启动连接时必填 |
| `FLEXCONNECT_USERNAME` | 用户名，启动连接时必填 |
| `FLEXCONNECT_GROUP` | VPN group，可选 |
| `FLEXCONNECT_PASSWORD` | 密码；不可与 `FLEXCONNECT_PASSWORD_FILE` 同时设置 |
| `FLEXCONNECT_PASSWORD_FILE` | 密码文件路径；只去掉末尾换行，适合 Docker secret |
| `FLEXCONNECT_ACCEPT_SERVER_ROUTES` | 是否接受服务器下发路由 |
| `FLEXCONNECT_AUTO_RECONNECT` | 是否在异常断开后自动重连；镜像默认 `true` |
| `FLEXCONNECT_APPLY_DNS` | 是否应用 VPN DNS |
| `FLEXCONNECT_MTU` | TUN MTU |
| `FLEXCONNECT_DNS` | 逗号分隔的 DNS override |
| `FLEXCONNECT_INCLUDE_ROUTES` | 逗号分隔的自定义 include routes |
| `FLEXCONNECT_EXCLUDE_ROUTES` | 逗号分隔的自定义 exclude routes |
| `FLEXCONNECT_SOCKS5_ENABLED` | 是否启用 VPN-only SOCKS5；镜像默认 `true` |
| `FLEXCONNECT_SOCKS5_LISTEN` | SOCKS5 监听地址；镜像默认 `0.0.0.0:1080` |

## 构建与安装

### Windows 服务

```powershell
./scripts/install-windows-service.ps1
./scripts/uninstall-windows-service.ps1
```

### Linux / macOS 服务模板

```bash
./scripts/install-linux.sh
./scripts/install-macos.sh
```

Linux daemon 的本地控制接口位于 `/run/flexconnect/flexconnect.sock`，仅允许
`root` 和 `flexconnect` 组访问。安装后将需要使用 CLI 或托盘的账户加入该组，
并重新登录以刷新组成员关系：

```bash
sudo usermod -aG flexconnect "$USER"
```

### 统一打包

```bash
go run ./cmd/dist list
go run ./cmd/dist build --version 2.0.0 linux/amd64/tgz
go run ./cmd/dist build --version 2.0.0 linux/amd64/deb
go run ./cmd/dist build --version 2.0.0 linux/amd64/rpm
go run ./cmd/dist build --version 2.0.0 windows/amd64/zip
go run ./cmd/dist build --version 2.0.0 windows/amd64/msi
go run ./cmd/dist build --version 2.0.0 darwin/amd64/pkg
go run ./cmd/dist build --version 2.0.0 darwin/arm64/pkg
```

发布 `v2.0.0` 前，需先获得 GeekTrust 上游授权，发布 GeekTrust 库版本，并在 FlexConnect 中固定远程版本。当前本地联调使用未提交的 Go workspace。

## 运行与配置

- `--socket` 用于指定本地 IPC 端点
- `--timeout` 设置 daemon 健康检查和普通 CLI 操作超时，默认 `15s`
- `--connect-timeout` 设置登录和 VPN 建链超时，默认 `2m`
- `--state` 用于指定状态文件
- `-v` 或 `--verbose` 启用更详细日志
- Windows 上直接启动 `flexconnectd` 时会自动请求管理员权限
- 密码通过系统密钥库保存，状态文件只保存非敏感元数据
- CLI 在执行 daemon 命令前通过 `/v3/live` 和 `/v3/ready` 校验 API major、capabilities 与组件 readiness
- Linux 本地控制接口通过 `0660 root:flexconnect` Unix socket 提供；Windows 使用受保护的 named pipe，不暴露公网 TCP 端口

## 项目结构

- `assets/`：图标和 Windows 运行时资源
- `client/`：面向用户的客户端代码
- `cmd/`：可执行程序入口
- `docs/`：项目说明文档
- `internal/`：守护进程、API、路由、IPC、存储、日志和 AnyConnect 实现
- `release/`：Debian 和 RPM 生命周期脚本
- `scripts/`：构建、打包、安装和运行脚本

## Credits
* [Tailscale](https://tailscale.com/) - 架构参考与实现参考
* [sslcon](https://github.com/tlslink/sslcon) - AnyConnect 协议实现参考

## 验证边界

2.0.0 的三平台原生 CI、安装包和容器验证仍需在固定 GeekTrust 远程版本后完成。实际 VPN/TUN 连接验证须按运行平台分别记录。

### Additional authentication in 2.0

When an aTrust controller requests SMS verification, the tray displays a notice.
Keep the connection attempt running and use another terminal:

```sh
flexconnect auth status
flexconnect auth respond
```

The response prompt masks terminal input. For automation, use
`flexconnect auth respond --response-stdin` with a private input source. Codes are
not accepted on the command line and are not saved. Requests expire within one
minute; submitting a code acknowledges delivery to the provider, while the ongoing
connection operation reports the final authentication result.
