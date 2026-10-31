# tailnet-ops

快速搭建自建 Headscale 网络：按地区分成几个 tailnet，地区之间可以用专线相连，也支持只能由一侧发起连接的单向专线。代码可以公开复用；每个人的站点配置、证书和密钥只放在自己电脑的私有目录里。

| 文件 | 内容 |
| --- | --- |
| [PLAN.md](PLAN.md) | 产品计划和第一阶段 |
| [AGENTS.md](AGENTS.md) | 工作规则 |
| [examples/site.example.toml](examples/site.example.toml) | 站点配置示例，用的是文档专用地址 |
| [LICENSE](LICENSE) | MIT 许可证 |

隐私保护：
- 仓库里没有任何站点数据，`make check` 会拦截真实地址和密钥。
- 证书和密钥在哪里用就在哪里生成，不经过别处，也不进日志。
- 不向第三方上报日志。默认不申请公开证书，也不加公开域名记录；只有给区设了 `domain`，才向 Let's Encrypt 申请证书（见下文）。

## 用法

需要 Python 3.11+、`ssh`/`scp`、`openssl`、`curl`。主机用 `~/.ssh/config` 里的别名。

| 命令 | 作用 |
| --- | --- |
| `./tn init` | 只问名字、专线入口地址和服务商放行的端口，其余通过只读 SSH 得出，写 `site.toml` |
| `./tn --tui` | 默认一次装好一个区的 Headscale 和 tn-agent：先问完所有问题（区、域名、Cloudflare Token、tn-agent 的名字），`site.toml` 只改一次，然后依次做完下面两部分；也可以只选其中一个。Headscale 部分：选区和证书方式（站点 CA，或 Cloudflare 上的域名加 Let's Encrypt，会列出 Cloudflare 里要做的事），改 `site.toml`（留 `site.toml.bak`），只读检查，记下现有节点和地址、在控制机上备份 Headscale，显示计划，输入 `yes` 后执行，验证；登录地址变了就把 tn 认得的节点一台台迁过去，最后和记录对比地址。tn-agent 部分：用 Cloudflare Token 查出你的 zone，建议名字 `agent-<区>.<zone>` 并写进 `site.toml`，策略里没有 agent tag 时先跑一次 `tn control apply`（Headscale 只重载策略），装好 tn-agent 和 Tunnel，再生成 passkey 登记链接和 MCP 令牌（都放进剪贴板）。改动前都会先问 |
| `./tn site check` | 校验站点目录（权限、不在 Git 里）和 `site.toml` |
| `./tn control plan <region>` | 打印简短计划：每一步做什么、怎么撤销；`--full` 看完整脚本。不改任何东西 |
| `./tn control preflight <region>` | 只读预检：系统、端口、已有文件 |
| `./tn control apply <region>` | 按计划部署 Headscale，要输入 `yes`。同时装上名字守护：每分钟更新本区机器的名字，并通过专线两端所在区的控制机互换名单（发起端那台用一把只能交换名单的 SSH 密钥去连另一台），所以任何方式入网、改名、删除，一分钟内各区都能解析。区设了 `entry_port` 时，还装上手机入口（见下文） |
| `./tn control verify <region>` | 从检查机只读验证 TLS `/health`、DERP、STUN |
| `./tn control rollback <region>` | 倒序回滚，只删 tailnet-ops 自己做的东西，要输入 `yes` |
| `./tn join` | 交互式入网：用方向键选机器（本机或 SSH 别名）、方案、地区，填名字；先只读检查并显示计划，再问要不要执行 |
| `./tn join plan [机器] [选项]` | 不提问，用选项：先只读检查，再列出步骤和撤销方法。不写机器就是本机。`--offline` 跳过检查，`--full` 看完整脚本 |
| `./tn join apply [机器] [选项]` | 装 Tailscale、信任站点 CA、用一次性密钥入网，要输入 `yes`。tn 会把这台机器怎么入网记在站点目录的 `joined.json` |
| `./tn join verify [机器]` | 只读检查：已连上、地址在本区网段、标签正确（个人设备没有标签、每个区都有账号）、用本区 DERP |
| `./tn join rollback [机器]` | 退出 tailnet，删掉入网时加的东西和那条记录，要输入 `yes` |
| `./tn join list` | 列出用 tn join 加入的机器 |
| `./tn join apply <名字> --app` | 用 Tailscale App（独立版）的 Mac，比如笔记本：在能连上控制机的机器上运行。没装 App 时先下载官方安装包（核对固定的 sha256 和 Tailscale 公司的签名）并安装；生成 App 能读的描述文件（站点 CA、名字、subnets 和 DNS），在系统设置里安装；再给每个区各加一个账号（本机直接完成，另一台 Mac 粘贴一段命令）；最后生成 Clash Verge 的扩展脚本。那台 Mac 不用 SSH，也不用装 tn |
| `./tn line list` | 列出站点里的所有专线：两端、入口、隧道地址、优先级（只读 `site.toml`） |
| `./tn line plan <line>` | 只读检查专线两端和它们的防火墙，列出会挡住转发的链、步骤和撤销方法 |
| `./tn line apply <line>` | 拉通两个 tailnet：WireGuard 隧道、地址映射和 NAT、给挡路的防火墙链加带标记的放行规则、宣告并批准路由、更新策略，最后逐台 ping 对方区的机器。要输入 `yes` |
| `./tn line verify <line>` | 只读：两端互相 ping 隧道地址，再 ping 对方区每台已入网机器的映射地址 |
| `./tn line rollback <line>` | 撤回路由和策略，停掉隧道，删掉 NAT 表、放行规则、定时器和文件，最后检查有无残留。要输入 `yes` |
| `./tn dns list` | 只读：列出每个区里每个名字解析到的地址（本区直连地址，或经专线的映射地址） |
| `./tn dns sync` | 立即同步各区的名字，要输入 `yes`；装了名字守护的控制机同时更新它的对端、密钥和名单。入网、拉专线和部署控制机时会自动做 |
| `./tn dns stop <region>` | 只拿掉这个区控制机上的名字守护（定时器、密钥、允许对端连进来的那行），之后名字回到手动同步；`tn control apply` 会再装上 |
| `./tn phone add <名字>` | 手机：在本机生成它的 WireGuard 密钥，在入口网段里给它一个地址，加到每个区的手机入口上；在站点目录的 `phones/<名字>/` 写出每个区一份 WireGuard 配置，和一份 Clash 片段（Stash、Clash Meta）：节点、选择组、规则和主机名。要输入 `yes`。再运行一次会刷新主机名和文件 |
| `./tn phone remove <名字>` | 从每个入口删掉这台手机，并删除它的文件，要输入 `yes` |
| `./tn phone list` | 列出已加的手机（只读站点目录） |
| `./tn phone status` | 只读：每个区的入口隧道、入口 DNS、放行规则是否在位，入口能否解析本区名字，以及每台手机最近一次握手和流量 |
| `./tn phone stop <region>` | 只拿掉这个区控制机上的手机入口（接口、密钥、nft 表、放行规则、定时器和文件），再检查有无残留；Headscale 和其他东西不动。要输入 `yes`。`tn control apply` 会再装上 |
| `./tn agent plan\|apply\|verify\|rollback <region>` | 在控制机上装 tn-agent：给 Agent 的 MCP 接口和给你的审批页。Agent 只能读网络、申请改动；每个改动都要你在审批页上用 passkey 批准。区里要有 `domain` 和 `agent_domain`。tn-agent 走 Cloudflare Tunnel，控制机不开任何端口 |
| `./tn agent enroll <region>` | 生成一次性登记链接（10 分钟内有效），登记你的 passkey。要输入 `yes` |
| `./tn agent token <region>` | 没有浏览器时用：在终端生成 MCP 令牌，放进剪贴板；它上次生成的令牌随即失效（网页上生成的不受影响）。要输入 `yes`。平时用令牌页 `https://<agent_domain>/tokens`：起个名字、按 passkey 生成，令牌只显示一次；同一页可以查看、撤销，每个操作都要 passkey |
| `./tn agent status <region>` | 只读：passkey、请求和最近的审计记录 |
| `./tn status <region>` | 列出节点 |
| `make check` | 离线测试，加上对工作区和全部历史的隐私检查 |

`site.toml` 只写别的机器要用的接入节点：控制机、检查机、专线两端。只是入网的机器（服务器或个人设备）不写，用 `tn join` 的选项或提问：

| 选项 | 含义 |
| --- | --- |
| `--server`（默认） | 服务器：固定在 `--region` 那个区，带区里的服务器标签 |
| `--personal` | 个人设备：用 `owner_user` 的身份加入每个区，从 `--region` 开始（默认第一个区）；换地方时用 `sudo tailscale switch <区名>` 切换 |
| `--name` | 在内网里的名字，默认是 SSH 别名或本机名 |
| `--port`、`--netfilter`、`--dns` | 服务商只放行部分端口、Linux 防火墙模式、是否用 MagicDNS |

控制机的证书有两种，在 `site.toml` 里按区选：

| | 站点 CA（默认） | Let's Encrypt（区里写 `domain = "hs-cn.example.com"`） |
| --- | --- | --- |
| 登录地址 | `https://<公网 IP>:<port>` | `https://<domain>:<port>` |
| 证书 | 本机的站点 CA 签发，私钥留在控制机 | acme.sh（固定版本，核对 sha256）用 DNS-01 申请，通过 Cloudflare API 加 TXT 记录，不占端口；定时器每天检查续期，换证后重启 Headscale |
| 入网的机器 | 要先信任站点 CA（Linux 装进系统证书库，Mac 加进钥匙串，App 用描述文件） | 系统本来就信任，不用装 CA；`tn join` 第 3 步只检查 |
| 需要准备 | 无 | 域名托管在 Cloudflare；一个 Cloudflare API Token，权限 Zone · Zone · Read 和 Zone · DNS · Edit（装 tn-agent 时再加 Account · Cloudflare Tunnel · Edit）。A 记录 tn 自己建：指向 `public_ipv4`、只做 DNS（不代理，Headscale 不能放在 Cloudflare 代理后面），带 tn 的标记；回滚只删它自己建的 |

Token 在第一次需要时输入（不显示），也可以放在环境变量 `CF_Token` 里；`tn --tui` 一开始就问，先用它只读地查一遍 zone 和记录。它经 SSH 的标准输入写进控制机的 `/etc/headscale/acme/`（只有 root 能读），用于续期；本机不写文件，也不进日志。第一次粘贴后可以选择存进 macOS 登录钥匙串（条目“tailnet-ops Cloudflare API token”，不信任任何程序，每次读取 macOS 都会弹窗问你，选“允许”而不是“始终允许”），以后就不用再输；`./tn site forget-token` 删掉它。回滚会删掉它，Cloudflare 那边的 Token 记得也删掉。改了登录地址后，已入网的机器再跑一次 `tn join apply`：tn 发现它连的是旧地址，就用新的一次性密钥迁过去，机器密钥不变。

入网密钥默认由 tn 登录控制机生成，直接通过管道交给 `tailscale up`，不显示也不保存。如果运行 tn 的机器登不上控制机，第 5 步会打印一条可以复制的命令：在能登上控制机的机器上运行它，得到一个一次性链接码（30 分钟有效），再粘贴回来（输入不显示）。这时名字同步和验证里需要控制机的部分会跳过；控制机装了名字守护的话，名字一分钟内自动出现，否则之后在能登上的机器上运行 `tn dns sync`。

Agent 管网络用 tn-agent（`tailnet_ops/agentd`，只用标准库，打成一个 zip 装到控制机），说明见 `skills/tailnet-ops/SKILL.md`，同一份内容也由 MCP 的 `tailnet_guide` 工具返回：

| | 怎么做 |
| --- | --- |
| Agent 能做的 | `list_nodes` 看节点；`join_script` 拿一条一次性命令，在它能 SSH 上的 Linux 机器上以 root 运行：装固定版本的 Tailscale，由这台机器自己把登录请求交给 tn-agent，打印审批链接；`request_status` 查结果；`request_leave` 申请让一台机器退出（只限通过 tn-agent 入网、带 `tag:<区>-agent` 的机器；你用 passkey 批准后，tn-agent 删掉这个节点），`leave_script` 给一条命令，在那台机器上卸掉 tn 装的 Tailscale；`resume_script` 在重启后用机器自己的密钥把 Tailscale 重新拉起来，不用再审批。没有 root 或 systemd 的机器（容器、沙箱）用 `command_without_root`：同一个固定版本以普通用户跑在用户目录里（userspace networking），其他程序通过它打印的 SOCKS5/HTTP 代理 `localhost:1055` 访问内网 |
| 你批准 | 打开审批链接（页面由控制机自己提供），核对登录请求来自的公网 IP、机器报告的主机名和系统，用 passkey 批准或拒绝。签名的是这一个请求的摘要，用一次就作废；请求 14 分钟内没批就过期 |
| 批准之后 | tn-agent 运行 `headscale auth register`，再把名字和 tag 改回批准的那样。这台机器带 `tag:<区>-agent`：别的机器能连它，它不能主动连别的机器 |
| Agent 拿不到的 | 任何入网密钥、登录链接、API key、站点目录；它不能批准、删除节点、改 tag 或改策略 |
| 控制机上 | 三个服务：`tn-cloudflared`（固定版本的 cloudflared，核对 sha256，动态用户，Tunnel 令牌只有 root 能读）把 `agent_domain` 的请求从 Cloudflare 带到本机回环；`tn-agent`（用户 `tn-agent-web`，只听 127.0.0.1、只许连回环，没有权限、不存任何东西，只转发）；`tn-agent-helper`（用户 `tn-agent`，属于 headscale 组，没有网络，只听 unix socket，自己校验令牌和每个 passkey 签名）。Cloudflare 在边缘解开 TLS，所以它看得到请求内容。两者都有 systemd 加固。连接数不设上限，只看内存：tn-agent 自己用到上限的 80%，或整台机器可用内存不到 10% 时，新请求回 429（稍后再试）；每个服务 200 MB 起被限速、256 MB 封顶，真不够用时内核先杀 tn-agent，不杀 Headscale。headscale 命令最多同时跑 2 个。令牌和登记码只存哈希；所有改动写进审计日志 |

最简单的是 `tn --tui` 里选 tn-agent，下面这些它都会替你做。手动的话：在区里加 `agent_domain = "agent-<区>.<你的域名>"`（同一个 Cloudflare 账号下的名字）。`tn agent apply` 用 Token 自己建 Tunnel、它唯一的转发规则（`agent_domain` → 本机 `127.0.0.1:agent_port`，默认 18480）和代理的 CNAME，都带 tn 的标记，回滚时一并删掉。在 Agent 平台上加一个自定义 MCP 服务器：地址 `https://<agent_domain>/mcp`，请求头 `Authorization: Bearer <令牌>`，令牌在 `https://<agent_domain>/tokens` 用 passkey 生成。加了 `agent_domain` 以后，先重跑一次 `tn control apply`，让策略里有 agent tag，再装 tn-agent。卸载用 `tn agent rollback`；先卸 tn-agent，再回滚控制机。

手机不装 Tailscale：手机同一时间只能开一个 VPN，那就是代理 App。所以在 `site.toml` 里给区加上 `entry_port`，`tn control apply` 会在控制机上多装一个手机入口：一个 WireGuard 接口 `tn-entry`（在这个 UDP 端口上，密钥在控制机上生成），加上 tailnet-ops 自己的 nft 表 `tn_entry`。手机的代理 App 里每个区一个 WireGuard 节点，按需选用。手机在每个入口上的地址都一样，访问机器也都用同一套地址：本区的内网地址直接到；经专线才能到的区，它的内网地址由入口换成映射地址，走专线过去。除此以外，入口一律不转发，不能当出口上网。入口地址（各区都是 `10.255.254.1`）兼做手机的 DNS：内网名字交给本机的 MagicDNS，答出的就是从这个入口能到的地址；其他名字交给控制机自己的上游 DNS。这个小服务 `tn-entry-dns` 只用标准库，跟着入口一起装、更新、拆除。手机的流量会伪装成控制机发出的，所以别的机器不用加回程路由。哪条防火墙链会挡这些流量，就在那里加带标记的放行规则，由定时器保持在位；回滚时只删这些。

系统自动识别：Linux 用固定版本的 Tailscale，由 systemd 管理；Alpine 等用 OpenRC 的系统改用 OpenRC 服务（supervise-daemon 守护），先装好 `apk add bash curl ca-certificates iproute2 tar iptables`；Mac 用 Homebrew 的 tailscale 和 launchd，站点 CA 加进系统钥匙串（macOS 会弹窗要密码或 Touch ID）。本机的脚本用 sudo 在本机执行，不走 SSH。

站点目录默认 `~/.config/tailnet-ops/`，也可用 `--site DIR` 或 `TN_SITE`。加 `--redact` 后，输出里的地址、主机名和密钥会换成固定占位符，方便分享。

当前状态：控制面、设备入网（Linux 和 macOS 的命令行、Mac 上的 Tailscale App）、单向专线和跨区名字都已完成，并在一个两区站点上实际部署验证。个人设备按所在地点自动切换区还没有做。

## English

tailnet-ops (`tn`) sets up self-hosted [Headscale](https://github.com/juanfont/headscale) networks: one tailnet
per region, joined by dedicated lines, including one-way lines where only one side may start connections.
It is Python 3.11+ with the standard library only, and drives your hosts over SSH.

- **Plans first.** Every command prints its steps and how each is undone; nothing changes until you type `yes`.
  Rollback removes only what tailnet-ops made, then checks that nothing is left.
- **Private by design.** Your site (addresses, host names, keys) lives in `~/.config/tailnet-ops/`, never in
  the repository. Certificates come from a site CA of your own, or, for a region with a `domain`, from
  Let's Encrypt (DNS-01 through the Cloudflare API, so no port is opened); no logs go to third parties. `make check`
  blocks real addresses, keys and your host names in every file and in all history.
- **Leaves your hosts alone.** It adds new services on free ports and never touches what already runs.

| Command | What it does |
| --- | --- |
| `./tn init` | Writes `site.toml` from a few answers plus read-only SSH checks |
| `./tn --tui` | Sets up or updates a region's Headscale step by step: certificate (site CA, or Let's Encrypt for a domain on Cloudflare), site.toml, checks, a record of the nodes and a backup on the control host, plan, apply, verify, and moving the nodes when the login address changes |
| `./tn control plan\|apply\|verify\|rollback <region>` | Deploys Headscale (TLS from the site CA, or Let's Encrypt for a region with a `domain`; embedded DERP and STUN) and a names keeper that refreshes every region's names each minute |
| `./tn join` | Joins a machine, asking which Tailscale (the command line daemon, or the app), which OS, which machine, and how: a tagged server in one region, or your personal device in every region (one profile each) |
| `./tn join plan\|apply\|verify\|rollback [host] [options]` | The same without questions; no host means this machine |
| `./tn join apply <name> --app` | A Mac with the Tailscale app: a configuration profile to install and one block to paste; no SSH to it |
| `./tn line plan\|apply\|verify\|rollback <line>` | A WireGuard line between two regions, with alias ranges, NAT and routes |
| `./tn dns list\|sync` | One name per host in every region: `<host>.<region>.<suffix>` |
| `./tn phone add\|remove\|list <name>` | Phones: with `entry_port` set, a region's control host also runs a WireGuard entry (its own nft table). A phone's proxy app gets one WireGuard node per region; tn makes the phone's key here and writes WireGuard and Clash (Stash, mihomo) files |
| `./tn agent plan\|apply\|enroll\|token\|status\|rollback <region>` | tn-agent on a region's control host, behind a Cloudflare tunnel at `agent_domain` (needs `domain` too; no port opens): an MCP endpoint where an Agent lists nodes and asks to join machines it reaches over SSH, and a page where you approve each request with a passkey. The Agent never holds a key. See `skills/tailnet-ops/SKILL.md` |

Start with `examples/site.example.toml` or `./tn init`. Licensed under MIT.
