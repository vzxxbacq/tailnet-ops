# tailnet-ops

快速搭建自建 Headscale 网络：按地区分成几个 tailnet，地区之间可以用专线相连，也支持只能由一侧发起连接的单向专线。代码可以公开复用；每个人的站点配置、证书和密钥只放在自己电脑的私有目录里。

| 文件 | 内容 |
| --- | --- |
| [PLAN.md](PLAN.md) | 产品计划和第一阶段 |
| [AGENTS.md](AGENTS.md) | 工作规则 |
| [examples/site.example.toml](examples/site.example.toml) | 站点配置示例，用的是文档专用地址 |

隐私保护：
- 仓库里没有任何站点数据，`make check` 会拦截真实地址和密钥。
- 证书和密钥在哪里用就在哪里生成，不经过别处，也不进日志。
- 不向第三方上报日志，不申请公开证书，也不加公开域名记录。

## 用法

需要 Python 3.11+、`ssh`/`scp`、`openssl`、`curl`。主机用 `~/.ssh/config` 里的别名。

| 命令 | 作用 |
| --- | --- |
| `./tn init` | 只问名字、专线入口地址和服务商放行的端口，其余通过只读 SSH 得出，写 `site.toml` |
| `./tn site check` | 校验站点目录（权限、不在 Git 里）和 `site.toml` |
| `./tn control plan <region>` | 打印简短计划：每一步做什么、怎么撤销；`--full` 看完整脚本。不改任何东西 |
| `./tn control preflight <region>` | 只读预检：系统、端口、已有文件 |
| `./tn control apply <region>` | 按计划部署 Headscale，要输入 `yes` |
| `./tn control verify <region>` | 从检查机只读验证 TLS `/health`、DERP、STUN |
| `./tn control rollback <region>` | 倒序回滚，只删 tailnet-ops 自己做的东西，要输入 `yes` |
| `./tn join` | 交互式入网：用方向键选机器（本机或 SSH 别名）、方案、地区，填名字；先只读检查并显示计划，再问要不要执行 |
| `./tn join plan [机器] [选项]` | 不提问，用选项：先只读检查，再列出步骤和撤销方法。不写机器就是本机。`--offline` 跳过检查，`--full` 看完整脚本 |
| `./tn join apply [机器] [选项]` | 装 Tailscale、信任站点 CA、用一次性密钥入网，要输入 `yes`。tn 会把这台机器怎么入网记在站点目录的 `joined.json` |
| `./tn join verify [机器]` | 只读检查：已连上、地址在本区网段、标签正确（个人设备没有标签、每个区都有账号）、用本区 DERP |
| `./tn join rollback [机器]` | 退出 tailnet，删掉入网时加的东西和那条记录，要输入 `yes` |
| `./tn join list` | 列出用 tn join 加入的机器 |
| `./tn line list` | 列出站点里的所有专线：两端、入口、隧道地址、优先级（只读 `site.toml`） |
| `./tn line plan <line>` | 只读检查专线两端和它们的防火墙，列出会挡住转发的链、步骤和撤销方法 |
| `./tn line apply <line>` | 拉通两个 tailnet：WireGuard 隧道、地址映射和 NAT、给挡路的防火墙链加带标记的放行规则、宣告并批准路由、更新策略，最后逐台 ping 对方区的机器。要输入 `yes` |
| `./tn line verify <line>` | 只读：两端互相 ping 隧道地址，再 ping 对方区每台已入网机器的映射地址 |
| `./tn line rollback <line>` | 撤回路由和策略，停掉隧道，删掉 NAT 表、放行规则、定时器和文件，最后检查有无残留。要输入 `yes` |
| `./tn dns list` | 只读：列出每个区里每个名字解析到的地址（本区直连地址，或经专线的映射地址） |
| `./tn dns sync` | 把各区看得到的对方机器名字写进各自的 Headscale，要输入 `yes`；入网和拉专线时会自动做 |
| `./tn status <region>` | 列出节点 |
| `make check` | 离线测试，加上对工作区和全部历史的隐私检查 |

`site.toml` 只写别的机器要用的接入节点：控制机、检查机、专线两端。只是入网的机器（服务器或个人设备）不写，用 `tn join` 的选项或提问：

| 选项 | 含义 |
| --- | --- |
| `--server`（默认） | 服务器：固定在 `--region` 那个区，带区里的服务器标签 |
| `--personal` | 个人设备：用 `owner_user` 的身份加入每个区，从 `--region` 开始（默认第一个区）；换地方时用 `sudo tailscale switch <区名>` 切换 |
| `--name` | 在内网里的名字，默认是 SSH 别名或本机名 |
| `--port`、`--netfilter`、`--dns` | 服务商只放行部分端口、Linux 防火墙模式、是否用 MagicDNS |

入网密钥默认由 tn 登录控制机生成，直接通过管道交给 `tailscale up`，不显示也不保存。如果运行 tn 的机器登不上控制机，第 5 步会打印一条可以复制的命令：在能登上控制机的机器上运行它，得到一个一次性链接码（30 分钟有效），再粘贴回来（输入不显示）。这时名字同步和验证里需要控制机的部分会跳过，并提示之后在能登上的机器上运行 `tn dns sync`。

系统自动识别：Linux 用固定版本的 Tailscale 和 systemd；Mac 用 Homebrew 的 tailscale 和 launchd，站点 CA 加进系统钥匙串（macOS 会弹窗要密码或 Touch ID）。本机的脚本用 sudo 在本机执行，不走 SSH。

站点目录默认 `~/.config/tailnet-ops/`，也可用 `--site DIR` 或 `TN_SITE`。加 `--redact` 后，输出里的地址、主机名和密钥会换成固定占位符，方便分享。

当前状态：第一阶段（控制面）已完成，并在第一个站点的两个地区部署、验证通过。第二阶段（设备入网和专线）尚未开始。
