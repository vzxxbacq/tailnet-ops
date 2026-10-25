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
| `./tn join plan <host>` | 打印入网的简短计划；`--full` 看完整脚本。不改任何东西 |
| `./tn join apply <host>` | 装 Tailscale、信任站点 CA、用一次性带标签密钥加入本区，要输入 `yes` |
| `./tn join verify <host>` | 只读检查：已连上、地址在本区网段、标签正确、用本区 DERP |
| `./tn join rollback <host>` | 退出 tailnet 并删掉入网时加的东西，要输入 `yes` |
| `./tn status <region>` | 列出节点 |
| `make check` | 离线测试，加上对工作区和全部历史的隐私检查 |

站点目录默认 `~/.config/tailnet-ops/`，也可用 `--site DIR` 或 `TN_SITE`。加 `--redact` 后，输出里的地址、主机名和密钥会换成固定占位符，方便分享。

当前状态：第一阶段（控制面）已完成，并在第一个站点的两个地区部署、验证通过。第二阶段（设备入网和专线）尚未开始。
