# l4fwd — 四层端口转发 / 原始套接字任意协议转发（Windows / Linux / OpenBSD）

一个小巧的跨平台转发工具：在本机任意地址的任意端口上监听，把收到的**整包数据原样**
转发到目标 IP 和端口。除了 TCP / UDP，它还能通过原始套接字（SOCK_RAW）转发**任意 IP 协议**
——包括你自己用原始套接字实现、系统协议栈根本不认识的非标准协议。带网页面板，可以随时增删规则、
看实时流量和日志。三个平台共用一套配置、一套面板、一套测试；平台差异见下面「平台支持」。

```
 客户端                 l4fwd (本机)                  目标服务器
    │  ① 发往 0.0.0.0:8080      │                         │
    ├──────────────────────────►│  ② 改写成来自本机       │
    │                           ├────────────────────────►│
    │                           │  ③ 回包映射回客户端      │
    │◄──────────────────────────┤◄────────────────────────┤
```

---

## 平台支持

| 能力 | Windows | Linux | OpenBSD |
|---|---|---|---|
| TCP / UDP 转发 | ✅ | ✅ | ✅ |
| 任意 IP 协议（RAW） | ✅ 需管理员 | ✅ 需 root 或 `CAP_NET_RAW` | ✅ 需 root |
| 混杂捕获 | ✅ `SIO_RCVALL`（监听地址必须是具体网卡 IP） | ✅ `AF_PACKET`（默认路由网卡，可指定） | ✅ `/dev/bpf` |
| TCP 透明转发 | ✅ 内核建连 + 握手门控 | ✅ 内核建连（门控在 accept 之后） | ✅ 同 Linux |
| 网页面板 / 热加载 | ✅ | ✅ | ✅ |
| 自动放行防火墙 | ✅ netsh | ❌ 自行 ufw/nftables | ❌ 自行 `/etc/pf.conf` |
| 双栈（IPv4+IPv6）监听 | ✅ | ✅ | ✅ |

差异要点：

- **目标门控**：Windows 用 `SO_CONDITIONAL_ACCEPT` 把客户端的握手挂在“目标连接成功”之后，
  所以 `tcping` 这类只做 connect 的探测能拿到目标端口的真实状态。Linux/OpenBSD 的内核在
  `accept()` 返回之前就完成了握手，用户态无法阻止；转发器仍会在目标不可达时**立刻发 RST**，
  所以读写会马上失败，但“只 connect 不看数据”的探测会先看到连接成功。这是平台能力差异，
  不是配置问题。
- **套接字缓冲**：Windows 把监听套接字的缓冲继承给 accept 出来的连接；Linux/OpenBSD 每个
  连接单独设置（`listenBufferKB` 同样生效）。Linux 上非 root 进程的 `SO_RCVBUF` 受
  `net.core.rmem_max` 限制（默认约 208 KiB），root 会用 `SO_RCVBUFFORCE` 绕过。
- **防火墙**：只有 Windows 能自动加规则。Linux/OpenBSD 的包过滤配置模型差异太大
  （ufw / nftables / pf），工具不替你改；面板会隐藏「放行防火墙」按钮，`-firewall`
  会提示手动命令。
- **UAC / 提权**：Windows 有 `l4fwd-admin.exe`（弹 UAC）；Linux/OpenBSD 用 `sudo` 启动即可，
  面板重启仍是普通重新执行，不提权。

---

## 功能

- **TCP 转发**：流式、字节级透明，支持半关闭（half-close）、TCP_NODELAY、keepalive、空闲超时、并发上限。
- **UDP 转发**：保持**数据报边界**，每个客户端一条独立上游 socket，会话空闲 TTL 到点自动回收（默认 60 秒），单个数据报最大 64 KiB。
- **RAW 任意协议转发**：`SOCK_RAW` + `IP_HDRINCL`，协议号 1–255 任意填写，也可用 `icmp` / `gre` / `esp` / `ah` / `sctp` / `ospf` 等名字。转发时重写 IP 头（源地址=本机，目的地址=目标），必要时同步改写端口、ICMP id / GRE key / ESP SPI，并修正校验和 —— 所以自己实现的非标准协议也能被转发。
- **「全部协议」一条搞定**：协议选 `all` 时，同一条规则、同一个端口同时收 TCP、UDP 和其余所有 IP 协议（每个协议号一个原始套接字），客户端用什么协议发过来都转到同一个目标。
- **TCP 透明转发（探测类客户端）**：自己构造 TCP 报文、只做一次 connect 的客户端（tcping、自制握手、非标准 TCP 客户端）也能被转发到目标的真实 TCP 端口；并且**连接成功与否取决于目标是否可达**，而不是转发器是否在跑。
- **网页面板**：规则增删改启停、实时速率/字节/包数/会话数、运行日志滚动（SSE 推送），可设账号密码，可只读模式。
- **配置热加载**：`config.json` 一改就自动生效（2 秒轮询），也可以在面板点“重载配置”。
- **命令行一把梭**：不写配置文件也能直接 `-listen` / `-target` 转发一条。
- **防火墙放行（仅 Windows）**：`l4fwd.exe -firewall` 或面板上的「放行防火墙」按钮，把每条规则真正占用的 TCP/UDP 端口加进 Windows 入站规则；面板还会**主动告警**哪些端口没放行（本机连得上、别的机器却超时，十有八九就是这个）。Linux/OpenBSD 请自行用 ufw/nftables/pf 放行，面板会隐藏这个按钮。
- 单文件绿色：不写注册表、不装驱动、不开服务（Linux/OpenBSD 也不装守护进程），删掉二进制就干净了。

---

## 快速开始

### 方式一：双击运行（推荐先试这个）

1. 拷贝 `bin\l4fwd.exe` 到任意目录（例如 `D:\tools\l4fwd\`）。
2. 双击运行。首次运行会在同目录生成 `config.json`。
3. 浏览器会自动打开面板 `http://127.0.0.1:8686/`，点**新建规则**：

   | 字段 | 例子 | 说明 |
   |---|---|---|
   | 协议类型 | TCP | TCP / UDP / RAW |
   | 监听地址 | `0.0.0.0` | 留空或 `0.0.0.0` = 所有网卡（同时监听 IPv6，所以 `ssh localhost` 也能连上） |
   | 监听端口 | `8080` | 客户端连这个端口 |
   | 目标地址 | `192.168.1.10` | 要转发到的机器，可写域名 |
   | 目标端口 | `80` | |

4. 保存即生效，规则表里能看到“运行中”和实时速率。

### 方式二：命令行

```bash
# 把本机 8080 转发到 192.168.1.10:80（TCP）
l4fwd.exe -listen 8080 -target 192.168.1.10:80

# UDP 53（DNS）
l4fwd.exe -type udp -listen 53 -target 10.0.0.53:53

# 只监听某一网卡
l4fwd.exe -listen 172.16.0.32:8080 -target 192.168.1.10:80

# 任意 IP 协议：把 GRE(47) 转发到 10.0.0.9（需管理员）
l4fwd.exe -type raw -proto 47 -target 10.0.0.9

# 自定义协议号 200，payload 前 4 字节是端口（见下文）
l4fwd.exe -type raw -proto 200 -listen 172.16.0.32 -target 172.16.0.41

# 不开面板、静默跑
l4fwd.exe -web off -listen 8080 -target 192.168.1.10:80

# 给配置里所有端口加防火墙放行规则（需管理员）
# TCP/UDP 规则、TCP 透明转发规则、以及「全部协议」规则的 TCP/UDP 部分都会被放行；
# 单一协议的 RAW 规则（ICMP/GRE/自定义协议号）没有端口，Windows 防火墙也不按协议号过滤
l4fwd.exe -firewall

# 只校验配置文件
l4fwd.exe -check
```

Linux / OpenBSD 的用法完全相同，二进制叫 `l4fwd`；原始套接字用 `sudo` 启动：

```bash
sudo ./l4fwd -listen 8080 -target 192.168.1.10:80          # TCP/UDP 其实不需要 root
sudo ./l4fwd -type raw -proto 200 -target 10.0.0.9         # RAW 需要 root
sudo setcap cap_net_raw+ep ./l4fwd                         # 或者只给二进制 CAP_NET_RAW（Linux）
./l4fwd -no-browser                                        # 面板默认只监听 127.0.0.1
```

常用参数（`l4fwd.exe -h` 看全部）：

| 参数 | 说明 |
|---|---|
| `-c <路径>` | 配置文件位置，默认 exe 同目录 `config.json` |
| `-listen <端口\|地址:端口>` | 临时添加一条转发规则的本地监听 |
| `-target <地址:端口>` | 临时规则的目标 |
| `-type tcp\|udp\|raw` | 临时规则类型（默认 tcp） |
| `-proto <47\|gre\|200>` | `-type raw` 时必填，IP 协议号或名称 |
| `-web <地址:端口\|off>` | 覆盖面板监听地址，`off` 关闭面板 |
| `-no-browser` | 不自动开浏览器 |
| `-log-level debug\|info\|warn\|error` | 日志级别 |
| `-log-file <路径>` | 同时写日志文件 |
| `-firewall` | 为配置内所有端口添加防火墙入站规则 |
| `-read-only` | 面板只读（禁止网页改规则） |
| `-check` | 只校验配置并退出 |

> 临时规则同样会写进 `config.json`，下次启动照样生效；不想要就在面板里删掉。

---

## 原始套接字（RAW）转发详解

这是本工具和普通端口转发器最大的区别：**它不只看 TCP/UDP，而是按“IP 协议号”转发整个 IP 数据包**，
所以任何协议都行。

### 为什么需要管理员

### 为什么需要特权

- **Windows**：从 Vista 起限制原始套接字：非管理员可以创建原始套接字**发送**报文，但**接收**
  会被拒绝（`WSAEACCES`）。要收包就必须以管理员身份运行。建议直接用 `bin\l4fwd-admin.exe`
  （已内嵌 `requireAdministrator` 清单，启动弹一次 UAC）或右键“以管理员身份运行”。
- **Linux**：需要 root 或 `CAP_NET_RAW`（`sudo setcap cap_net_raw+ep ./l4fwd` 后普通用户也能跑）。
- **OpenBSD**：原始套接字与 `/dev/bpf` 都只对 root 开放。

TCP/UDP 转发不需要任何特权（监听 1024 以下的端口除外）。

### 监听地址（Windows 限制）

Windows 不允许在 `0.0.0.0` 上做原始套接字的混杂捕获（`SIO_RCVALL` 会返回 `WSAEINVAL`），
所以 **Windows 上** RAW 规则的监听地址要写具体网卡 IP，程序会在日志里告诉你本机有哪些可用地址。
面板上的监听地址输入框带下拉候选，就是这些地址。

Linux/OpenBSD 没有这个限制：`0.0.0.0` 会收所有本机地址的该协议报文；混杂捕获在
`0.0.0.0` 时自动挂到默认路由网卡（Linux 读 `/proc/net/route`，OpenBSD 取第一个非回环网卡），
也可以用 `listenHost` 指定网卡 IP 来收窄范围。

### 三种工作模式

| 模式 | 触发条件 | 收到的包 | 适用场景 |
|---|---|---|---|
| 本地收包 | `listenHost` = 本机 IP（或 `0.0.0.0`），不勾混杂 | 目的地址是本机 IP 的、该协议的包 | 对端主动连本机（最常见） |
| 混杂捕获 | 勾选“混杂捕获” | 该网卡上**所有**该协议的包，包括发给别人 IP 的 | 旁路监听/透明接管 |
| 纯发送 | 只用于内部 | — | — |

混杂捕获的实现按平台不同：Windows `SIO_RCVALL`、Linux `AF_PACKET`（内核里按协议号过滤，
所以“全部协议”规则不会把同一份流量放大 250 倍）、OpenBSD `/dev/bpf`。

### TCP 协议要选“透明转发”

TCP 是有状态协议，按包转发会直接破坏连接（Windows 甚至禁止原始 TCP 套接字：bind/发送都会返回
`WSAEINVAL`）。所以「协议号填 tcp / 6」时改用**透明转发**：

- 转发器在本机监听规则里的端口，收到连接后**用内核协议栈替客户端连到目标的真实 TCP 端口**，
  双向数据原样搬运；
- **Windows** 默认开启**目标门控**：客户端的 TCP 握手要等到目标那边连接成功才完成，目标连不上
  就直接拒绝，所以 tcping 这类“只做一次 connect 来判断端口通不通”的工具，得到的是**目标端口
  的真实状态**（`"gate": false` 可关掉这个行为）；
- **Linux/OpenBSD** 的内核在 `accept()` 之前就完成了握手，门控无法阻止 connect 成功；目标不可达时
  转发器会立刻 RST 掉连接，读写马上报错，但只做 connect 的探测会先看到“连上了”。详见「平台支持」；
- 只做 connect 不发数据的探测、以及正常的 TCP 客户端，都走同一条路径，日志里能看到
  `TCP 透明转发 ... 已建连`。

命令行同样可以：`l4fwd.exe -type raw -proto tcp -listen 19001 -target 10.0.0.9:19001`
（程序会自动选 transparent 模式；显式写 `-proto 6` 也一样）。

### 想省事就选「全部协议」

协议那一栏除了填单个协议号/名称，还可以选 **「全部协议（TCP + UDP + 其余所有 IP 协议）」**
（配置里 `"protocol": "all"`）。一条规则会同时监听你填的那个端口上的：

| 部分 | 承载方式 | 说明 |
|---|---|---|
| TCP | 透明转发（内核协议栈建连到目标端口） | TCP 有状态，不能按包转发 |
| UDP | 普通 UDP 数据报转发 | 保持数据报边界，按客户端分会话 |
| 其余所有 IP 协议 | 每个协议号一个原始套接字 | 1–254 里除 4 / 6 / 17 / 41 之外的 250 个协议号，各自的会话独立 |

也就是说：客户端用 TCP、UDP、SCTP(132)、GRE(47)、ESP(50)、ICMP(1)，或者你自己编的协议号，
只要发到同一个监听端口，都会被转给同一个目标。面板里它仍然只有**一行**，统计是所有部分之和；
日志里会写明「已启动 252 个监听器」。因此：

- 「全部协议」规则**需要同时填写监听端口和目标端口**（TCP/UDP 部分要用）；
- 它按主机独占原始套接字，所以**同一台机器上一条「全部协议」规则就够了**，再建一条会提示冲突；
  和普通 TCP 规则抢同一个端口也会提示冲突。
- 有少数协议号系统会拒绝（占用中或驱动不支持），这些会记一条 WARN 日志跳过，不影响其他协议。

命令行示例：

```bash
# 一个端口收所有协议，全部转给 10.0.0.9 的对应端口
l4fwd.exe -type raw -proto all -listen 19001 -target 10.0.0.9:19001
```

### 自定义协议（端口写在 payload 里）

很多自己用原始套接字写的协议，会在 payload 前 4 字节放一对“源端口/目的端口”（大端 16 位）。
勾选 **“payload 端口”**（配置里 `"payloadPorts": true`）后，l4fwd 会：

1. 用这 4 字节区分不同客户端的会话；
2. 转发时代换成自己的代理端口（所以目标回包不会串到别的客户端）；
3. 回包时再换回客户端原本的端口。

协议本身没有端口字段（例如 GRE、纯 IPIP）也可以不勾，此时按“客户端 IP”区分会话，
适合一个客户端一条流的情况；带 ICMP echo id / GRE key / ESP SPI 的协议会自动用这些字段区分。

### 各协议的校验和怎么处理

| 协议 | 处理方式 |
|---|---|
| TCP / UDP / UDP-Lite / DCCP | 增量修正伪首部校验和（按 RFC 1624，不重算整包） |
| ICMP / ICMPv6 | 修正 ICMP 自身校验和（ICMPv6 含伪首部） |
| SCTP | 完整重算 CRC32c |
| GRE / ESP / AH / IPIP 等 | 协议本身不涉地址，保持原样 |

### 直接改写/伪造源 IP

规则里的 `sourceIP` 用来指定转发出去时用的源地址（默认自动选本机第一个可用 IPv4）。
留空即可，除非你的目标要求特定源地址。

---

## 网页面板

- 默认地址 `http://127.0.0.1:8686/`，只监听本机回环，不会被外部访问。
- 顶部四张卡片：运行中规则数、活动会话、入站/出站流量（速率同时给**字节/秒与包/秒**，小包场景下只看字节会误判为空闲）。
- 规则表：类型、监听、目标、状态、活动会话、累计入/出字节与包数、速率（字节/秒 + 包/秒），行内可**停用/启用/编辑/删除**。
- **多选与批量操作**：表头复选框 = 全选/取消全选（部分选中显示为半选态）；勾选任意行后表格底部出现
  「启用选中 / 停用选中 / 删除选中 / 取消选择」，一次请求改完所有选中规则（`POST /api/rules/batch`），
  删除会先弹确认框。批量操作和单条操作一样会写回 `config.json`。
- 底部日志窗：SSE 实时推送，带级别过滤显示，可暂停自动滚动。
- **防火墙状态**：顶部会提示哪些监听端口还没放行（"本机连得上、别的机器超时"基本就是这个），
  点右上角**「放行防火墙」**按钮即可添加（需要以管理员运行）。
- **重载配置**：手动重新读盘（等价于改 config.json 后的自动重载）。
- 设了 `web.password` 之后面板会要求登录，用户名见 `web.username`（默认 admin）；登录态存在
  内存里的 12 小时令牌，浏览器刷新不用重登。
- 只读模式：`l4fwd.exe -read-only` 启动后所有写操作（增删改、启停、批量、重载）返回 403。

想从别的机器看面板，把 `web.listen` 改成 `0.0.0.0:8686`，并**务必设置密码**。

---

## 配置文件 `config.json`

完整示例见 [config.example.json](config.example.json)。最小可用文件：

```json
{
  "version": 1,
  "settings": { "logLevel": "info", "dialTimeoutSec": 10, "udpSessionTTLSec": 60 },
  "web": { "enabled": true, "listen": "127.0.0.1:8686", "username": "admin", "password": "" },
  "rules": [
    { "id": "r1", "name": "web", "kind": "tcp",
      "listenHost": "0.0.0.0", "listenPort": 8080,
      "targetHost": "192.168.1.10", "targetPort": 80, "enabled": true }
  ]
}
```

### 全局设置

| 字段 | 默认 | 说明 |
|---|---|---|
| `logLevel` | `info` | `debug` 能看到每条连接/会话的细节 |
| `logToFile` / `logFile` | `false` / `l4fwd.log` | 是否同时写日志文件 |
| `dialTimeoutSec` | `10` | 连目标超时 |
| `idleTimeoutSec` | `0` | 整条连接空闲多久断开，`0` = 不限 |
| `udpSessionTTLSec` | `60` | UDP/RAW 会话空闲回收时间；到点的会话连它的上游 socket 一起关掉 |
| `bufferKB` | `64` | 转发器自己用的拷贝缓冲区大小（KB）；它也是 UDP 会话自动上限的依据（64 MiB ÷ 缓冲大小） |
| `listenBufferKB` | `1024` | **内核**给每个 TCP 连接预留的收发缓冲（KB）。Windows 默认 64 KiB、Linux 约 128 KiB、OpenBSD 32 KiB 左右，都会把批量吞吐压到一半以下，见下方「关于吞吐」 |
| `samplerMs` | `1000` | 面板速率采样周期 |
| `startOnBoot` / `autoStartRules` | `false` | 预留开关（当前由计划任务/启动项控制自启） |

### 规则字段

| 字段 | 适用 | 说明 |
|---|---|---|
| `id` | 全部 | 留空自动生成；重名会覆盖 |
| `name` / `description` / `tags` | 全部 | 备注用 |
| `kind` | 全部 | `tcp` / `udp` / `raw` |
| `protocol` | raw | IP 协议号或名称：`47`、`gre`、`200`、`icmp`、`tcp`…；`all` = 全部协议（TCP + UDP + 其余所有 IP 协议） |
| `rawTransport` | raw | 转发方式：`own`（本项目自己的原始套接字，默认）或 `transparent`（TCP 交给内核协议栈建连到目标端口；`protocol` 为 tcp/6 时自动选中） |
| `gate` | raw+transparent | 默认 `true`：TCP 握手等到目标连接成功才完成，探测类客户端拿到的是目标的真实状态 |
| `listenHost` | 全部 | 空/`0.0.0.0`/`::` = 所有网卡（**双栈监听**，IPv4 与 IPv6 客户端都能连）；raw 规则必须写具体 IPv4 地址 |
| `listenPort` | tcp/udp + transparent | 本地监听端口（raw own 模式可选，用于限定端口） |
| `targetHost` / `targetPort` | 全部 | 目标地址（可写域名）与端口 |
| `enabled` | 全部 | 是否启用 |
| `dialTimeoutSec` / `idleTimeoutSec` / `udpSessionTTLSec` | 全部 | 覆盖全局设置 |
| `maxConns` | tcp/udp + transparent | 并发连接/会话上限；`0` 表示按内存预算自动取值（UDP ≈ 64 MiB ÷ 会话缓冲，RAW 默认 4096），**不会真正无限制**，上限可在配置里调高（UDP 最大 65536，RAW 最大 16384）。「全部协议」规则里 TCP 这一半不参与均分、至少 512（见下方「资源上限」） |
| `payloadPorts` | raw (own) | payload 前 4 字节是端口对 |
| `sniff` | raw (own) | 混杂捕获（Windows `SIO_RCVALL` / Linux `AF_PACKET` / OpenBSD `/dev/bpf`） |
| `sourceIP` | raw (own) | 转发时报文使用的源地址 |
| `ttl` | raw (own) | 改写 TTL，`0` 保留原值 |

> **监听冲突**：`(类型, 监听地址, 端口)` 组合唯一。同一个端口上 TCP 与 UDP 可以共存，
> 但两条 TCP 规则不能抢同一个端口，保存时会直接报错。TCP 透明转发规则占用的是真实 TCP
> 端口，因此和 TCP 规则共用同一套冲突检查。

---

## 常见用法示例

```bash
# 内网穿透/跳板：把本机 3389 转给内网 RDP
l4fwd.exe -listen 13389 -target 10.0.0.20:3389

# 数据库跳板
l4fwd.exe -listen 13306 -target 10.0.0.30:3306

# 游戏/语音 UDP 服务转发
l4fwd.exe -type udp -listen 27015 -target 10.0.0.40:27015

# 转发 GRE 隧道端点（需要管理员）
l4fwd.exe -type raw -proto gre -target 10.0.0.9

# 转发自定义协议 200，客户端发的目的端口是 4000，目标要收在 5000
l4fwd.exe -type raw -proto 200 -listen 172.16.0.32 -target 10.0.0.9
#   然后在面板里把该规则的目标端口改成 5000，并勾上“payload 端口”

# 给只用 TCP connect 判断端口通不通的自建客户端（tcping 类）做转发
l4fwd.exe -type raw -proto tcp -listen 19001 -target 10.0.0.9:19001
#   目标在线 → 探测成功；目标不在线 → 探测失败（连接被拒绝），不会误报
```

---

## 构建

需要 Go 1.26+（本仓库自带一份工具链时，用 `env.sh` 注入环境）。三个平台共用同一份源码：

```bash
bash scripts/build.sh                      # 构建当前系统
TARGET_OS=linux   bash scripts/build.sh    # 交叉编译 Linux  → bin/l4fwd-linux-amd64
TARGET_OS=openbsd bash scripts/build.sh    # 交叉编译 OpenBSD → bin/l4fwd-openbsd-amd64
bash scripts/test.sh                       # go vet + 单元测试 + TCP/UDP 真实收发集成测试
bash scripts/e2e.sh                        # 端到端测试：真实启动二进制验证 TCP/UDP/RAW 与面板
```

`bin/` 下的产物：

| 平台 | 文件 | 说明 |
|---|---|---|
| Windows | `l4fwd.exe` | 普通版（asInvoker）。TCP/UDP 转发开箱可用，不弹 UAC；RAW 功能会提示需要管理员 |
| Windows | `l4fwd-admin.exe` | 全功能版（requireAdministrator）。启动弹 UAC，RAW 原始套接字可用 |
| Windows | `rawtest.exe` | 原始套接字抓包/发包工具，用来验证 RAW 转发、模拟自定义协议 |
| Linux | `l4fwd` | 单文件；RAW 需要 root 或 `CAP_NET_RAW` |
| OpenBSD | `l4fwd-openbsd-amd64` | 单文件；RAW 与 `/dev/bpf` 需要 root |
| 全平台 | `rawtest` | 与 Windows 版功能相同，用法见下 |

`rawtest` 用法（Windows 上加 `.exe`；`-sniff` 在三个平台上都能用，分别走 SIO_RCVALL / AF_PACKET / BPF）：

```bash
# 混杂捕获某协议报文（需特权），只打印目标端口是 4000 的
rawtest observe -iface 172.16.0.32 -proto 200 -seconds 10 -port 4000 -sniff

# 构造并发送一个原始 IPv4 报文（前 4 字节当作端口）
rawtest.exe send -src 172.16.0.40 -dst 172.16.0.32 -proto 200 -sport 33000 -dport 4000 -payload hello
```

---

## 测试

```bash
bash scripts/test.sh     # 单元 + 集成（约 40 秒，含资源回收/压力用例）
sudo bash scripts/e2e.sh # 端到端（Linux/OpenBSD 需要 root 跑 RAW 用例）
```

端到端里的 RAW 测试需要两个“本机上的不同地址”分别扮演客户端和目标：

- **Linux / OpenBSD**：`127.0.0.0/8` 全是本机地址，默认直接用 `127.0.0.2`（客户端）、
  `127.0.0.1`（监听）、`127.0.0.3`（目标），不需要配置。原始套接字用 `sudo` 跑。
- **Windows**：回环流量不会交给 `SIO_RCVALL`，要在网卡上临时加两个别名地址，脚本会自动处理：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/e2e-aliases.ps1 -Add      # 添加 172.16.0.40/41
bash scripts/e2e.sh
powershell -ExecutionPolicy Bypass -File scripts/e2e-aliases.ps1 -Remove   # 用完清理
```

CI 在 GitHub Actions 上跑三个平台：`windows-latest`、`ubuntu-latest`（测试与端到端用 sudo），
以及 `vmactions/openbsd-vm` 启动的 OpenBSD 7.9 虚拟机（测试在虚拟机里以 root 执行）。
`.github/workflows/build.yml` 会把三平台的测试、端到端、构建、发布串起来。

覆盖范围（125 个测试函数 + 6 个基准，`go test -bench . ./internal/engine/` 可复现性能数字）：

- `internal/netutil`：IPv4 头解析/生成、校验和（RFC 1624 增量修正与整包重算一致性、**ICMPv4 校验和不随地址改写变化**、
  **UDP 零校验和保持为零**、**SCTP CRC32c 拒绝增量修补**）、各协议流标识解析、地址/端口改写、
  监听地址解析、**双栈监听（IPv4 与 IPv6 回环都必须连通、端口冲突必须明确报错）**、
  **WinConn 读必须停在 WSAPoll（不得退化成忙等）**、**WinConn 必须关闭 Nagle**、
  **门控回调必须一次注册（参数个数写错会把每个连接都拒掉，有对照测试）**，
  外加对随机/超短输入的模糊测试（2 万组随机"报文"不得 panic）。
- `internal/config`：配置读写、校验、冲突检测、热加载通知、深拷贝隔离、原始协议选型与门控默认值、
  500 组随机配置的 JSON 往返。
- `internal/engine`：TCP 二进制安全收发、半关闭、并发客户端、目标不可达、UDP 数据报边界、
  会话隔离与 TTL 回收、64 KiB 大报文、RAW 地址与端口改写、回包映射、**自环抑制（含本机目标与
  发送轨迹兜底）**、会话回收、TCP 透明转发（含目标不可达时拒绝连接、40 轮连续建连压力、
  **2500 次连续建连不得耗尽 Go 回调表**、**连接爆发不得被门控串行化**、**探测连接不得泄漏**）、
  **Stop 必须及时返回（空闲连接不得挂住配置重载）**、
  **空闲连接不得烧 CPU（进程自身 CPU 时间实测）**、**共享轮询器必须真正叫醒收到包的协程**、
  **自环兜底表必须记住刚发出的包、必须过期、必须有界**、**并发 Apply 串行化**、
  **反复增删规则不泄漏句柄/协程**、连接数上限、畸形报文不得 panic。
- `internal/stats`：采样器同时算出字节速率与**包速率**（含计数器回绕/重载导致的负增量保护）。
- `internal/webui`：路由与错误码、设置项持久化（空密码不清空）、密码门控与令牌登录。
- `test/e2e`：真实二进制 + HTTP 面板 API（单条 CRUD、批量启停删、错误码）+ TCP/UDP/RAW
  真实收发 + TCP 透明转发（目标在线/下线两种状态）+ 全协议规则（同一端口 TCP/UDP/自定义协议）+
  **SSH 式规则同时服务 127.0.0.1 与 ::1** + **端口冲突在面板上可见** + 热加载 +
  **性能验收（单字节往返、写-写-读往返、64 MiB 吞吐，两种 TCP 转发形态都测）**。

> **关于资源上限（不会造孤儿、不会把机器吃满）**：UDP 每个客户端会话要占一个上游 socket、
> 一个协程和一个接收缓冲，RAW 每个会话还要占一个代理端口和回包映射。这类资源能被"伪造源地址/端口
> 的洪泛"凭空放大，所以两类会话表都有**不可关闭的上限**：UDP 默认按 `64 MiB ÷ bufferKB` 计算
> （64 KiB 缓冲时是 1024 个会话），RAW 默认 4096 个，可用 `maxConns` 调整（上限分别是 65536 / 16384）。
> 达到上限时新会话被丢弃并计入错误统计（面板能看到"会话数达到上限"），已有会话不受影响；
> 「全部协议」规则会把 RAW/UDP 部分的会话预算**按监听器数量均分**，不会因为 252 个协议号就把上限
> 乘以 252。**TCP 那一半例外**：它不参与均分，至少保留 512 个连接（未设置 `maxConns` 时按 4096）。
> 原因是一个 TCP 连接只能由客户端完成握手产生、无法用伪造报文凭空创建，均分后的十几个连接远低于
> 一个真实端口的需求 —— 实测 30 个并发连接会有一半被上限拒掉，剩下的连上就断。
> 会话空闲 `udpSessionTTLSec` 秒后连同上游 socket 一起回收，停用规则则立即回收全部（252 个监听器
> 的「全部协议」规则实测 0.4 秒停用、1.1 秒启用）。反复增删规则不会泄漏句柄或协程（有回归测试）。

> **关于 IP 分片**：Windows 会在把报文交给原始套接字**之前**完成重组，所以转发侧
> 永远是完整数据报；出方向超出 MTU 时由协议栈自动分片。Linux 的原始套接字会看到分片，
> OpenBSD 也可能；代码对分片做了兼容处理（保留分片字段、按 IP ID 找到会话、只改首片校验和），
> 两个平台都会走到那条分支。

> **关于延迟**：转发不引入人为等待。两条硬约束都写进了代码与回归测试：
> ① **Nagle 必须关闭**（`TCP_NODELAY`）—— Windows 上接受连接的 socket 由 `netutil.WinConn`
> 包装，普通的 `conn.(*net.TCPConn)` 断言对它不成立，所以 `NewWinConn` 自己关掉 Nagle，监听
> socket 上也设了，新连接继承该选项；Linux/OpenBSD 上由 `tuneTCP` 统一设置；
> ② **非阻塞读必须停在 `WSAPoll`**（Linux/OpenBSD 是 `poll(2)`），不得退化成轮询忙等
> （曾经会让空闲连接把一个核跑满）。实测本机回环单字节往返：直连约 0.03 ms，经 TCP 转发约
> 0.3 ms（+0.3 ms），经透明转发约 0.35 ms；32 MiB 单向吞吐 200 MiB/s 以上。

> **关于长跑稳定性**：`WSAAccept` 的目标门控回调在**进程内只注册一次**（Go 的
> `syscall.NewCallback` 按函数值建表，上限 2000；每个连接注册一个闭包会让程序在约 2000 次
> 建连后直接 `fatal error: too many callback functions` 崩溃）。回调通过 `dwCallbackData`
> 传进来的整数键在共享表里找自己的槽位。回归测试连续建连 2500 次。
>
> **关于并发连接（Windows 特有的坑）**：`SO_CONDITIONAL_ACCEPT` 的回调由内核**逐个串行**执行，
> 而回调没返回之前，后面到达的 SYN 一直不会完成握手 —— Windows 客户端大约 1 秒就放弃了。所以
> 门控里**不能**为每个连接各拨一次目标：一次 12 个并发连接会变成 12 次串行的目标建连（每次约
> 180 ms），前几个成功、后面全部"连接超时"。现在的做法是**门控只回答已知信息**（`targetProbe`）：
>
> - 拨号在**后台协程**里进行，并把结论（成功/失败 + 拨出的那条链路）缓存 `probeTTL`；
> - **只有一个**连接会等这次拨号，最多等 `gateBudget = 250 ms`。目标在预算内应答就如实回答：
>   不可达就拒绝（探针语义保住了，实测目标宕机时客户端 1~10 ms 内收到拒绝），可达就把探测
>   拨出的链路给这个连接；
> - 其余连接**一律立即放行**（回调查询本身是串行的，每个都等 250 ms 会累积成好几秒），各自
>   在握手完成后拨目标；等超预算的那一个也立即放行。
>
> 实测：180 ms 的目标上 30 个并发连接全部成功、建连 197~202 ms（整批一次往返，与直连同量级）；
> 目标拨号要比预算慢（1 秒）时 4 个并发连接仍然 4/4 成功，且每个客户端都由自己的后端连接服务；
> 40 次串行连接 40/40 成功。被直接放行的连接在错误统计里可见（`target slow: ...`）。
>
> **关于 SO_REUSEADDR**：门控监听保留 `SO_REUSEADDR`（重启后端口处于 TIME_WAIT 时才能立刻
> 重绑），代价是 Windows 也允许**第二个监听**绑同一端口，于是通配地址在绑定前会显式探测
> IPv4 侧，把这种静默抢占变成明确的「端口已被占用」错误。

> **关于空闲开销（「全部协议」规则尤其明显）**：一条 252 个监听器的「全部协议」规则会开
> ~250 个原始套接字。如果每个套接字各自停在一个 `WSAPoll` 里，光是"等着"就要付出
> **250 次系统调用 + 250 次线程唤醒**：这台机器实测空闲 6% 单核。现在同一规则的原始套接字
> **共用一次 `WSAPoll`**（Linux/OpenBSD 上是一次 `poll(2)`，同一个 `rawPollSet` 抽象；
> 一个协程轮询所有套接字，命中后唤醒对应的捕获协程去排空），
> 空闲降到 **0.2%~1% 单核**，而每个协议仍然在自己的协程上处理，吞吐不受影响。实测（安静端口上
> 的 252 监听全协议规则）：优化前 0.45~0.65 CPU 秒 / 10 秒，优化后 0.02~0.11 CPU 秒 / 10 秒。
>
> 接收路径本身也做了减负：捕获缓冲区**原地使用**（`handlePacket` 只读输入，转发出去的是另一份
> 缓冲区，所以不再每包复制一次），自环兜底表从 `map`+字符串键改成**定长环 + 可比较结构键**
> （0 分配，`isOwnEgress` 从 390 ns / 2 allocs 降到 23 ns / 0 allocs），IPv4 头解析**复用同一个
> Header 并不再分配 IP 对象**（`Header.Src/Dst` 就是报文里的 4 个字节，地址比较走 `SameIP`），
> 会话表与分片表的键也从 `string` 换成可比较的结构体，**转发用的缓冲区按监听器复用**（每个监听器
> 一个，随包长大，不再每包分配一块新缓冲）。接收路径现在是**每包 0 次分配**：
> `handlePacket` **0.7~1.0 µs / 0 allocs**（512 字节载荷；13 次分配 → 0，最早是 4.7 µs），
> 小包 0.65~0.75 µs。`internal/engine/bench_test.go` 有 6 个基准，
> `allocbudget_test.go` 把"热路径每包 0 次分配"写成了断言，改坏了会直接测试失败。

> **关于 TCP 转发速率（重要）**：批量吞吐的瓶颈是**内核给每个连接预留的 socket 缓冲**，
> 不是转发器自己的拷贝循环。三个平台的默认值都不大（Windows 64 KiB；Linux 约 128 KiB 且受
> `net.core.rmem_max` 限制；OpenBSD 32 KiB 左右），转发器把数据从内核收上来、再写回内核，
> 两个方向各一个窗口，整条链路就被限制在这个窗口的周转速度上。
> Windows 本机回环实测（512 MiB 单流，各 6 轮取中位数）：

| 路径 | 默认 64 KiB 缓冲 | `listenBufferKB: 1024` |
|---|---|---|
| 直连（无转发器） | 592 MiB/s | — |
| 经 TCP 转发 | 436 MiB/s | **514 MiB/s** |
| 经透明转发（门控） | **247 MiB/s** | **493 MiB/s** |

> 所以 `listenBufferKB` 现在是**默认 1 MiB**。Windows 上它设在监听套接字上，监听套接字的
> 收发缓冲会**继承给 accept 出来的连接**（有回归测试 `TestListenerBuffersAreInherited` 钉住这一点）；
> Linux/OpenBSD 不继承，`tuneTCP` 在 accept 之后对每个连接单独 setsockopt（Linux 上 root 还会尝试
> `SO_RCVBUFFORCE` 突破 `rmem_max`）。透明转发路径受益最大（+100%），因为门控监听比普通监听
> 更容易在握手后暴露这个窗口。转发器自身的 CPU 大约是一个核的 50~60%，其中 85% 是内核态拷贝。
>
> 客户端侧在透明路径上由 `WinConn` 驱动，现在是**先收后等**：`WSARecv` 先试一次，只有队列空
> （`WSAEWOULDBLOCK`）才停到 `WSAPoll` 上。转发器的对端通常已经有数据在排队，所以绝大多数读都
> 省掉了那次 poll。Linux/OpenBSD 走 Go runtime 的 epoll/kqueue，同样是先收后等。
>
> 参照数据（Windows 本机回环，同一台机器）：Windows 自带的 `netsh interface portproxy`（内核态
> 转发）实测只有 **55~63 MiB/s**，不到这个转发器的九分之一；一个"照抄 nginx 参数"的最小 Go
> 转发器（大缓冲 + 非阻塞读 + 回环快通道）实测 380~440 MiB/s。也就是说现在的数字已经贴着这台机器
> 用户态转发的上限，再往上要换掉整条数据通路。Linux/OpenBSD 的数字由 CI 的
> `TestTCPStreamThroughput` 每次构建复测（断言只要求转发 ≥ 直连的 1/5、透明 ≥ 普通转发的 60%，
> 避免共享 runner 的抖动误报）。

---

## 排错

| 现象 | 原因与处理 |
|---|---|
| 日志出现 `需要管理员权限` / `需要 root`、RAW 规则启动失败 | Windows 用 `l4fwd-admin.exe` 或右键以管理员身份运行；Linux 用 `sudo` 或 `setcap cap_net_raw+ep`；OpenBSD 用 `sudo` |
| **SSH 转发失败 / 提示 Connection refused** | 两个常见原因：① 客户端用 `ssh localhost`，而 localhost 在 Windows 上优先解析成 `::1`（sshd/OpenSSH 客户端不会回退到 127.0.0.1）。l4fwd 现在是**双栈监听**（同时出现在 `0.0.0.0` 和 `[::]`），如果日志里只看到 IPv4 监听，说明用了旧版本；② 目标那侧没有 SSH 服务或端口不对，转发器日志会写 `dial ... failed`。 |
| 规则一直「运行中」但客户端连不上 | Windows 用 `netstat -ano \| findstr <端口>`，Linux/OpenBSD 用 `ss -ltnp` / `netstat -an` 确认 l4fwd 真的在监听；如果端口被别的程序占着，日志会明确报 `端口 N 已被其它程序占用`，面板的状态列也会显示错误。 |
| Windows RAW 规则报 `SIO_RCVALL requires binding to a specific local IP` | 监听地址填了 `0.0.0.0`；改成具体网卡 IP（面板输入框有下拉候选）。Linux/OpenBSD 没有这个限制 |
| RAW 规则的监听地址必须是 IPv4 | 原始套接字工作在第 3 层，只支持 IPv4 地址；TCP/UDP 规则则支持 IPv6 监听地址 |
| 面板打不开 | 检查 `web.listen` 端口是否被占用，或启动时加了 `-web off`；Linux/OpenBSD 用 `-no-browser` 时不会自动开浏览器 |
| Linux 上 RAW 规则报 `operation not permitted` | 进程没有 root/CAP_NET_RAW；用 `sudo`，或 `sudo setcap cap_net_raw+ep ./l4fwd` 后普通用户运行 |
| OpenBSD 上混杂捕获报 `open /dev/bpf` | `/dev/bpf` 只有 root 可开，且内核要启用 bpf；用 `sudo` 启动 |
| 目标回包到不了客户端 | 确认目标的回包是发往本机（l4fwd 的源地址）；必要时在规则里指定 `sourceIP` |
| UDP 大报文丢包 | 提高 `bufferKB`，并检查中间设备 MTU |
| 全协议规则建了第二条被拒绝 | 「全部协议」按主机独占全部协议号，同一台机器一条就够 |
| 日志出现某个协议号 `部分启动失败` | 该协议号被系统占用或驱动不支持，其余协议不受影响 |
| 想抓包确认 | 用 `rawtest observe -sniff`，或 Wireshark 按 `ip.proto == 200` 过滤 |
| 感觉"延迟比两段加起来还高" | 转发路径本身不加等待（本机回环单字节往返 +0.3 ms 左右）。真正的延迟来自三个可配置项：`dialTimeoutSec` 只影响建连失败判定，不影响成功路径；`idleTimeoutSec` 非 0 时会在读上设截止时间，长静默连接会被断开；如果客户端自身的协议是"小包一问一答"，确认没有别的中间设备开着实时代理。用 `bash scripts/e2e.sh -run TestTCPLatency` 可复现基线数字。 |
| **并发连接一部分"连接超时"，单独连却正常**（Windows） | 这是门控回调被串行执行的表现（见上面「关于并发连接」）。现在的版本把一次目标探测的结论共用，并给门控设了 250 ms 预算：目标比预算慢就直接放行。20~30 个并发连接实测全部成功；如果还看到超时，请确认用的是最新构建。 |
| 规则启动时报「端口 N 已被其它程序占用」 | 通配监听会在绑定前探测 IPv4 侧（否则双栈绑定会成功，但连接被两个套接字瓜分）。关掉占用该端口的程序，或换端口。 |
| 连接建立要等 200 ms 以上（Windows） | 这是**到目标的实际建连时间**（透明转发在握手期间就要连上目标，否则无法如实回答探测）。本机目标应该是毫秒级；若是公网目标，这个数字等于这条路径的 RTT。超过 250 ms 不会一直等：门控会先放行，之后由这条连接自己拨号。 |
| Linux/OpenBSD 上 tcping 目标已下线仍显示"连上" | 内核在 accept 前就完成了握手，用户态无法阻止；转发器会立刻 RST，读写会失败。只做 connect 的探测在两个平台上无法如实反映目标状态，见「平台支持」 |
| 句柄/文件描述符数偏高 | 全协议规则会持有 ~250 个原始套接字，属正常；反复增删规则后若不回落才需排查（测试已覆盖） |

---

## 目录结构

```
cmd/l4fwd/            程序入口与命令行解析
internal/cli/         启动流程：配置、日志、引擎、面板、信号、热加载
internal/config/      config.json 结构与校验、原子保存、冲突检测
internal/engine/      TCP / UDP / RAW(own) 转发实现 + TCP 透明转发 + 规则管理器 + 共享 poll
internal/netutil/     IPv4 头与校验和、协议解析、原始套接字（各平台一套）、门控监听、套接字缓冲
internal/platform/    提权检测/提权重启、防火墙（Windows 实现，其它平台明确降级）、单实例、开浏览器
internal/logx/        带内存环形缓冲与订阅的日志器（面板实时日志用）
internal/stats/       计数器与速率采样
internal/webui/       内嵌网页面板（HTML + JSON API + SSE，含批量操作接口）
build/                manifest（普通版/管理员版）与资源嵌入工具（仅 Windows）
tools/rawtest/        原始套接字抓包/发包测试工具（三平台）
scripts/              构建、测试、端到端脚本
test/e2e/             端到端测试（共享用例 + Windows/Unix 两套 raw 端）
```

netutil 的平台文件：

| 文件 | 平台 | 内容 |
|---|---|---|
| `rawsock_windows.go` / `gatedlisten_windows.go` | Windows | `WSASocket` / `IP_HDRINCL` / `SIO_RCVALL` / `WSAPoll`，`SO_CONDITIONAL_ACCEPT` 门控 |
| `rawsock_unix.go` | Linux + OpenBSD | `AF_INET SOCK_RAW` + `IP_HDRINCL`，非阻塞 + `poll(2)` |
| `rawsock_sniff_linux.go` | Linux | `AF_PACKET` + 内核 BPF 过滤器 |
| `rawsock_sniff_openbsd.go` | OpenBSD | `/dev/bpf`（`BIOCSETIF`/`BIOCPROMISC`/`BIOCIMMEDIATE`） |
| `gatedlisten_other.go` | Linux + OpenBSD | accept 之后执行门控，失败用 `SO_LINGER=0` 发 RST |
| `sockbuf_linux.go` | Linux | `SO_*BUFFORCE` 优先，突破 `net.core.rmem_max` |

---

## 许可

仅供合法用途：请在你拥有或已获授权的网络与设备上使用。
