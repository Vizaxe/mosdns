# mosdns

一个插件化的 DNS 转发器/代理，支持灵活的规则路由、DNS 分流与广告过滤。

[![Go Version](https://img.shields.io/badge/Go-1.26-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/License-GPL--3.0-green)](LICENSE)
[![Release](https://img.shields.io/github/v/release/IrineSistiana/mosdns?label=latest)](https://github.com/IrineSistiana/mosdns/releases)

## 项目简介

mosdns 是一个纯 Go 编写的 DNS 转发器，通过**插件链**机制将 DNS 处理流程编排为可组合的逻辑单元。你可以像搭积木一样组合：

- 多种上游（UDP/TCP/DoT/DoH/DoQ）
- 域名匹配与分流（精确/通配/正则/GeoIP/GeoSite）
- 缓存（内存/Redis/两级分层）
- 广告/恶意域名过滤
- EDNS Client Subnet 处理
- 速率限制与访问控制

最终搭建出一个高性能、高度可定制的 DNS 服务。

**适用场景**：家庭/企业网络 DNS 分流、广告过滤、DNS 透明代理、CDN 优化、上游冗余与故障转移。

## 核心特性

| 分类 | 能力 |
|---|---|
| **DNS 协议** | UDP、TCP、DNS-over-TLS (DoT)、DNS-over-HTTPS (DoH)、DNS-over-QUIC (DoQ) |
| **路由匹配** | 查询类型、域名（精确/通配/正则）、客户端 IP、响应 IP、CNAME、GeoIP/GeoSite |
| **上游转发** | 多上游并发查询、负载均衡、自动故障转移、UDP 丢包自动重试 |
| **缓存** | 内存 LRU 缓存、Redis 持久化缓存、两级分层缓存 |
| **分流** | 按域名/地理/IP 将不同请求发送到不同上游 |
| **过滤** | Hosts 文件、域名集合、IP 集合黑/白名单、黑洞响应 |
| **ECS 控制** | EDNS Client Subnet 发送/清理/双栈处理 |
| **可观测性** | Prometheus 指标、结构化日志、HTTP API |
| **双栈** | 自动/手动 IPv4/IPv6 偏好选择（带缓存） |

## 架构概览

```
DNS 客户端
    │
    ├── UDP Server ──────────────╮
    ├── TCP Server ──────────────┤
    ├── QUIC Server (DoQ) ───────┤
    └── HTTP Server (DoH) ───────┤
                                  ▼
                         EntryHandler（超时、校验）
                                  │
                                  ▼
                         Sequence（插件执行链）
                                  │
                    ┌─────────────┼─────────────┐
                    ▼             ▼             ▼
                Matcher       Executable    RecursiveExec
              (条件判断)     (执行动作)     (fallback 等)
                    │             │             │
                    └─────────────┼─────────────┘
                                  ▼
                           上游 DNS 服务器
```

所有 DNS 请求与响应通过 `query_context.Context` 承载，在插件链中逐级流动。

## 快速开始

### 从 Release 下载

前往 [Releases](https://github.com/IrineSistiana/mosdns/releases) 下载对应平台的预编译二进制文件，解压后直接运行：

```bash
./mosdns start -c config.yml
```

预编译包覆盖以下平台：linux (amd64/arm/arm64/mips64le/mipsle)、darwin (amd64/arm64)、freebsd (amd64)。

### 从源码构建

```bash
# 需要 Go 1.26+

# 克隆仓库
git clone https://github.com/IrineSistiana/mosdns.git
cd mosdns

# 构建（必须关闭 CGO）
CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(git describe --tags --long --always)" -trimpath -o mosdns

# 运行
./mosdns start -c config.yml
```

### Docker

```bash
docker run -d --name mosdns \
  -v $PWD/config.yml:/config.yml \
  irinesistiana/mosdns start -c /config.yml
```

## 配置简介

mosdns 使用 YAML 配置文件，通过 `tag` 标记插件并在执行链中按名称引用：

```yaml
log:
  level: info                     # 日志级别: debug/info/warn/error

api:
  http: ":8080"                   # HTTP API 监听地址（可选）

include:                          # 引入其他配置文件
  - "rules.yml"

plugins:
  # 上游定义
  - tag: "ali_dns"
    type: "forward"
    args:
      upstreams:
        - addr: "https://dns.alidns.com/dns-query"

  # 缓存
  - tag: "cache"
    type: "cache"
    args:
      size: 1024

  # 域名集合（广告过滤）
  - tag: "ad_domains"
    type: "domain_set"
    args:
      files:
        - "data/geosite.dat:category-ads"

  # 执行链路
  - tag: "main_sequence"
    type: "sequence"
    args:
      - matches: "qname $ad_domains"
        exec: "black_hole 0.0.0.0"
      - exec: "$cache"
      - exec: "$ali_dns"
```

详细配置教程请参阅 [Wiki](https://irine-sistiana.gitbook.io/mosdns-wiki/)。

## 插件目录

### 执行插件 (executable) — 28 种

| 插件 | 功能 |
|---|---|
| `forward` | DNS 上游转发（UDP/TCP/DoT/DoH/DoQ） |
| `sequence` / `fallback` | 插件执行链编排 / 故障备降 |
| `cache` | 内存缓存 / Redis 持久化缓存 / 两级分层缓存 |
| `hosts` | 本地 Hosts 文件解析 |
| `domain_map` | 域名→IP 静态映射 |
| `redirect` | DNS 请求重定向 |
| `black_hole` | 黑洞/丢弃响应（屏蔽指定域名） |
| `ttl` | 修改响应 TTL |
| `reverse_lookup` | 反向查找 A/AAAA → PTR |
| `dual_selector` | IPv4/IPv6 双栈选择 |
| `ecs_handler` | EDNS Client Subnet 控制 |
| `forward_edns0opt` | EDNS0 Option 转发控制 |
| `rate_limiter` | 客户端速率限制 |
| `ipset` / `nftset` | 自动管理 ipset/nftables set |
| `metrics_collector` | Prometheus 指标采集 |
| `query_summary` | 查询统计汇总 |
| `drop_resp` | 按条件丢弃响应 |
| `sleep` / `debug_print` | 调试工具 |
| `network_interface` | 按网卡接口索引（配合 Unix Socket） |
| `arbitrary` | 自定义 Lua 脚本处理 |

### 匹配器 (matcher) — 18 种

| 匹配器 | 说明 |
|---|---|
| `qtype` / `qname` / `qclass` | 查询类型、域名、类 |
| `client_ip` / `client_interface` | 客户端 IP / 网络接口 |
| `cname` / `resp_ip` / `ptr_ip` | CNAME、响应 IP、PTR IP |
| `has_resp` / `has_wanted_ans` / `rcode` | 响应状态判断 |
| `random` | 随机概率匹配 |
| `string_exp` | 字符串表达式（支持正则） |
| `base_domain` / `base_int` / `base_ip` | 基础域名/整数/IP 匹配 |
| `env` | 环境变量匹配 |
| `has_dot` | 主机名是否含点 |

### 数据源 (data_provider) — 4 种

| 数据源 | 说明 |
|---|---|
| `domain_set` | 域名集合（支持 geosite 和纯文本列表） |
| `geoip` | GeoIP 地理位置数据库 |
| `geosite` | GeoSite 域名分类数据库 |
| `ip_set` | IP 地址集合 |

### 服务器 (server) — 4 种

TCP / UDP / QUIC (DoQ) / HTTP (DoH) 监听器。

### 混合插件 (mark)

`mark` 可对查询上下文打标签，后续匹配器可基于标签进行判断（兼具匹配与执行能力）。

## 参考链接

| 链接 | 说明 |
|---|---|
| [Wiki](https://irine-sistiana.gitbook.io/mosdns-wiki/) | 完整文档、配置教程 |
| [Releases](https://github.com/IrineSistiana/mosdns/releases) | 预编译文件下载与更新日志 |
| [Docker Hub](https://hub.docker.com/r/irinesistiana/mosdns) | Docker 镜像 |
| [Issues](https://github.com/IrineSistiana/mosdns/issues) | Bug 反馈与功能建议 |
| [Discussions](https://github.com/IrineSistiana/mosdns/discussions) | 配置讨论与分享 |

## 许可证

[GPL-3.0](LICENSE)

---

> 本仓库 [vizaxe/mosdns](https://github.com/vizaxe/mosdns) fork 自 [IrineSistiana/mosdns](https://github.com/IrineSistiana/mosdns) (v5.x)。
