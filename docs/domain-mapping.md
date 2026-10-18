# MosDNS 域名映射桥接

`domain-mapping` 在真实 IP 连接首次分流前，向 MosDNS 查询该客户端最近收到的 DNS 域名关联。映射只提供域名规则所需的证据，保持客户端选择的目标 IP 和端口，适用于 MosDNS 负责解析、Mihomo 接管透明代理流量的部署。

这是两端配套扩展：MosDNS 必须安装并启用 `domain_mapping` 插件，Mihomo 必须使用包含本功能的内核。已有的 MosDNS `reverse_lookup` 接口不能直接替代下面的 v1 接口。

长期维护入口为 [Mihomo fork 的 Meta](https://github.com/LianZiZhou/mihomo/tree/Meta) 与 [MosDNS fork 的 main](https://github.com/LianZiZhou/mosdns/tree/main)。`Meta` 是此 Mihomo fork 的默认分支。

## 配置与部署

将以下配置合并进现有 Mihomo 配置；入站监听、代理和规则沿用自己的部署。可复制的片段见 [examples/domain-mapping.yaml](examples/domain-mapping.yaml)。

```yaml
domain-mapping:
  enable: true
  timeout: 50
  providers:
    - name: mosdns
      type: mosdns-http-v1
      endpoint: http://127.0.0.1:9091/plugins/domain_index/v1/lookup
```

| 字段 | 行为 |
| --- | --- |
| `enable` | 默认 `false`。开启后至少配置一个 provider。 |
| `timeout` | 整数毫秒；省略或填写 `0` 使用 **50 ms**。负值无效。多个 provider、HTTP 读写、JSON 解析和等待共享一次查询的总预算；预算到期后不接受命中。 |
| `providers` | 按配置顺序查询；第一个有效命中结束查询，未命中或失败时在剩余预算内继续后续 provider。 |
| `name` | 必填且不能重名，用于连接诊断。 |
| `type` | 当前支持 `mosdns-http-v1`。 |
| `endpoint` | 完整 HTTP(S) lookup URL；`domain_index` 必须与 MosDNS 插件 tag 一致。不能包含 URL 用户名、密码或 fragment。 |

该功能独立于 `dns.enable` 和 `sniffer.enable`：关闭内置 DNS、关闭报文嗅探时仍可使用。若开启现有 sniffer，外部映射未命中时仍有原来的嗅探回退路径。

MosDNS API 应只监听可信本机地址，例如 `127.0.0.1:9091`。这里的 provider 未增加身份认证参数，不能将无认证的索引 API 暴露到不可信网络。HTTP 查询直接连接配置的服务，不使用系统 HTTP 代理，也不经过 Mihomo 自己的代理选择；不接受 HTTP 重定向。

客户端经过 dnsmasq 时，MosDNS 需要从可信 dnsmasq 对端的完整 ECS 恢复客户端地址，使 lookup 中的 `client` 与 DNS 索引身份一致。现有按客户端分配上游的策略，应在恢复身份后执行，并按上游策略隔离缓存。完整客户端 ECS 只用于受信任的本地一跳，不应原样转发至公网。

## 分流行为与连接诊断

查询只针对没有显式入站域名、拥有真实目标 IP 的连接。显式入站域名及已配置 fake-IP 池中的地址沿用既有处理；fake-IP 映射缺失时，也不会借外部结果绕过原错误处理。

- **TCP**：每条新连接在内置真实 IP 映射和报文嗅探之前查询外部 provider。
- **UDP**：每个新 NAT 会话在首次异步选路协程中查询，不阻塞公共收包入口；等待期间首包进入既有发送队列。命中会释放 QUIC 嗅探状态，保留待发送数据。
- **命中**：写入仅供规则使用的 `DomainMappingHost`，跳过报文嗅探和内置 IP 到域名的替换，不修改 `Host` 或 `DstIP`，也不重新解析返回的域名。
- **未命中、异常或超时**：继续已有的内置映射、嗅探及规则流程。UDP 保留其原有的嗅探与元数据预处理顺序。

`Metadata.RuleHost()` 的优先级为 `DomainMappingHost → SniffHost → Host`。因此 DOMAIN、DOMAIN-SUFFIX 等域名规则可使用映射证据，拨号仍使用原目标 IP。此改动没有调整负载均衡按 `Host` 计算哈希等既有语义。

连接 API 的 metadata 新增如下字段，旧面板可能仍只展示 `host` 或目标 IP：

```json
{
  "host": "",
  "destinationIP": "203.0.113.20",
  "domainMappingHost": "service.example",
  "domainResolution": {
    "provider": "mosdns",
    "source": "a",
    "lookupStatus": "hit",
    "scope": "client",
    "conflict": false,
    "expiresAt": "2026-10-18T12:05:00+08:00"
  }
}
```

`lookupStatus` 可为 `hit`、`miss`、`error`、`timeout`、`canceled`。关闭桥接或因显式域名、fake-IP 而跳过查询时不新增诊断对象。`provider` 表示配置中的服务名，`source` 表示 DNS 证据类型；MosDNS 当前来源包括 `a`、`aaaa`、`https_hint`、`svcb_hint`。只有成功命中时，`scope`、`conflict` 和有效期才应用于规则证据；错误诊断可能保留服务返回的原字段。

相同客户端 IP 与目标 IP 的并发查询共享一个在途请求。单个调用方取消等待，不会取消其他调用方共享的查询。完成后的成功结果、未命中和错误均不缓存：共享 IP 的域名归属可能在旧记录 TTL 到期前发生变化。HTTP 连接本身继续复用，不执行应用层重试。

共享请求使用固定截止时间，后加入者只等待剩余预算；已过期但尚未退出的 provider 不会让新请求继承旧超时。等待方独立执行超时回退，provider 在截止时间之后返回的结果不会应用到分流。

## HTTP API v1

请求：

```http
GET /plugins/domain_index/v1/lookup?ip=203.0.113.20&client=192.168.1.8
Accept: application/json
```

`ip` 是目标 IPv4/IPv6；`client` 是入站源 IP，不包含端口。源 IP 不可用时省略 `client`，由 MosDNS 查询全局索引。IPv4 映射 IPv6 地址先转换成普通 IPv4；IPv6 参数由 HTTP 客户端自动进行 URL 编码。

命中示例（时间仅演示格式，实时应答必须填写实际尚未过期的时间）：

```json
{
  "version": 1,
  "status": "hit",
  "ip": "203.0.113.20",
  "domain": "service.example",
  "scope": "client",
  "source": "a",
  "observed_at": "2026-10-18T12:00:00+08:00",
  "expires_at": "2026-10-18T12:05:00+08:00",
  "conflict": false,
  "candidates": [
    {
      "domain": "service.example",
      "source": "a",
      "observed_at": "2026-10-18T12:00:00+08:00",
      "expires_at": "2026-10-18T12:05:00+08:00"
    }
  ]
}
```

未命中示例：

```json
{
  "version": 1,
  "status": "miss",
  "ip": "203.0.113.20",
  "scope": "global",
  "conflict": false,
  "candidates": []
}
```

两者均返回 HTTP 200；非法请求参数由 MosDNS 返回 400。客户端要求响应 `version=1`、`ip` 与请求匹配、状态为 `hit` 或 `miss`；命中时还要求合法域名、`scope` 为 `client` 或 `global`，且 **`expires_at` 必填并晚于当前时间**。时间使用 Go `time.Time` 兼容的 RFC3339/RFC3339Nano 格式。域名统一小写并去除一个末尾点。非 200 响应、无效 JSON、过期证据或超过 1 MiB 的应答均按查询失败回退。

MosDNS 优先客户端索引，再回退全局索引。多个有效候选存在时，服务端选择最近观察的域名并设置 `conflict=true`；Mihomo 使用服务返回的选中域名，诊断字段保留冲突信息。这是兼容既定分流行为的选择，不能消除共享 IP 的歧义。

MosDNS 的 `candidates` 最多列出最近 32 个不同域名，仅供诊断，不代表索引的完整内容。Mihomo HTTP provider 校验整份 JSON 的语法，但不解码和复制候选列表；分流使用顶层选中域名、有效期及冲突标记。旧服务返回的较大候选列表仍受 1 MiB 响应上限约束。

## 开发扩展与热重载

实现位于 `component/domainmapping`，Go 扩展接口为：

```go
type Provider interface {
    Lookup(ctx context.Context, clientIP, destinationIP netip.Addr) (Result, error)
    CloseIdleConnections()
}
```

这是编译期扩展，不加载动态 `.so` 插件。增加 provider 类型时，实现接口，并同时扩展 `Validate` 的配置校验和 `New` 中的 provider 构造分派。`Lookup` 必须遵守 `ctx`，返回合法且有效的域名证据，不改写连接目的地址；设置 `Result.Provider` 供诊断使用。自定义实现应提供与 HTTP v1 相当的证据校验，运行时不会替其验证任意结果。

运行时可以停止等待并拒绝过期结果，但无法强制终止 Go goroutine。扩展 provider 必须限制自身工作量、响应取消并释放资源，不能依靠等待方超时回收其内部任务。

`Runtime` 负责查询总预算和并发合并，`Manager` 使用原子指针替换运行时，独立于 `resolver.DefaultHostMapper`。配置解析先校验配置；应用配置时切换到新运行时。已有在途请求仍由旧运行时完成，不因重载中止；旧运行时退休时关闭空闲 HTTP 连接，并在请求完成后再次回收连接。关闭 `enable` 后新连接不再查询，已建立 TCP/UDP 会话保持既有路由。

新增 UDP 多包嗅探包装器若保留嗅探状态，可实现可选 `SkipSniff()` 方法：只清理嗅探缓冲和等待状态，不关闭底层 `PacketSender`，也不丢弃排队数据。现有 QUIC 包装器已经实现该方法。

## 能力边界与验证

ECH、不可识别的 QUIC 数据、分片或报文嗅探失败不会阻止已有 DNS 映射参与分流。本功能依赖实际观察到的 DNS 关联，不解密 ECH 内层域名。客户端绕过 MosDNS、索引重启后尚未积累、TTL 过期或不同域名共享目标 IP 时，仍可能未命中或出现歧义。

DNS 请求的 IPv4、IPv6、隐私地址并不会自动关联成同一设备。跨地址族可能回退全局索引。HTTP/2、HTTP/3 连接合并和多路复用还可能让多个域名共用已建立的连接；首次分流不能为同一连接内每个后续请求重新选择出站，因此不承诺所有实际流量 100% 正确归因。

Mihomo 既有 UDP NAT key 使用源地址和源端口。同一 UDP socket 改变目标时可能继续复用原会话和路由；本功能只在创建 NAT 会话时查询。验证独立 UDP 连接应使用新的源端口或等待原会话结束。

在仓库根目录执行：

```sh
go test ./component/domainmapping ./constant ./component/sniffer ./tunnel ./config ./hub/executor
go vet ./component/domainmapping ./constant ./component/sniffer ./tunnel ./config ./hub/executor
```

测试覆盖协议验证、过期、超时恢复、HTTP 连接复用、无正负结果缓存、并发合并与独立取消、客户端隔离、多 provider 顺序、重载、独立于 DNS 的配置、规则域名和目的 IP 保持、fake-IP/显式域名兼容、TCP 跳过嗅探、UDP 入口非阻塞和排队数据保留。

有受支持的 C 编译器及 CGO 环境时，可额外运行：

```sh
go test -race ./component/domainmapping ./component/sniffer ./tunnel
```

当前 Windows 开发环境的 `CGO_ENABLED=0` 且没有 GCC，race 检查尚未完成。单元测试通过不代表真实 OpenWrt 的透明代理、dnsmasq 缓存、ECS 转发以及设备差异已经完成验收；这些需要单独做完整链路测试。

## 在 Meta 跟进上游

`origin` 指向自己的 fork，`upstream` 指向 `https://github.com/MetaCubeX/mihomo.git`。保持 `Meta` 为维护分支，合并上游内核的同名分支以保留桥接提交历史。在工作区干净时执行；如有冲突，解决后测试再推送：

```sh
git switch Meta
git fetch upstream
git merge upstream/Meta
go test ./...
git push origin Meta
```

MosDNS 在其 `main` 分支采用同样流程。涉及域名映射协议、DNS 入口或 TCP/UDP 选路的上游更新，还应重跑 MosDNS 仓库的 `scripts/domain_bridge_smoke.py`。
