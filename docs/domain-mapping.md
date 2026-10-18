# MosDNS 域名映射桥接

`domain-mapping` 在真实 IP 连接首次分流前，向 MosDNS 查询该客户端最近收到的 DNS 域名关联。映射只提供域名规则所需的证据，保持客户端选择的目标 IP 和端口，适用于 MosDNS 负责解析、Mihomo 接管透明代理流量的部署。

这是两端配套扩展：MosDNS 必须安装并启用 `domain_mapping` 插件，Mihomo 必须使用包含本功能的内核。已有的 MosDNS `reverse_lookup` 接口不能直接替代下面的 v1 接口。

长期维护入口为 [Mihomo fork 的 Meta](https://github.com/LianZiZhou/mihomo/tree/Meta) 与 [MosDNS fork 的 main](https://github.com/LianZiZhou/mosdns/tree/main)。`Meta` 是此 Mihomo fork 的默认分支。

## 客户端真实 IP 分配与共享候选（v2）

新部署推荐 `mosdns-http-v2`，配合 MosDNS 的 `allocation.client_scope`。v1 保留原行为，以便独立升级和回滚。v2 不把共享地址的最新 DNS 域名当作唯一归属。

```yaml
domain-mapping:
  enable: true
  timeout: 50
  max-connections: 16
  max-inflight: 128
  conflict-policy: proxy-preferred
  conflict-fallback: REJECT
  providers:
    - name: mosdns
      type: mosdns-http-v2
      endpoint: http://127.0.0.1:9091/plugins/domain_index/v2/lookup
```

主机制是在 MosDNS 向客户端应答前，从该域名的真实候选中挑选地址。按客户端分别占用，已有分配稳定复用；只有获准共享的域名可复用其他域名的地址。筛选只作用于最终响应，不修改全量上游缓存。没有可用候选时保留原答案，并记录全部返回地址带来的共享。

共享约束固定如下：未命中域名规则的域名之间允许共享；只有未命中路径确定走 DIRECT，显式 DIRECT 域名才可加入同一共享类。其他情况按域名隔离，包括默认出口为代理组时的显式 DIRECT 域名。相同代理组、组当前选中 DIRECT、分类尚未查到，都不是扩大共享的依据。仍正常执行连接的 IP、端口、进程等规则。

Mihomo 提供 `POST /dns-policy/classify` 权威分类接口。它使用控制器 Bearer 认证，要求已设置控制器 secret，且仅接受实际 loopback 对端；不信任转发头。请求为 `{"version":1,"queries":[{"domain":"example.com","client":"192.168.6.180"}]}`，最多 64 项及 32 KiB。响应含 `version`、`epoch`、`valid_for_ms` 和同序 `results`，每项含 `domain`、`client`、`class`、`share_eligible`。分类为 `unmatched`、`direct`、`isolated` 或 `unknown`。未知连接端口、协议、进程的条件采用保守判断，不拿 DNS 查询的端口和协议代替应用连接属性。

MosDNS 异步合批获取分类并本地缓存，未知或过期分类暂时独占；分类服务不可用不阻塞 DNS。配置及规则集变化会改变分类 epoch。已有客户端地址不会因规则更新而消失；曾经兼容的共享域名在规则变化后可能成为冲突，连接阶段仍按实际候选与当前规则处理。

v2 lookup 使用 `GET /plugins/domain_index/v2/lookup?ip=...&client=...`，不发送 v1 的 `view` 参数。唯一结果为 `status:hit`、`complete:true`、`total:1` 及合法 `domain`；共享或历史不完整为 `status:ambiguous`，`domain` 必须为空，携带 `domains`、`total`、`complete`、`generation` 和可选 `reason`。已知结果仍需合法 scope 和未来 `expires_at`。候选最多接收 1024 个，响应上限仍为 1 MiB。不完整集合不能用于宣称策略一致。v1 的最多 32 项诊断列表不会用于 v2 路由。

- 唯一域名按正常规则分流，保持实际目的 IP。
- 完整共享候选逐一评估完整规则，策略一致时直接使用该策略，无需协议 sniff。
- 策略冲突时才应用 `conflict-policy`。`proxy-preferred`（默认）保护候选实际命中的显式域名代理规则，显式拒绝优先；多个保护目标按完整规则路径排序。`rule-priority` 则直接选择配置顺序中最早的候选结果。二者都可能影响共享地址上的其他域名，这是兜底策略，不能视作准确识别。
- 候选不完整、规则快照失败或评估预算耗尽时，先按原顺序检查能够证明不依赖未知域名的连接属性规则，例如前置 IP REJECT；遇到无法确定的域名条件后才使用 `conflict-fallback`（默认 REJECT）。可显式设置需要保护的策略组。该策略必须存在，不能使用 PASS、REMATCH 等非终止策略；UDP 还要求支持 UDP。错误配置会使该连接选路失败。

共享结果不会填写虚假的 `domainMappingHost`，也不会因没有唯一域名就意外触发 sniff。诊断额外包含 `candidateCount`、`complete`、`generation`、`decision`（`consensus` 或 `fallback`）、`policy`、`policyDomain`（仅冲突决策的依据）和 `reason`。实际 TCP/UDP 目标 IP 保持不变；已有连接不重新分流。

AND/OR/NOT 在单个候选内评估，SUB-RULE 按完整子规则路径排序。规则、provider 和 GEOSITE 使用冻结视图；每个候选先在私有元数据上完成 REMATCH 的纯转换，再比较最终策略，只有获选路径提交统计及元数据。未就绪或含无法解析条目的 provider 不能证明未命中，配置挂起期间也不签发共享分类。处理过程有 50 ms 检查预算、一百万步和递归限制，失败进入显式兜底；这不承诺硬实时上限，调度、GC、原生规则操作及正则超时检测仍可能有额外延迟。普通唯一查询不执行多候选评估，也不新增分类 RPC。

DNS TTL 不证明客户端已经忘记地址。迁移需要导入已有观察并保守保护未完整导出的历史，不能通过重启清空占用来制造独占。DNSSEC、复杂服务绑定等无法安全筛选的答案保持原样；HTTP/2、HTTP/3 的跨域连接复用也不能仅凭 DNS 对每个加密请求重新分流。

## 配置与部署（v1 兼容模式）

将以下配置合并进现有 Mihomo 配置；入站监听、代理和规则沿用自己的部署。可复制的片段见 [examples/domain-mapping.yaml](examples/domain-mapping.yaml)。

```yaml
domain-mapping:
  enable: true
  timeout: 50
  max-connections: 16
  max-inflight: 128
  providers:
    - name: mosdns
      type: mosdns-http-v1
      endpoint: http://127.0.0.1:9091/plugins/domain_index/v1/lookup
```

| 字段 | 行为 |
| --- | --- |
| `enable` | 默认 `false`。开启后至少配置一个 provider。 |
| `timeout` | 整数毫秒；省略或填写 `0` 使用 **50 ms**。负值无效。多个 provider、HTTP 读写、JSON 解析和等待共享一次查询的总预算；预算到期后不接受命中。 |
| `max-connections` | 每个 HTTP provider 的连接上限；省略或 `0` 使用 **16**。包括正在拨号、活动及空闲连接。负值无效。 |
| `max-inflight` | 当前运行时全部未完成的共享查询上限；省略或 `0` 使用 **128**。等待连接以及超时后仍未退出的 provider 工作也计入。负值无效。 |
| `providers` | 按配置顺序查询；第一个有效命中结束查询，未命中或失败时在剩余预算内继续后续 provider。 |
| `name` | 必填且不能重名，用于连接诊断。 |
| `type` | 支持 `mosdns-http-v1` 和 `mosdns-http-v2`，须与 endpoint 版本对应。 |
| `endpoint` | 完整 HTTP(S) lookup URL；`domain_index` 必须与 MosDNS 插件 tag 一致。不能包含 URL 用户名、密码或 fragment。 |

该功能独立于 `dns.enable` 和 `sniffer.enable`：关闭内置 DNS、关闭报文嗅探时仍可使用。若开启现有 sniffer，外部映射未命中时仍有原来的嗅探回退路径。

MosDNS API 应只监听可信本机地址，例如 `127.0.0.1:9091`。这里的 provider 未增加身份认证参数，不能将无认证的索引 API 暴露到不可信网络。HTTP 查询直接连接配置的服务，不使用系统 HTTP 代理，也不经过 Mihomo 自己的代理选择；不接受 HTTP 重定向。

客户端经过 dnsmasq 时，MosDNS 需要从可信 dnsmasq 对端的完整 ECS 恢复客户端地址，使 lookup 中的 `client` 与 DNS 索引身份一致。现有按客户端分配上游的策略，应在恢复身份后执行，并按上游策略隔离缓存。完整客户端 ECS 只用于受信任的本地一跳，不应原样转发至公网。

## 分流行为与连接诊断

查询只针对没有显式入站域名、拥有真实目标 IP 的连接。显式入站域名及已配置 fake-IP 池中的地址沿用既有处理；fake-IP 映射缺失时，也不会借外部结果绕过原错误处理。

- **TCP**：每条新连接在内置真实 IP 映射和报文嗅探之前查询外部 provider。
- **UDP**：每个新 NAT 会话在首次异步选路协程中查询，不阻塞公共收包入口；等待期间首包进入既有发送队列。命中会释放 QUIC 嗅探状态，保留待发送数据。
- **命中**：写入仅供规则使用的 `DomainMappingHost`，跳过报文嗅探和内置 IP 到域名的替换，不修改 `Host` 或 `DstIP`，也不重新解析返回的域名。
- **未命中、容量饱和、异常或超时**：继续已有的内置映射、嗅探及规则流程。UDP 保留其原有的嗅探与元数据预处理顺序。

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

`lookupStatus` 可为 `hit`、`miss`、`error`、`timeout`、`canceled`、`overloaded`、`retired`。`overloaded` 表示当前运行时的共享查询容量已满，因此没有发起新的 provider 查询；`retired` 表示该调用获取的旧运行时已在重载期间退休，同样不再接纳新查询。关闭桥接或因显式域名、fake-IP 而跳过查询时不新增诊断对象。`provider` 表示配置中的服务名，`source` 表示 DNS 证据类型；MosDNS 当前来源包括 `a`、`aaaa`、`https_hint`、`svcb_hint`。只有成功命中时，`scope`、`conflict` 和有效期才应用于规则证据；错误诊断可能保留服务返回的原字段。

相同客户端 IP 与目标 IP 的并发查询共享一个在途请求。单个调用方取消等待，不会取消其他调用方共享的查询。完成后的成功结果、未命中和错误均不缓存：共享 IP 的域名归属可能在旧记录 TTL 到期前发生变化。HTTP 连接本身继续复用，不执行应用层重试。

MosDNS 支持独立的证据保留策略，推荐在其 `domain_mapping.args` 设置 `size: 262144` 和 `retention: {mode: lru, ttl_multiplier: 10, min_window: 300, max_window: 86400}`。`lru` 不因 DNS TTL 或路由窗口届满删除映射，直到容量淘汰；同客户端路由命中刷新有效期至至少 `now + clamp(10 × baseTTL, 300s, 86400s)`。例如 TTL 300 秒，每次命中延至至少 50 分钟后。仅修改 Mihomo 的 DNS cache 大小或 fake-IP TTL 不会改变 MosDNS 这份索引。完整配置见 [MosDNS 保留策略](https://github.com/LianZiZhou/mosdns/blob/main/docs/mihomo-bridge.md#dns-到期路由续期与容量淘汰)。

使用新策略时，连接诊断额外包含 `dnsExpiresAt`、`dnsStale`（为 true 时输出）和 `retentionMode`；`expiresAt` 表示查询返回时的路由有效期。真实 DNS 截止已过去而路由证据仍有效是正常情况。上述字段是创建连接时的快照，已有连接不随 DNS TTL 或路由有效期到期而重新分流。Mihomo 仍校验 `expires_at` 晚于当前时间，不会因 `dns_stale=true` 接受已过期的路由租约。

共享请求使用固定截止时间，后加入者只等待剩余预算；已过期但尚未退出的 provider 不会让新请求继承旧超时。等待方独立执行超时回退，provider 在截止时间之后返回的结果不会应用到分流。

### 资源与延迟边界

默认最多接纳 128 个尚未结束的共享查询，所有 provider 共用这个运行时额度。等待 HTTP 连接的查询已经占用额度，容量满后新的不同查询立即以 `overloaded` 回退，没有另外增长的等待队列。已有相同客户端/IP 且尚未到期的查询仍可加入共享。查询超时之后，如果 provider 尚未退出，额度继续保留到它实际结束；反复请求不能绕过上限积累后台工作。

每个 provider 使用独立连接池，默认最多 16 条连接，空闲池也使用相同上限。额度从 TCP 拨号开始持有，直到实际连接关闭后释放，HTTP/2 协议接管或 GOAWAY 不会提前释放额度。普通本机 HTTP 使用 HTTP/1.1 长连接；HTTPS 保留正常证书验证及 HTTP/2 协商，HTTP/2 可在同一连接上承载多个查询，因此连接数和在途查询数是不同的限制。流名额不足时在原查询预算内等待。未复用连接时才增加建连成本，复用时仍需一次 HTTP 请求往返。多个 provider 的连接上限分别计算。

为避免 HTTP/2 依赖库在多个请求同时预留流时互相等待，每个 HTTPS provider 串行处理流预留及请求头发送阶段，已发送请求的响应仍可并行。新建 HTTP/2 连接时，第一个请求收到响应头或结束后才放行后续请求，确保服务端初始 SETTINGS 已处理；首个响应较慢时会暂时延迟后续查询，但等待仍计入各自原预算，不增加探测请求或额外往返。连接重建后同样适用。

等待连接、TCP 建立及 TLS 握手沿用最初查询的绝对截止时间；不会在排到连接或进入握手时重新获得完整预算。实现将查询的截止时间及取消信号恢复到 Transport 的拨号上下文，避免请求已超时但后台仍沿用默认 30 秒拨号时间。为使单个拨号额度对应最多一个 TCP 建连尝试，不并行竞速 IPv4/IPv6；本机部署建议使用字面 IP。默认 50 毫秒是本桥接等待预算，不是整个业务建连的硬实时上限：调度和 GC 可能带来额外延迟，回退后的原有嗅探与出站拨号也另有成本。

MosDNS 的 `domain_mapping.args.api` 可配置 `max_concurrent`（默认 128）及 `timeout`（默认 1000 毫秒）；lookup 和 stats 共用服务端额度，超额请求和查询超时尝试返回 HTTP 503。请求体读取与应答写入共享服务端的绝对截止时间，包括 HTTP 自动排空未完成的请求体及最后 flush，避免声明 Content-Length 或分块请求体后停止发送的连接长期占住额度。若截止时间已到或 headers 已经发出，客户端可能只收到连接关闭或不完整应答，不能保证 503 送达。非 200 响应或不完整响应按 provider 错误处理，可在剩余预算内继续下一个 provider；服务端 `/v1/stats` 的 `api_rejected` 和 `api_timeouts` 可辅助区分服务端容量与超时。服务端额度统计 handler 执行，不是整个 HTTP 服务器的 socket 上限；该超时从进入插件 handler 开始，不包含此前的请求头读取。降低上限会减少资源占用，也可能降低突发时的映射成功率，需结合目标设备的 CPU、内存及 DNS 应答延迟调节。

## HTTP API v1

请求：

```http
GET /plugins/domain_index/v1/lookup?ip=203.0.113.20&client=192.168.1.8&view=route
Accept: application/json
```

`ip` 是目标 IPv4/IPv6；`client` 是入站源 IP，不包含端口。源 IP 不可用时省略 `client`，由 MosDNS 查询全局索引。IPv4 映射 IPv6 地址先转换成普通 IPv4；IPv6 参数由 HTTP 客户端自动进行 URL 编码。

Mihomo 始终设置 `view=route`，请求仅包含选中域名证据的精简 JSON，hit 和 miss 都不发送 `candidates`。在 MosDNS 的 `sliding` / `lru` 模式下，该视图还表示真实选路访问，可刷新访问 LRU，客户端命中还续期；默认完整视图只诊断、不续期。全局命中不延长其他客户端记录的存储有效期。旧 MosDNS 忽略 `view` 参数并返回完整 v1 响应时仍然兼容，不增加能力探测请求。人工诊断可省略 `view` 或设置 `view=full`。

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
  "conflict": false
}
```

未命中示例：

```json
{
  "version": 1,
  "status": "miss",
  "ip": "203.0.113.20",
  "scope": "global",
  "conflict": false
}
```

两者均返回 HTTP 200；非法请求参数由 MosDNS 返回 400。客户端要求响应 `version=1`、`ip` 与请求匹配、状态为 `hit` 或 `miss`；命中时还要求合法域名、`scope` 为 `client` 或 `global`，且 **`expires_at` 必填并晚于当前时间**。时间使用 Go `time.Time` 兼容的 RFC3339/RFC3339Nano 格式。域名统一小写并去除一个末尾点。非 200 响应、无效 JSON、过期证据或超过 1 MiB 的应答均按查询失败回退。

MosDNS 优先客户端索引，再回退全局索引。多个保留的域名候选存在时，服务端选择最近实际 DNS 观察的域名并设置 `conflict=true`；路由查询续期只改变访问热度和有效期，不改变 DNS 观察顺序。Mihomo 使用服务返回的选中域名，诊断字段保留冲突信息。LRU 保留会延长歧义记录的寿命，不能证明选中的域名就是应用真实意图。

v1 可选字段 `dns_expires_at`、`dns_stale`、`retention_mode` 只用于诊断；`expires_at` 始终是 provider 接受命中的有效期判据。旧服务不提供这些字段时保持原行为，旧 Mihomo 也可忽略新字段并使用新 MosDNS 返回的未来路由有效期。新模式不会增加协议版本探测或额外查询。

MosDNS 完整视图中的 `candidates` 最多列出最近 32 个不同域名，仅供诊断，不代表索引的完整内容。收到完整响应时，Mihomo HTTP provider 校验整份 JSON 的语法，但不解码和复制候选列表；分流使用顶层选中域名、有效期及冲突标记。更早服务返回的较大候选列表仍受 1 MiB 响应上限约束。精简查询直接使用 MosDNS 维护的最新记录及不同域名计数，不需要先构造完整诊断列表再丢弃。

## 开发扩展与热重载

实现位于 `component/domainmapping`，Go 扩展接口为：

```go
type Provider interface {
    Lookup(ctx context.Context, clientIP, destinationIP netip.Addr) (Result, error)
    CloseIdleConnections()
}
```

这是编译期扩展，不加载动态 `.so` 插件。增加 provider 类型时，实现接口，并同时扩展 `Validate` 的配置校验和 `New` 中的 provider 构造分派。`Lookup` 必须遵守 `ctx`，返回合法且有效的域名证据，不改写连接目的地址；设置 `Result.Provider` 供诊断使用。自定义实现应提供与 HTTP v1 相当的证据校验，运行时不会替其验证任意结果。

运行时可以停止等待并拒绝过期结果，但无法强制终止 Go goroutine。扩展 provider 必须限制自身工作量、响应取消并释放资源，不能依靠等待方超时回收其内部任务。`max-inflight` 限制 Runtime 发起的工作数量，不限制 provider 自行创建的额外 goroutine、连接或内存。provider 可额外实现幂等的 `Close()` 方法，在运行时退休且所有已接纳查询结束后执行终态清理；未实现时仍调用 `CloseIdleConnections()`。

`Runtime` 负责查询总预算、容量限制和并发合并，`Manager` 使用原子指针替换运行时，独立于 `resolver.DefaultHostMapper`。配置解析先校验配置；应用配置时切换到新运行时。已有在途请求仍由旧运行时完成，不因重载中止；旧运行时拒绝新查询，关闭空闲 HTTP 连接，并在全部查询完成后关闭剩余底层连接。收到 HTTP/2 GOAWAY 后，连接退出复用池并等待已有流完成；清理最多等待一个配置的查询预算，随后关闭连接，避免对端保留空闲 TCP 占住最后一个额度。上限按运行时及 provider 计算，重载期间新旧运行时的资源可以暂时并存，并非整个进程永远只有一份连接上限。关闭 `enable` 后新连接不再查询，已建立 TCP/UDP 会话保持既有路由。

新增 UDP 多包嗅探包装器若保留嗅探状态，可实现可选 `SkipSniff()` 方法：只清理嗅探缓冲和等待状态，不关闭底层 `PacketSender`，也不丢弃排队数据。现有 QUIC 包装器已经实现该方法。

## 能力边界与验证

ECH、不可识别的 QUIC 数据、分片或报文嗅探失败不会阻止已有 DNS 映射参与分流。本功能依赖实际观察到的 DNS 关联，不解密 ECH 内层域名。客户端绕过 MosDNS、索引重启后尚未积累、容量淘汰、严格 TTL / sliding 模式到期或不同域名共享目标 IP 时，仍可能未命中或出现歧义。

DNS 请求的 IPv4、IPv6、隐私地址并不会自动关联成同一设备。跨地址族可能回退全局索引。HTTP/2、HTTP/3 连接合并和多路复用还可能让多个域名共用已建立的连接；首次分流不能为同一连接内每个后续请求重新选择出站，因此不承诺所有实际流量 100% 正确归因。

Mihomo 既有 UDP NAT key 使用源地址和源端口。同一 UDP socket 改变目标时可能继续复用原会话和路由；本功能只在创建 NAT 会话时查询。验证独立 UDP 连接应使用新的源端口或等待原会话结束。

在仓库根目录执行：

```sh
go test ./component/domainmapping ./constant ./component/sniffer ./tunnel ./config ./hub/executor
go vet ./component/domainmapping ./constant ./component/sniffer ./tunnel ./config ./hub/executor
```

测试覆盖协议验证、过期、超时恢复、HTTP 连接复用、无正负结果缓存、并发合并与独立取消、客户端隔离、多 provider 顺序、重载、独立于 DNS 的配置、规则域名和目的 IP 保持、fake-IP/显式域名兼容、TCP 跳过嗅探、UDP 入口非阻塞和排队数据保留。资源限制的验收包括连接队列使用原预算、饱和后既有共享仍可加入、迟到 provider 继续占用额度直到退出及 TCP/TLS 取消回收。真实 TLS 回归覆盖 HTTP/2 单流饱和恢复、多流响应并行、冷启动与连接重建后的突发、GOAWAY 清理、活动流退休及 HTTPS HTTP/1.1 回退；跨进程脚本还覆盖新 Mihomo 与忽略 `view` 的旧 API 兼容。

性能验收应同时观察映射查询延迟、DNS 应答延迟和资源峰值，覆盖大索引桶、批量过期、突发新目标及不可用 provider。容量限制与精简 JSON 不构成目标设备 p99 延迟的保证；ARM/MIPS 设备仍需实测。

本轮精简查询与资源限制已通过两仓库的 `go test ./...` 及相关包 `go vet`。Windows 直接可信 ECS 与 WSL Linux amd64 的真实 dnsmasq 2.92 跨进程链路各通过 1000/1000 条 TCP 连接、100/100 个 UDP 会话，覆盖 route/full 一致性、过期回退、重载及旧 API 兼容；Linux 链路同时通过 ECS 策略与缓存隔离、TCP DNS、UDP 截断、相关 HTTPS Additional 及 provider 不可用后的原嗅探回退。Linux arm64 和 mipsle softfloat 的两个内核均交叉编译成功，尚未在目标设备运行。MosDNS 的真实 TCP 回归覆盖阻塞写入、完整/精简/stats 请求的不完整 Content-Length、分块数据与 trailer、超额拒绝后的连接清理及 keepalive 后续请求。这些检查不替代 OpenWRT 实机性能与透明代理验收。

有受支持的 C 编译器及 CGO 环境时，可额外运行：

```sh
go test -race ./component/domainmapping ./component/sniffer ./tunnel
```

Windows 开发环境的 `CGO_ENABLED=0` 且没有 GCC；本轮使用 WSL Linux 的 GCC 执行 race 检查。单元测试通过不代表真实 OpenWrt 的透明代理、dnsmasq 缓存、ECS 转发以及设备差异已经完成验收；这些需要单独做完整链路测试。

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
