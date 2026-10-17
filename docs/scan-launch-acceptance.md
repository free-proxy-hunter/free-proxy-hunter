# free-proxy-scanner 上线验收评估（2026-09-29）

结论：**还不能上线。** 上线不按日历日期，按本文第 3 节的通过/失败标准停止。标准全部满足就可以停，不必再无限开发。

本次没有做全网随机 IP 实扫，也没有复现用户记忆里那一次「扫出来的地址全部不能用」的现场。下面的因果来自当前源码和这次实际跑出的测试，不沿用 2026-04～07 的 plan 结论。

评估范围：`free-proxy-scanner` 的 `internal/scanner/probe`、`validator`（含 `ip_verifier.go`、`post_validator.go`）、`enhanced_scanner`、`reporter`、`cmd/scanner`。默认入口是 `scanner_type=ip_pool`（`internal/config/config.go` 的 `viper.SetDefault("scanner.scanner_type", "ip_pool")`，`cmd/scanner/cmd/scan.go` 在该值下构造 `scanner.NewIPScanner`）。

## 1. 现在的扫描链路做了什么

上报出去的 IP 是被扫到的那个地址，不是出口 IP。两条链路：

| 入口 | 识别 | 是否证明「真的转发」 | 是否比较出口 IP ≠ 扫描器自身 IP | 谁上报 |
|---|---|---|---|---|
| 默认 `IPScanner.scanIPTask`（`internal/scanner/ip_scanner_task.go`） | `probe.ScanAndIdentifyPort`，非代理用 `probe.IsNonProxyService` 丢掉 | `validator.ValidateProxy` | 只在 `ValidateProxy` 内部、且扫描器公网 IP 已经拿到时 | `reporter.Reporter.Report`，**不经过** `PostValidator` |
| `scanner_type` 不是 `ip_pool` 时的 `Scanner.processIPBatch`（`internal/scanner/scanner_batch.go`） | 同上 | `ValidateProxy` 之后再 `PostValidator.PostValidate` | 二次校验仍会在「自身 IP 未知」时放行 | 二次校验通过才 `Report` |

`IPScanner` 结构体里没有 `postValidator` 字段（`internal/scanner/ip_scanner_main.go` 的 `NewIPScanner`）。2026-06 生产就绪文档把「没有二次校验」写成 P0；二次校验的代码后来写上了，但**默认入口没有接上**。

`Reporter.Stop` 会先 `Flush` 再关后台循环（`internal/scanner/reporter/reporter.go`）。`processIPBatch` 用 `atomic.AddInt64` 计已扫 IP。这两处与 2026-06 文档里的「Stop 不 Flush」「`*scannedIPs++` 数据竞争」已经对不上，那两条不再构成单独的上线阻塞。

## 2. 「扫到的全是错误 IP」对照当前上报路径

用户看到的「错误 IP」是候选地址被当成代理写进去。当前代码仍可能写出三类，外加一条这次已经能观察到、但容易被误读成「修好了」的现象。

### 2.1 协议误判：不是代理，响应长得像代理

`validator.validateHTTPProxyViaCONNECT`（`internal/scanner/validator/validator.go`）在 HTTP 状态是 200、正文里出现 `connection established` 或 `tunnel` 时，直接返回「是代理」，**不**调用后面的 `verifyConnectTunnel`。`probe.probeHTTPProxy`（`internal/scanner/probe/proxy_probes.go`）对同样的字样同样直接当成 `http-proxy`。

`verifyConnectTunnel` 只检查隧道里读到的字节是否以 `HTTP/` 开头，不检查目标是谁、出口是谁。

因此：一个只回 `HTTP/1.1 200 Connection established`、隧道里不转发的端口，会通过协议形状检查。真正把它挡下来的只有后面的出口 IP 校验。这次在 goat 上、**打开** IP 校验时，9164 CONNECT Garbage、9249 Half-Open、9250 Chunked GET、9245 HTTP/2 模仿、9247 mTLS 模仿都被 `ValidateProxy` 拒绝，日志是 `IP验证失败：出口IP()与扫描器IP相同`（出口是空的，请求没走通，和「解析到了另一个公网 IP」不是同一件事）。见 `/tmp/grok-goal-808488ea3943/implementer/validator-ip-and-trap.txt` 里的 `TestHalfOpenTunnelTrapRejectedByRealIPVerify`，以及 `/tmp/grok-goal-808488ea3943/implementer/testpkg-goat.txt` 里对 9164 的拒绝记录。

同一批陷阱在 `SetSkipIPVerify(true)` 下会被接受。`test/validator_layer_test.go` 的 `TestValidatorTrapRejection` 把这写成预期，日志原文包括：

- `PASSED trap half-open-tunnel-proxy (port=9249, status=available)`
- `PASSED trap chunked-get-proxy (port=9250, status=available)`
- `PASSED trap http2-proxy (port=9245, status=available)`
- `PASSED trap mtls-auth-proxy (port=9247, status=available)`
- `PASSED trap apache-reverse-proxy (port=9194, status=available)`

`TestScannerPrecision_Comprehensive` 把 9164 的期望写成「应该是代理」，并在调用前 `SetSkipIPVerify(true)`，所以它报的 `False Positives: 0` 不包含「跳过出口校验时半开隧道被接收」这件事。

需要认证的端口更早返回：CONNECT 407，或 SOCKS5 握手要求认证，`ValidateProxy` 直接给出 `auth_required`，不做转发、也不做出口比较（`validateHTTPProxy` 在 `needsAuth` 时跳过 IP 段；`validateSOCKS5Proxy` 在拨号转发之前返回）。`PostValidate` 对 `RequireAuth == true` 直接记 `PostValidated=true` 并返回 true（`post_validator.go` 的 `PostValidate`）。默认入口会把这些地址 `Report` 出去。

### 2.2 出口 IP 与扫描器相同，或根本没校验

比较逻辑在 `IPVerifier.VerifyProxyHTTP` / `VerifyProxySOCKS5`（`internal/scanner/validator/ip_verifier.go`）：从 `http://httpbin.org/ip`、`http://ip-api.com/json`、`http://ipinfo.io/json` 取扫描器自身 IP，再经代理取出口 IP，两者都是公网 IPv4 且不相等才算通过。`parseIPFromResponse` 先抽 JSON 字段 `ip` / `origin` / `query` / `ipaddress` / `client_ip`，抽不到再退回正文里第一个公网 IPv4。`isValidPublicIP` 只接受 IPv4，私网、回环、`169.254.0.0/16` 丢掉。

调用点：

- HTTP：`validateHTTPProxy`，条件是 `!skipIPVerify && ipVerifier != nil && ScannerIP() != ""`。
- SOCKS5：`validateSOCKS5Proxy`（`socks_validator.go`），同样要求 `ScannerIP() != ""`。
- SOCKS4：`validateSOCKS4Connect` 注释写明「IP 验证交给 PostValidator」。`PostValidate` 的 SOCKS4 路径 `postValidateSOCKS4` / `trySOCKS4Fetch` 只要求隧道里出现 `HTTP/1.` 和 2xx，**不调用** `verifyIPChange`。`verifyIPChange` 对 `socks4` 走 `default`，直接 `return true`（`TestVerifyIPChange_DefaultProtocol_Skips` 锁的就是这个放行）。

三处放行（拿不到自身 IP 就当校验通过）：

1. `VerifyProxyHTTP` / `VerifyProxySOCKS5` 在 `ScannerIP()==""` 时返回 `("", true)`。单测名：`TestIPVerifierWithMockServer/VerifyProxyHTTP_degrades_pass_when_scannerIP_unknown`，本次通过。
2. `validateHTTPProxy` / `validateSOCKS5Proxy` 在 `ScannerIP()==""` 时整段比较不执行，协议形状通过就返回代理对象。
3. `PostValidator.verifyIPChange` 在 `ipVerifier == nil` 或 `ScannerIP()==""` 时返回 true（`TestVerifyIPChange_NilVerifier_Skips`、`TestVerifyIPChange_EmptyScannerIP_Skips`）。`SetSkipIPVerify(true)` 的实现是把 `ipVerifier` 置 nil。

自身 IP 探测失败会维持空值，30 秒内不再试（`retryInterval`）。探测目标就是上面三个境外回显站。它们不通时，默认 `ip_pool` 路径会把第 2.1 节那种「200 Connection established」地址报上去。这是当前代码里仍能批量产生「错误 IP」的条件。本次环境回显站是通的，所以没有在这次测试里走出这条放行；放行行为由上面的单测锁定，不是推测。

自身 IP 已知、且回显站经代理拿到的 IP 与之相同：HTTP/SOCKS5 会拒绝，错误文本是 `IP验证失败：出口IP(%s)与扫描器IP相同`。本次 goat 上的真实 HTTP 代理（重映射端口 28080）走的就是这条，日志：

`真实代理验证结果: err=IP验证失败：出口IP(219.142.145.17)与扫描器IP相同，流量未经过代理转发`

来源：`test/ip_verifier_trap_test.go` 的 `TestIPVerifierWithGoatServer/IPVerifier_真实代理应返回IP变更`。该子测试失败也只 `t.Logf`，整包测试仍然 PASS。goat 和扫描器在同一台机器上，代理转发出去的公网地址就是这台机器的地址，**必然相等**。这证明「相同则拒绝」在自身 IP 已知时会触发；**不能**写成「错误 IP 已在真实网络上修好」，也**没有**观察到任何一次「被接受的代理，其出口 IP ≠ 扫描器 IP」。`TestHalfOpenTunnelTrapRejectedByRealIPVerify` 注入的是假扫描器 IP `203.0.113.55` 和本地 echo，陷阱因隧道没数据被拒绝，同样不是「真实出口 IP 已验证」。

旧的「从 JSON 里抽错 IP」已不在当前解析里：`ip_verifier.go` 的 `jsonFieldRegexes` 按标准 `"ip": "x.x.x.x"` 抽取。`TestParseIPFromResponse_JSONFieldPreferredOverBareIP` 本次通过。若响应正文里另有一个公网 IP、而 JSON 字段抽失败，仍会退回裸 IP 正则，那是残留风险，不是这次观察到的主因。

### 2.3 目标不可达，或隧道没有把流量交出去

SOCKS5/SOCKS4 的 `ValidateProxy` 要求目标返回 2xx 才算转发成功。目标列表把 `http://www.example.com` 放在前面，再加上 `NewValidator` 的 `targetURL`（配置默认 `scan.test_url` 是 `http://www.google.com`，`internal/config/config.go`）。目标都不通时，这两类协议会拒绝，表现为漏报，不是把死地址报上去。

HTTP CONNECT 路径相反：`connection established` / `tunnel` 在读完 CONNECT 响应后就判真，不要求 `connectTarget()` 上的主机真的应答。目标不可达时，半开隧道仍然穿过第 2.1 节的形状检查，只靠第 2.2 节的出口校验拦截。出口校验被跳过时，不可达目标上的假隧道会入库。

`IPVerifier` 自己的回显 URL 和 Validator 的 `targetURL` 不是同一份。Validator 指向本地或 example.com 成功，不代表出口比较用的 httpbin / ip-api / ipinfo 成功。比较用的 URL 全失败且自身 IP 已知时，`VerifyProxyHTTP` 返回 `("", false)`，代理被拒（错误文本仍写「与扫描器 IP 相同」，此时括号里是空的）。这是拒假，不是证明出口变了。

### 2.4 旧文档里哪些说法已经被当前代码推翻

`SCANNER_BUGS_ANALYSIS.md` 不能再当现状：

| 旧结论 | 当前代码 |
|---|---|
| Bug 1：读 banner 失败就当 HTTP（文中的 `identifyService`） | `probe.ScanAndIdentifyPort` 在读失败或 0 字节时调用 `probeProxyService`，主动做 CONNECT/SOCKS 探测 |
| Bug 3：SOCKS4 用 SOCKS5 拨号器 | `validateSOCKS4Connect` 自己组 SOCKS4/4a 字节，不用 `proxy.SOCKS5` |
| Bug 4：`ScanAndIdentifyPort` 连两次 | 该函数只 `DialTimeout` 一次。协议探测会再各自拨号，那是另一次连接 |
| Bug 2：`isLikelyProxyService` 把 unknown 限制在一小份端口表 | 该函数只被 `scanner_core_test.go` 调用，不在 `scanIPTask` / `processIPBatch` 上。线上过滤是 `IsNonProxyService` 加 probe 的 `isLikelyProxy` |
| JSON 字段正则多一个引号、抽到正文里别的 IP | `jsonFieldRegexes` 已按标准 JSON 编译，并有单测 |

`docs/superpowers/plans/2026-05-29-scanner-maturity-assessment.md` 写精度约 3/5、误报未收口、不能当生产完成。方向仍然对（见第 3 节阻塞项），但文中的具体 banner 误报清单不能代替上面的当前符号。

`docs/superpowers/plans/2026-06-04-scanner-production-readiness.md` 有两句互相打架、且都不能直接沿用：

- 「goat 上 0 误报，准确性可以投产」——那些数字来自 `SetSkipIPVerify(true)` 的靶场。本次 `TestScannerPrecision_Comprehensive` 仍是这套开关，91/91、False Positives 0。同一次运行里，`TestValidatorTrapRejection` 在同一开关下接受 9249/9250/9245/9247。0 误报是测试oracle在跳过出口校验时的计数，不是真实网络出口校验通过。
- 「不能投产，因为没有 PostValidator、`scanner_batch.go` 数据竞争、Reporter 停止丢数据」——后两件当前代码已不是那样（见第 1 节）。PostValidator 有了，默认 `ip_pool` 不用它。文中「SOCKS4 无 IP 验证」这一行仍然成立。

`TestScannerPrecision_GoatServer` 仍去连原生 8080/8081。本机 8080 不是 goat（goat 的 HTTP 代理在 28080，进程 `goat-server` pid 2251296）。该测试 Probe 10/12、Validator 9/12，阈值 70%，所以整测 PASS。不能拿它当验收。权威端口在 `TestScannerPrecision_Comprehensive` 的 28080 那一行，且那一行跳过了出口校验。

## 3. 停止开发的验收标准

不按日期。下面五条同时为真就停，可以上线。做不到的留在第 4 节，不要为了第 5 节的非阻塞项继续开版本。

1. **正样本。** 一台会真实转发的 HTTP 代理和一台 SOCKS5 代理（出口地址与扫描器不是同一个公网 IP）。出口校验保持默认开启（禁止 `SetSkipIPVerify(true)`，禁止把 `ipVerifier` 置 nil）。`ValidateProxy` 返回 `available`，且 `VerifyProxyHTTP` / `VerifyProxySOCKS5` 解析到的出口 IP 不等于 `ScannerIP()`。
2. **负样本。** 同一开关下，普通 Web/SSH，以及 goat 的 9164、9245、9247、9249、9250，`ValidateProxy` 必须返回错误，默认入口不得 `Report`。
3. **自身 IP 未知时失败关闭。** `ScannerIP()` 为空时，不得把候选写成 `available`。当前 `VerifyProxyHTTP` 返回 `ok=true`、`validateHTTPProxy` 跳过比较，这条未满足。
4. **默认入口。** `scanner_type=ip_pool` 的 `scanIPTask` 在 `Report` 前执行与第 1–3 条相同的检查。现在它只调用 `ValidateProxy`，第 3 条的放行会直接入库。
5. **SOCKS4。** 要么在上报前做与 SOCKS5 同级的「出口 IP ≠ 自身 IP」，要么默认任务不再把 `socks4` 报成 `available`。现在 Validator 和 PostValidator 都不比较。

第 1 条本次**未验证**，列为上线阻塞。同机 goat 出口必然等于扫描器（本次实测 219.142.145.17），全绿不能顶替第 1 条。

建议的复跑命令（本次已跑，原始输出在评估所用的 scratch 目录）：

```text
# 不访问「出口必须变」的证明；自身 IP 未知则放行，由单测锁死
cd free-proxy-scanner
go test -count=1 -timeout 240s -v ./internal/scanner/validator/ \
  -run 'TestParseIPFromResponse|TestIsValidPublicIP|TestIPVerifierWithMockServer|TestHalfOpenTunnelTrapRejectedByRealIPVerify|TestValidateSOCKS5Proxy_IPVerifyFails|TestVerifyIPChange_|TestPostValidateHTTP_HTTP200NoIPChange|TestPostValidateHTTP_NonProxyServer'

# 本地探针，无公网
go test -count=1 -timeout 300s -v ./internal/scanner/probe/ \
  -run 'TestProbeHTTPProxy_200|TestAnalyzeBanner_HTTP_|TestIsKnownForwardProxyServer_Precision|TestMentionsKnownWebServer_Precision|TestProbeHTTPAbsoluteURIProxy_Bare200|TestProbeHTTPAbsoluteURIProxy_404|TestProbeHTTPAbsoluteURIProxy_405'

# goat 精度。内部 SetSkipIPVerify(true)，不能当第 1 条
go test -count=1 -timeout 420s -v ./internal/scanner/ \
  -run 'TestScannerPrecision_Comprehensive|TestScannerPrecision_GoatServer'

# goat 上的接受/拒绝。多数子测试 SetSkipIPVerify(true)
cd test
go test -count=1 -timeout 600s -v \
  -run 'TestTrapServiceRejection|TestRealProxyAcceptance|TestValidatorProxyAcceptance|TestValidatorTrapRejection|TestValidatorNonProxyRejection|TestIPVerifierHTTPProxyConnectLayerTraps|TestDeterministicTunnelCasesValidator|TestIPVerifierWithGoatServer'
```

goat-server 这次已经在听 28080/1080/9249 等端口，没有出现启动失败。不需要另附启动失败日志。

## 4. 上线阻塞（做完第 3 节即可停）

1. 默认 `ip_pool` 在扫描器自身公网 IP 未知时仍会上报「形状像代理」的地址。这是「错误 IP」还能成批出现的路径。
2. 没有一条已通过的证据表明：被接受的代理，出口 IP 不等于扫描器自身 IP。本次唯一的现场样本是同机 goat 真代理被拒（出口等于 219.142.145.17）。
3. SOCKS4 上报前不比较出口 IP。默认协议列表若含 socks4，第 3 节第 5 条不过。
4. `auth_required` 未证明转发就被 `Report`。若调用方把这种记录当可用代理去连，它们就是另一批不能用的地址。产品若把该状态排除出可用集合，这条可以改成非阻塞；当前 `scanIPTask` 没有这个区分。

## 5. 明确推迟，不是上线条件

下面这些缺了，不会把「非代理」或「出口等于扫描器」报上去。不要为它们挡上线，也不要为它们继续无限期做：

- 新协议、IPv6（`isValidPublicIP` 非 IPv4 会丢弃；IPv6 出口现在是漏报，不是误报）
- 匿名分级（`ClassifyAnonymity` 已在 HTTP 成功路径上填字段，分错等级不影响「是不是代理」）
- 字典爆破是否扫全（`enhanced_scanner` 的爆破不在 `scanIPTask` 的上报主路径上）
- 分布式扫描、多格式导出、覆盖率刷到 100%
- `scanner.go` 里那份不再被扫描调用的 `isLikelyProxyService` 端口表

## 6. 这次测试和结论是否一致

| 命令输出 | 结果 | 能否支撑「可以上线」 |
|---|---|---|
| `/tmp/grok-goal-808488ea3943/implementer/validator-ip-and-trap.txt` | PASS。含「自身 IP 未知则 VerifyProxyHTTP 放行」，以及注入 IP 后半开隧道被拒 | 不能。放行被测成了预期；半开拒绝不是真实出口 IP 不同 |
| `/tmp/grok-goal-808488ea3943/implementer/probe-local.txt` | PASS。nginx 等不是代理；`connection established` 会被 probe 当成代理 | 只能说明形状分类，不能说明出口 |
| `/tmp/grok-goal-808488ea3943/implementer/precision-goat.txt` | Comprehensive 91/91、FP 0，但 `SetSkipIPVerify(true)`。旧端口测试 8080/8081 识别失败仍因 70% 阈值 PASS | 不能 |
| `/tmp/grok-goal-808488ea3943/implementer/testpkg-goat.txt` | PASS。skip 模式下 9249 等陷阱 `status=available`；未 skip 时 28080 因出口 IP `219.142.145.17` 与扫描器相同被拒 | 不能。与「还不能上线」一致 |

**还不能上线。** 阻塞项是第 4 节那四条，不是日期，也不是第 5 节那些能力。四条里和第 3 节五条对得上之后就停。
