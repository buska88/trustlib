# trustlib 设计（P1 定稿）

- 日期：2026-10-19
- 状态：定稿，已实现；代码和测试与本文一致
- 依据版本：AR4SI draft-ietf-rats-ar4si-10；EAR 草案；go-tdx-guest b0a2dd8；go-tpm-tools v0.4.9；veraison/ear v1.1.3
- 来源：Buska 的设计稿（~/work/learn/P1-design.md）经审查对齐后定稿。“依据”一栏的节号、题号指《P1 讲义》

## 题目回顾

把三种输入归一成可以比较的信任结论：EAR（校验方签的证明结果）、TDX Quote、TPM Quote。以后还会加 GPU 证明、云厂商的 JSON 结论等。

消费者的需求：
- 调度侧只要一个能比较好坏的等级。没有结论时（校验方故障、证据缺失）要能容忍一段时间；有证据表明不行时要立即处置。
- 发钥侧和审计要看细节。发钥侧只要有任何不确定，就不发钥。

约束：不依赖 K8s；参考值和背书不写死在库里，由调用方传入；同一份消费者代码在三种来源之间零改动；没给参考值时不能判为可信；校验时间能从外面注入。

## 总览：两段式

```
            构造时（调用方给）                    每次调用（调用方给）
            信任锚、背书、参考值                  输入、期望的 nonce、校验时刻
                   │                                  │
                   ▼                                  ▼
  ┌──────────────────────────────┐   Evaluate   ┌────────────┐   Collapse / Judge   ┌──────┐
  │ 来源适配器：ear / tdx / tpm   │ ───────────▶ │   Result   │ ──────────────────▶  │ Tier │
  │ 第一段：证据 → 八维向量       │              │ 八维 + 明细 │   第二段：向量 → 档位  └──────┘
  └──────────────────────────────┘              └────────────┘   （关键维由消费者选）
```

- 第一段：校验方评估证据、得出八维。EAR 来源由外部校验方做完了这一段，适配器只验签、取值；TDX、TPM 来源由依赖方自己兼任校验方。
- 第二段：依赖方按自己的策略把向量塌缩成档位。

---

## D1 输入分类与接口边界

**结论**
- 输入分两类：别人评估过的证明结果（EAR），和要自己评估的原始证据（TDX、TPM）。两类的区别只体现在构造时要给什么：EAR 要校验方公钥；证据要信任锚、背书、参考值。
- 消费者只看到一个接口 `trustlib.Evaluator`（`Name()`、`Evaluate(Request)`），再用 `Collapse` 或 `Judge` 得出档位，不知道来源类型。
- 每次调用只传会变的东西：`Request{Input, Nonce, Now}`。信任锚、背书、参考值在构造时传入。库里不写死，也从不联网去取。
- 加一种新来源，就是新加一个实现 `Evaluator` 的包，现有文件一行不改。

**否掉的方案**
1. trustlib 自己当校验方，输出签名的 EAR 给消费者（设计稿原方案）：消费者和 trustlib 在同一个进程里，没有信任边界。能改输出的人也能改校验逻辑，签名防不住任何人，还要多管一把密钥。
2. 信任锚、参考值、背书在线获取（设计稿原方案）：信任锚必须事先经可信渠道配置，从对方或不可信通道拿来的公钥，攻击者换成自己的就能通过。背书有 Intel 签名，技术上可以在线取，但题卡规定不做。参考值来自构建镜像的一方，也只能由调用方给。
3. 一个 `Normalize(input)` 统一处理所有输入：证据没有参考值就得不出结论。结果要么 TDX、TPM 几乎全输出“没判断”，要么参考值被偷偷写死在库里。
4. 每次调用都传参考值（执行卡附录 v0 的 `Appraise(evidence, rv, e, now)`）：参考值跟着工作负载的镜像走，不是每次请求都变；换参考值就构造一个新的 Evaluator，代价很小。每次调用只传输入、nonce、时刻，接口最窄。
5. 让消费者直接调各来源的专有接口：违反“消费者零改动”。

**理由**：消费者零改动要求接口与来源无关；“不写死、不联网”要求所有信任材料都从调用方进来；按“会不会每次变”来划分构造参数和调用参数，接口最窄。

**依据**：讲义 1.1、1.3、3.7、5.1、5.5；自测 2、4、15、21、22。RFC 9334 允许一个实体同时担任依赖方和校验方。

---

## D2 统一结果的数据模型

**结论**：`Result` 字段如下。

| 字段 | 内容 |
|---|---|
| `Source` | 来源名 |
| `Vector` | 合并后的八维原始值（int8，保留原值，不先归档） |
| `Submods` | 每个子模块各自的向量；证据来源只有一个，名字就是来源名 |
| `Status` | EAR 的 `ear.status`，多个子模块取最差；证据来源为空 |
| `TCB` | 平台 TCB 状态（Intel TCB 信息里匹配级别的状态、QE 状态、tcbDate），目前只有 TDX 有 |
| `Nonce` | 输入里实际带的 nonce |
| `IssuedAt` | EAR 的 iat |
| `Raw` | 原始输入 |

多个子模块：按维取最差（`MergeWorst`），档位相同时取子模块名靠前的那个，结果确定；同时在 `Submods` 里保留每个子模块的原始向量。

**否掉的方案**
1. 只输出塌缩后的结论（设计稿的 xA_yN_zW_kC 字符串）：发钥侧和审计要看细节；塌缩规则一改，历史结论没法重算。
2. 合并子模块、不留明细：会丢掉“哪个部件出了问题”（附录否掉合并的理由）。保留明细之后这个理由就不成立了。
3. 要求调用方指定读哪个子模块（附录 v0）：多数消费者不想关心部件构成。复合设备的可信度取决于最弱的那部分，默认取短板更安全；要看单个部件，读 `Submods`。
4. TCB 状态并进 hardware：见 D4。

**理由**：原始值能派生出档位，档位推不回原始值，所以存原始值。区分“没检查”和“校验方故障”（评判标准 3）也要靠原始值：0 和 −1 归档后都是无结论，只有原值能把它们分开。

**依据**：讲义 2.1、2.4、3.6、3.8、5.5；自测 6、9、11、14；RFC 9334 §3.3（复合设备）。

---

## D3 塌缩规则

**结论**（`Collapse`）
1. 每一维先按 AR4SI §2.3.2 的区间归档，不直接比数值：
   - 认可：2..31、−2..−32
   - 有保留：32..95、−33..−96
   - 不认可：96..127、−97..−128
   - 无结论：0、1、−1。0 和“没给出”同等对待（AR4SI §2.3.2 的 SHOULD NOT 区分）。
2. 只看关键维。用掩码 `Mask` 表示（第 d 位为 1 表示关注维度 d，这是设计稿的做法），为 0 时用 `DefaultMask` = hardware、configuration、executables。
3. 取关键维里最差的一档。档位从差到好：**不认可 < 无结论 < 有保留 < 认可**。所以任何一维不认可，结果就是不认可；否则任何一维无结论，结果就是无结论。
4. 有 `ear.status` 时，再和它取更差的那个。

隐含维度（AR4SI §2.3.6）在来源适配器里处理：TDX 来源直接把 runtime-opaque 填出来，消费者不需要知道 TEE 类型。

`Judge` 是给消费者的入口：评估出错时返回无结论，并带上原始错误。

**否掉的方案**
1. 直接比数值取最小：−5 会被当成最差，0 会排在 32 前面。
2. 按档位计数排序（设计稿的 xA_yN_zW_kC）：认可会抵消不认可。例：关键维三个，X = 认可、认可、不认可，Y = 认可、无结论、无结论，计数排序让 X 排在 Y 前面，可题卡要求 X 立即处置、Y 容忍。合成必须是一票否决式的。
3. 先查“有没有没判断”再取最差（执行卡附录 v0 的写法）：不认可 + 没判断会塌缩成无结论、被容忍。这是附录的错误，已更正。
4. 把无结论当成最差：校验方一次故障，节点就会被立即驱逐。
5. 默认关注全部八维（设计稿原方案）：TDX、TPM 判断不了 file-system 等维，它们恒为 0，结果永远是无结论，发钥侧永远不发。

**理由**：调度侧要的“没结论容忍、有证据不行立即处置”，正好对应“无结论排在不认可之上、取最差”。发钥侧只在认可时发钥，自然满足“任何不确定就不发”。`ear.status` 取更差的那个：EAR §3.1 规定 status 不得高于最差一维，取更差的永远不违反规范。

关于 AR4SI §4.2：“必需的维都认可、一票否决的维不能不认可”写在 Below Zero Trust 模型里，原文用的是 has to，同节第 6 步称之为“一个合理的流程”，是范式而不是规定。本规则与它相容：关键维 = 必需的维，并且关键维都是一票否决的。

**依据**：讲义 2.2、2.3、2.4、5.2、5.4；自测 7、8、9、23；AR4SI §2.3.2、§2.3.6、§4.2；EAR §3.1。

---

## D4 TDX 的维度映射

**结论**

| 维度 | 由什么决定 | 取值 |
|---|---|---|
| hardware | 签名链（信任锚 → PCK 证书 → QE 报告 → AK → Quote）、背书、吊销，加上 MRTD 比参考值 | 通过 → 2；签名链验不过 → 97；PCK 证书被吊销 → 96；MRTD 不符 → 96；MRTD 没给参考值 → 0 |
| configuration | 调试位、XFAM、RTMR0 | 调试位打开 → 96；否则 XFAM 和 RTMR0 都符 → 2，有一项不符 → 96，没给全 → 0 |
| executables | RTMR1、RTMR2 | 都符 → 3；有一项不符 → 96；没给全 → 0 |
| runtime-opaque | 签名链通过且调试位为 0 | 是 → 2；调试位为 1 → 96；签名链验不过 → 0 |
| 其余四维 | 不判断 | 0 |

- TCB 状态放进 `Result.TCB`，不进 hardware。样例平台在 Intel 的 TCB 信息里找不到匹配级别，记为 `NoMatchingLevel`；它的 QE 是 UpToDate。
- nonce：Quote 的 report_data 必须和调用方给的 64 字节逐字节相等。nonce 怎样放进 report_data 是调用方和证明方之间的约定。检查放在签名链之后，因为签名验过之后 report_data 才可信。
- 背书通过调用方给的 `Getter` 提供，必须非空：go-tdx-guest 在 Getter 为空时会自己联网去 Intel PCS 取。

**否掉的方案**
1. TCB 并进 hardware（设计稿想填 N，或者填 32）：N 的意思是“没判断”，这里明明做了判断。“硬件是不是真的”和“固件是不是最新”是两个问题，调度侧可以给宽限期，发钥侧可能不给。并进去之后，样例永远拿不到 UpToDate，good 和 bad 会塌缩成同一档。
2. runtime-opaque 留 0（Trustee 的做法）：本项目最关心的就是推理时内存不被宿主看到。AR4SI 附录 B.3 写的是虚机级机密计算的这一维“隐含在签名里”。
3. executables 给 2（执行卡附录 v0）：2 的定义是“启动中和启动后加载的都认可”，RTMR1、2 只覆盖启动阶段，应给 3（与 Trustee 一致）。已更正。
4. 签名链验不过也返回错误：会把“被证明是假硬件”和“网络抖动拿不到背书”混成一类，而前者应该立即处置。
5. 证书过期判成 97：过期是“现在评估不了”，不是“证明是假硬件”。实现时测出来的：样例 PCK 证书 2029-09-20 到期，go-tdx-guest 报的是 crypto/x509 的过期错误，现在归为 `ErrEndorsement`。

**理由**：签名只回答“是不是真硬件”，“跑的是什么”只能靠测量值比参考值。签名链和测量值分开判，各维才有明确的含义。

**依据**：讲义 3.4–3.9、5.2–5.4；自测 12–16、23；AR4SI 附录 B.3；DCAP §2.3.1、§2.3.2。

---

## D5 TPM 的维度映射

**结论**

输入是 go-tpm-tools 的 `Attestation`（protobuf），只看 SHA-256 bank。

| 维度 | 由什么决定 | 取值 |
|---|---|---|
| hardware | AK 有担保，并且 Quote 验得过；再加 PCR0（核心固件）比参考值 | 通过 → 2；AK 无担保或 Quote 验不过 → 97；PCR0 不符 → 96；没给 → 0 |
| configuration | PCR7（安全启动状态） | 符 → 2；不符 → 96；没给 → 0 |
| executables | PCR4（引导程序）、PCR11（UKI）中调用方给了参考值的那几个 | 都符 → 3；有一个不符 → 96；一个都没给 → 0 |
| runtime-opaque | TPM 不保护运行时内存（AR4SI 附录 B.1：n/a） | 0 |
| 其余四维 | 不判断 | 0 |

- AK 的担保，二选一：AK 证书能验到调用方给的根证书（`AKRoots`），并且证书里的公钥就是这把 AK；或者这把 AK 在调用方事先登记的名单里（`TrustedAKs`）。两样都没给时拒绝构造。
- AK 证书链按注入的时刻校验。做法照 go-tpm-tools 的 `server.VerifyAKCert`，但那个函数只能用当前时间，所以自己实现了一遍。
- Quote 先用它自带的 extraData 验签，回答“是不是这把 AK 签的、PCR 有没有被改”；再单独比 nonce。这样伪造和重放能分开报。
- Quote 没选某个 PCR 时，用到它的那一维算“没检查完”，是 0。

**否掉的方案**
1. 证明方发来的 AK 公钥直接当背书（设计稿原方案）：攻击者附上自己的公钥和签名，核对永远通过，伪造成本为零。
2. AK 当参考值（Trustee 的做法）：AK 不是测量值，放进参考值会让“比参考值”和“验签名”混在一起。名单本身保留，作为担保方式之一。
3. hardware 只看 AK（执行卡附录 v0）：AR4SI 附录 B.1 写的是 hardware 要做“从 BIOS 到 MBR 的 PCR 检查”。而且 TDX 的 MRTD 对应 TPM 的 PCR0，两边都归到 hardware，整个项目只有一套映射。
4. 所有 PCR 一律归 executables：PCR7 记的是安全启动状态，是配置。
5. 用 `server.VerifyAttestation`：它要重放事件日志、解析启动事件，超出 P1 的范围；P1 只做整值比对。

**理由**：TPM 和 TDX 回答同样的三个问题，映射保持对称：固件 → hardware，配置 → configuration，引导链 → executables。

**依据**：讲义 4.1–4.6、5.3、5.4；自测 17–20、24；AR4SI 附录 B.1；UAPI Linux TPM PCR Registry。

---

## D6 失败语义

**结论**：有证据表明不行是**结论**，用不认可档的值表达；评估不了是**错误**，消费者按无结论处理（`Judge`）。两者不混。

| 情况 | 处理 | 理由 |
|---|---|---|
| 输入解析失败 | `ErrParse` | 得不出任何结论 |
| 缺信任锚、背书来源或期望的 nonce | `ErrConfig` | 调用方没给齐 |
| EAR 验签失败 | `ErrUntrustedResult` | 结论不来自可信的校验方，内容一个字都不读 |
| nonce 不符 | `ErrNonceMismatch` | 可能是重放 |
| EAR 太旧（设了 MaxAge） | `ErrStale` | 结论过期 |
| 背书缺失、过期或无效；证书过期 | `ErrEndorsement` | 现在评估不了 |
| Quote 签名链验不过；AK 无担保 | hardware = 97 | 有证据表明不是真硬件 |
| 证书被吊销 | hardware = 96 | 认得，但不认可 |
| 测量值与参考值不符 | 对应维 = 96 | 有证据表明不认可 |
| 没给参考值 | 对应维 = 0 | 没检查，塌缩后是无结论，不是认可 |
| EAR 里某维是 −1 | 保持 −1 | 校验方故障，塌缩后是无结论 |

错误用 `errors.Is` 判断类别。

**否掉的方案**
1. 解析失败返回错误、其余一律低档位（设计稿原方案）：区分不了“没检查 / 不通过 / 故障”。而且 EAR 验签失败时还去读里面的值，等于信了不可信的内容。
2. 签名链失败也返回错误：见 D4 第 4 条。

**理由**：调度侧需要区分“容忍”和“立即处置”，这两种处理分别落在无结论和不认可上，不能混。

**依据**：讲义 1.3、1.4、2.4、3.2、3.6、5.4；自测 4、5、10、13、14。

---

## 对照评判标准

1. **加第四种来源要改几处**：新加一个包，实现 `Evaluator` 的两个方法，现有文件不改。需要新的 AR4SI 取值常量时，可以在 `tier.go` 加一行（可选）。
2. **消费者能不能完全不知道来源类型**：能。`consumer_test.go` 用同一个 `admit` 函数跑三种来源。
3. **能不能区分没检查、检查了不通过、校验方故障**：能，看原始值和错误类别：没检查 = 0；不通过 = 96、97；校验方故障 = EAR 里的 −1，或者 `Evaluate` 返回的错误。
4. **fail-closed 能不能被单元测试覆盖**：能。
   - ear：`TestWrongVerifierKey`、`TestNonce`、`TestMaxAge`、`TestNotAJWS`
   - tdx：`TestTamperedQuote`、`TestNonce`、`TestEndorsementExpired`、`TestCertificateChainExpired`、`TestEndorsementMissing`、`TestGarbage`、`TestMapping/no_reference_values`
   - tpm：`TestUnvouchedAK`、`TestCertificateForAnotherKey`、`TestWrongRoot`、`TestCertificateExpired`、`TestTamperedPCR`、`TestNonce`、`TestPCRMismatch/no_reference_values`
   - 塌缩：`TestCollapse` 全表、`TestJudge`
   - 缺口：吊销路径没有单元测试（见“已知局限”）。
5. **每个决定能不能一句话说清**：
   - D1：输入按“别人评估过的结果”和“要自己评估的证据”两类进来，消费者只看到一个 Evaluator，信任锚、参考值、背书全由调用方给。
   - D2：结果保留八维原始值和每个子模块的明细，TCB 单独放；档位是派生出来的，不是唯一输出。
   - D3：先归档再比较，关键维里取最差一档；不认可压过一切，无结论排在不认可之上。
   - D4：签名链只证明真硬件，MRTD、XFAM 和 RTMR0、RTMR1 和 RTMR2 分别决定 hardware、configuration、executables；runtime-opaque 由签名推出，被调试位否决。
   - D5：AK 必须由事先给的根证书或名单担保，PCR0、PCR7、PCR4 或 PCR11 分别决定三维，TPM 不判 runtime-opaque。
   - D6：有证据表明不行是结论，评估不了是错误，两者不混。

## 已知局限与待复核

- **吊销没有单元测试**：要构造一份列出样例 PCK 证书的 CRL，必须有 Intel 的签名密钥，做不到。
- **两处靠错误文案判断**：吊销（"was revoked"）和证书过期（crypto/x509 的过期文案），因为 go-tdx-guest 没有导出对应的错误值，或者用 %v 吞掉了原始类型。升级 go-tdx-guest 时要复核；`TestCertificateChainExpired` 能发现过期文案的变化。
- **测试时刻是钉死的**：TDX 测试钉在 2023-07-01（样例背书在 2026-10 已过期，PCK 证书 2029-09-20 到期）；TPM 测试钉在 2026-01-01（测试 AK 证书有效期 2025–2035）。
- **TPM 只做整值比对**：不重放事件日志，只看 SHA-256 bank。
- **EAR 子模块里的 eat_nonce 没有解析**：veraison/ear v1.1.3 不解析它。
- **AR4SI 编辑稿有变化**：2026-10 的编辑稿新增了 Incomplete 档，尚未作为新版本发布。发布后要复核 −1 等取值的归档。
- **go 版本**：go.mod 必须写 `go 1.24.0` 或更高，因为 go-tpm-tools v0.4.9 要求 1.24.0。

## 与执行卡附录 v0 的差异

附录 v0 有三处错误，已在执行卡里更正：
1. D1：函数签名里没有期望的 nonce，但 D6 要求“nonce 不符返回错误”。现在 `Request.Nonce` 由调用方传入。
2. D3：合成时先查“没判断”，导致“不认可 + 没判断”被容忍。现在直接取最差一档。
3. D4、D5：executables 给 2，应为 3。

另外两处按设计稿改了附录的做法：多子模块默认按维取最差并保留明细；关键维用掩码表示。

## 类型一览

```go
// 包 trustlib
type Dimension uint8           // 八维：InstanceIdentity … SourcedData
type Mask uint8                // 关键维掩码；DefaultMask = hardware|configuration|executables
type Vector [8]int8            // 八维原始值
type Tier uint8                // Contraindicated < None < Warning < Affirming
type ReferenceValues map[string][][]byte
type Measurement struct{ Name string; Value []byte }
type PlatformTCB struct{ Status, QEStatus, Date string }
type Result struct{ Source string; Vector Vector; Submods map[string]Vector; Status *Tier; TCB *PlatformTCB; Nonce []byte; IssuedAt time.Time; Raw []byte }
type Request struct{ Input, Nonce []byte; Now time.Time }
type Evaluator interface{ Name() string; Evaluate(Request) (*Result, error) }
type Verdict struct{ Tier Tier; Decisive []Dimension; ByStatus bool; Err error }

func Classify(v int8) Tier
func Collapse(res *Result, mask Mask) Verdict
func Judge(res *Result, err error, mask Mask) Verdict
func MergeWorst(submods map[string]Vector) Vector
func (rv ReferenceValues) Check(good, bad int8, ms ...Measurement) int8

// 包 ear：New(Config{VerifierKey, Alg, MaxAge})，ParseJWK
// 包 tdx：New(Config{TrustedRoots, Getter, Reference})，参考值键 mr_td、xfam、rtmr0、rtmr1、rtmr2
// 包 tpm：New(Config{TrustedAKs, AKRoots, Reference})，参考值键 pcr0、pcr7、pcr4、pcr11
```
