# trustlib

把不同来源的远程证明归一成 AR4SI 的八维可信度向量，再按调用方选的关键维塌缩成一个可以比较好坏的档位。设计细节见 [docs/design.md](docs/design.md)，验收记录见 [docs/acceptance.md](docs/acceptance.md)。

## 1. 解决什么问题

机密计算节点交上来的证明五花八门：校验服务签发的 EAR、TDX Quote、TPM Quote，以后还有 GPU 证明、云厂商的 JSON 结论。消费者（调度侧、发钥侧、审计）不该为每一种格式各写一套判断。trustlib 把它们统一成同一种结果，并且把三种情况分清楚：

- 没检查：没给参考值，结果是无结论；
- 检查了不通过：有证据表明不行，结果是不认可；
- 评估不了：解析失败、验签失败、nonce 不符、背书缺失或过期，返回错误，消费者按无结论处理。

## 2. 接口

```go
ev, _ := tdx.New(tdx.Config{TrustedRoots: roots, Getter: getter, Reference: refs}) // 构造时给信任锚、背书、参考值
res, err := ev.Evaluate(trustlib.Request{Input: quote, Nonce: reportData, Now: now}) // 每次给输入、nonce、时刻
verdict := trustlib.Judge(res, err, trustlib.DefaultMask)                            // 塌缩成档位
```

输入分两类：

| 类 | 来源 | 依赖方要给的 |
|---|---|---|
| 别人评估过的证明结果 | `ear`：EAR（JWT） | 校验方公钥 |
| 要自己评估的证据 | `tdx`：TDX Quote（v4/v5） | Intel SGX 根证书、背书来源（Getter）、参考值 |
| | `tpm`：go-tpm-tools 的 Attestation（protobuf） | AK 的根证书或可信 AK 名单、参考值 |

为什么这样分：证据要连同参考值和背书一起评估才得出结论，证明结果已经是结论，只需验签。两类要的信任材料不同，但构造好之后对消费者是同一个 `trustlib.Evaluator`。消费者只依赖 `Evaluator` 和 `Judge` / `Collapse`，换来源不改代码。加一种来源，就是新加一个实现 `Evaluator` 的包。

## 3. 为什么边界画在 AR4SI 上

AR4SI 定义了一套和 TEE 无关的结论词表：八个维度，每维一个 int8 值，按区间分成认可、有保留、不认可、无结论四档。TDX 的 MRTD、TPM 的 PCR0 这些厂商相关的细节，在适配器里翻译成同一个词表，消费者就不用认识任何一种 TEE。EAR 本身就用这套词表，所以校验服务给的结论也能直接接进来。

塌缩规则：先按区间归档，不直接比数值；只看关键维（默认 hardware、configuration、executables）；取最差的一档，顺序是不认可 < 无结论 < 有保留 < 认可。

## 4. 维度映射表

| 维度 | TDX | TPM |
|---|---|---|
| hardware | 签名链 + 背书 + 吊销，加 MRTD 比参考值：通过 2；签名链验不过 97；被吊销 96；MRTD 不符 96 | AK 有担保 + Quote 验得过，加 PCR0 比参考值：通过 2；AK 无担保或 Quote 验不过 97；PCR0 不符 96 |
| configuration | 调试位、XFAM、RTMR0：调试位打开 96；都符 2；不符 96 | PCR7：符 2；不符 96 |
| executables | RTMR1、RTMR2：都符 3；不符 96 | PCR4 或 PCR11：都符 3；不符 96 |
| runtime-opaque | 签名链通过且调试位为 0：2；调试位为 1：96 | 0（TPM 不保护运行时内存） |
| 其余四维 | 0 | 0 |

某一维用到的参考值没给全，这一维就是 0。TDX 的 TCB 状态单独放在 `Result.TCB`，不进 hardware。

## 5. 可替换性演示

`examples/consumer/main.go` 只用 `Evaluate` 和 `Judge` 两步。六次运行之间 main.go 一字未改（md5 前后相同）：

```
$ for s in ear tdx tpm; do for c in good bad; do go run ./examples/consumer -src=$s -case=$c; done; done
ear/good tier=affirming       decisive=[configuration executables hardware] err=<nil>
ear/bad  tier=contraindicated decisive=[executables] err=<nil>
tdx/good tier=affirming       decisive=[configuration executables hardware] err=<nil>
tdx/bad  tier=contraindicated decisive=[executables] err=<nil>
tpm/good tier=affirming       decisive=[configuration executables hardware] err=<nil>
tpm/bad  tier=contraindicated decisive=[configuration] err=<nil>
```

bad 样例：EAR 是校验方判了 executables 96；TDX 是参考值里的 rtmr1 改了一个字节；TPM 是参考值里的 pcr7 改了一个字节。

## 6. 已知缺口

- TPM 样例来自软件模拟器，AK 证书是测试 CA 签的，不是厂商或云厂商的担保。
- TDX 样例平台在 Intel 的 TCB 信息里找不到匹配级别，永远拿不到 UpToDate；样例背书在 2026-10 已过期，测试把校验时刻钉在 2023-07-01。
- 证书吊销的处理没有单元测试：构造一份吊销样例证书的 CRL 需要 Intel 的签名密钥。
- 吊销和证书过期的识别靠 go-tdx-guest 的错误文案，升级时要复核。
- TPM 只做 PCR 整值比对，不重放事件日志，只看 SHA-256 bank。

## 7. 不做什么

- 不联网：不在线取背书，不取参考值。go-tdx-guest 在 Getter 为空时会自己联网，所以 `tdx.New` 拒绝空的 Getter。
- 不缓存，不处理并发，不读配置文件。
- 不依赖 Kubernetes。
- 不产出参考值：参考值由构建镜像的一方提供。
- 不签名输出：trustlib 和消费者在同一个进程里，没有信任边界。

## 开发

```sh
go mod tidy                                                   # 第一次运行，生成 go.sum
go vet ./... && go test -race -count=1 -cover ./...
go run -tags tpmsim ./internal/gentpm                         # 重新生成 TPM 样例，需要 cgo 和 OpenSSL
go run -tags genear ./internal/genear <veraison/ear 的 arc/data/skey.json>   # 重新生成 EAR 样例
```
