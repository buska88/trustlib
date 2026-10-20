# P1 验收记录

对照执行卡环节四末尾的验收清单。“这边”指实现时用的云端环境（Go 1.24.7，Linux）；标“待本机”的项要在 Buska 的 Mac 上跑。

| # | 验收项 | 状态 | 证据 |
|---|---|---|---|
| 1 | `go list -m all \| grep -c 'k8s.io'` 输出 0 | 待本机 | 这边拉不全完整模块图；已下载的所有依赖的 go.mod 里都没有 k8s.io |
| 2 | `go test -race ./... -cover` 退出码 0，覆盖率 ≥ 70% | 通过 | 见下方输出：库的四个包 83%–87% |
| 3 | `golangci-lint run` 退出码 0 | 待本机复跑 | 本机第一次跑报了 3 个 QF1001（tier_test.go 里可以套德摩根律的条件），已改写。这边当时漏掉，是因为 staticcheck 命令行版不跑 QF 类检查，golangci-lint 会跑。改完后这边补跑了 QF 类检查，连同 `go vet`、staticcheck（`-checks all`）、errcheck、ineffassign，全部 0 个问题 |
| 4 | 三种来源各有 good、bad 测试，共六个，全部通过 | 通过 | ear：`TestGoodEAR`、`TestBadEAR`；tdx：`TestMapping/all_references_match`、`TestMapping/rtmr1_mismatch`；tpm：`TestVouchedByCertificate`、`TestPCRMismatch/pcr7_mismatch` |
| 5 | TDX 与 TPM 各有“参考值为空”的测试，塌缩结果不是最高档 | 通过 | `TestMapping/no_reference_values`、`TestPCRMismatch/no_reference_values` |
| 6 | 塌缩的边界用例全部通过，每个期望值都能在设计里找到依据 | 通过 | `collapse_test.go` 每行注明依据 D3-1…D3-4；设计在 docs/design.md（执行卡里叫 decisions.md） |
| 7 | arc 对照：八维逐维相同 | 通过 | `TestArcSamples`；两份输出见下方 |
| 8 | 可替换性：六次运行满足 4.6 的过关条件 | 通过 | 见 README 第 5 节 |
| 9 | README 七节齐全 | 通过 | README 1–7 节 |
| 10 | `gh repo view --json visibility` 显示 PUBLIC | 待本机 | 仓库还没推到 GitHub |

全部测试：46 个（含子测试）通过，0 个失败。

## 2. race + cover

```
$ go test -race -count=1 -cover ./...
ok  	trustlib	1.049s	coverage: 86.2% of statements
ok  	trustlib/ear	1.039s	coverage: 86.8% of statements
	trustlib/examples/consumer		coverage: 0.0% of statements
	trustlib/examples/samples		coverage: 0.0% of statements
ok  	trustlib/tdx	1.172s	coverage: 85.7% of statements
ok  	trustlib/tpm	1.032s	coverage: 83.1% of statements
```

examples 是演示程序，没有测试。

## 7. arc 对照

testdata/ear 里的两份 EAR，是按 arc create 的做法生成的（internal/genear）：claims 来自 veraison/ear 仓库 arc/data 下的 ear-claims-tv-ok.json，bad 版把 executables 改成 96、ear.status 改成 contraindicated，用同一个仓库里的测试私钥签名。

左栏是 veraison/ear 的 `TrustVector.Report`，也就是 `arc verify --verbose` 打印的那个函数的输出；右栏是 trustlib 的结果。在本机可以用 `arc verify --pkey testdata/ear/pkey.json --verbose testdata/ear/tv.jwt` 再对一遍。

**tv.jwt**

| 维度 | arc（TrustVector.Report） | trustlib |
|---|---|---|
| instance-identity | affirming | 2 |
| configuration | affirming | 2 |
| executables | affirming（启动阶段加载的都认可） | 3 |
| file-system | affirming | 2 |
| hardware | affirming | 2 |
| runtime-opaque | affirming | 2 |
| storage-opaque | affirming | 2 |
| sourced-data | affirming | 2 |
| ear.status / 塌缩 | affirming | affirming（默认关键维） |

**bad.jwt**

| 维度 | arc（TrustVector.Report） | trustlib |
|---|---|---|
| executables | contraindicated | 96 |
| 其余七维 | affirming | 2 |
| ear.status / 塌缩 | contraindicated | contraindicated，决定它的维：executables |
