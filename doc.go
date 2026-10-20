// Package trustlib 把不同来源的远程证明归一成 AR4SI 的八维可信度向量，
// 再按调用方选的关键维塌缩成一个可以比较好坏的档位。
//
// 来源（各在一个子包里）：
//   - ear：校验方签发的证明结果（EAR）
//   - tdx：Intel TDX 的 Quote，依赖方自己当校验方
//   - tpm：TPM / vTPM 的 Quote，依赖方自己当校验方
//
// 用法分两段（设计见 docs/design.md）：
//  1. 构造某个来源的 Evaluator。信任锚、背书、参考值都在这一步由调用方传入，库里不写死，也不联网去取。
//  2. 每来一份输入，调 Evaluate 得到 Result（八维原始值 + 明细），再用 Collapse 或 Judge 塌缩成档位。
//
// 消费者代码只依赖 Evaluator 接口和 Collapse / Judge，换来源不用改。
//
// 失败分三种，互不混淆：
//   - 没检查（没给参考值）：对应维为 0，塌缩后是无结论；
//   - 检查了不通过：对应维是不认可档的值（96、97），塌缩后是不认可；
//   - 评估不了（解析失败、验签失败、nonce 不符、背书缺失或过期）：返回 error，Judge 把它当无结论。
package trustlib
