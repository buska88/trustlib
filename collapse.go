package trustlib

import "errors"

// errNoResult 用在 Judge 收到空结果、又没有错误的时候。
var errNoResult = errors.New("trustlib: no result")

// Verdict 是塌缩的结果。
type Verdict struct {
	// Tier 是最终档位。
	Tier Tier
	// Decisive 列出决定这个档位的关键维，也就是档位等于 Tier 的那几维。
	// 最终档位来自 ear.status 或评估出错时，它可能为空。
	Decisive []Dimension
	// ByStatus 为 true，表示 ear.status 比按向量算出的档位更差，最终档位取自 ear.status。
	ByStatus bool
	// Err 只在 Judge 里设置：评估出错时，Tier 是无结论，Err 是原始错误。
	Err error
}

// Collapse 把 Result 按关键维塌缩成一个档位（docs/design.md D3）：
//
//  1. 每一维先按 AR4SI 的区间归档（Classify），不直接比数值；
//  2. 只看 mask 里的维，mask 为 0 时用 DefaultMask；
//  3. 取其中最差的一档：任何一维不认可，结果就是不认可；否则任何一维无结论，结果就是无结论；以此类推；
//  4. 有 ear.status 时，再和它取更差的那个。EAR §3.1 规定 ear.status 不得高于最差一维，
//     所以取更差的那个永远不违反规范。
//
// 它不看来源类型：同一段消费者代码对三种来源都适用。
func Collapse(res *Result, mask Mask) Verdict {
	if res == nil {
		return Verdict{Tier: None, Err: errNoResult}
	}
	if mask == 0 {
		mask = DefaultMask
	}

	dims := mask.Dimensions()
	tier := Affirming
	for _, d := range dims {
		tier = Worst(tier, Classify(res.Vector[d]))
	}

	v := Verdict{Tier: tier}
	if res.Status != nil && *res.Status < tier {
		v.Tier = *res.Status
		v.ByStatus = true
	}
	for _, d := range dims {
		if Classify(res.Vector[d]) == v.Tier {
			v.Decisive = append(v.Decisive, d)
		}
	}
	return v
}

// Judge 是给消费者的便捷入口，直接接 Evaluate 的两个返回值：
// 出错时返回无结论，并把错误放进 Verdict.Err；没出错时等同于 Collapse。
//
// 出错按无结论处理，满足两侧的需要：调度侧能容忍一段时间，不立即驱逐；
// 发钥侧只在认可时发钥，无结论就不发。
func Judge(res *Result, err error, mask Mask) Verdict {
	if err != nil {
		return Verdict{Tier: None, Err: err}
	}
	if res == nil {
		return Verdict{Tier: None, Err: errNoResult}
	}
	return Collapse(res, mask)
}
