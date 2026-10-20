package trustlib

import (
	"bytes"
	"sort"
	"time"
)

// Request 是每次评估的输入。
type Request struct {
	// Input 是原始输入：EAR 令牌、TDX Quote 或 TPM 证明，格式见各来源包的文档。
	Input []byte

	// Nonce 是调用方期望在输入里看到的 nonce：
	//   - TDX：必须和 Quote 的 report_data（64 字节）逐字节相等。nonce 怎样放进 report_data
	//     （原样补零，还是先做哈希）是调用方和证明方之间的约定，调用方按约定算好再传进来；
	//   - TPM：必须和 Quote 的 extraData 相等；
	//   - EAR：非空时必须和顶层 eat_nonce 相等；为空表示不靠 nonce，只看 iat。
	Nonce []byte

	// Now 是校验时刻，零值表示 time.Now()。离线测试把它钉在背书的有效期内。
	Now time.Time
}

// Time 返回校验时刻：Now 为零值时用当前时间。
func (r Request) Time() time.Time {
	if r.Now.IsZero() {
		return time.Now()
	}
	return r.Now
}

// Evaluator 是消费者唯一要依赖的接口，一种来源一个实现。加一种新来源，就是新加一个实现它的包。
type Evaluator interface {
	// Name 返回来源名，例如 "ear"、"tdx"、"tpm"。
	Name() string

	// Evaluate 把一份输入变成 Result。
	//
	// 返回 error 表示评估不了（错误类别见 errors.go），这时没有任何可信的结论，消费者应按无结论处理。
	// 有证据表明不行时不返回 error，而是在向量里写不认可档的值。
	Evaluate(req Request) (*Result, error)
}

// ReferenceValues 是参考值：键是测量项的名字（例如 "mr_td"、"rtmr1"、"pcr7"），
// 值是可以接受的取值列表，命中其中任何一个就算相符。参考值由调用方传入，库里不写死。
type ReferenceValues map[string][][]byte

// Match 报告 name 有没有参考值（provided），以及 got 是否命中其中之一（ok）。
func (rv ReferenceValues) Match(name string, got []byte) (provided, ok bool) {
	want, provided := rv[name]
	if !provided || len(want) == 0 {
		return false, false
	}
	for _, w := range want {
		if bytes.Equal(w, got) {
			return true, true
		}
	}
	return true, false
}

// Measurement 是证据里的一项测量值：Name 是它在参考值里的键，Value 是实际值。
// Value 为 nil 表示证据里没有这一项（例如 TPM Quote 没选这个 PCR）。
type Measurement struct {
	Name  string
	Value []byte
}

// Check 把某一维用到的一组测量值和参考值比，得出这一维的取值（docs/design.md D4、D5）：
//   - 任何一项给了参考值、证据里也有这一项，却不相符 → bad（有证据表明不行）；
//   - 每一项都给了参考值、证据里都有、并且都相符 → good；
//   - 其余情况（有项没给参考值，或证据里没有这一项）→ 0：没检查完，不能判为可信。
func (rv ReferenceValues) Check(good, bad int8, ms ...Measurement) int8 {
	complete := len(ms) > 0
	for _, m := range ms {
		if m.Value == nil {
			complete = false
			continue
		}
		provided, ok := rv.Match(m.Name, m.Value)
		if provided && !ok {
			return bad
		}
		if !provided {
			complete = false
		}
	}
	if complete {
		return good
	}
	return NoClaim
}

// TCBNoMatchingLevel 表示 Intel 的 TCB 信息里找不到与本平台匹配的级别。
const TCBNoMatchingLevel = "NoMatchingLevel"

// PlatformTCB 是平台的 TCB 状态（目前只有 TDX 有）。它单独放一个字段，不并进 hardware 维：
// “硬件是不是真的”和“固件是不是最新”是两个问题，调度侧和发钥侧对它的容忍度也不同（docs/design.md D4）。
type PlatformTCB struct {
	// Status 是 Intel TCB 信息里与本平台匹配的那一级的状态，例如 UpToDate、OutOfDate、
	// SWHardeningNeeded；找不到匹配的级别时是 TCBNoMatchingLevel。
	Status string
	// QEStatus 是 QE 身份里与本平台 QE 匹配的那一级的状态。
	QEStatus string
	// Date 是匹配级别的 tcbDate，原样保留。
	Date string
}

// Result 是归一化之后的结果（docs/design.md D2）。
type Result struct {
	// Source 是来源名，例如 "tdx"。
	Source string
	// Vector 是合并后的八维原始值。有多个子模块时按维取最差（见 MergeWorst）。
	Vector Vector
	// Submods 是每个子模块各自的向量，审计时用来看“是哪个部件出了问题”。
	// 证据来源只有一个子模块，名字就是来源名。
	Submods map[string]Vector
	// Status 是 EAR 里的 ear.status；有多个子模块时取最差。证据来源没有它，为 nil。
	Status *Tier
	// TCB 是平台 TCB 状态，不适用时为 nil。
	TCB *PlatformTCB
	// Nonce 是输入里实际带的 nonce（TDX 的 report_data、TPM 的 extraData、EAR 的顶层 eat_nonce）。
	Nonce []byte
	// IssuedAt 是 EAR 的签发时间 iat；证据来源为零值。
	IssuedAt time.Time
	// Raw 是原始输入，留给审计。
	Raw []byte
}

// MergeWorst 把多个子模块的向量按维合并：每一维取档位最差的那个子模块的值。
// 档位相同时取子模块名排序靠前的那个，保证结果确定。
//
// 0 属于无结论，所以一个子模块判了认可、另一个子模块没判，合并结果是无结论：
// 复合设备的可信度取决于最弱的那部分。
func MergeWorst(submods map[string]Vector) Vector {
	names := make([]string, 0, len(submods))
	for name := range submods {
		names = append(names, name)
	}
	sort.Strings(names)

	var merged Vector
	for _, d := range AllDimensions() {
		for i, name := range names {
			v := submods[name][d]
			if i == 0 || Classify(v) < Classify(merged[d]) {
				merged[d] = v
			}
		}
	}
	return merged
}
