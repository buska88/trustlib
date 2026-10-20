package trustlib

import "fmt"

// Tier 是 AR4SI 的四个档位。数值越小越差，所以“取最差”就是取最小值。
// 四档之间的顺序是本库的设计决定（docs/design.md D3）：
//
//	不认可 < 无结论 < 有保留 < 认可
//
// 无结论排在不认可之上：无结论是没有证据，不认可是有证据表明不行。
type Tier uint8

const (
	Contraindicated Tier = iota // 不认可：有证据表明不行
	None                        // 无结论：没检查、证据不足或校验方故障
	Warning                     // 有保留：通过了，但有已知问题
	Affirming                   // 认可
)

// String 返回 AR4SI 里的档位名。
func (t Tier) String() string {
	switch t {
	case Contraindicated:
		return "contraindicated"
	case None:
		return "none"
	case Warning:
		return "warning"
	case Affirming:
		return "affirming"
	}
	return fmt.Sprintf("tier(%d)", uint8(t))
}

// Classify 按 AR4SI §2.3.2 的区间把一个取值归到档位：
//   - 认可：2..31，以及实现自定理由的 −2..−32
//   - 有保留：32..95，以及 −33..−96
//   - 不认可：96..127，以及 −97..−128
//   - 无结论：0、1、−1
//
// 比较之前一定要先归档：−5 比 0 小却是认可，0 比 32 小却是无结论。
func Classify(v int8) Tier {
	switch {
	case v >= -1 && v <= 1:
		return None
	case (v >= 2 && v <= 31) || (v >= -32 && v <= -2):
		return Affirming
	case (v >= 32 && v <= 95) || (v >= -96 && v <= -33):
		return Warning
	default:
		return Contraindicated
	}
}

// Worst 返回两个档位里更差的那个。
func Worst(a, b Tier) Tier {
	if a < b {
		return a
	}
	return b
}

// 适配器写进向量的 AR4SI 标准取值（draft-ietf-rats-ar4si-10 §2.3.4，名字沿用 veraison/ear）。
const (
	NoClaim             int8 = 0  // 没有声明：没检查，或证据不足以下结论
	VerifierMalfunction int8 = -1 // 校验方自己出了故障

	HardwareGenuine         int8 = 2  // 硬件与固件校验通过
	HardwareContraindicated int8 = 96 // 认得这块硬件，但不认可（例如固件测量值不符、证书被吊销）
	HardwareUnrecognized    int8 = 97 // 认不出：签名链验不到信任锚

	ConfigurationApproved      int8 = 2  // 已知且认可的配置
	ConfigurationUnsupportable int8 = 96 // 配置不可接受

	ExecutablesApprovedBoot    int8 = 3  // 启动阶段加载的都认可（不覆盖启动之后）
	ExecutablesContraindicated int8 = 96 // 有不认可的对象

	RuntimeOpaqueEncrypted int8 = 2  // 运行时内存加密，宿主不可见
	RuntimeOpaqueVisible   int8 = 96 // 运行时内存对宿主可见
)
