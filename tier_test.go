package trustlib

import (
	"math"
	"testing"

	"github.com/veraison/ear"
)

// 区间边界逐个核对（AR4SI §2.3.2）。
func TestClassifyBoundaries(t *testing.T) {
	cases := []struct {
		v    int8
		want Tier
	}{
		{0, None}, {1, None}, {-1, None},
		{2, Affirming}, {3, Affirming}, {31, Affirming}, {-2, Affirming}, {-5, Affirming}, {-32, Affirming},
		{32, Warning}, {33, Warning}, {36, Warning}, {95, Warning}, {-33, Warning}, {-96, Warning},
		{96, Contraindicated}, {97, Contraindicated}, {99, Contraindicated}, {127, Contraindicated},
		{-97, Contraindicated}, {-128, Contraindicated},
	}
	for _, c := range cases {
		if got := Classify(c.v); got != c.want {
			t.Errorf("Classify(%d) = %v, want %v", c.v, got, c.want)
		}
	}
}

// 全部 256 个取值都和 veraison/ear 的归档一致：两边按同一份 AR4SI 区间实现。
func TestClassifyAgreesWithVeraison(t *testing.T) {
	toOurs := map[ear.TrustTier]Tier{
		ear.TrustTierNone:            None,
		ear.TrustTierAffirming:       Affirming,
		ear.TrustTierWarning:         Warning,
		ear.TrustTierContraindicated: Contraindicated,
	}
	for i := math.MinInt8; i <= math.MaxInt8; i++ {
		v := int8(i)
		want := toOurs[ear.TrustClaim(v).GetTier()]
		if got := Classify(v); got != want {
			t.Errorf("Classify(%d) = %v, veraison says %v", v, got, want)
		}
	}
}

// 静默失败 10：不能直接比数值大小。两个反例各推翻一种直接比法：
// −5 < 0，但 −5（认可）比 0（无结论）好，所以“数值大的好”不成立；
// 0 < 32，但 0（无结论）比 32（有保留）差，所以“数值小的好”也不成立。
func TestNumericOrderIsNotTierOrder(t *testing.T) {
	if Classify(-5) <= Classify(0) {
		t.Error("−5 应该比 0 好：−5 是认可，0 是无结论")
	}
	if Classify(0) >= Classify(32) {
		t.Error("0 应该比 32 差：0 是无结论，32 是有保留")
	}
}

func TestTierOrder(t *testing.T) {
	// 从差到好：不认可 < 无结论 < 有保留 < 认可（docs/design.md D3）。
	order := []Tier{Contraindicated, None, Warning, Affirming}
	for i := 1; i < len(order); i++ {
		if order[i-1] >= order[i] {
			t.Fatalf("tier order broken: %v should be below %v", order[i-1], order[i])
		}
	}
	if Worst(None, Contraindicated) != Contraindicated || Worst(Affirming, Warning) != Warning {
		t.Fatal("Worst broken")
	}
}
