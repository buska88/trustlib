package trustlib

import (
	"errors"
	"reflect"
	"testing"
)

// vec 用“维度 → 取值”的写法构造向量，没写到的维是 0。
func vec(m map[Dimension]int8) Vector {
	var v Vector
	for d, x := range m {
		v[d] = x
	}
	return v
}

func tierPtr(t Tier) *Tier { return &t }

// D3 塌缩规则的用例表。每一行的期望值都写明依据的是 D3 的哪一条：
//
//	D3-1 每一维先按 AR4SI 区间归档，不直接比数值
//	D3-2 只看关键维，默认 hardware、configuration、executables
//	D3-3 取关键维里最差的一档：不认可 < 无结论 < 有保留 < 认可
//	D3-4 有 ear.status 时，再和它取更差的那个
func TestCollapse(t *testing.T) {
	allAffirming := map[Dimension]int8{Hardware: 2, Configuration: 2, Executables: 3}

	cases := []struct {
		name         string
		vector       map[Dimension]int8
		status       *Tier
		mask         Mask
		want         Tier
		wantDecisive []Dimension
		wantByStatus bool
	}{
		{
			name:         "all key dims affirming",
			vector:       allAffirming,
			want:         Affirming, // D3-3：三维都认可
			wantDecisive: []Dimension{Configuration, Executables, Hardware},
		},
		{
			name:         "nothing judged",
			vector:       nil,
			want:         None, // D3-1：0 是无结论；全部没判断 → 无结论
			wantDecisive: []Dimension{Configuration, Executables, Hardware},
		},
		{
			name:         "verifier malfunction -1",
			vector:       map[Dimension]int8{Hardware: 2, Configuration: 2, Executables: -1},
			want:         None, // D3-1：−1 是无结论（校验方故障），不是不认可
			wantDecisive: []Dimension{Executables},
		},
		{
			name:         "one key dim not judged",
			vector:       map[Dimension]int8{Hardware: 2, Configuration: 0, Executables: 3},
			want:         None, // D3-3：关键维有一维没判断 → 无结论
			wantDecisive: []Dimension{Configuration},
		},
		{
			name:         "non-standard affirming -5",
			vector:       map[Dimension]int8{Hardware: -5, Configuration: 2, Executables: 3},
			want:         Affirming, // D3-1：−5 归认可，不能因为数值小于 0 就当成最差
			wantDecisive: []Dimension{Configuration, Executables, Hardware},
		},
		{
			name:         "contraindicated 96",
			vector:       map[Dimension]int8{Hardware: 2, Configuration: 2, Executables: 96},
			want:         Contraindicated, // D3-3：任何一维不认可 → 不认可
			wantDecisive: []Dimension{Executables},
		},
		{
			name:         "warning 32",
			vector:       map[Dimension]int8{Hardware: 32, Configuration: 2, Executables: 3},
			want:         Warning, // D3-3：最差的一维是有保留
			wantDecisive: []Dimension{Hardware},
		},
		{
			name:         "contraindicated beats not judged",
			vector:       map[Dimension]int8{Hardware: 97, Configuration: 2, Executables: 0},
			want:         Contraindicated, // D3-3：不认可比无结论更差；不能因为有一维没判断就整体降成无结论
			wantDecisive: []Dimension{Hardware},
		},
		{
			name:         "not judged beats warning",
			vector:       map[Dimension]int8{Hardware: 32, Configuration: 2, Executables: 0},
			want:         None, // D3-3：无结论比有保留更差
			wantDecisive: []Dimension{Executables},
		},
		{
			name:         "non-key dim contraindicated is ignored",
			vector:       map[Dimension]int8{Hardware: 2, Configuration: 2, Executables: 3, FileSystem: 96},
			want:         Affirming, // D3-2：file-system 不在默认关键维里
			wantDecisive: []Dimension{Configuration, Executables, Hardware},
		},
		{
			name:         "caller adds runtime-opaque, source cannot judge it",
			vector:       allAffirming, // 例如 TPM 来源：runtime-opaque 恒为 0
			mask:         DefaultMask | MaskOf(RuntimeOpaque),
			want:         None, // D3-2：发钥侧加上 runtime-opaque，TPM 来源永远拿不到认可
			wantDecisive: []Dimension{RuntimeOpaque},
		},
		{
			name:         "caller narrows to hardware only",
			vector:       map[Dimension]int8{Hardware: 2, Executables: 96},
			mask:         MaskOf(Hardware),
			want:         Affirming, // D3-2：只关心 hardware
			wantDecisive: []Dimension{Hardware},
		},
		{
			name:         "ear.status worse than vector",
			vector:       allAffirming,
			status:       tierPtr(Warning),
			want:         Warning, // D3-4：按向量是认可，ear.status 是有保留 → 取更差的有保留
			wantByStatus: true,
		},
		{
			name:         "ear.status better than vector",
			vector:       map[Dimension]int8{Hardware: 2, Configuration: 2, Executables: 96},
			status:       tierPtr(Affirming),
			want:         Contraindicated, // D3-4：校验方违反了 EAR §3.1，按向量重算的结果更差，以它为准
			wantDecisive: []Dimension{Executables},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := &Result{Vector: vec(c.vector), Status: c.status}
			got := Collapse(res, c.mask)
			if got.Tier != c.want {
				t.Errorf("tier = %v, want %v (vector: %v)", got.Tier, c.want, res.Vector)
			}
			if got.ByStatus != c.wantByStatus {
				t.Errorf("ByStatus = %v, want %v", got.ByStatus, c.wantByStatus)
			}
			if !reflect.DeepEqual(got.Decisive, c.wantDecisive) {
				t.Errorf("Decisive = %v, want %v", got.Decisive, c.wantDecisive)
			}
		})
	}
}

// Judge：评估出错按无结论处理，并保留原始错误（docs/design.md D6）。
func TestJudge(t *testing.T) {
	v := Judge(nil, ErrNonceMismatch, 0)
	if v.Tier != None || !errors.Is(v.Err, ErrNonceMismatch) {
		t.Errorf("Judge(err) = %+v, want None with ErrNonceMismatch", v)
	}
	if v := Judge(nil, nil, 0); v.Tier != None || v.Err == nil {
		t.Errorf("Judge(nil, nil) = %+v, want None with an error", v)
	}
	res := &Result{Vector: vec(map[Dimension]int8{Hardware: 2, Configuration: 2, Executables: 3})}
	if v := Judge(res, nil, 0); v.Tier != Affirming || v.Err != nil {
		t.Errorf("Judge(res) = %+v, want Affirming", v)
	}
}

func TestMaskZeroMeansDefault(t *testing.T) {
	res := &Result{Vector: vec(map[Dimension]int8{Hardware: 2, Configuration: 2, Executables: 3})}
	if a, b := Collapse(res, 0), Collapse(res, DefaultMask); a.Tier != b.Tier {
		t.Errorf("mask 0 = %v, DefaultMask = %v", a.Tier, b.Tier)
	}
	if DefaultMask.String() != "configuration|executables|hardware" {
		t.Errorf("DefaultMask = %s", DefaultMask)
	}
}
