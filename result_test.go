package trustlib

import "testing"

// 多个子模块按维取最差（docs/design.md D2）。
func TestMergeWorst(t *testing.T) {
	submods := map[string]Vector{
		// 你方案里的例子：关注 hardware 和 file-system，模块 A 是认可和有保留，模块 B 是无结论和有保留。
		"a": vec(map[Dimension]int8{Hardware: 2, FileSystem: 32}),
		"b": vec(map[Dimension]int8{Hardware: 0, FileSystem: 33}),
	}
	got := MergeWorst(submods)
	if got[Hardware] != 0 {
		t.Errorf("hardware = %d, want 0 (b 没判断，短板是无结论)", got[Hardware])
	}
	// 两边都是有保留：档位相同取子模块名靠前的 a 的值 32。
	if got[FileSystem] != 32 {
		t.Errorf("file-system = %d, want 32 (同档取名字靠前的子模块)", got[FileSystem])
	}

	one := vec(map[Dimension]int8{Hardware: 2, Executables: 3})
	if got := MergeWorst(map[string]Vector{"cpu0": one}); got != one {
		t.Errorf("single submod changed: %v", got)
	}
	// −5（非标准的认可）和 0（无结论）合并：取无结论，不能按数值取 −5。
	got = MergeWorst(map[string]Vector{
		"a": vec(map[Dimension]int8{Configuration: -5}),
		"b": vec(map[Dimension]int8{Configuration: 0}),
	})
	if got[Configuration] != 0 {
		t.Errorf("configuration = %d, want 0", got[Configuration])
	}
}

// ReferenceValues.Check：一维用到的测量值全部给了参考值且都相符才算通过；
// 有一项不符就是不认可；没给全、或证据里缺这一项，都是 0（没检查完）。
func TestReferenceValuesCheck(t *testing.T) {
	rv := ReferenceValues{"a": {{1}}, "b": {{2}}}
	m := func(name string, v ...byte) Measurement { return Measurement{Name: name, Value: v} }
	cases := []struct {
		name string
		ms   []Measurement
		want int8
	}{
		{"all match", []Measurement{m("a", 1), m("b", 2)}, 2},
		{"one mismatch", []Measurement{m("a", 1), m("b", 9)}, 96},
		{"mismatch wins over missing reference", []Measurement{m("c", 3), m("b", 9)}, 96},
		{"one reference missing", []Measurement{m("a", 1), m("c", 3)}, 0},
		{"value absent from evidence", []Measurement{m("a", 1), {Name: "b"}}, 0},
		{"no measurements", nil, 0},
	}
	for _, c := range cases {
		if got := rv.Check(2, 96, c.ms...); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

func TestReferenceValuesMatch(t *testing.T) {
	rv := ReferenceValues{"pcr7": {{1}, {2}}}
	if p, ok := rv.Match("pcr7", []byte{2}); !p || !ok {
		t.Error("second acceptable value should match")
	}
	if p, ok := rv.Match("pcr7", []byte{3}); !p || ok {
		t.Error("unknown value should be provided-but-mismatched")
	}
	if p, _ := rv.Match("pcr4", []byte{1}); p {
		t.Error("missing key should be not-provided")
	}
	if p, _ := (ReferenceValues{"pcr4": nil}).Match("pcr4", nil); p {
		t.Error("empty list should count as not provided")
	}
}
