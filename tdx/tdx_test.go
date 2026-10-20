package tdx

import (
	"crypto/x509"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	tg "github.com/google/go-tdx-guest/testing"

	"github.com/buska88/trustlib"
)

// 样例 Quote 和它的背书来自 go-tdx-guest 的测试数据。背书的有效期覆盖这个时刻（讲义 3.9 的 F）。
var sampleTime = time.Date(2023, time.July, 1, 1, 0, 0, 0, time.UTC)

type sample struct {
	raw  []byte
	body *pb.TDQuoteBody
}

func loadSample(t *testing.T) sample {
	t.Helper()
	raw, err := os.ReadFile("../testdata/tdx/tdx_prod_quote_SPR_E4.dat")
	if err != nil {
		t.Fatal(err)
	}
	q, err := abi.QuoteToProto(raw)
	if err != nil {
		t.Fatal(err)
	}
	return sample{raw: raw, body: q.(*pb.QuoteV4).GetTdQuoteBody()}
}

func intelRoot(t *testing.T) *x509.CertPool {
	t.Helper()
	pem, err := os.ReadFile("../testdata/tdx/intel_sgx_root_ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("bad root PEM")
	}
	return pool
}

// refsFrom 用样例 Quote 自己的测量值当参考值，模拟“参考值全都对上了”。
func refsFrom(b *pb.TDQuoteBody) trustlib.ReferenceValues {
	r := b.GetRtmrs()
	return trustlib.ReferenceValues{
		RefMRTD:  {b.GetMrTd()},
		RefXFAM:  {b.GetXfam()},
		RefRTMR0: {r[0]},
		RefRTMR1: {r[1]},
		RefRTMR2: {r[2]},
	}
}

func newEval(t *testing.T, rv trustlib.ReferenceValues) *Evaluator {
	t.Helper()
	e, err := New(Config{TrustedRoots: intelRoot(t), Getter: tg.TestGetter, Reference: rv})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func flip(b []byte) []byte {
	out := append([]byte(nil), b...)
	out[0] ^= 0xff
	return out
}

// D4：各维的取值。参考值来自样例自己，再逐项改坏一项。
func TestMapping(t *testing.T) {
	s := loadSample(t)
	good := refsFrom(s.body)
	with := func(key string, val []byte) trustlib.ReferenceValues {
		rv := trustlib.ReferenceValues{}
		for k, v := range good {
			rv[k] = v
		}
		rv[key] = [][]byte{val}
		return rv
	}
	without := func(keys ...string) trustlib.ReferenceValues {
		rv := trustlib.ReferenceValues{}
		for k, v := range good {
			rv[k] = v
		}
		for _, k := range keys {
			delete(rv, k)
		}
		return rv
	}
	// RTMR1 给了两个可接受的值：一个不对，一个对。
	several := without()
	several[RefRTMR1] = [][]byte{flip(s.body.GetRtmrs()[1]), s.body.GetRtmrs()[1]}

	cases := []struct {
		name     string
		rv       trustlib.ReferenceValues
		hardware int8
		config   int8
		exec     int8
		ro       int8
		collapse trustlib.Tier
	}{
		// 全部对上：hardware 2、configuration 2、executables 3（只覆盖启动阶段）、runtime-opaque 2。
		{"all references match", good, 2, 2, 3, 2, trustlib.Affirming},
		// 没给参考值：除了不需要参考值的 runtime-opaque，各维都是 0；塌缩后是无结论，绝不是认可。
		{"no reference values", nil, 0, 0, 0, 2, trustlib.None},
		{"mr_td mismatch", with(RefMRTD, flip(s.body.GetMrTd())), 96, 2, 3, 2, trustlib.Contraindicated},
		{"xfam mismatch", with(RefXFAM, flip(s.body.GetXfam())), 2, 96, 3, 2, trustlib.Contraindicated},
		{"rtmr0 mismatch", with(RefRTMR0, flip(s.body.GetRtmrs()[0])), 2, 96, 3, 2, trustlib.Contraindicated},
		{"rtmr1 mismatch", with(RefRTMR1, flip(s.body.GetRtmrs()[1])), 2, 2, 96, 2, trustlib.Contraindicated},
		{"rtmr2 mismatch", with(RefRTMR2, flip(s.body.GetRtmrs()[2])), 2, 2, 96, 2, trustlib.Contraindicated},
		// 只给了 RTMR1、没给 RTMR2：executables 没查全，是 0。
		{"rtmr2 not provided", without(RefRTMR2), 2, 2, 0, 2, trustlib.None},
		// 一项参考值可以有多个可接受的值，命中其中之一就算相符。
		{"one of several acceptable values", several, 2, 2, 3, 2, trustlib.Affirming},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := newEval(t, c.rv).Evaluate(trustlib.Request{Input: s.raw, Nonce: s.body.GetReportData(), Now: sampleTime})
			if err != nil {
				t.Fatal(err)
			}
			v := res.Vector
			if v[trustlib.Hardware] != c.hardware || v[trustlib.Configuration] != c.config ||
				v[trustlib.Executables] != c.exec || v[trustlib.RuntimeOpaque] != c.ro {
				t.Errorf("vector = %v", v)
			}
			for _, d := range []trustlib.Dimension{trustlib.InstanceIdentity, trustlib.FileSystem, trustlib.StorageOpaque, trustlib.SourcedData} {
				if v[d] != 0 {
					t.Errorf("%s = %d, want 0 (TDX 不判断这一维)", d, v[d])
				}
			}
			if got := trustlib.Collapse(res, 0).Tier; got != c.collapse {
				t.Errorf("collapse = %v, want %v", got, c.collapse)
			}
		})
	}
}

// 没给参考值时，只关心 runtime-opaque 的调用方能拿到认可：这一维隐含在签名里，不需要参考值。
func TestRuntimeOpaqueNeedsNoReference(t *testing.T) {
	s := loadSample(t)
	res, err := newEval(t, nil).Evaluate(trustlib.Request{Input: s.raw, Nonce: s.body.GetReportData(), Now: sampleTime})
	if err != nil {
		t.Fatal(err)
	}
	if got := trustlib.Collapse(res, trustlib.MaskOf(trustlib.RuntimeOpaque)).Tier; got != trustlib.Affirming {
		t.Errorf("collapse(runtime-opaque) = %v, want affirming", got)
	}
}

// D4：TCB 状态单独放，不进 hardware。样例平台在 Intel 的 TCB 信息里找不到匹配级别（讲义 3.6）。
func TestTCBIsSeparate(t *testing.T) {
	s := loadSample(t)
	res, err := newEval(t, refsFrom(s.body)).Evaluate(trustlib.Request{Input: s.raw, Nonce: s.body.GetReportData(), Now: sampleTime})
	if err != nil {
		t.Fatal(err)
	}
	if res.TCB == nil || res.TCB.Status != trustlib.TCBNoMatchingLevel || res.TCB.QEStatus != "UpToDate" {
		t.Errorf("TCB = %+v", res.TCB)
	}
	if res.Vector[trustlib.Hardware] != trustlib.HardwareGenuine {
		t.Errorf("hardware = %d, TCB 状态不该影响 hardware", res.Vector[trustlib.Hardware])
	}
}

// D6：签名链失败是结论（hardware 97），不是错误。改的是报告体里 mr_config_id 的一个字节（u1check 的 E）。
func TestTamperedQuote(t *testing.T) {
	s := loadSample(t)
	bad := append([]byte(nil), s.raw...)
	bad[0x100] ^= 0xff
	res, err := newEval(t, refsFrom(s.body)).Evaluate(trustlib.Request{Input: bad, Nonce: s.body.GetReportData(), Now: sampleTime})
	if err != nil {
		t.Fatalf("tampered quote should be a conclusion, got error %v", err)
	}
	want := trustlib.Vector{}
	want[trustlib.Hardware] = trustlib.HardwareUnrecognized
	if res.Vector != want {
		t.Errorf("vector = %v, want only hardware=97", res.Vector)
	}
	if got := trustlib.Collapse(res, 0).Tier; got != trustlib.Contraindicated {
		t.Errorf("collapse = %v, want contraindicated", got)
	}
}

// D6：nonce 不符返回错误（可能是重放）；调用方没给 nonce 也是错误。
func TestNonce(t *testing.T) {
	s := loadSample(t)
	e := newEval(t, refsFrom(s.body))
	if _, err := e.Evaluate(trustlib.Request{Input: s.raw, Nonce: flip(s.body.GetReportData()), Now: sampleTime}); !errors.Is(err, trustlib.ErrNonceMismatch) {
		t.Errorf("err = %v, want ErrNonceMismatch", err)
	}
	if _, err := e.Evaluate(trustlib.Request{Input: s.raw, Now: sampleTime}); !errors.Is(err, trustlib.ErrConfig) {
		t.Errorf("err = %v, want ErrConfig", err)
	}
}

// D6：背书过期是“评估不了”，返回错误。同一份 Quote 和背书，校验时刻换成现在，TCB 信息已经过期（讲义 3.9 的 F）。
func TestEndorsementExpired(t *testing.T) {
	s := loadSample(t)
	_, err := newEval(t, refsFrom(s.body)).Evaluate(trustlib.Request{Input: s.raw, Nonce: s.body.GetReportData(), Now: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)})
	if !errors.Is(err, trustlib.ErrEndorsement) {
		t.Errorf("err = %v, want ErrEndorsement", err)
	}
}

// D6：PCK 证书过期也是“评估不了”，不能判成假硬件。样例的 PCK 证书 2029-09-20 到期。
func TestCertificateChainExpired(t *testing.T) {
	s := loadSample(t)
	res, err := newEval(t, refsFrom(s.body)).Evaluate(trustlib.Request{Input: s.raw, Nonce: s.body.GetReportData(), Now: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)})
	if !errors.Is(err, trustlib.ErrEndorsement) {
		t.Errorf("err = %v, result = %v; want ErrEndorsement, not a hardware=97 conclusion", err, res)
	}
}

// failingGetter 模拟背书取不到。
type failingGetter struct{}

func (failingGetter) Get(string) (map[string][]string, []byte, error) {
	return nil, nil, errors.New("endorsements unavailable")
}

// D6：背书缺失返回错误。
func TestEndorsementMissing(t *testing.T) {
	s := loadSample(t)
	e, err := New(Config{TrustedRoots: intelRoot(t), Getter: failingGetter{}, Reference: refsFrom(s.body)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Evaluate(trustlib.Request{Input: s.raw, Nonce: s.body.GetReportData(), Now: sampleTime}); !errors.Is(err, trustlib.ErrEndorsement) {
		t.Errorf("err = %v, want ErrEndorsement", err)
	}
}

// D6：解析失败返回错误。
func TestGarbage(t *testing.T) {
	_, err := newEval(t, nil).Evaluate(trustlib.Request{Input: []byte("garbage"), Nonce: []byte{1}, Now: sampleTime})
	if !errors.Is(err, trustlib.ErrParse) {
		t.Errorf("err = %v, want ErrParse", err)
	}
}

// 信任锚和背书来源必填：库里不写死，也不自己联网去取。
func TestNewRequiresTrustAnchorAndGetter(t *testing.T) {
	if _, err := New(Config{Getter: tg.TestGetter}); !errors.Is(err, trustlib.ErrConfig) {
		t.Errorf("no roots: err = %v", err)
	}
	if _, err := New(Config{TrustedRoots: intelRoot(t)}); !errors.Is(err, trustlib.ErrConfig) {
		t.Errorf("no getter: err = %v", err)
	}
}

// fakeBody 是构造出来的报告体，用来测签名验不出来的情形，例如调试位打开。
type fakeBody struct {
	mrtd, xfam, attrs, reportData []byte
	rtmrs                         [][]byte
}

func (f fakeBody) GetMrTd() []byte         { return f.mrtd }
func (f fakeBody) GetRtmrs() [][]byte      { return f.rtmrs }
func (f fakeBody) GetXfam() []byte         { return f.xfam }
func (f fakeBody) GetTdAttributes() []byte { return f.attrs }
func (f fakeBody) GetReportData() []byte   { return f.reportData }

// D4：调试位打开时，宿主能读 TD 内存。configuration 和 runtime-opaque 都判不认可，参考值全对上也一样。
func TestDebugBit(t *testing.T) {
	b := fakeBody{
		mrtd:  []byte{1},
		xfam:  []byte{2},
		attrs: []byte{0x01, 0, 0, 0, 0, 0, 0, 0}, // 第 0 位：DEBUG
		rtmrs: [][]byte{{3}, {4}, {5}, {6}},
	}
	rv := trustlib.ReferenceValues{
		RefMRTD: {{1}}, RefXFAM: {{2}}, RefRTMR0: {{3}}, RefRTMR1: {{4}}, RefRTMR2: {{5}},
	}
	v := appraise(b, rv)
	if v[trustlib.Configuration] != 96 || v[trustlib.RuntimeOpaque] != 96 {
		t.Errorf("debug TD: configuration=%d runtime-opaque=%d, want 96 and 96", v[trustlib.Configuration], v[trustlib.RuntimeOpaque])
	}
	if v[trustlib.Hardware] != 2 || v[trustlib.Executables] != 3 {
		t.Errorf("debug bit should not change hardware/executables: %v", v)
	}

	b.attrs = make([]byte, 8)
	if v := appraise(b, rv); v[trustlib.Configuration] != 2 || v[trustlib.RuntimeOpaque] != 2 {
		t.Errorf("non-debug TD: %v", v)
	}
}
