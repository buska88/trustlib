package ear

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	vear "github.com/veraison/ear"

	"github.com/buska88/trustlib"
)

var testNow = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// appraisal 构造一个子模块的评估：status 和八维向量。
func appraisal(status vear.TrustTier, tv vear.TrustVector) *vear.Appraisal {
	return &vear.Appraisal{Status: &status, TrustVector: &tv}
}

// signEAR 用测试密钥签一份 EAR。默认一个子模块 cpu0，三维都认可，签发时间是 testNow。
func signEAR(t *testing.T, key *ecdsa.PrivateKey, mutate func(*vear.AttestationResult)) []byte {
	t.Helper()
	ar := vear.NewAttestationResult("cpu0", "test-verifier-1.0", "trustlib-tests")
	iat := testNow.Unix()
	ar.IssuedAt = &iat
	ar.Submods["cpu0"] = appraisal(vear.TrustTierAffirming, vear.TrustVector{Hardware: 2, Configuration: 2, Executables: 3})
	if mutate != nil {
		mutate(ar)
	}
	tok, err := ar.Sign(jwa.ES256(), key)
	if err != nil {
		t.Fatalf("sign EAR: %v", err)
	}
	return tok
}

func evaluator(t *testing.T, cfg Config) *Evaluator {
	t.Helper()
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestGoodEAR(t *testing.T) {
	key := newKey(t)
	e := evaluator(t, Config{VerifierKey: &key.PublicKey})
	res, err := e.Evaluate(trustlib.Request{Input: signEAR(t, key, nil), Now: testNow})
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != "ear" || res.Vector[trustlib.Hardware] != 2 || res.Vector[trustlib.Executables] != 3 {
		t.Errorf("unexpected result: %+v", res)
	}
	if res.Status == nil || *res.Status != trustlib.Affirming {
		t.Errorf("status = %v, want affirming", res.Status)
	}
	if !res.IssuedAt.Equal(testNow) {
		t.Errorf("iat = %v, want %v", res.IssuedAt, testNow)
	}
	if v := trustlib.Collapse(res, 0); v.Tier != trustlib.Affirming {
		t.Errorf("collapse = %v, want affirming", v.Tier)
	}
}

// bad 样例：签名没问题，但校验方判了 executables 96、ear.status 不认可。这是结论，不是错误。
func TestBadEAR(t *testing.T) {
	key := newKey(t)
	e := evaluator(t, Config{VerifierKey: &key.PublicKey})
	tok := signEAR(t, key, func(ar *vear.AttestationResult) {
		ar.Submods["cpu0"] = appraisal(vear.TrustTierContraindicated, vear.TrustVector{Hardware: 2, Configuration: 2, Executables: 96})
	})
	res, err := e.Evaluate(trustlib.Request{Input: tok, Now: testNow})
	if err != nil {
		t.Fatal(err)
	}
	v := trustlib.Collapse(res, 0)
	if v.Tier != trustlib.Contraindicated || len(v.Decisive) != 1 || v.Decisive[0] != trustlib.Executables {
		t.Errorf("collapse = %+v, want contraindicated decided by executables", v)
	}
}

// D6：EAR 验签失败返回错误，内容一个字都不读。
func TestWrongVerifierKey(t *testing.T) {
	signer, other := newKey(t), newKey(t)
	e := evaluator(t, Config{VerifierKey: &other.PublicKey})
	_, err := e.Evaluate(trustlib.Request{Input: signEAR(t, signer, nil), Now: testNow})
	if !errors.Is(err, trustlib.ErrUntrustedResult) {
		t.Fatalf("err = %v, want ErrUntrustedResult", err)
	}
	if v := trustlib.Judge(nil, err, 0); v.Tier != trustlib.None {
		t.Errorf("Judge = %v, want none (评估不了按无结论处理)", v.Tier)
	}
}

// D6：解析失败返回错误。
func TestNotAJWS(t *testing.T) {
	key := newKey(t)
	e := evaluator(t, Config{VerifierKey: &key.PublicKey})
	if _, err := e.Evaluate(trustlib.Request{Input: []byte("not a token"), Now: testNow}); !errors.Is(err, trustlib.ErrParse) {
		t.Fatalf("err = %v, want ErrParse", err)
	}
}

// D6：nonce 不符返回错误；调用方没给 nonce 时不检查。
func TestNonce(t *testing.T) {
	key := newKey(t)
	e := evaluator(t, Config{VerifierKey: &key.PublicKey})
	tok := signEAR(t, key, func(ar *vear.AttestationResult) {
		n := "nonce-123"
		ar.Nonce = &n
	})
	if _, err := e.Evaluate(trustlib.Request{Input: tok, Nonce: []byte("nonce-123"), Now: testNow}); err != nil {
		t.Errorf("matching nonce: %v", err)
	}
	if _, err := e.Evaluate(trustlib.Request{Input: tok, Nonce: []byte("nonce-999"), Now: testNow}); !errors.Is(err, trustlib.ErrNonceMismatch) {
		t.Errorf("err = %v, want ErrNonceMismatch", err)
	}
	if _, err := e.Evaluate(trustlib.Request{Input: signEAR(t, key, nil), Nonce: []byte("nonce-123"), Now: testNow}); !errors.Is(err, trustlib.ErrNonceMismatch) {
		t.Errorf("EAR without eat_nonce but caller expects one: err = %v, want ErrNonceMismatch", err)
	}
	if res, err := e.Evaluate(trustlib.Request{Input: tok, Now: testNow}); err != nil || string(res.Nonce) != "nonce-123" {
		t.Errorf("no expected nonce: res=%v err=%v", res, err)
	}
}

// 校验时刻从外面注入：同一份 EAR，钉在签发后 30 分钟算新鲜，钉在 2 小时后算太旧。
func TestMaxAge(t *testing.T) {
	key := newKey(t)
	e := evaluator(t, Config{VerifierKey: &key.PublicKey, MaxAge: time.Hour})
	tok := signEAR(t, key, nil)
	if _, err := e.Evaluate(trustlib.Request{Input: tok, Now: testNow.Add(30 * time.Minute)}); err != nil {
		t.Errorf("fresh EAR rejected: %v", err)
	}
	if _, err := e.Evaluate(trustlib.Request{Input: tok, Now: testNow.Add(2 * time.Hour)}); !errors.Is(err, trustlib.ErrStale) {
		t.Errorf("err = %v, want ErrStale", err)
	}
}

// D2：多个子模块按维取最差，同时保留每个子模块自己的向量。
func TestMultipleSubmods(t *testing.T) {
	key := newKey(t)
	e := evaluator(t, Config{VerifierKey: &key.PublicKey})
	tok := signEAR(t, key, func(ar *vear.AttestationResult) {
		ar.Submods["gpu0"] = appraisal(vear.TrustTierAffirming, vear.TrustVector{Hardware: 2})
	})
	res, err := e.Evaluate(trustlib.Request{Input: tok, Now: testNow})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Submods) != 2 || res.Submods["cpu0"][trustlib.Executables] != 3 || res.Submods["gpu0"][trustlib.Executables] != 0 {
		t.Errorf("submods not kept: %v", res.Submods)
	}
	if res.Vector[trustlib.Executables] != 0 || res.Vector[trustlib.Hardware] != 2 {
		t.Errorf("merged vector = %v", res.Vector)
	}
	// gpu0 没判 configuration 和 executables，短板是无结论。
	if v := trustlib.Collapse(res, 0); v.Tier != trustlib.None {
		t.Errorf("collapse = %v, want none", v.Tier)
	}
}

// D3-4：ear.status 比向量更差时取 ear.status。
func TestStatusWorseThanVector(t *testing.T) {
	key := newKey(t)
	e := evaluator(t, Config{VerifierKey: &key.PublicKey})
	tok := signEAR(t, key, func(ar *vear.AttestationResult) {
		ar.Submods["cpu0"] = appraisal(vear.TrustTierWarning, vear.TrustVector{Hardware: 2, Configuration: 2, Executables: 3})
	})
	res, err := e.Evaluate(trustlib.Request{Input: tok, Now: testNow})
	if err != nil {
		t.Fatal(err)
	}
	if v := trustlib.Collapse(res, 0); v.Tier != trustlib.Warning || !v.ByStatus {
		t.Errorf("collapse = %+v, want warning by status", v)
	}
}

// −1（校验方故障）塌缩成无结论，不是不认可。
func TestVerifierMalfunction(t *testing.T) {
	key := newKey(t)
	e := evaluator(t, Config{VerifierKey: &key.PublicKey})
	tok := signEAR(t, key, func(ar *vear.AttestationResult) {
		ar.Submods["cpu0"] = appraisal(vear.TrustTierNone, vear.TrustVector{Hardware: 2, Configuration: 2, Executables: -1})
	})
	res, err := e.Evaluate(trustlib.Request{Input: tok, Now: testNow})
	if err != nil {
		t.Fatal(err)
	}
	if v := trustlib.Collapse(res, 0); v.Tier != trustlib.None {
		t.Errorf("collapse = %v, want none", v.Tier)
	}
}

// arc 对照：testdata/ear 里的 EAR 按 arc create 的做法生成（internal/genear），用 veraison 的测试公钥验签。
// 解出的八维必须和 claims 文件里写的逐维相同。
func TestArcSamples(t *testing.T) {
	pkey, err := os.ReadFile("../testdata/ear/pkey.json")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ParseJWK(pkey)
	if err != nil {
		t.Fatal(err)
	}
	e := evaluator(t, Config{VerifierKey: key})

	for _, c := range []struct {
		jwt, claims string
		want        trustlib.Tier
	}{
		{"tv.jwt", "ear-claims-tv-ok.json", trustlib.Affirming},
		{"bad.jwt", "ear-claims-bad.json", trustlib.Contraindicated},
	} {
		tok, err := os.ReadFile("../testdata/ear/" + c.jwt)
		if err != nil {
			t.Fatal(err)
		}
		res, err := e.Evaluate(trustlib.Request{Input: tok})
		if err != nil {
			t.Fatalf("%s: %v", c.jwt, err)
		}
		if got := claimsVector(t, "../testdata/ear/"+c.claims); res.Vector != got {
			t.Errorf("%s: vector = %v\n  claims say %v", c.jwt, res.Vector, got)
		}
		if v := trustlib.Collapse(res, 0); v.Tier != c.want {
			t.Errorf("%s: collapse = %v, want %v", c.jwt, v.Tier, c.want)
		}
	}
}

// claimsVector 直接从 claims JSON 读出 test 子模块的八维，作为对照。
func claimsVector(t *testing.T, path string) trustlib.Vector {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Submods map[string]struct {
			TV map[string]int8 `json:"ear.trustworthiness-vector"`
		} `json:"submods"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	var v trustlib.Vector
	for _, d := range trustlib.AllDimensions() {
		v[d] = doc.Submods["test"].TV[d.String()]
	}
	return v
}

func TestNewRequiresVerifierKey(t *testing.T) {
	if _, err := New(Config{}); !errors.Is(err, trustlib.ErrConfig) {
		t.Fatalf("err = %v, want ErrConfig", err)
	}
}
