package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	attest "github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm/legacy/tpm2"
	"google.golang.org/protobuf/proto"

	"github.com/buska88/trustlib"
)

// 测试数据由 internal/gentpm 用软件 TPM 生成。AK 证书的有效期是 2025–2035，校验时刻钉在里面。
var testNow = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../testdata/tpm/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testNonce(t *testing.T) []byte {
	t.Helper()
	n, err := hex.DecodeString(strings.TrimSpace(string(readFile(t, "nonce.hex"))))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func akCA(t *testing.T) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(readFile(t, "ak_ca.pem"))
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func parse(t *testing.T, raw []byte) *attest.Attestation {
	t.Helper()
	var att attest.Attestation
	if err := proto.Unmarshal(raw, &att); err != nil {
		t.Fatal(err)
	}
	return &att
}

func marshal(t *testing.T, att *attest.Attestation) []byte {
	t.Helper()
	b, err := proto.Marshal(att)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func akPubOf(t *testing.T, att *attest.Attestation) crypto.PublicKey {
	t.Helper()
	area, err := tpm2.DecodePublic(att.GetAkPub())
	if err != nil {
		t.Fatal(err)
	}
	k, err := area.Key()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// refsFrom 用证明里自己的 PCR 值当参考值，模拟“参考值全都对上了”。executables 用 PCR4。
func refsFrom(att *attest.Attestation) trustlib.ReferenceValues {
	pcrs := att.GetQuotes()[0].GetPcrs().GetPcrs()
	return trustlib.ReferenceValues{RefPCR0: {pcrs[0]}, RefPCR7: {pcrs[7]}, RefPCR4: {pcrs[4]}}
}

func evaluate(t *testing.T, cfg Config, raw []byte, now time.Time) (*trustlib.Result, error) {
	t.Helper()
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e.Evaluate(trustlib.Request{Input: raw, Nonce: testNonce(t), Now: now})
}

func wantVector(t *testing.T, got trustlib.Vector, hardware, config, exec int8) {
	t.Helper()
	var want trustlib.Vector
	want[trustlib.Hardware], want[trustlib.Configuration], want[trustlib.Executables] = hardware, config, exec
	if got != want {
		t.Errorf("vector = %v\n  want  %v", got, want)
	}
}

// D5：AK 由证书担保，PCR 全对上。runtime-opaque 恒为 0：TPM 不保护运行时内存。
func TestVouchedByCertificate(t *testing.T) {
	raw := readFile(t, "attestation.pb")
	res, err := evaluate(t, Config{AKRoots: []*x509.Certificate{akCA(t)}, Reference: refsFrom(parse(t, raw))}, raw, testNow)
	if err != nil {
		t.Fatal(err)
	}
	wantVector(t, res.Vector, 2, 2, 3)
	if got := trustlib.Collapse(res, 0).Tier; got != trustlib.Affirming {
		t.Errorf("collapse = %v, want affirming", got)
	}
	// 发钥侧加上 runtime-opaque：TPM 来源永远拿不到认可，这是对的。
	if got := trustlib.Collapse(res, trustlib.DefaultMask|trustlib.MaskOf(trustlib.RuntimeOpaque)).Tier; got != trustlib.None {
		t.Errorf("collapse with runtime-opaque = %v, want none", got)
	}
}

// D5：AK 由事先登记的名单担保（Trustee 的做法）。
func TestVouchedByList(t *testing.T) {
	raw := readFile(t, "attestation.pb")
	att := parse(t, raw)
	res, err := evaluate(t, Config{TrustedAKs: []crypto.PublicKey{akPubOf(t, att)}, Reference: refsFrom(att)}, raw, testNow)
	if err != nil {
		t.Fatal(err)
	}
	wantVector(t, res.Vector, 2, 2, 3)
}

// D5、D6：AK 没人担保 → hardware 97，其余各维不判断。这是结论，不是错误。
func TestUnvouchedAK(t *testing.T) {
	good := parse(t, readFile(t, "attestation.pb"))
	raw := readFile(t, "attestation_unvouched.pb")
	res, err := evaluate(t, Config{
		AKRoots:    []*x509.Certificate{akCA(t)},
		TrustedAKs: []crypto.PublicKey{akPubOf(t, good)},
		Reference:  refsFrom(parse(t, raw)),
	}, raw, testNow)
	if err != nil {
		t.Fatal(err)
	}
	wantVector(t, res.Vector, 97, 0, 0)
	if got := trustlib.Collapse(res, 0).Tier; got != trustlib.Contraindicated {
		t.Errorf("collapse = %v, want contraindicated", got)
	}
}

// 附一张别的 AK 的合法证书也不行：证书里的公钥必须就是这把 AK。
func TestCertificateForAnotherKey(t *testing.T) {
	good := parse(t, readFile(t, "attestation.pb"))
	other := parse(t, readFile(t, "attestation_unvouched.pb"))
	other.AkCert = good.GetAkCert()
	res, err := evaluate(t, Config{AKRoots: []*x509.Certificate{akCA(t)}, Reference: refsFrom(other)}, marshal(t, other), testNow)
	if err != nil {
		t.Fatal(err)
	}
	wantVector(t, res.Vector, 97, 0, 0)
}

// 证书验不到调用方给的根 → 没有担保。
func TestWrongRoot(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "some other CA"},
		NotBefore: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2045, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	otherCA, _ := x509.ParseCertificate(der)

	raw := readFile(t, "attestation.pb")
	res, err := evaluate(t, Config{AKRoots: []*x509.Certificate{otherCA}, Reference: refsFrom(parse(t, raw))}, raw, testNow)
	if err != nil {
		t.Fatal(err)
	}
	wantVector(t, res.Vector, 97, 0, 0)
}

// D6：AK 证书过期是“评估不了”，返回错误。校验时刻从外面注入，钉在证书到期之后。
func TestCertificateExpired(t *testing.T) {
	raw := readFile(t, "attestation.pb")
	_, err := evaluate(t, Config{AKRoots: []*x509.Certificate{akCA(t)}, Reference: refsFrom(parse(t, raw))}, raw, time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC))
	if !errors.Is(err, trustlib.ErrEndorsement) {
		t.Errorf("err = %v, want ErrEndorsement", err)
	}
}

// D6：改了一个 PCR 值，摘要对不上签名 → hardware 97。
func TestTamperedPCR(t *testing.T) {
	att := parse(t, readFile(t, "attestation.pb"))
	refs := refsFrom(att)
	pcrs := att.GetQuotes()[0].GetPcrs().GetPcrs()
	pcrs[7] = append([]byte(nil), pcrs[7]...)
	pcrs[7][0] ^= 0xff
	res, err := evaluate(t, Config{AKRoots: []*x509.Certificate{akCA(t)}, Reference: refs}, marshal(t, att), testNow)
	if err != nil {
		t.Fatal(err)
	}
	wantVector(t, res.Vector, 97, 0, 0)
}

// D6：nonce 不符返回错误（可能是重放）；调用方没给 nonce 也是错误。
func TestNonce(t *testing.T) {
	raw := readFile(t, "attestation.pb")
	e, err := New(Config{AKRoots: []*x509.Certificate{akCA(t)}, Reference: refsFrom(parse(t, raw))})
	if err != nil {
		t.Fatal(err)
	}
	other := append([]byte(nil), testNonce(t)...)
	other[0] ^= 0xff
	if _, err := e.Evaluate(trustlib.Request{Input: raw, Nonce: other, Now: testNow}); !errors.Is(err, trustlib.ErrNonceMismatch) {
		t.Errorf("err = %v, want ErrNonceMismatch", err)
	}
	if _, err := e.Evaluate(trustlib.Request{Input: raw, Now: testNow}); !errors.Is(err, trustlib.ErrConfig) {
		t.Errorf("err = %v, want ErrConfig", err)
	}
}

// D5：各 PCR 和参考值不符时，对应的那一维判不认可。
func TestPCRMismatch(t *testing.T) {
	raw := readFile(t, "attestation.pb")
	wrong := func(key string) trustlib.ReferenceValues {
		rv := refsFrom(parse(t, raw))
		rv[key] = [][]byte{make([]byte, 32)}
		return rv
	}
	cases := []struct {
		name                  string
		rv                    trustlib.ReferenceValues
		hardware, config, exe int8
	}{
		{"pcr0 mismatch", wrong(RefPCR0), 96, 2, 3},
		{"pcr7 mismatch", wrong(RefPCR7), 2, 96, 3},
		{"pcr4 mismatch", wrong(RefPCR4), 2, 2, 96},
		// 没给参考值：各维都是 0，塌缩后是无结论，不是认可。
		{"no reference values", nil, 0, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := evaluate(t, Config{AKRoots: []*x509.Certificate{akCA(t)}, Reference: c.rv}, raw, testNow)
			if err != nil {
				t.Fatal(err)
			}
			wantVector(t, res.Vector, c.hardware, c.config, c.exe)
			if got := trustlib.Collapse(res, 0).Tier; got == trustlib.Affirming {
				t.Errorf("collapse = %v; a mismatch or missing reference must never be affirming", got)
			}
		})
	}
}

// D5：用统一内核镜像（UKI）启动时，executables 看 PCR11。
func TestUKI(t *testing.T) {
	raw := readFile(t, "attestation.pb")
	pcr11 := parse(t, raw).GetQuotes()[0].GetPcrs().GetPcrs()[11]
	rv := refsFrom(parse(t, raw))
	delete(rv, RefPCR4)
	rv[RefPCR11] = [][]byte{pcr11}
	res, err := evaluate(t, Config{AKRoots: []*x509.Certificate{akCA(t)}, Reference: rv}, raw, testNow)
	if err != nil {
		t.Fatal(err)
	}
	wantVector(t, res.Vector, 2, 2, 3)

	rv[RefPCR11] = [][]byte{make([]byte, 31)}
	res, err = evaluate(t, Config{AKRoots: []*x509.Certificate{akCA(t)}, Reference: rv}, raw, testNow)
	if err != nil {
		t.Fatal(err)
	}
	wantVector(t, res.Vector, 2, 2, 96)
}

// Quote 没选某个 PCR：用到它的那一维没检查完，是 0，而不是不认可。
func TestPCRNotInQuote(t *testing.T) {
	pcrs := map[uint32][]byte{0: {1}, 7: {7}}
	rv := trustlib.ReferenceValues{RefPCR0: {{1}}, RefPCR7: {{7}}, RefPCR4: {{4}}}
	v := appraise(pcrs, rv)
	if v[trustlib.Executables] != 0 || v[trustlib.Hardware] != 2 || v[trustlib.Configuration] != 2 {
		t.Errorf("vector = %v", v)
	}
}

// D6：解析失败返回错误。
func TestGarbage(t *testing.T) {
	_, err := evaluate(t, Config{AKRoots: []*x509.Certificate{akCA(t)}}, []byte("garbage"), testNow)
	if !errors.Is(err, trustlib.ErrParse) {
		t.Errorf("err = %v, want ErrParse", err)
	}
}

// AK 本身不能自证：没有任何担保来源时拒绝构造。
func TestNewRequiresVouching(t *testing.T) {
	if _, err := New(Config{}); !errors.Is(err, trustlib.ErrConfig) {
		t.Errorf("err = %v, want ErrConfig", err)
	}
}
