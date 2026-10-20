package trustlib_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	tg "github.com/google/go-tdx-guest/testing"
	attest "github.com/google/go-tpm-tools/proto/attest"
	"github.com/lestrrat-go/jwx/v3/jwa"
	vear "github.com/veraison/ear"
	"google.golang.org/protobuf/proto"

	"github.com/buska88/trustlib"
	"github.com/buska88/trustlib/ear"
	"github.com/buska88/trustlib/tdx"
	"github.com/buska88/trustlib/tpm"
)

// admit 代表消费者代码，比如调度侧的准入判断。它只认识 trustlib.Evaluator 和 trustlib.Judge，
// 不知道来源是 EAR、TDX 还是 TPM（评判标准 2：同一份消费者代码，三种来源零改动）。
func admit(ev trustlib.Evaluator, input, nonce []byte, now time.Time) trustlib.Verdict {
	res, err := ev.Evaluate(trustlib.Request{Input: input, Nonce: nonce, Now: now})
	return trustlib.Judge(res, err, trustlib.DefaultMask)
}

// source 是一种来源加上它的一份输入。
type source struct {
	ev    trustlib.Evaluator
	input []byte
	nonce []byte
	now   time.Time
}

func TestSameConsumerCodeForAllSources(t *testing.T) {
	sources := map[string]source{
		"ear": earSource(t),
		"tdx": tdxSource(t),
		"tpm": tpmSource(t),
	}
	for name, s := range sources {
		v := admit(s.ev, s.input, s.nonce, s.now)
		if v.Tier != trustlib.Affirming || v.Err != nil {
			t.Errorf("%s: verdict = %+v, want affirming", name, v)
		}
		if s.ev.Name() != name {
			t.Errorf("Name() = %q, want %q", s.ev.Name(), name)
		}
	}
}

func earSource(t *testing.T) (s source) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ar := vear.NewAttestationResult("cpu0", "test-verifier", "trustlib-tests")
	iat := now.Unix()
	ar.IssuedAt = &iat
	status := vear.TrustTierAffirming
	ar.Submods["cpu0"] = &vear.Appraisal{Status: &status, TrustVector: &vear.TrustVector{Hardware: 2, Configuration: 2, Executables: 3}}
	tok, err := ar.Sign(jwa.ES256(), key)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := ear.New(ear.Config{VerifierKey: &key.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	s.ev, s.input, s.now = ev, tok, now
	return s
}

func tdxSource(t *testing.T) (s source) {
	raw, err := os.ReadFile("testdata/tdx/tdx_prod_quote_SPR_E4.dat")
	if err != nil {
		t.Fatal(err)
	}
	q, err := abi.QuoteToProto(raw)
	if err != nil {
		t.Fatal(err)
	}
	body := q.(*tdxpb.QuoteV4).GetTdQuoteBody()
	r := body.GetRtmrs()
	pemBytes, err := os.ReadFile("testdata/tdx/intel_sgx_root_ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pemBytes)
	ev, err := tdx.New(tdx.Config{
		TrustedRoots: roots,
		Getter:       tg.TestGetter,
		Reference: trustlib.ReferenceValues{
			tdx.RefMRTD: {body.GetMrTd()}, tdx.RefXFAM: {body.GetXfam()},
			tdx.RefRTMR0: {r[0]}, tdx.RefRTMR1: {r[1]}, tdx.RefRTMR2: {r[2]},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	s.ev, s.input, s.nonce = ev, raw, body.GetReportData()
	s.now = time.Date(2023, time.July, 1, 1, 0, 0, 0, time.UTC)
	return s
}

func tpmSource(t *testing.T) (s source) {
	raw, err := os.ReadFile("testdata/tpm/attestation.pb")
	if err != nil {
		t.Fatal(err)
	}
	var att attest.Attestation
	if err := proto.Unmarshal(raw, &att); err != nil {
		t.Fatal(err)
	}
	pcrs := att.GetQuotes()[0].GetPcrs().GetPcrs()
	block, _ := pem.Decode(mustRead(t, "testdata/tpm/ak_ca.pem"))
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := hex.DecodeString(strings.TrimSpace(string(mustRead(t, "testdata/tpm/nonce.hex"))))
	if err != nil {
		t.Fatal(err)
	}
	ev, err := tpm.New(tpm.Config{
		AKRoots:   []*x509.Certificate{ca},
		Reference: trustlib.ReferenceValues{tpm.RefPCR0: {pcrs[0]}, tpm.RefPCR7: {pcrs[7]}, tpm.RefPCR4: {pcrs[4]}},
	})
	if err != nil {
		t.Fatal(err)
	}
	s.ev, s.input, s.nonce = ev, raw, nonce
	s.now = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return s
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
