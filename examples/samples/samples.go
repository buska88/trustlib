// Package samples 为演示程序准备三种来源的 good、bad 样例：构造好的 Evaluator 和一次请求。
// 它只做“接线”，消费者逻辑在 examples/consumer 里。要从仓库根目录运行（读 testdata）。
package samples

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
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

// Load 返回来源 src（ear、tdx、tpm）的 good 或 bad 样例。
//
//   - ear：现场签一份 EAR；bad 是校验方判了 executables 96、ear.status 不认可；
//   - tdx：go-tdx-guest 的样例 Quote，参考值取自它自己；bad 是参考值里的 rtmr1 改了一个字节；
//   - tpm：软件 TPM 生成的证明，参考值取自它自己；bad 是参考值里的 pcr7 改了一个字节。
func Load(src, kase string) (trustlib.Evaluator, trustlib.Request, error) {
	if kase != "good" && kase != "bad" {
		return nil, trustlib.Request{}, fmt.Errorf("case must be good or bad, got %q", kase)
	}
	bad := kase == "bad"
	switch src {
	case "ear":
		return earSample(bad)
	case "tdx":
		return tdxSample(bad)
	case "tpm":
		return tpmSample(bad)
	}
	return nil, trustlib.Request{}, fmt.Errorf("src must be ear, tdx or tpm, got %q", src)
}

// Must 和 Load 一样，出错时打印错误并退出，只给演示程序用。
func Must(src, kase string) (trustlib.Evaluator, trustlib.Request) {
	ev, req, err := Load(src, kase)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	return ev, req
}

func earSample(bad bool) (trustlib.Evaluator, trustlib.Request, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, trustlib.Request{}, err
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	status, exec := vear.TrustTierAffirming, vear.TrustClaim(3)
	if bad {
		status, exec = vear.TrustTierContraindicated, 96
	}
	ar := vear.NewAttestationResult("cpu0", "demo-verifier", "trustlib")
	iat := now.Unix()
	ar.IssuedAt = &iat
	ar.Submods["cpu0"] = &vear.Appraisal{Status: &status, TrustVector: &vear.TrustVector{Hardware: 2, Configuration: 2, Executables: exec}}
	tok, err := ar.Sign(jwa.ES256(), key)
	if err != nil {
		return nil, trustlib.Request{}, err
	}
	ev, err := ear.New(ear.Config{VerifierKey: &key.PublicKey})
	return ev, trustlib.Request{Input: tok, Now: now}, err
}

func tdxSample(bad bool) (trustlib.Evaluator, trustlib.Request, error) {
	raw, err := os.ReadFile("testdata/tdx/tdx_prod_quote_SPR_E4.dat")
	if err != nil {
		return nil, trustlib.Request{}, err
	}
	q, err := abi.QuoteToProto(raw)
	if err != nil {
		return nil, trustlib.Request{}, err
	}
	body := q.(*tdxpb.QuoteV4).GetTdQuoteBody()
	r := body.GetRtmrs()
	rtmr1 := append([]byte(nil), r[1]...)
	if bad {
		rtmr1[0] ^= 0xff
	}
	rootPEM, err := os.ReadFile("testdata/tdx/intel_sgx_root_ca.pem")
	if err != nil {
		return nil, trustlib.Request{}, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		return nil, trustlib.Request{}, errors.New("bad Intel root PEM")
	}
	ev, err := tdx.New(tdx.Config{
		TrustedRoots: roots,
		Getter:       tg.TestGetter, // 样例背书，来自 go-tdx-guest 的测试数据
		Reference: trustlib.ReferenceValues{
			tdx.RefMRTD: {body.GetMrTd()}, tdx.RefXFAM: {body.GetXfam()},
			tdx.RefRTMR0: {r[0]}, tdx.RefRTMR1: {rtmr1}, tdx.RefRTMR2: {r[2]},
		},
	})
	req := trustlib.Request{Input: raw, Nonce: body.GetReportData(), Now: time.Date(2023, time.July, 1, 1, 0, 0, 0, time.UTC)}
	return ev, req, err
}

func tpmSample(bad bool) (trustlib.Evaluator, trustlib.Request, error) {
	raw, err := os.ReadFile("testdata/tpm/attestation.pb")
	if err != nil {
		return nil, trustlib.Request{}, err
	}
	var att attest.Attestation
	if err := proto.Unmarshal(raw, &att); err != nil {
		return nil, trustlib.Request{}, err
	}
	pcrs := att.GetQuotes()[0].GetPcrs().GetPcrs()
	pcr7 := append([]byte(nil), pcrs[7]...)
	if bad {
		pcr7[0] ^= 0xff
	}
	caPEM, err := os.ReadFile("testdata/tpm/ak_ca.pem")
	if err != nil {
		return nil, trustlib.Request{}, err
	}
	block, _ := pem.Decode(caPEM)
	if block == nil {
		return nil, trustlib.Request{}, errors.New("bad AK CA PEM")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, trustlib.Request{}, err
	}
	nonceHex, err := os.ReadFile("testdata/tpm/nonce.hex")
	if err != nil {
		return nil, trustlib.Request{}, err
	}
	nonce, err := hex.DecodeString(strings.TrimSpace(string(nonceHex)))
	if err != nil {
		return nil, trustlib.Request{}, err
	}
	ev, err := tpm.New(tpm.Config{
		AKRoots:   []*x509.Certificate{ca},
		Reference: trustlib.ReferenceValues{tpm.RefPCR0: {pcrs[0]}, tpm.RefPCR7: {pcr7}, tpm.RefPCR4: {pcrs[4]}},
	})
	return ev, trustlib.Request{Input: raw, Nonce: nonce, Now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}, err
}
