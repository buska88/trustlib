//go:build tpmsim

// gentpm 用 go-tpm-tools 的软件 TPM 生成 tpm 包的测试数据（testdata/tpm）。
//
// 平时的 go build / go test 不编译它：模拟器要 cgo 和 OpenSSL。需要重新生成时运行
//
//	go run -tags tpmsim ./internal/gentpm
//
// 每次生成的 AK 和签名都不同，重新生成后测试照样能过（测试从数据本身读期望值）。
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/google/go-tpm-tools/client"
	attest "github.com/google/go-tpm-tools/proto/attest"
	tpmpb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"google.golang.org/protobuf/proto"
)

// nonce 是测试用的固定 nonce：sha256("trustlib-tpm-test-nonce")。
var nonce = sum("trustlib-tpm-test-nonce")

func sum(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func main() {
	out := "testdata/tpm"
	must(os.MkdirAll(out, 0o755))

	sim, err := simulator.Get()
	must(err)
	defer func() {
		if err := sim.Close(); err != nil {
			log.Printf("close simulator: %v", err)
		}
	}()

	// 模拟启动链：固件（PCR0）、引导程序（PCR4）、安全启动状态（PCR7）各扩展一次固定内容。
	for _, pcr := range []int{0, 4, 7} {
		must(tpm2.PCRExtend(sim, tpmutil.Handle(pcr), tpm2.AlgSHA256, sum(fmt.Sprintf("trustlib boot event pcr%d", pcr)), ""))
	}
	sel := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{0, 4, 7, 11}}

	// 被担保的 AK：ECC，带一张测试 CA 签的 AK 证书。
	ak, err := client.AttestationKeyECC(sim)
	must(err)
	defer ak.Close()
	q, err := ak.Quote(sel, nonce)
	must(err)
	caKey, caCert := newCA()
	akCert := issueAKCert(caKey, caCert, ak.PublicKey())
	writeAttestation(filepath.Join(out, "attestation.pb"), ak, q, akCert.Raw)
	writePEM(filepath.Join(out, "ak_ca.pem"), caCert.Raw)

	// 没人担保的 AK：RSA，不带证书，也不在名单里。
	other, err := client.AttestationKeyRSA(sim)
	must(err)
	defer other.Close()
	q2, err := other.Quote(sel, nonce)
	must(err)
	writeAttestation(filepath.Join(out, "attestation_unvouched.pb"), other, q2, nil)

	must(os.WriteFile(filepath.Join(out, "nonce.hex"), []byte(hex.EncodeToString(nonce)+"\n"), 0o644))
	for _, i := range sel.PCRs {
		log.Printf("pcr%d = %x", i, q.GetPcrs().GetPcrs()[uint32(i)])
	}
}

func writeAttestation(path string, k *client.Key, q *tpmpb.Quote, akCert []byte) {
	pub, err := k.PublicArea().Encode()
	must(err)
	b, err := proto.Marshal(&attest.Attestation{AkPub: pub, Quotes: []*tpmpb.Quote{q}, AkCert: akCert})
	must(err)
	must(os.WriteFile(path, b, 0o644))
}

// newCA 生成测试用的 AK 根证书。有效期覆盖 2025–2045，测试把校验时刻钉在这段时间里。
func newCA() (*ecdsa.PrivateKey, *x509.Certificate) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "trustlib test AK root CA"},
		NotBefore:             time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2045, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	must(err)
	cert, err := x509.ParseCertificate(der)
	must(err)
	return key, cert
}

// issueAKCert 用测试 CA 给 AK 签一张证书，有效期 2025–2035。
func issueAKCert(caKey *ecdsa.PrivateKey, ca *x509.Certificate, akPub any) *x509.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "trustlib test AK"},
		NotBefore:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, akPub, caKey)
	must(err)
	cert, err := x509.ParseCertificate(der)
	must(err)
	return cert
}

func writePEM(path string, der []byte) {
	must(os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644))
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
