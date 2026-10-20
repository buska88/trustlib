// Package tpm 评估 TPM / vTPM 的 Quote，依赖方自己当校验方。
//
// 输入是 go-tpm-tools 的 Attestation（protobuf 序列化）：里面有 AK 公钥、各 PCR bank 的 Quote，
// 可能还有 AK 证书。本包只看 SHA-256 bank。
//
// AK 本身不能自证：它是证明方发来的，必须由调用方事先给的东西担保（讲义 1.3、4.4），二选一：
//   - AK 证书能验到调用方给的根证书（AKRoots），并且证书里的公钥就是这把 AK；
//   - 这把 AK 在调用方事先登记的名单里（TrustedAKs）。
//
// 注意 vTPM 的信任根是宿主：hardware 判认可，意思是“提供 vTPM 的云厂商说这台虚机启动了这些东西”（讲义 4.1）。
// TPM 只记录启动过什么，不保护运行时内存，所以不判 runtime-opaque（AR4SI 附录 B.1）。
package tpm

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	attest "github.com/google/go-tpm-tools/proto/attest"
	tpmpb "github.com/google/go-tpm-tools/proto/tpm"
	tpmquote "github.com/google/go-tpm-tools/quote"
	"github.com/google/go-tpm/legacy/tpm2"
	"google.golang.org/protobuf/proto"

	"github.com/buska88/trustlib"
)

// Name 是这个来源的名字。
const Name = "tpm"

// 参考值的键（SHA-256 bank 的 PCR 值）。PCR 用途见讲义 4.2。
const (
	RefPCR0  = "pcr0"  // 核心固件的可执行代码 → hardware
	RefPCR4  = "pcr4"  // 引导程序 → executables
	RefPCR7  = "pcr7"  // 安全启动状态 → configuration
	RefPCR11 = "pcr11" // 统一内核镜像（UKI）的全部组件 → executables
)

// Config 是构造 TPM 来源时由调用方给的东西。TrustedAKs 和 AKRoots 至少给一样。
type Config struct {
	// TrustedAKs 是事先登记的可信 AK 公钥名单。
	TrustedAKs []crypto.PublicKey
	// AKRoots 是 AK 证书的根证书，例如提供 vTPM 的云厂商的根 CA。
	AKRoots []*x509.Certificate
	// Reference 是参考值，键见 Ref* 常量。
	Reference trustlib.ReferenceValues
}

// Evaluator 是 TPM 来源，实现 trustlib.Evaluator。
type Evaluator struct{ cfg Config }

var _ trustlib.Evaluator = (*Evaluator)(nil)

// New 检查配置并返回 TPM 来源。没有任何能担保 AK 的东西时返回 trustlib.ErrConfig。
func New(cfg Config) (*Evaluator, error) {
	if len(cfg.TrustedAKs) == 0 && len(cfg.AKRoots) == 0 {
		return nil, fmt.Errorf("%w: tpm: TrustedAKs or AKRoots is required to vouch for the AK", trustlib.ErrConfig)
	}
	return &Evaluator{cfg: cfg}, nil
}

// Name 返回 "tpm"。
func (e *Evaluator) Name() string { return Name }

// Evaluate 评估一份 TPM 证明（docs/design.md D5、D6）。
//
// 按顺序检查：
//  1. 解析：失败返回 trustlib.ErrParse；
//  2. AK 有没有担保：没有 → hardware = 97，这是结论；AK 证书过期返回 trustlib.ErrEndorsement；
//  3. Quote 的签名、TPM_GENERATED 魔数、PCR 摘要：验不过 → hardware = 97；
//  4. nonce：extraData 和 req.Nonce 不一致返回 trustlib.ErrNonceMismatch；
//  5. PCR 比参考值，得出各维（见 appraise）。
func (e *Evaluator) Evaluate(req trustlib.Request) (*trustlib.Result, error) {
	if len(req.Nonce) == 0 {
		return nil, fmt.Errorf("%w: tpm: an expected nonce (extraData) is required", trustlib.ErrConfig)
	}

	var att attest.Attestation
	if err := proto.Unmarshal(req.Input, &att); err != nil {
		return nil, fmt.Errorf("%w: tpm: %v", trustlib.ErrParse, err)
	}
	akArea, err := tpm2.DecodePublic(att.GetAkPub())
	if err != nil {
		return nil, fmt.Errorf("%w: tpm: AK public area: %v", trustlib.ErrParse, err)
	}
	akPub, err := akArea.Key()
	if err != nil {
		return nil, fmt.Errorf("%w: tpm: AK public key: %v", trustlib.ErrParse, err)
	}
	q := sha256Quote(&att)
	if q == nil {
		return nil, fmt.Errorf("%w: tpm: no SHA-256 quote", trustlib.ErrParse)
	}
	ad, err := tpm2.DecodeAttestationData(q.GetQuote())
	if err != nil {
		return nil, fmt.Errorf("%w: tpm: quote data: %v", trustlib.ErrParse, err)
	}

	res := &trustlib.Result{Source: Name, Nonce: []byte(ad.ExtraData), Raw: req.Input}

	// 2. AK 的担保。
	vouched, err := e.vouched(&att, akPub, req.Time())
	if err != nil {
		return nil, err
	}
	if !vouched {
		return finish(res, trustlib.Vector{trustlib.Hardware: trustlib.HardwareUnrecognized}), nil
	}

	// 3. 用 Quote 里自带的 extraData 验签：这一步只回答“是不是这把 AK 签的、PCR 有没有被改”，
	// nonce 对不对放到下一步单独判断，这样“伪造”和“重放”能分开报。
	if err := tpmquote.Verify(q, akPub, ad.ExtraData); err != nil {
		return finish(res, trustlib.Vector{trustlib.Hardware: trustlib.HardwareUnrecognized}), nil
	}

	// 4. nonce。
	if !bytes.Equal(ad.ExtraData, req.Nonce) {
		return nil, fmt.Errorf("%w: tpm: extraData %x, want %x", trustlib.ErrNonceMismatch, []byte(ad.ExtraData), req.Nonce)
	}

	// 5. PCR 比参考值。
	return finish(res, appraise(q.GetPcrs().GetPcrs(), e.cfg.Reference)), nil
}

// appraise 是 D5 的映射本身：AK 有担保、Quote 验过之后，各 PCR 分别决定哪一维。
//
//	hardware       ← PCR0（核心固件）比参考值：符 → 2，不符 → 96，没给 → 0。AK 有担保是前提
//	configuration  ← PCR7（安全启动状态）：符 → 2，不符 → 96，没给 → 0
//	executables    ← PCR4（引导程序）、PCR11（UKI）里调用方给了参考值的那几个：都符 → 3，有一个不符 → 96，一个都没给 → 0
//	runtime-opaque ← 0：TPM 不保护运行时内存（AR4SI 附录 B.1 写的是 n/a）
//	其余四维        ← 0
//
// Quote 没选某个 PCR 时，用到它的那一维算“没检查完”，是 0。
func appraise(pcrs map[uint32][]byte, rv trustlib.ReferenceValues) trustlib.Vector {
	var v trustlib.Vector
	v[trustlib.Hardware] = rv.Check(trustlib.HardwareGenuine, trustlib.HardwareContraindicated,
		trustlib.Measurement{Name: RefPCR0, Value: pcrs[0]})
	v[trustlib.Configuration] = rv.Check(trustlib.ConfigurationApproved, trustlib.ConfigurationUnsupportable,
		trustlib.Measurement{Name: RefPCR7, Value: pcrs[7]})

	var exec []trustlib.Measurement
	if _, ok := rv[RefPCR4]; ok {
		exec = append(exec, trustlib.Measurement{Name: RefPCR4, Value: pcrs[4]})
	}
	if _, ok := rv[RefPCR11]; ok {
		exec = append(exec, trustlib.Measurement{Name: RefPCR11, Value: pcrs[11]})
	}
	v[trustlib.Executables] = rv.Check(trustlib.ExecutablesApprovedBoot, trustlib.ExecutablesContraindicated, exec...)
	return v
}

// vouched 判断这把 AK 有没有调用方事先给的东西担保。
func (e *Evaluator) vouched(att *attest.Attestation, akPub crypto.PublicKey, now time.Time) (bool, error) {
	if len(att.GetAkCert()) > 0 && len(e.cfg.AKRoots) > 0 {
		cert, err := x509.ParseCertificate(att.GetAkCert())
		if err != nil {
			return false, fmt.Errorf("%w: tpm: AK certificate: %v", trustlib.ErrParse, err)
		}
		var inters []*x509.Certificate
		for _, der := range att.GetIntermediateCerts() {
			c, err := x509.ParseCertificate(der)
			if err != nil {
				return false, fmt.Errorf("%w: tpm: intermediate certificate: %v", trustlib.ErrParse, err)
			}
			inters = append(inters, c)
		}
		err = verifyAKCert(cert, e.cfg.AKRoots, inters, now)
		var invalid x509.CertificateInvalidError
		if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
			return false, fmt.Errorf("%w: tpm: AK certificate: %v", trustlib.ErrEndorsement, err)
		}
		// 证书验得过，还要确认证书里的公钥就是这把 AK：否则攻击者可以随便附一张别人的合法证书。
		if err == nil && samePublicKey(cert.PublicKey, akPub) {
			return true, nil
		}
	}
	for _, k := range e.cfg.TrustedAKs {
		if samePublicKey(k, akPub) {
			return true, nil
		}
	}
	return false, nil
}

var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// verifyAKCert 按调用方给的时刻验 AK 证书链。做法照 go-tpm-tools 的 server.VerifyAKCert，
// 区别是校验时刻从外面注入（那个函数只能用当前时间）。
func verifyAKCert(cert *x509.Certificate, roots, inters []*x509.Certificate, now time.Time) error {
	// AK 证书常把 SAN 标成关键扩展，但里面不是 x509 认识的名字类型，x509 会把它当成未处理的关键扩展。
	var exts []asn1.ObjectIdentifier
	for _, ext := range cert.UnhandledCriticalExtensions {
		if !ext.Equal(oidSubjectAltName) {
			exts = append(exts, ext)
		}
	}
	cert.UnhandledCriticalExtensions = exts

	rootPool, interPool := x509.NewCertPool(), x509.NewCertPool()
	for _, c := range roots {
		rootPool.AddCert(c)
	}
	for _, c := range inters {
		interPool.AddCert(c)
	}
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: interPool,
		CurrentTime:   now,
		// AK 证书的用途是 TCG 定义的，不是 x509 默认的服务器认证。
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}

func samePublicKey(a, b crypto.PublicKey) bool {
	ka, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && ka.Equal(b)
}

func sha256Quote(att *attest.Attestation) *tpmpb.Quote {
	for _, q := range att.GetQuotes() {
		if q.GetPcrs().GetHash() == tpmpb.HashAlgo_SHA256 {
			return q
		}
	}
	return nil
}

func finish(res *trustlib.Result, v trustlib.Vector) *trustlib.Result {
	res.Vector = v
	res.Submods = map[string]trustlib.Vector{Name: v}
	return res
}
