// Package tdx 评估 Intel TDX 的 Quote（v4、v5），依赖方自己当校验方。
//
// 签名链、背书、吊销和 TCB 等级交给 go-tdx-guest。测量值和参考值的比对、
// 各项检查分别决定哪一维，是本包自己的事（docs/design.md D4）。
//
// 本包从不联网：信任锚和背书都由调用方给。
package tdx

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify"
	"github.com/google/go-tdx-guest/verify/trust"

	"github.com/buska88/trustlib"
)

// Name 是这个来源的名字。
const Name = "tdx"

// 参考值的键（trustlib.ReferenceValues 里用）。
const (
	RefMRTD  = "mr_td" // TD 的初始内存（含 TDVF 固件）的测量值 → hardware
	RefRTMR0 = "rtmr0" // 固件配置与安全启动状态 → configuration
	RefRTMR1 = "rtmr1" // 引导程序（固件直接引导时含内核）→ executables
	RefRTMR2 = "rtmr2" // 操作系统阶段：内核、initrd、命令行 → executables
	RefXFAM  = "xfam"  // 允许 TD 使用的 CPU 扩展功能集合 → configuration
)

// Config 是构造 TDX 来源时由调用方给的东西。
type Config struct {
	// TrustedRoots 是 Intel SGX 根证书，也就是信任锚，必填。
	TrustedRoots *x509.CertPool

	// Getter 提供背书：TCB 信息、QE 身份和两份吊销列表，必填。
	// 它按 Intel PCS 的地址返回内容，至于内容从哪来（本地文件、机房里的 PCCS 缓存、测试数据），
	// 由调用方决定。本包只调用它，从不自己联网。
	Getter trust.HTTPSGetter

	// Reference 是参考值，键见 Ref* 常量。某一维用到的参考值没给全，这一维就是 0（没检查）。
	Reference trustlib.ReferenceValues
}

// Evaluator 是 TDX 来源，实现 trustlib.Evaluator。
type Evaluator struct{ cfg Config }

var _ trustlib.Evaluator = (*Evaluator)(nil)

// New 检查配置并返回 TDX 来源。缺信任锚或背书来源时返回 trustlib.ErrConfig。
//
// 背书来源为什么必填：go-tdx-guest 在 Getter 为空时会自己去 Intel PCS 取，这违反“不联网”的约束。
func New(cfg Config) (*Evaluator, error) {
	if cfg.TrustedRoots == nil {
		return nil, fmt.Errorf("%w: tdx: TrustedRoots (Intel SGX root CA) is required", trustlib.ErrConfig)
	}
	if cfg.Getter == nil {
		return nil, fmt.Errorf("%w: tdx: Getter (source of endorsements) is required", trustlib.ErrConfig)
	}
	return &Evaluator{cfg: cfg}, nil
}

// Name 返回 "tdx"。
func (e *Evaluator) Name() string { return Name }

// Evaluate 评估一份 TDX Quote（docs/design.md D4、D6）。
//
// 按顺序检查，每一步的失败有不同的含义：
//  1. 解析：失败返回 trustlib.ErrParse；
//  2. 签名链（信任锚 → PCK 证书 → QE 报告 → AK → Quote）：证书过期返回 trustlib.ErrEndorsement；
//     其余失败不返回错误，而是 hardware = 97，因为这是“有证据表明不是真硬件”，属于结论，不是故障；
//  3. nonce：report_data 和 req.Nonce 不一致返回 trustlib.ErrNonceMismatch；
//  4. 背书和吊销：证书被吊销时 hardware = 96；背书缺失、过期或无效返回 trustlib.ErrEndorsement；
//  5. 测量值比参考值，得出各维（见 appraise）；TCB 等级放进 Result.TCB，不进 hardware。
func (e *Evaluator) Evaluate(req trustlib.Request) (*trustlib.Result, error) {
	if len(req.Nonce) == 0 {
		return nil, fmt.Errorf("%w: tdx: an expected nonce (report_data) is required", trustlib.ErrConfig)
	}

	quote, err := abi.QuoteToProto(req.Input)
	if err != nil {
		return nil, fmt.Errorf("%w: tdx: %v", trustlib.ErrParse, err)
	}
	if err := abi.CheckQuote(quote); err != nil {
		return nil, fmt.Errorf("%w: tdx: %v", trustlib.ErrParse, err)
	}
	body, err := bodyOf(quote)
	if err != nil {
		return nil, fmt.Errorf("%w: tdx: %v", trustlib.ErrParse, err)
	}

	res := &trustlib.Result{Source: Name, Nonce: body.GetReportData(), Raw: req.Input}
	now := req.Time()

	// 2. 签名链：只用信任锚，不取背书。
	chainOpts := &verify.Options{TrustedRoots: e.cfg.TrustedRoots, Now: timeSet(now)}
	if err := verify.TdxQuote(quote, chainOpts); err != nil {
		if isExpired(err) {
			return nil, fmt.Errorf("%w: tdx: PCK certificate chain: %v", trustlib.ErrEndorsement, err)
		}
		return finish(res, trustlib.Vector{trustlib.Hardware: trustlib.HardwareUnrecognized}), nil
	}

	// 3. nonce：签名验过之后 report_data 才可信，所以放在签名链之后。
	if !bytes.Equal(body.GetReportData(), req.Nonce) {
		return nil, fmt.Errorf("%w: tdx: report_data %x, want %x", trustlib.ErrNonceMismatch, body.GetReportData(), req.Nonce)
	}

	// 4. 背书与吊销。TCB 等级单独取，所以这里关掉 go-tdx-guest 的 TCB 状态检查，免得它直接报错。
	collOpts := &verify.Options{
		TrustedRoots:          e.cfg.TrustedRoots,
		Now:                   timeSet(now),
		GetCollateral:         true,
		CheckRevocations:      true,
		Getter:                e.cfg.Getter,
		DisableTcbStatusCheck: true,
	}
	if err := verify.TdxQuote(quote, collOpts); err != nil {
		if isRevoked(err) {
			return finish(res, trustlib.Vector{trustlib.Hardware: trustlib.HardwareContraindicated}), nil
		}
		return nil, fmt.Errorf("%w: tdx: %v", trustlib.ErrEndorsement, err)
	}
	res.TCB = tcbOf(quote, collOpts)

	// 5. 测量值比参考值。
	return finish(res, appraise(body, e.cfg.Reference)), nil
}

// quoteBody 是 v4、v5 报告体共有的字段。
type quoteBody interface {
	GetMrTd() []byte
	GetRtmrs() [][]byte
	GetXfam() []byte
	GetTdAttributes() []byte
	GetReportData() []byte
}

func bodyOf(quote any) (quoteBody, error) {
	var b quoteBody
	switch q := quote.(type) {
	case *pb.QuoteV4:
		b = q.GetTdQuoteBody()
	case *pb.QuoteV5:
		b = q.GetTdQuoteBodyDescriptor().GetTdQuoteBodyV5()
	default:
		return nil, fmt.Errorf("unsupported quote type %T", quote)
	}
	if len(b.GetRtmrs()) < 3 || len(b.GetTdAttributes()) != 8 {
		return nil, errors.New("malformed TD quote body")
	}
	return b, nil
}

// appraise 是 D4 的映射本身：签名链已经通过之后，各项检查分别决定哪一维。
// 它是纯函数，可以不经过签名、直接用构造的报告体测试（例如调试位打开的情形）。
//
//	hardware       ← MRTD 比参考值：符 → 2，不符 → 96，没给 → 0
//	configuration  ← 调试位、XFAM、RTMR0：调试位打开 → 96；否则 XFAM、RTMR0 都符 → 2，有一项不符 → 96，没给全 → 0
//	executables    ← RTMR1、RTMR2：都符 → 3（只覆盖启动阶段），有一项不符 → 96，没给全 → 0
//	runtime-opaque ← 调试位：为 0 → 2，为 1 → 96。AR4SI 附录 B.3：虚机级机密计算的这一维“隐含在签名里”
//	其余四维        ← 不判断，0
func appraise(b quoteBody, rv trustlib.ReferenceValues) trustlib.Vector {
	var v trustlib.Vector
	rtmrs := b.GetRtmrs()
	debug := isDebug(b.GetTdAttributes())

	v[trustlib.Hardware] = rv.Check(trustlib.HardwareGenuine, trustlib.HardwareContraindicated,
		trustlib.Measurement{Name: RefMRTD, Value: b.GetMrTd()})

	if debug {
		v[trustlib.Configuration] = trustlib.ConfigurationUnsupportable
		v[trustlib.RuntimeOpaque] = trustlib.RuntimeOpaqueVisible
	} else {
		v[trustlib.Configuration] = rv.Check(trustlib.ConfigurationApproved, trustlib.ConfigurationUnsupportable,
			trustlib.Measurement{Name: RefXFAM, Value: b.GetXfam()},
			trustlib.Measurement{Name: RefRTMR0, Value: rtmrs[0]})
		v[trustlib.RuntimeOpaque] = trustlib.RuntimeOpaqueEncrypted
	}

	v[trustlib.Executables] = rv.Check(trustlib.ExecutablesApprovedBoot, trustlib.ExecutablesContraindicated,
		trustlib.Measurement{Name: RefRTMR1, Value: rtmrs[1]},
		trustlib.Measurement{Name: RefRTMR2, Value: rtmrs[2]})
	return v
}

// isDebug 读 TD 属性的第 0 位（DEBUG）。打开时宿主能读 TD 的内存。
func isDebug(tdAttributes []byte) bool {
	return binary.LittleEndian.Uint64(tdAttributes)&0x1 != 0
}

// tcbOf 读出与本平台匹配的 TCB 等级。go-tdx-guest 找不到匹配级别时会报错，这里不当失败，记成 TCBNoMatchingLevel。
func tcbOf(quote any, opts *verify.Options) *trustlib.PlatformTCB {
	tcb, qe, _ := verify.SupportedTcbLevelsFromCollateral(quote, opts)
	out := &trustlib.PlatformTCB{
		Status:   string(tcb.TcbStatus),
		QEStatus: string(qe.TcbStatus),
		Date:     tcb.TcbDate,
	}
	if out.Status == "" {
		out.Status = trustlib.TCBNoMatchingLevel
	}
	if out.QEStatus == "" {
		out.QEStatus = trustlib.TCBNoMatchingLevel
	}
	return out
}

func finish(res *trustlib.Result, v trustlib.Vector) *trustlib.Result {
	res.Vector = v
	res.Submods = map[string]trustlib.Vector{Name: v}
	return res
}

func timeSet(t time.Time) *verify.TimeSet {
	return &verify.TimeSet{PckCertChain: t, TcbInfo: t, QeIdentity: t, PckCrl: t, RootCaCrl: t}
}

// isExpired 判断签名链失败是不是因为证书过期或尚未生效：这是“现在评估不了”，不是“证明是假硬件”。
func isExpired(err error) bool {
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
		return true
	}
	if errors.Is(err, verify.ErrPckLeafCertExpired) ||
		errors.Is(err, verify.ErrIntermediateCaCertExpired) ||
		errors.Is(err, verify.ErrRootCaCertExpired) {
		return true
	}
	// go-tdx-guest 用 %v 包了一层 crypto/x509 的错误，errors.As 拿不到原始类型，只能看文案。
	// 升级 go-tdx-guest 时要复核（TestCertificateChainExpired 会发现变化）。
	return strings.Contains(err.Error(), "certificate has expired or is not yet valid")
}

// isRevoked 判断背书检查失败是不是因为证书被吊销。go-tdx-guest 对吊销没有导出的错误值，
// 只能按它的错误文案（"... was revoked at ..."）判断，升级 go-tdx-guest 时要复核。
func isRevoked(err error) bool {
	return strings.Contains(err.Error(), "was revoked")
}
