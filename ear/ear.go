// Package ear 把校验方签发的 EAR（EAT Attestation Result）归一成 trustlib.Result。
//
// 输入是 EAR 的 JWT 序列化（JWS 紧凑格式）。验签和解析交给 veraison/ear，本包不自己实现 JWS 校验。
// 信任锚是校验方的公钥，构造时由调用方传入（讲义 1.3）。
package ear

import (
	"bytes"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	vear "github.com/veraison/ear"

	"github.com/buska88/trustlib"
)

// Name 是这个来源的名字。
const Name = "ear"

// Config 是构造 EAR 来源时由调用方给的东西。
type Config struct {
	// VerifierKey 是校验方的公钥，也就是依赖方的信任锚，必填。
	// 可以是 crypto.PublicKey，也可以是 jwk.Key；从 JWK 文件读取可以用 ParseJWK。
	VerifierKey any
	// Alg 是 EAR 的签名算法，零值时用 ES256。
	Alg jwa.KeyAlgorithm
	// MaxAge 非零时，签发时间早于“校验时刻 − MaxAge”的结果返回 trustlib.ErrStale。
	MaxAge time.Duration
}

// Evaluator 是 EAR 来源，实现 trustlib.Evaluator。
type Evaluator struct{ cfg Config }

var _ trustlib.Evaluator = (*Evaluator)(nil)

// New 检查配置并返回 EAR 来源。缺校验方公钥时返回 trustlib.ErrConfig。
func New(cfg Config) (*Evaluator, error) {
	if cfg.VerifierKey == nil {
		return nil, fmt.Errorf("%w: ear: VerifierKey (the verifier's public key) is required", trustlib.ErrConfig)
	}
	if cfg.Alg == nil {
		cfg.Alg = jwa.ES256()
	}
	return &Evaluator{cfg: cfg}, nil
}

// ParseJWK 从 JWK 的 JSON（例如 arc 生成的 pkey.json）读出公钥，结果可以直接放进 Config.VerifierKey。
func ParseJWK(data []byte) (jwk.Key, error) {
	k, err := jwk.ParseKey(data)
	if err != nil {
		return nil, fmt.Errorf("%w: ear: parse JWK: %v", trustlib.ErrConfig, err)
	}
	return k, nil
}

// Name 返回 "ear"。
func (e *Evaluator) Name() string { return Name }

// Evaluate 验 EAR 的签名，再把每个子模块的八维向量取出来（docs/design.md D1、D2、D6）。
//
// 返回的错误：
//   - trustlib.ErrParse：不是合法的 JWS，或者签名对但内容不是合法的 EAR；
//   - trustlib.ErrUntrustedResult：签名验不过，内容一个字都不读；
//   - trustlib.ErrNonceMismatch：调用方给了 nonce，和顶层 eat_nonce 不一致；
//   - trustlib.ErrStale：设了 MaxAge，签发时间太早。
func (e *Evaluator) Evaluate(req trustlib.Request) (*trustlib.Result, error) {
	// 分三步，是为了把“格式不对”“签名不对”“签名对但内容不对”分开报。
	if _, err := jws.Parse(req.Input); err != nil {
		return nil, fmt.Errorf("%w: ear: not a JWS: %v", trustlib.ErrParse, err)
	}
	if _, err := jws.Verify(req.Input, jws.WithKey(e.cfg.Alg, e.cfg.VerifierKey)); err != nil {
		return nil, fmt.Errorf("%w: ear: %v", trustlib.ErrUntrustedResult, err)
	}
	var ar vear.AttestationResult
	if err := ar.Verify(req.Input, e.cfg.Alg, e.cfg.VerifierKey); err != nil {
		return nil, fmt.Errorf("%w: ear: signed but not a valid EAR: %v", trustlib.ErrParse, err)
	}

	res := &trustlib.Result{
		Source:  Name,
		Submods: make(map[string]trustlib.Vector, len(ar.Submods)),
		Raw:     req.Input,
	}
	if ar.IssuedAt != nil {
		res.IssuedAt = time.Unix(*ar.IssuedAt, 0).UTC()
	}
	if ar.Nonce != nil {
		res.Nonce = []byte(*ar.Nonce)
	}

	// 新鲜性（讲义 2.4）：调用方给了 nonce，就必须和顶层 eat_nonce 一致；设了 MaxAge，就看 iat。
	if len(req.Nonce) > 0 && !bytes.Equal(res.Nonce, req.Nonce) {
		return nil, fmt.Errorf("%w: ear: eat_nonce %q, want %q", trustlib.ErrNonceMismatch, res.Nonce, req.Nonce)
	}
	if e.cfg.MaxAge > 0 {
		if ar.IssuedAt == nil {
			return nil, fmt.Errorf("%w: ear: no iat", trustlib.ErrStale)
		}
		if age := req.Time().Sub(res.IssuedAt); age > e.cfg.MaxAge {
			return nil, fmt.Errorf("%w: ear: issued %v ago, max %v", trustlib.ErrStale, age, e.cfg.MaxAge)
		}
	}

	if len(ar.Submods) == 0 {
		return nil, fmt.Errorf("%w: ear: no submods", trustlib.ErrParse)
	}
	for name, appraisal := range ar.Submods {
		if appraisal == nil {
			return nil, fmt.Errorf("%w: ear: submod %q is empty", trustlib.ErrParse, name)
		}
		res.Submods[name] = toVector(appraisal.TrustVector)
		if appraisal.Status != nil {
			t := trustlib.Classify(int8(*appraisal.Status))
			if res.Status == nil || t < *res.Status {
				res.Status = &t
			}
		}
	}
	res.Vector = trustlib.MergeWorst(res.Submods)
	return res, nil
}

// toVector 把 veraison/ear 的 TrustVector 换成 trustlib.Vector。没有向量时八维都是 0。
func toVector(tv *vear.TrustVector) trustlib.Vector {
	var v trustlib.Vector
	if tv == nil {
		return v
	}
	v[trustlib.InstanceIdentity] = int8(tv.InstanceIdentity)
	v[trustlib.Configuration] = int8(tv.Configuration)
	v[trustlib.Executables] = int8(tv.Executables)
	v[trustlib.FileSystem] = int8(tv.FileSystem)
	v[trustlib.Hardware] = int8(tv.Hardware)
	v[trustlib.RuntimeOpaque] = int8(tv.RuntimeOpaque)
	v[trustlib.StorageOpaque] = int8(tv.StorageOpaque)
	v[trustlib.SourcedData] = int8(tv.SourcedData)
	return v
}
