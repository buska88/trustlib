package trustlib

import "errors"

// 下面这些错误都表示“评估不了”：拿不到任何可信的结论。
// 消费者应该把它们当无结论处理（Judge 就是这么做的），而不是当成“有证据表明不行”。
// 有证据表明不行时，来源适配器不返回错误，而是在向量里写不认可档的值（docs/design.md D6）。
//
// 用 errors.Is 判断类别，例如 errors.Is(err, trustlib.ErrNonceMismatch)。
var (
	// ErrConfig：调用方没给齐必需的东西，比如信任锚、背书来源或期望的 nonce。
	ErrConfig = errors.New("trustlib: missing or invalid configuration")

	// ErrParse：输入解析不了。
	ErrParse = errors.New("trustlib: input cannot be parsed")

	// ErrUntrustedResult：EAR 验签失败。结论不是来自可信的校验方，里面一个字都不能信。
	ErrUntrustedResult = errors.New("trustlib: attestation result signature is invalid")

	// ErrNonceMismatch：输入里的 nonce 和调用方给的不一致，可能是重放。
	ErrNonceMismatch = errors.New("trustlib: nonce mismatch")

	// ErrStale：EAR 的签发时间太早。
	ErrStale = errors.New("trustlib: attestation result is too old")

	// ErrEndorsement：背书缺失、过期或无效，无法评估。
	ErrEndorsement = errors.New("trustlib: endorsements are missing, expired or invalid")
)
