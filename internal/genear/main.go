//go:build genear

// genear 按 veraison 的 arc create 的做法（解析 claims → 读 JWK 私钥 → ES256 签名），
// 生成 testdata/ear 里的样例 EAR：tv.jwt 来自 ear-claims-tv-ok.json，bad.jwt 来自 ear-claims-bad.json。
//
// 签名私钥用 veraison/ear 仓库自带的 arc/data/skey.json（公开的测试密钥，对应 testdata/ear/pkey.json），
// 本仓库不收录它。重新生成时运行：
//
//	go run -tags genear ./internal/genear <path/to/veraison/ear/arc/data/skey.json>
package main

import (
	"log"
	"os"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	vear "github.com/veraison/ear"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: genear <skey.json>")
	}
	skey, err := os.ReadFile(os.Args[1])
	must(err)
	key, err := jwk.ParseKey(skey)
	must(err)
	for claims, out := range map[string]string{
		"testdata/ear/ear-claims-tv-ok.json": "testdata/ear/tv.jwt",
		"testdata/ear/ear-claims-bad.json":   "testdata/ear/bad.jwt",
	} {
		b, err := os.ReadFile(claims)
		must(err)
		var ar vear.AttestationResult
		must(ar.UnmarshalJSON(b))
		tok, err := ar.Sign(jwa.ES256(), key)
		must(err)
		must(os.WriteFile(out, tok, 0o644))
		log.Printf("%s -> %s", claims, out)
	}
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
