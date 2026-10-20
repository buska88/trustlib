# trustlib

P1 of Buska's portfolio plan (从简历反推的能力建设计划). A Go library that normalizes remote-attestation inputs — EAR attestation results, Intel TDX quotes, TPM/vTPM quotes — into AR4SI eight-dimension trustworthiness vectors, then collapses them into one comparable tier. Later modules consume it: a scheduler side (needs one comparable tier; tolerate "no conclusion", act at once on "proven bad") and a key-release side (needs details; release only when affirming).

## Read first

- `docs/design.md` — the settled design, decisions D1–D6. **Do not change a decision on your own; if something falls outside it, stop and ask Buska.**
- Buska's own notes live in `~/work/notes/`, his study material in `~/work/learn/`. The P1 讲义 and 执行卡 are online docs; section and question numbers in comments (讲义 3.7, 自测 15) refer to them.

## Layout

```
trustlib (root)   Dimension, Mask, Vector, Tier, Classify, Result, Request, Evaluator,
                  ReferenceValues.Check, MergeWorst, Collapse, Judge, error sentinels
ear/              EAR (JWT) source — veraison/ear does JWS + parsing
tdx/              TDX quote source — go-tdx-guest does chain/collateral/TCB; we map to dimensions
tpm/              TPM source — input is go-tpm-tools attest.Attestation (protobuf), SHA-256 bank only
internal/gentpm/  TPM fixture generator, build tag `tpmsim` (needs cgo + OpenSSL)
internal/genear/  EAR fixture generator, build tag `genear` (needs veraison's arc/data/skey.json)
examples/         consumer demo (six runs in README §5) + sample wiring
testdata/         sample TDX quote + Intel SGX root; TPM fixtures; arc-style EAR samples + veraison test pubkey
docs/             design.md (decisions), acceptance.md (执行卡 checklist status)
```

## Commands

```sh
go mod tidy                                   # first time: creates go.sum
go vet ./... && go test -race -count=1 -cover ./...
go run ./examples/consumer -src=tdx -case=bad # from repo root
go run -tags tpmsim ./internal/gentpm         # regenerate testdata/tpm (software TPM)
go run -tags genear ./internal/genear <skey.json>
```

Buska's Mac: Go 1.27 at /usr/local/go, `GOPROXY=https://goproxy.cn,direct`, `GOSUMDB=sum.golang.google.cn`. `go.mod` must say `go 1.24.0` or higher (go-tpm-tools v0.4.9 requires it).

## Rules that must hold

- Trust anchors, endorsements and reference values come from the caller. Never hard-code them, never fetch online. go-tdx-guest fetches from Intel PCS when its Getter is nil, so `tdx.New` rejects a nil Getter.
- Verification time is injectable via `Request.Now`; never call `time.Now()` inside a check when a request time is available.
- Classify before comparing: `Classify(v)` per AR4SI ranges. −5 is affirming; 0, 1, −1 are none; 0 ≡ absent.
- Collapse = worst tier over key dims; order Contraindicated < None < Warning < Affirming. Default key dims: hardware, configuration, executables.
- Proven bad is a value (96/97); cannot evaluate is an error (`ErrParse`, `ErrConfig`, `ErrUntrustedResult`, `ErrNonceMismatch`, `ErrStale`, `ErrEndorsement`, wrapped with `%w`). Never mix the two.
- Missing reference values → that dimension is 0, never affirming.
- executables from boot-time measurements (RTMR1/2, PCR4/11) is 3, not 2.

## Conventions

- Comments in Chinese, using the 讲义 vocabulary: 证明方 / 校验方 / 依赖方 / 背书 / 参考值 / 信任锚; tiers 认可 / 有保留 / 不认可 / 无结论. Identifiers in English.
- Table-driven tests; each expected value says which design rule it comes from (D3-3, D6 …).
- Test times are pinned: TDX 2023-07-01T01:00Z (sample collateral validity), TPM 2026-01-01 (test AK cert valid 2025–2035), EAR 2026-01-01.

## Known fragile spots

- `tdx.isRevoked` and the fallback in `tdx.isExpired` match go-tdx-guest error text. Re-check when upgrading go-tdx-guest; `TestCertificateChainExpired` catches the expiry case, the revocation path has no test (needs an Intel-signed CRL).
- AR4SI editor's draft (2026-10) adds an "Incomplete" tier. When it is published, revisit how −1 is classified.
