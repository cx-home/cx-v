# stdlib depth-audit findings (2026-06-06)

Adversarial correctness + performance audit beyond first-pass coverage (which
only asserts ≥1 happy case per function). Each item below was REPRODUCED
against the built binary. Severity: **P0** crash/DoS, **P1** silent wrong data,
**P2** wrong error/edge, **P3** performance.

Status legend: ✅ fixed+regression-fixtured · ⬜ open · 🗣 needs spec decision.

## math — ✅ ALL FIXED (commit be8f53a9)
- ✅ P0 `percentile`/`quantile` out-of-domain arg → V panic (array OOB), crashed interpreter → CXER3003 guard.
- ✅ P1 `lcm` silent i64 overflow wrap; `gcd(i64_min,0)` negative → CXER3000 checked-overflow.
- ✅ P2 `factorial(-n)` reported bogus overflow → CXER3003 domain error.
- ✅ P3 `mode`/`multimode` O(n²) → O(n) bit-keyed map.

## json — ⬜ OPEN (highest priority — a crash + silent data loss)
- ⬜ P0 deep nesting with raised `max-depth` → **SIGSEGV** (native recursion has no ceiling; only the user max-depth guards it). Fix: hard native recursion cap independent of max-depth. (~5000–8000 levels.)
- ⬜ P1 `parse "1e400"` → `+inf`, then `emit` → silently `'null'` (data loss, no error). Fix: reject non-finite on parse (CXER3105/3100).
- ⬜ P2 leading zeros accepted (`01`→`1`); incomplete numbers accepted (`1.`→`1.0`, `1e`→`1.0`) — invalid per RFC 8259. Fix: strict number grammar.
- ⬜ P2 lone low surrogate `\uDC00` → emits invalid UTF-8 (high-surrogate path is validated, low is not).

## geo — ⬜ OPEN (DoS)
- ⬜ P0 `normalize-lon` is `for l>180 {l-=360}` — O(|lon|/360); a large finite lon (1e13) hangs >20s. Propagates through `point`/`normalize-point`/`normalize-bbox`/`destination`. Fix: modulo wrap (also inf-safe).
- 🗣 P2 `parse-wkt`/`parse-geojson` build points via `geo_point()` bypassing the lat∈[-90,90] check the `point` constructor enforces (lat=200 flows into distance math). Decide: validate on parse (CXER3601) vs documented lenient.

## path — ⬜ OPEN
- ⬜ P0/DoS `match-glob` `*` → exponential backtracking; ~16 stars wedges the process (a `pure` fn). Fix: linear glob matcher (two-pointer or DP).
- ⬜ P1 `match-glob` negated classes `[!a]`/`[^a]` fully inverted (negation unimplemented). Fix: implement class negation.

## bytes — ⬜ OPEN (silent corruption)
- ⬜ P1 `from-hex` odd-length silently accepted (`"abc"`→2 bytes); should CXER2301.
- ⬜ P1 `from-base64` invalid chars → silent zero/garbage; accepts URL-alphabet `-_` + embedded whitespace; should CXER2302.
- ⬜ P1 `from-base32` invalid chars → silent zeros; lowercase → garbage; should error.
  (Root: wrappers trust V's `encoding.{hex,base64,base32}` to signal malformed, but those return partial/zero output; only an empty-result guard exists. Fix: validate alphabet/length explicitly.)
- ⬜ P2 `zstd-decompress(zstd-compress(""))` fails (empty round-trip); gzip handles it. Add empty-frame handling.
- 🗣 P1 `unpack "<Q"` for u64 ≥ 2^63 → negative (i64 wrap); full u64 unreachable. Architectural (scalar int is i64) — spec note or wider repr.

## strings — ⬜ OPEN
- ⬜ P1 `is-alpha`/`is-alphanumeric` coarse heuristic: emoji/symbols (≥0xC0) → true; some letters (U+00AA) → false. Fix: real Unicode letter classification.
- ⬜ P3 `find-all`/`count` O(n²) — re-runes the whole string per match (100k → 60s). Fix: rune once, search the slice.
- 🗣 P2 `unescape-html` decodes only ~35 of the spec-mandated ~2200 HTML5 named entities. Decide: ship full WHATWG table vs narrow the spec.

## url — ⬜ OPEN
- ⬜ P1 `build` with a leading-space path segment folds the root `/`→`%2F` into the authority (`https://h.com%2Fhello%20world`) — structurally wrong URL.
- ⬜ P2 `build`/`normalize` over-encode path sub-delims (`@`,`+`) → breaks round-trips / non-idempotent (`mailto:a@b.com`→`mailto:a%40b.com`).

## re — ⬜ OPEN
- ⬜ P2 accessor on a `[no-match]` (e.g. `group` after a failed `find`) and wrong-typed args surface as `user-undefined "no callable re-group"` instead of a clean domain/type error (the `none`-return convention hits the generic dispatch fallback). Fix: map validation `none`→typed CXER before fallback.
- ⬜ P3 `find-all`/`find-iter` copy the entire subject string into every match element → super-linear allocation. Fix: share subject by ref / lazy.

## random — ⬜ OPEN
- ⬜ P2 global `float-range(lo,hi)` with lo>hi silently swaps instead of CXER1901 (the other four range builtins are correct — isolated outlier).
- note: conformance `random-049` has a stale `TODO(impl pending)` — `float-range-with` IS implemented+correct; remove the TODO.

## time — ⬜ OPEN (silent wrong data)
- ⬜ P1 numeric parse (`parse-date`/`-datetime`/`-instant`/`-rfc3339`) accumulates the year in unchecked i64 → `2^64+2024`-style input wraps to a plausible wrong date (`'2024-01-01'`) instead of CXER3301. Fix: overflow-checked digit accumulation.
- ⬜ P1 duration construction/arithmetic (`duration-h/m/d/s/ms`, `duration-mul/add`, `parse-duration`) wrap silently on i64 overflow; CXER3304 exists but is only raised for div-by-zero. Fix: checked arithmetic.
- ⬜ P2 `yy` LDML format token emits negative text for BC (negative) years (`year % 100` not sign-handled).

## Clean (zero confirmed defects)
- **csv**, **hash**, **uuid** — robust under adversarial probing.

## Not yet depth-audited (wave 3+)
format, validate, locale, i18n, mime, html, email, ft, log, env, io, process,
prof, crypto (behavior-tested but not adversarially), store, fp (traverse bug
already filed: task_e1b2b368), test, dispatch/caps.

## ── WAVE 3 (2026-06-06, post http/net/io merge) ──

### CORE (not a module — affects many) — ⬜ OPEN P0
- ⬜ **core eval/parser SIGSEGV on deep nesting (~1600 levels)** — unbounded native recursion; a bare deeply-nested value crashes the interpreter with NO module loaded. This is the ROOT of the json/html/validate deep-nesting crashes. Fix: a native recursion-depth guard in the eval/render walk → CXER (not segfault). Highest-leverage fix (kills 3+ module crashes at once).

### http — ⬜ OPEN (security-critical, network-facing)
- ⬜ P0/SEC static-file **symlink escape** from webroot (serve_file.v rejects literal `..` only; never `os.real_path`-confines under root). `link->/etc/hosts` served. Fix: resolve + confine.
- ⬜ P0/SEC client **cap resource ignores URL userinfo** (`http_authority` keeps `user@host`) → cap host ≠ connect host (SSRF/confused-deputy). Latent (granted client dial is stubbed) but wrong now.
- ⬜ P1 server **drops request body** unconditionally (handlers never see POST/PUT body).
- ⬜ P1 server emits **malformed status line** for out-of-range handler status (listener path has no 100–599 clamp; `http_respond_impl` does).
- ⬜ P2/DoS static-file cache **unbounded** (no max-bytes/LRU) → memory exhaustion.

### net — ⬜ OPEN (transport is a STUB; pure surface + guards real)
- ⬜ P0/SEC §4.5 mandatory **SSRF deny-set absent** (loopback/private/link-local-metadata not blocked under grant). Must land before real dial.
- ⬜ P1 `addr-to-string` loses abstract-vs-filesystem unix distinction (drops `scheme`); doesn't re-percent-encode unix paths (non-bijective).
- 🗣 IPv6 not RFC-5952 canonicalized (uncertain if required). NOTE: whole transport layer unimplemented stub — re-audit when real syscalls land.

### html — ⬜ OPEN (security)
- ⬜ P0/SEC/DoS `sanitize`/`parse` **SIGSEGV** on ~60KB deeply-nested hostile HTML (the module's exact threat model — inbound email HTML). Same core-recursion root. Content-FILTERING is otherwise robust: zero XSS bypasses across a large vector set.
- ⬜ P2 serializer doesn't escape `<`/`>` in attribute values (latent mutation-XSS; inert while `"` boundary holds).

### email — ⬜ OPEN (security)
- ⬜ P0/SEC **header injection** via `build`/`emit`/`format-address`: CRLF (or bare LF) in a header value (subject/to/display-name) injects new headers (Bcc/arbitrary) — textbook mail injection. Fix: reject/strip CR/LF in header names+values on emit.
- ⬜ P2 top-level `parse` over-strict (CXER1300 on a stray no-colon line) vs the lenient per-part parser; minor lenient address deviations.

### locale — ⬜ OPEN
- ⬜ P1 `format-number`/`format-currency` silent i64 overflow on |v|≳9.2e18 → garbage; non-numeric string → silent `0`; `bool` arg → cryptic "no callable"; negative-currency sign placement `$-1,234.56` (should `-$1,234.56`).

### validate — ⬜ OPEN
- ⬜ P1 nested-schema (`type=element schema=`) validation broken for single-field nested records: `val_field_node` over-unwraps → false `REQUIRED_MISSING`. (conformance validate-016 passes by coincidence — asserts path not code.)

### format — ⬜ OPEN
- ⬜ P2 `line-width` opt is a complete no-op (parsed/validated, never consumed by the pretty emitter).

### Clean in wave 3 (zero confirmed defects)
- **mime**, **i18n**, **ft** — robust under adversarial probing.

### io / process / prof / crypto / store / fp / env — not yet wave-3 adversarial-audited
(io/process/env/crypto behavior-tested in the granted-lane work; fp/traverse bug filed task_e1b2b368.)
