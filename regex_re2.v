module cx

// V FFI binding to the libcx RE2 shim (vcx/deps/re2_shim/).
//
// Locked by spec/schema.md §7 + spec/abi.md §3 — all `:pat='...'`
// constraint checking goes through libcx-side RE2, not the host
// language's regex engine. This eliminates per-binding regex-flavor
// drift; bindings call cx_validate / cx_validate_apply_defaults and
// receive identical match results across V/Python/Go/Rust/etc.
//
// v0.6.0 ships with system RE2 (Homebrew `re2` on macOS,
// `libre2-dev` on Debian/Ubuntu). Submodule-pinned RE2 source is
// queued post-tag for full source determinism (build-version
// guarantee). Switching from system → vendored is a build-system
// change, not an API change; the wire-level FullMatch semantics are
// stable.

#flag -I @VMODROOT/deps/re2_shim
#flag darwin -I/opt/homebrew/include
#flag linux -I/usr/include
#flag -L @VMODROOT/target
#flag darwin -L/opt/homebrew/lib
#flag -lcx_re2_shim
#flag darwin -lre2 -lc++
#flag linux -lre2 -lstdc++

#include "re2_shim.h"

@[typedef]
pub struct C.cx_re2 {}

fn C.cx_re2_compile(pattern &char) &C.cx_re2
fn C.cx_re2_full_match(re &C.cx_re2, text &char, text_len u64) int
fn C.cx_re2_destroy(re &C.cx_re2)

// re2_full_match returns true when `text` fully matches `pattern`
// per RE2 FullMatch semantics. Returns false on pattern-compile
// failure (the schema validator surfaces compile failures as
// schema-load errors S009 elsewhere).
//
// The validator's S008 callsite uses this directly. Other CX features
// that want regex semantics (none today; reserved for post-v0.6.0)
// would call this same helper.
pub fn re2_full_match(pattern string, text string) bool {
	if pattern == '' { return true }  // permissive default — empty pattern allows anything
	re := C.cx_re2_compile(pattern.str)
	if re == unsafe { nil } { return false }
	defer { C.cx_re2_destroy(re) }
	rc := C.cx_re2_full_match(re, text.str, u64(text.len))
	return rc == 1
}

// re2_compiles is a cheap "does this pattern compile under RE2?"
// probe used by schema-load to surface S008 compile failures at
// schema parse time (rather than at every document validation).
// TODO(phase-7.74d): wire this into parse_schema's per-AttrRule.pat
// validation pass.
pub fn re2_compiles(pattern string) bool {
	if pattern == '' { return true }
	re := C.cx_re2_compile(pattern.str)
	if re == unsafe { nil } { return false }
	C.cx_re2_destroy(re)
	return true
}
