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
fn C.cx_re2_partial_match(re &C.cx_re2, text &char, text_len u64) int
fn C.cx_re2_find(re &C.cx_re2, text &char, text_len u64, start_offset u64,
	out_start &u64, out_end &u64) int
fn C.cx_re2_replace_all(re &C.cx_re2, text &char, text_len u64,
	replacement &char, replacement_len u64) &char
fn C.cx_re2_free_string(s &char)
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

// ── XPath 4.0 fn:matches / fn:tokenize / fn:replace backings (C5) ────────────
// These wrap the v0.7.0 shim additions (partial-match, find, replace-
// all) so cx evaluator's [?matches] / [?tokenize] / [?regex-replace]
// directives go through libcx-vendored RE2 — same engine as schema
// :pat=, identical semantics across all bindings.

// re2_partial_match: returns true when `pattern` matches anywhere in
// `text`. Backs fn:matches semantics. Errors on bad pattern surface
// to the caller as a compile failure (returns ? / error).
pub fn re2_partial_match(pattern string, text string) !bool {
	if pattern == '' { return true }
	re := C.cx_re2_compile(pattern.str)
	if re == unsafe { nil } {
		return error('cx-err:FORX0002:invalid regex pattern: ${pattern}')
	}
	defer { C.cx_re2_destroy(re) }
	rc := C.cx_re2_partial_match(re, text.str, u64(text.len))
	return rc == 1
}

// re2_tokenize: split `text` on each non-overlapping match of
// `pattern`. Mirrors XQuery fn:tokenize 2-arg form. Empty matches
// at the same position advance one char to avoid infinite loops
// (RE2's standard fix for `()` / `\b` empty-match patterns).
pub fn re2_tokenize(pattern string, text string) ![]string {
	if pattern == '' {
		return error('cx-err:FORX0003:tokenize pattern must not be empty (would match between every character)')
	}
	re := C.cx_re2_compile(pattern.str)
	if re == unsafe { nil } {
		return error('cx-err:FORX0002:invalid regex pattern: ${pattern}')
	}
	defer { C.cx_re2_destroy(re) }
	mut parts := []string{}
	mut cursor := u64(0)
	tlen := u64(text.len)
	for cursor <= tlen {
		mut match_start := u64(0)
		mut match_end := u64(0)
		found := C.cx_re2_find(re, text.str, tlen, cursor, &match_start, &match_end)
		if found != 1 {
			parts << text[int(cursor)..text.len]
			break
		}
		parts << text[int(cursor)..int(match_start)]
		if match_end == match_start {
			// Empty match — advance one char to avoid spinning.
			cursor = match_start + 1
			if cursor > tlen {
				break
			}
		} else {
			cursor = match_end
		}
	}
	return parts
}

// re2_replace_all: replace every non-overlapping match of `pattern`
// with `replacement`. RE2 replacement syntax — `\1`..`\9` for capture
// back-refs. Backs XQuery fn:replace 3-arg form.
pub fn re2_replace_all(pattern string, replacement string, text string) !string {
	re := C.cx_re2_compile(pattern.str)
	if re == unsafe { nil } {
		return error('cx-err:FORX0002:invalid regex pattern: ${pattern}')
	}
	defer { C.cx_re2_destroy(re) }
	out := C.cx_re2_replace_all(re, text.str, u64(text.len),
		replacement.str, u64(replacement.len))
	if out == unsafe { nil } {
		return error('cx-err:CXER0003:RE2 replace_all internal failure (likely OOM)')
	}
	defer { C.cx_re2_free_string(out) }
	return unsafe { cstring_to_vstring(out) }
}
