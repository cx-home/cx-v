module cx

// V FFI binding to the libcx RE2 shim (vcx/deps/re2_shim/).
//
// Locked by spec/schema.md §7 + spec/abi.md §3 — all `:pat='...'`
// constraint checking goes through libcx-side RE2, not the host
// language's regex engine. This eliminates per-binding regex-flavor
// drift; bindings call cx_validate / cx_validate_apply_defaults and
// receive identical match results across V/Python/Go/Rust/etc.
//
// Ships with VENDORED RE2 (#573): third_party/re2, submodule-pinned to
// the last pre-abseil release (2023-03-01) and linked as a STATIC
// archive built in-tree (vcx/Makefile re2-static) — no system-re2
// runtime dependency on any platform, and full source determinism
// (the previously queued post-tag item). The shim uses only the stable
// compile/match/replace API; the wire-level FullMatch semantics are
// identical across the pin and later releases.

#flag -I @VMODROOT/deps/re2_shim
#flag -I @VMODROOT/../third_party/re2
#flag -L @VMODROOT/target
#flag -lcx_re2_shim
#flag @VMODROOT/../third_party/re2/obj/libre2.a
#flag darwin -lc++
#flag linux -lstdc++ -lpthread

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

// cx-stdlib/re full surface (spec/std-lib/re.md).
fn C.cx_re2_compile_opts(pattern &char, case_insensitive int, multiline int,
	dotall int, literal int) &C.cx_re2
fn C.cx_re2_num_groups(re &C.cx_re2) int
fn C.cx_re2_group_names(re &C.cx_re2) &char
fn C.cx_re2_match_at(re &C.cx_re2, text &char, text_len u64, startpos u64,
	out_starts &i64, out_ends &i64, max_groups int) int
fn C.cx_re2_quote_meta(s &char, s_len u64) &char

// re2_full_match returns true when `text` fully matches `pattern`
// per RE2 FullMatch semantics. Returns false on pattern-compile
// failure (the schema validator surfaces compile failures as
// schema-load errors S009 elsewhere).
//
// The validator's S008 callsite uses this directly. Other CX features
// that want regex semantics (none today; reserved for future use)
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
// These wrap the shim additions (partial-match, find, replace-
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

// ── cx-stdlib/re full surface (spec/std-lib/re.md) ───────────────────────
//
// These back the cx-stdlib/re module. Compiled-pattern values carry only
// the source pattern + flags (spec §3 permits no compile cache), so every
// operation recompiles via cx_re2_compile_opts from (pattern, flags). The
// unicode class rewrite and unsupported-feature pre-scan happen here so
// the C shim stays encoding-agnostic and so CXER3200 (unsupported PCRE
// feature) is distinguished from CXER3201 (plain syntax error).

// Re2Flags is the effective flag set for a compiled pattern (spec §4.1).
pub struct Re2Flags {
pub mut:
	case_insensitive bool
	multiline        bool
	dotall           bool
	unicode          bool = true
	literal          bool
	max_match_bytes  i64
}

// Re2Span is a byte [start, end) span for one capture group; an absent
// group has start == -1.
pub struct Re2Span {
pub:
	start i64
	end   i64
}

// re2_unsupported_feature scans `pattern` for PCRE constructs RE2 rejects
// by design (spec §2 / §6 → CXER3200). Honours backslash + class context
// so an escaped metacharacter is not misread. Returns true on the first
// unsupported feature found.
pub fn re2_unsupported_feature(pattern string) bool {
	mut i := 0
	for i < pattern.len {
		c := pattern[i]
		if c == `\\` {
			if i + 1 < pattern.len {
				n := pattern[i + 1]
				// \1..\9 numeric backreference; \k<name> / \k{name} named
				// backreference; \g back-ref; \Q..\E literal region.
				if n >= `1` && n <= `9` {
					return true
				}
				if n == `k` || n == `g` || n == `Q` || n == `E` {
					return true
				}
			}
			i += 2
			continue
		}
		if c == `(` && i + 2 < pattern.len && pattern[i + 1] == `?` {
			n := pattern[i + 2]
			// (?=  (?!  positive/negative lookahead;
			// (?<= (?<! lookbehind; (?>  atomic group.
			if n == `=` || n == `!` || n == `>` {
				return true
			}
			if n == `<` && i + 3 < pattern.len {
				m := pattern[i + 3]
				// (?<= / (?<! lookbehind — but (?<name> is a named group.
				if m == `=` || m == `!` {
					return true
				}
			}
		}
		i++
	}
	return false
}

// re2_apply_unicode_classes rewrites Perl shorthand classes to their
// Unicode-aware RE2 equivalents (spec §5): \d→\p{Nd}, \w→[\p{L}\p{Nd}_],
// \s→[\s\p{Z}] (and the negated \D/\W/\S). Skips escaped backslashes so
// `\\d` (literal backslash + d) is left untouched. Only applied when the
// `unicode` flag is true; with unicode=false RE2's default ASCII classes
// stand.
fn re2_apply_unicode_classes(pattern string) string {
	mut out := []u8{cap: pattern.len + 16}
	mut i := 0
	for i < pattern.len {
		c := pattern[i]
		if c == `\\` && i + 1 < pattern.len {
			n := pattern[i + 1]
			match n {
				`d` { out << '\\p{Nd}'.bytes() }
				`D` { out << '\\P{Nd}'.bytes() }
				`w` { out << '[\\p{L}\\p{Nd}_]'.bytes() }
				`W` { out << '[^\\p{L}\\p{Nd}_]'.bytes() }
				`s` { out << '[\\s\\p{Z}]'.bytes() }
				`S` { out << '[^\\s\\p{Z}]'.bytes() }
				else {
					out << c
					out << n
				}
			}
			i += 2
			continue
		}
		out << c
		i++
	}
	return out.bytestr()
}

// re2_effective_pattern assembles the pattern RE2 actually compiles:
// inline flag prefix ((?i)/(?m)/(?s)) + optional unicode class rewrite.
// Literal patterns are passed through verbatim (the literal Option makes
// every byte literal, so flags + class rewrites do not apply).
fn re2_effective_pattern(pattern string, flags Re2Flags) string {
	if flags.literal {
		return pattern
	}
	mut body := pattern
	if flags.unicode {
		body = re2_apply_unicode_classes(body)
	}
	mut inline := ''
	if flags.case_insensitive {
		inline += 'i'
	}
	if flags.multiline {
		inline += 'm'
	}
	if flags.dotall {
		inline += 's'
	}
	if inline.len > 0 {
		return '(?${inline})${body}'
	}
	return body
}

// re2_compile_checked compiles (pattern, flags), distinguishing the two
// compile-time error classes: an err whose message begins `CXER3200`
// (unsupported PCRE feature) or `CXER3201` (syntax error). The caller maps
// these onto the spec error nodes.
fn re2_compile_checked(pattern string, flags Re2Flags) !&C.cx_re2 {
	if re2_unsupported_feature(pattern) {
		return error('CXER3200:E_RE_FEATURE_UNSUPPORTED: ${pattern}')
	}
	eff := re2_effective_pattern(pattern, flags)
	ci := if flags.case_insensitive { 1 } else { 0 }
	ml := if flags.multiline { 1 } else { 0 }
	ds := if flags.dotall { 1 } else { 0 }
	lit := if flags.literal { 1 } else { 0 }
	re := C.cx_re2_compile_opts(eff.str, ci, ml, ds, lit)
	if re == unsafe { nil } {
		return error('CXER3201:E_RE_PATTERN_INVALID: ${pattern}')
	}
	return re
}

// re2_validate compiles + immediately frees, surfacing the compile-time
// error class (CXER3200 / CXER3201) or ok. Backs `compile` / the flag
// validation path.
pub fn re2_validate(pattern string, flags Re2Flags) ! {
	re := re2_compile_checked(pattern, flags)!
	C.cx_re2_destroy(re)
}

// re2_num_groups returns the number of capturing groups (excluding group
// 0) for (pattern, flags).
pub fn re2_num_groups(pattern string, flags Re2Flags) !int {
	re := re2_compile_checked(pattern, flags)!
	defer { C.cx_re2_destroy(re) }
	return C.cx_re2_num_groups(re)
}

// re2_group_names returns the named capturing groups in ascending group-
// index order (spec §4.6 group-names ordering follows pattern order).
pub fn re2_group_names(pattern string, flags Re2Flags) ![]string {
	re := re2_compile_checked(pattern, flags)!
	defer { C.cx_re2_destroy(re) }
	raw := C.cx_re2_group_names(re)
	if raw == unsafe { nil } {
		return error('CXER3201:E_RE_PATTERN_INVALID: group-names OOM')
	}
	defer { C.cx_re2_free_string(raw) }
	text := unsafe { cstring_to_vstring(raw) }
	mut pairs := [][]string{} // [name, idx]
	for line in text.split('\n') {
		if line.len == 0 {
			continue
		}
		parts := line.split('\t')
		if parts.len == 2 {
			pairs << [parts[0], parts[1]]
		}
	}
	pairs.sort_with_compare(fn (a &[]string, b &[]string) int {
		ia := a[1].int()
		ib := b[1].int()
		return ia - ib
	})
	mut names := []string{cap: pairs.len}
	for p in pairs {
		names << p[0]
	}
	return names
}

// re2_named_index returns the 1-based group index for a named group, or
// -1 when no such name exists.
pub fn re2_named_index(pattern string, flags Re2Flags, name string) !int {
	re := re2_compile_checked(pattern, flags)!
	defer { C.cx_re2_destroy(re) }
	raw := C.cx_re2_group_names(re)
	if raw == unsafe { nil } {
		return -1
	}
	defer { C.cx_re2_free_string(raw) }
	text := unsafe { cstring_to_vstring(raw) }
	for line in text.split('\n') {
		parts := line.split('\t')
		if parts.len == 2 && parts[0] == name {
			return parts[1].int()
		}
	}
	return -1
}

// re2_match_at runs one UNANCHORED match at byte `startpos` over `text`
// (full buffer passed for anchor context). Returns the per-group spans
// (index 0 = full match) on success, or an EMPTY slice on no-match (a
// successful match always carries at least group 0, so `len == 0`
// unambiguously signals no-match). Errors only on compile failure.
pub fn re2_match_at(pattern string, flags Re2Flags, text string, startpos int) ![]Re2Span {
	re := re2_compile_checked(pattern, flags)!
	defer { C.cx_re2_destroy(re) }
	ng := C.cx_re2_num_groups(re)
	max_groups := ng + 1
	mut starts := []i64{len: max_groups, init: -1}
	mut ends := []i64{len: max_groups, init: -1}
	rc := unsafe {
		C.cx_re2_match_at(re, text.str, u64(text.len), u64(startpos),
			&starts[0], &ends[0], max_groups)
	}
	if rc != 1 {
		return []Re2Span{}
	}
	mut spans := []Re2Span{cap: max_groups}
	for i in 0 .. max_groups {
		spans << Re2Span{
			start: starts[i]
			end:   ends[i]
		}
	}
	return spans
}

// re2_full_match_flags returns true iff `text` fully matches (pattern,
// flags) — backs `matches` (spec §4.2: true iff the ENTIRE string
// matches). Implemented by anchoring the effective pattern at both ends.
pub fn re2_full_match_flags(pattern string, flags Re2Flags, text string) !bool {
	re := re2_compile_checked(pattern, flags)!
	defer { C.cx_re2_destroy(re) }
	rc := C.cx_re2_full_match(re, text.str, u64(text.len))
	return rc == 1
}

// re2_escape returns RE2 QuoteMeta(s) — the canonical literal escape
// (spec §4.6).
pub fn re2_escape(s string) string {
	out := C.cx_re2_quote_meta(s.str, u64(s.len))
	if out == unsafe { nil } {
		return s
	}
	defer { C.cx_re2_free_string(out) }
	return unsafe { cstring_to_vstring(out) }
}

// re2_utf8_advance returns the byte length of the UTF-8 codepoint starting
// at byte `i` in `text` (1 for ASCII / invalid lead bytes). Used for the
// spec §4.2 one-codepoint zero-width advance.
pub fn re2_utf8_advance(text string, i int) int {
	if i >= text.len {
		return 1
	}
	b := text[i]
	if b < 0x80 {
		return 1
	} else if b & 0xe0 == 0xc0 {
		return 2
	} else if b & 0xf0 == 0xe0 {
		return 3
	} else if b & 0xf8 == 0xf0 {
		return 4
	}
	return 1
}
