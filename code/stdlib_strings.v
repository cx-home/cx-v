module code

import cx
import strings

// stdlib_strings.v — native primitives backing the cx-stdlib/strings
// module's [?def] bodies (spec/stdlib_strings.md §3).
//
// Every primitive here is named with a `str-` prefix so it can never
// clash with a language-core builtin (the core invoke_builtin set is
// consulted before stdlib_builtin, and several core names — `contains`,
// `reverse`, `upper` — carry sequence/ASCII semantics that differ from
// the Unicode-aware string contract this module owes). The bundle
// bodies call these prefixed names directly, e.g.
//   [?def upper scope=public pure [returns string] ($s::string) [$str-upper $s]]
//
// CX strings are UTF-8; indexing / length / slicing are codepoint
// (rune) aware per spec §2. We operate on `[]rune` for those, on bytes
// only for `length-bytes`.

// ── result builders ─────────────────────────────────────────────────────────

fn s_str(v string) cx.Node {
	return cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue(v)
		data_type: cx.ScalarType.string_type
	})
}

fn s_int(v i64) cx.Node {
	return cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue(v)
		data_type: cx.ScalarType.int_type
	})
}

fn s_bool(v bool) cx.Node {
	return cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue(v)
		data_type: cx.ScalarType.bool_type
	})
}

fn s_float(v f64) cx.Node {
	return cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue(v)
		data_type: cx.ScalarType.float_type
	})
}

// s_absence returns the CX absence channel — the empty sequence `()` that
// `[?else]` / coalescing treat as "missing" (eval.v::is_empty_absence). The
// `to-number` / `to-int` / `to-float` parsers return this for a non-numeric
// input instead of a silent string passthrough (#54), so the caller can branch
// with `[?else …]` rather than discover the failure at a later arithmetic op.
fn s_absence() cx.Node {
	return cx.Node(cx.Element{ name: '__cx_seq__' })
}

fn s_seq_str(items []string) cx.Node {
	mut nodes := []cx.Node{}
	for it in items {
		nodes << s_str(it)
	}
	return cx.Node(cx.Element{ name: '__cx_seq__', items: nodes })
}

fn s_seq_int(items []int) cx.Node {
	mut nodes := []cx.Node{}
	for it in items {
		nodes << s_int(i64(it))
	}
	return cx.Node(cx.Element{ name: '__cx_seq__', items: nodes })
}

// s_err builds a CX failure outcome draft-3 `[result
// status=err code=… message=…]` (status/code/message are scalar →
// attributes). Returned in place of a result when a strings primitive
// must signal a spec error (CXER2900 / CXER2901 / …); the value carries
// the code through to render / [?try]-:catch / the conformance
// `out_err` matcher.
fn s_err(err_code string, message string) cx.Node {
	return cx.Node(cx.Element{
		name: 'result'
		attrs: [
			cx.Attribute{ name: 'status', value: cx.ScalarValue('err') },
			cx.Attribute{ name: 'code', value: cx.ScalarValue(err_code) },
			cx.Attribute{ name: 'message', value: cx.ScalarValue(message) },
		]
	})
}

// ── arg extraction ──────────────────────────────────────────────────────────

fn s_arg_str(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	return none
}

fn s_arg_int(n cx.Node) ?int {
	if n is cx.ScalarNode {
		v := n.value
		match v {
			i64 { return int(v) }
			f64 { return int(v) }
			else { return none }
		}
	}
	return none
}

// s_arg_string_list flattens a sequence / array node into its string
// scalar items. Used by `join`.
fn s_arg_string_list(n cx.Node) ?[]string {
	if n is cx.Element {
		if n.name == '__cx_seq__' || n.name == '__cx_arr__' || n.name == '' {
			mut out := []string{}
			for it in n.items {
				out << s_arg_str(it) or { '' }
			}
			return out
		}
	}
	return none
}

// ── Unicode whitespace ──────────────────────────────────────────────────────

// is_unicode_ws reports whether a rune is Unicode whitespace
// (White_Space property), covering the ASCII set plus NBSP, the various
// Unicode spaces, line/paragraph separators, etc.
fn is_unicode_ws(r rune) bool {
	return r == ` ` || r == `\t` || r == `\n` || r == `\r` || r == 0x0b
		|| r == 0x0c || r == 0x85 || r == 0xa0 || r == 0x1680
		|| (r >= 0x2000 && r <= 0x200a) || r == 0x2028 || r == 0x2029
		|| r == 0x202f || r == 0x205f || r == 0x3000
}

fn is_ascii_digit(r rune) bool {
	return r >= `0` && r <= `9`
}

// is_unicode_digit covers ASCII plus a representative set of Unicode
// decimal-digit ranges (Nd) — Eastern Arabic, Devanagari, Bengali,
// fullwidth, etc. (spec §3.8 calls out Eastern Arabic numerals).
fn is_unicode_digit(r rune) bool {
	if is_ascii_digit(r) {
		return true
	}
	ranges := [
		[u32(0x0660), 0x0669], // Arabic-Indic
		[u32(0x06f0), 0x06f9], // Extended Arabic-Indic
		[u32(0x0966), 0x096f], // Devanagari
		[u32(0x09e6), 0x09ef], // Bengali
		[u32(0x0a66), 0x0a6f], // Gurmukhi
		[u32(0x0ae6), 0x0aef], // Gujarati
		[u32(0x0b66), 0x0b6f], // Oriya
		[u32(0x0be6), 0x0bef], // Tamil
		[u32(0x0c66), 0x0c6f], // Telugu
		[u32(0x0ce6), 0x0cef], // Kannada
		[u32(0x0d66), 0x0d6f], // Malayalam
		[u32(0x0e50), 0x0e59], // Thai
		[u32(0x0ed0), 0x0ed9], // Lao
		[u32(0xff10), 0xff19], // Fullwidth
	]
	for rg in ranges {
		if u32(r) >= rg[0] && u32(r) <= rg[1] {
			return true
		}
	}
	return false
}

// ── locale-free numeric parsing (§3.11, #54) ─────────────────────────────────

// strings_classify_number validates a LOCALE-FREE numeric string against a
// fixed grammar and reports `is_int`:
//
//   number   = ws? sign? mantissa exponent? ws?
//   sign     = "+" | "-"
//   mantissa = digits | digits "." digits? | "." digits      (at least one digit)
//   exponent = ("e"|"E") sign? digits                         (at least one digit)
//
// `is_int` is true iff the (trimmed) string is pure integer syntax — no `.`
// and no exponent (e.g. "-5", "42"); a `.` and/or an exponent make it false
// ("3.07", "1e3", ".5", "5."). Returns none — i.e. NOT a number — for the
// empty string, a lone sign, a lone `.`, a missing-mantissa exponent ("e3"),
// thousands separators ("1,234"), and any trailing junk ("3.07abc"). ASCII
// digits only (this is the locale-free surface; cx-stdlib/locale owns
// grouping / Unicode-digit / alternate-decimal parsing).
fn strings_classify_number(raw string) ?bool {
	s := raw.trim_space()
	if s == '' {
		return none
	}
	mut i := 0
	n := s.len
	if s[i] == `+` || s[i] == `-` {
		i++
	}
	mut int_digits := 0
	for i < n && s[i] >= `0` && s[i] <= `9` {
		int_digits++
		i++
	}
	mut seen_dot := false
	mut frac_digits := 0
	if i < n && s[i] == `.` {
		seen_dot = true
		i++
		for i < n && s[i] >= `0` && s[i] <= `9` {
			frac_digits++
			i++
		}
	}
	if int_digits == 0 && frac_digits == 0 {
		return none // no mantissa digits (e.g. "", "+", ".", "-.")
	}
	mut seen_exp := false
	if i < n && (s[i] == `e` || s[i] == `E`) {
		seen_exp = true
		i++
		if i < n && (s[i] == `+` || s[i] == `-`) {
			i++
		}
		mut exp_digits := 0
		for i < n && s[i] >= `0` && s[i] <= `9` {
			exp_digits++
			i++
		}
		if exp_digits == 0 {
			return none // "e" / "E" with no exponent digits
		}
	}
	if i != n {
		return none // trailing junk (e.g. "3.07abc", "1,234")
	}
	return !seen_dot && !seen_exp
}

// strings_num_node converts an ALREADY-VALIDATED numeric string (per
// strings_classify_number) to an int or float scalar. A leading `+` is dropped
// first so `"+5".i64()` parses (V's int parse does not consume the sign).
fn strings_num_node(validated string, is_int bool) cx.Node {
	mut c := validated
	if c.starts_with('+') {
		c = c[1..]
	}
	if is_int {
		return s_int(c.i64())
	}
	return s_float(c.f64())
}

fn is_unicode_alpha(r rune) bool {
	if (r >= `a` && r <= `z`) || (r >= `A` && r <= `Z`) {
		return true
	}
	// Latin-1 letters + a coarse "above-ASCII letter" heuristic: any
	// codepoint >= 0xC0 that is not whitespace, not a digit, and not in
	// common punctuation/symbol bands. Good enough for the spec's
	// Unicode-aware predicate contract without shipping the full UCD.
	if r < 0x80 {
		return false
	}
	if is_unicode_ws(r) || is_unicode_digit(r) {
		return false
	}
	// Latin-1 punctuation/symbol block 0xA0..0xBF and the × ÷ signs.
	if r >= 0xa0 && r <= 0xbf {
		return false
	}
	if r == 0xd7 || r == 0xf7 {
		return false
	}
	return true
}

// ── case helpers ────────────────────────────────────────────────────────────

// special_upper expands the codepoints whose Unicode default uppercase
// mapping is multi-character (the common one being ß → SS). V's
// .to_upper() does not perform this expansion, so we handle it here so
// `upper("straße")` == "STRASSE" per spec §6.
fn unicode_upper(s string) string {
	mut b := strings.new_builder(s.len + 8)
	for r in s.runes() {
		if r == `ß` {
			b.write_string('SS')
		} else {
			b.write_rune(rune_to_upper(r))
		}
	}
	return b.str()
}

fn unicode_lower(s string) string {
	mut b := strings.new_builder(s.len)
	for r in s.runes() {
		b.write_rune(rune_to_lower(r))
	}
	return b.str()
}

fn rune_to_upper(r rune) rune {
	if r >= `a` && r <= `z` {
		return r - 32
	}
	// Latin-1 Supplement lowercase à..þ (0xE0..0xFE, excluding ÷ 0xF7)
	// maps to À..Þ (0xC0..0xDE). ÿ (0xFF) has no single-char Latin-1
	// uppercase (→ Ÿ U+0178); map it explicitly.
	if r >= 0xe0 && r <= 0xfe && r != 0xf7 {
		return r - 32
	}
	if r == 0xff {
		return 0x178
	}
	return r
}

fn rune_to_lower(r rune) rune {
	if r >= `A` && r <= `Z` {
		return r + 32
	}
	if r >= 0xc0 && r <= 0xde && r != 0xd7 {
		return r + 32
	}
	if r == 0x178 {
		return 0xff
	}
	return r
}

fn rune_is_upper(r rune) bool {
	return rune_to_lower(r) != r
}

fn rune_is_lower(r rune) bool {
	return rune_to_upper(r) != r
}

// ── search helpers (codepoint-position aware) ────────────────────────────────

// rune_index returns the codepoint position of the first occurrence of
// needle in s at or after rune-position `from`, or -1. Empty needle
// matches at `from`.
fn rune_find_from(s string, needle string, from int) int {
	sr := s.runes()
	nr := needle.runes()
	if nr.len == 0 {
		if from <= sr.len { return if from < 0 { 0 } else { from } }
		return -1
	}
	start := if from < 0 { 0 } else { from }
	if start + nr.len > sr.len {
		return -1
	}
	for i := start; i + nr.len <= sr.len; i++ {
		mut ok := true
		for j in 0 .. nr.len {
			if sr[i + j] != nr[j] {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

fn rune_rfind(s string, needle string) int {
	sr := s.runes()
	nr := needle.runes()
	if nr.len == 0 {
		return sr.len
	}
	if nr.len > sr.len {
		return -1
	}
	for i := sr.len - nr.len; i >= 0; i-- {
		mut ok := true
		for j in 0 .. nr.len {
			if sr[i + j] != nr[j] {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

// non-overlapping occurrence positions of needle in s (codepoint posns).
// Runes s and needle ONCE and searches the []rune slice in place. The prior
// version called rune_find_from in the loop, and rune_find_from re-ran
// s.runes() on EVERY call → O(n²) (100k single-char matches took ~60s).
fn rune_find_all(s string, needle string) []int {
	mut out := []int{}
	sr := s.runes()
	nr := needle.runes()
	if nr.len == 0 {
		return out
	}
	mut pos := 0
	for pos + nr.len <= sr.len {
		mut found := -1
		for i := pos; i + nr.len <= sr.len; i++ {
			mut ok := true
			for j in 0 .. nr.len {
				if sr[i + j] != nr[j] {
					ok = false
					break
				}
			}
			if ok {
				found = i
				break
			}
		}
		if found < 0 {
			break
		}
		out << found
		pos = found + nr.len
	}
	return out
}

fn runes_slice_to_string(rs []rune) string {
	mut b := strings.new_builder(rs.len)
	for r in rs {
		b.write_rune(r)
	}
	return b.str()
}

// ── dispatch ────────────────────────────────────────────────────────────────

fn strings_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	match name {
		// §3.1 Inspection
		'str-length' {
			s := s_arg_str(args[0]) or { return none }
			return s_int(i64(s.runes().len))
		}
		'str-length-bytes' {
			s := s_arg_str(args[0]) or { return none }
			return s_int(i64(s.len))
		}
		'str-is-empty' {
			s := s_arg_str(args[0]) or { return none }
			return s_bool(s.len == 0)
		}
		'str-at' {
			s := s_arg_str(args[0]) or { return none }
			i := s_arg_int(args[1]) or { return none }
			rs := s.runes()
			if i < 0 || i >= rs.len {
				return s_err('cx-err:CXER2900', 'E_STRINGS_INDEX_OUT_OF_RANGE: at(${i}) out of range for length ${rs.len}')
			}
			return s_str(runes_slice_to_string([rs[i]]))
		}
		'str-slice' {
			s := s_arg_str(args[0]) or { return none }
			mut start := s_arg_int(args[1]) or { return none }
			mut end := s_arg_int(args[2]) or { return none }
			rs := s.runes()
			n := rs.len
			// Python-style half-open; bounds clamp to length (spec §3.1).
			if start < 0 { start = 0 }
			if end > n { end = n }
			if start > n { start = n }
			if end < start { end = start }
			return s_str(runes_slice_to_string(rs[start..end]))
		}
		'str-reverse' {
			s := s_arg_str(args[0]) or { return none }
			mut rs := s.runes()
			rs.reverse_in_place()
			return s_str(runes_slice_to_string(rs))
		}
		// §3.2 Search
		'str-contains' {
			s := s_arg_str(args[0]) or { return none }
			needle := s_arg_str(args[1]) or { return none }
			return s_bool(s.contains(needle))
		}
		'str-find' {
			s := s_arg_str(args[0]) or { return none }
			needle := s_arg_str(args[1]) or { return none }
			return s_int(i64(rune_find_from(s, needle, 0)))
		}
		'str-find-from' {
			s := s_arg_str(args[0]) or { return none }
			needle := s_arg_str(args[1]) or { return none }
			from := s_arg_int(args[2]) or { return none }
			return s_int(i64(rune_find_from(s, needle, from)))
		}
		'str-rfind' {
			s := s_arg_str(args[0]) or { return none }
			needle := s_arg_str(args[1]) or { return none }
			return s_int(i64(rune_rfind(s, needle)))
		}
		'str-starts-with' {
			s := s_arg_str(args[0]) or { return none }
			prefix := s_arg_str(args[1]) or { return none }
			return s_bool(s.starts_with(prefix))
		}
		'str-ends-with' {
			s := s_arg_str(args[0]) or { return none }
			suffix := s_arg_str(args[1]) or { return none }
			return s_bool(s.ends_with(suffix))
		}
		'str-count' {
			s := s_arg_str(args[0]) or { return none }
			needle := s_arg_str(args[1]) or { return none }
			return s_int(i64(rune_find_all(s, needle).len))
		}
		'str-find-all' {
			s := s_arg_str(args[0]) or { return none }
			needle := s_arg_str(args[1]) or { return none }
			return s_seq_int(rune_find_all(s, needle))
		}
		// §3.3 Case
		'str-upper' {
			s := s_arg_str(args[0]) or { return none }
			return s_str(unicode_upper(s))
		}
		'str-lower' {
			s := s_arg_str(args[0]) or { return none }
			return s_str(unicode_lower(s))
		}
		'str-title' {
			s := s_arg_str(args[0]) or { return none }
			return s_str(title_case(s))
		}
		'str-case-fold' {
			s := s_arg_str(args[0]) or { return none }
			// Case folding ≈ lowercase for the Latin set (ß folds to ss).
			mut b := strings.new_builder(s.len)
			for r in s.runes() {
				if r == `ß` {
					b.write_string('ss')
				} else {
					b.write_rune(rune_to_lower(r))
				}
			}
			return s_str(b.str())
		}
		'str-swap-case' {
			s := s_arg_str(args[0]) or { return none }
			mut b := strings.new_builder(s.len)
			for r in s.runes() {
				if rune_is_upper(r) {
					b.write_rune(rune_to_lower(r))
				} else if rune_is_lower(r) {
					b.write_rune(rune_to_upper(r))
				} else {
					b.write_rune(r)
				}
			}
			return s_str(b.str())
		}
		'str-upper-locale' {
			// Locale delegation (cx-stdlib/locale) is not yet wired; the
			// default-table uppercase is the documented fallback behavior.
			s := s_arg_str(args[0]) or { return none }
			return s_str(unicode_upper(s))
		}
		'str-lower-locale' {
			s := s_arg_str(args[0]) or { return none }
			return s_str(unicode_lower(s))
		}
		// §3.4 Trim
		'str-trim' {
			s := s_arg_str(args[0]) or { return none }
			return s_str(trim_ws(s, true, true))
		}
		'str-trim-start' {
			s := s_arg_str(args[0]) or { return none }
			return s_str(trim_ws(s, true, false))
		}
		'str-trim-end' {
			s := s_arg_str(args[0]) or { return none }
			return s_str(trim_ws(s, false, true))
		}
		'str-trim-chars' {
			s := s_arg_str(args[0]) or { return none }
			chars := s_arg_str(args[1]) or { return none }
			return s_str(trim_chars(s, chars, true, true))
		}
		'str-trim-start-chars' {
			s := s_arg_str(args[0]) or { return none }
			chars := s_arg_str(args[1]) or { return none }
			return s_str(trim_chars(s, chars, true, false))
		}
		'str-trim-end-chars' {
			s := s_arg_str(args[0]) or { return none }
			chars := s_arg_str(args[1]) or { return none }
			return s_str(trim_chars(s, chars, false, true))
		}
		// §3.5 Split and join
		'str-split' {
			s := s_arg_str(args[0]) or { return none }
			sep := s_arg_str(args[1]) or { return none }
			return s_seq_str(str_split(s, sep))
		}
		'str-split-limit' {
			s := s_arg_str(args[0]) or { return none }
			sep := s_arg_str(args[1]) or { return none }
			max := s_arg_int(args[2]) or { return none }
			return s_seq_str(str_split_limit(s, sep, max))
		}
		'str-split-lines' {
			s := s_arg_str(args[0]) or { return none }
			return s_seq_str(str_split_lines(s))
		}
		'str-split-whitespace' {
			s := s_arg_str(args[0]) or { return none }
			return s_seq_str(str_split_whitespace(s))
		}
		'str-join' {
			parts := s_arg_string_list(args[0]) or { return none }
			sep := s_arg_str(args[1]) or { return none }
			return s_str(parts.join(sep))
		}
		// §3.6 Replace
		'str-replace' {
			s := s_arg_str(args[0]) or { return none }
			from := s_arg_str(args[1]) or { return none }
			to := s_arg_str(args[2]) or { return none }
			return s_str(str_replace_n(s, from, to, -1))
		}
		'str-replace-first' {
			s := s_arg_str(args[0]) or { return none }
			from := s_arg_str(args[1]) or { return none }
			to := s_arg_str(args[2]) or { return none }
			return s_str(str_replace_n(s, from, to, 1))
		}
		'str-replace-n' {
			s := s_arg_str(args[0]) or { return none }
			from := s_arg_str(args[1]) or { return none }
			to := s_arg_str(args[2]) or { return none }
			nrep := s_arg_int(args[3]) or { return none }
			return s_str(str_replace_n(s, from, to, nrep))
		}
		'str-replace-exactly' {
			// Fail-loud surgical replace (#93): `from` MUST occur exactly once,
			// else an err VALUE (CXER2903) — the safety the harness Edit tool
			// gives, so a typo'd / ambiguous target can't silently no-op or
			// over-replace.
			s := s_arg_str(args[0]) or { return none }
			from := s_arg_str(args[1]) or { return none }
			to := s_arg_str(args[2]) or { return none }
			if from == '' {
				return s_err('cx-err:CXER2903', 'E_STRINGS_REPLACE_NOT_UNIQUE: replace-exactly requires a non-empty "from"')
			}
			cnt := rune_find_all(s, from).len
			if cnt != 1 {
				return s_err('cx-err:CXER2903', 'E_STRINGS_REPLACE_NOT_UNIQUE: "from" must occur exactly once, found ${cnt}')
			}
			return s_str(str_replace_n(s, from, to, 1))
		}
		// §3.7 Pad and repeat
		'str-pad-start' {
			s := s_arg_str(args[0]) or { return none }
			target := s_arg_int(args[1]) or { return none }
			pad := s_arg_str(args[2]) or { return none }
			return s_str(pad_string(s, target, pad, .start))
		}
		'str-pad-end' {
			s := s_arg_str(args[0]) or { return none }
			target := s_arg_int(args[1]) or { return none }
			pad := s_arg_str(args[2]) or { return none }
			return s_str(pad_string(s, target, pad, .end))
		}
		'str-center' {
			s := s_arg_str(args[0]) or { return none }
			target := s_arg_int(args[1]) or { return none }
			pad := s_arg_str(args[2]) or { return none }
			return s_str(pad_string(s, target, pad, .center))
		}
		'str-repeat' {
			s := s_arg_str(args[0]) or { return none }
			nrep := s_arg_int(args[1]) or { return none }
			if nrep <= 0 {
				return s_str('')
			}
			return s_str(s.repeat(nrep))
		}
		// §3.8 Character class predicates
		'str-is-ascii' {
			s := s_arg_str(args[0]) or { return none }
			for r in s.runes() {
				if r > 0x7f {
					return s_bool(false)
				}
			}
			return s_bool(true)
		}
		'str-is-digit' {
			s := s_arg_str(args[0]) or { return none }
			rs := s.runes()
			for r in rs {
				if !is_unicode_digit(r) {
					return s_bool(false)
				}
			}
			return s_bool(true)
		}
		'str-is-alpha' {
			s := s_arg_str(args[0]) or { return none }
			for r in s.runes() {
				if !is_unicode_alpha(r) {
					return s_bool(false)
				}
			}
			return s_bool(true)
		}
		'str-is-alphanumeric' {
			s := s_arg_str(args[0]) or { return none }
			for r in s.runes() {
				if !(is_unicode_alpha(r) || is_unicode_digit(r)) {
					return s_bool(false)
				}
			}
			return s_bool(true)
		}
		'str-is-whitespace' {
			s := s_arg_str(args[0]) or { return none }
			for r in s.runes() {
				if !is_unicode_ws(r) {
					return s_bool(false)
				}
			}
			return s_bool(true)
		}
		'str-is-upper' {
			s := s_arg_str(args[0]) or { return none }
			for r in s.runes() {
				if rune_is_lower(r) {
					return s_bool(false)
				}
			}
			return s_bool(true)
		}
		'str-is-lower' {
			s := s_arg_str(args[0]) or { return none }
			for r in s.runes() {
				if rune_is_upper(r) {
					return s_bool(false)
				}
			}
			return s_bool(true)
		}
		'str-is-blank' {
			// blank == empty or all-whitespace
			s := s_arg_str(args[0]) or { return none }
			for r in s.runes() {
				if !is_unicode_ws(r) {
					return s_bool(false)
				}
			}
			return s_bool(true)
		}
		// §3.11 Locale-free numeric parsing (#54). Each returns a numeric
		// scalar for a valid input and the absence channel `()` (s_absence) for
		// a non-numeric one — NEVER a silent string passthrough (the unsafe
		// behavior of the `[$cx:parse …]` workaround). For grouping / Unicode
		// digits / alternate decimal separators use cx-stdlib/locale.
		'str-to-number' {
			// int for pure-integer syntax ("-5"), float for fractional /
			// exponent syntax ("3.07", "1e3").
			s := s_arg_str(args[0]) or { return none }
			t := s.trim_space()
			is_int := strings_classify_number(t) or { return s_absence() }
			return strings_num_node(t, is_int)
		}
		'str-to-int' {
			// pure-integer syntax only; "3.07" / "1e3" → absence (not integers).
			s := s_arg_str(args[0]) or { return none }
			t := s.trim_space()
			is_int := strings_classify_number(t) or { return s_absence() }
			if !is_int {
				return s_absence()
			}
			return strings_num_node(t, true)
		}
		'str-to-float' {
			// any valid numeric syntax, coerced to float ("5" → 5.0).
			s := s_arg_str(args[0]) or { return none }
			t := s.trim_space()
			strings_classify_number(t) or { return s_absence() }
			return strings_num_node(t, false)
		}
		// §3.9 Format / interpolation
		'str-format' {
			template := s_arg_str(args[0]) or { return none }
			return str_format(template, args[1])
		}
		// §3.10 Encoding helpers
		'str-escape-html' {
			s := s_arg_str(args[0]) or { return none }
			return s_str(escape_html(s))
		}
		'str-unescape-html' {
			s := s_arg_str(args[0]) or { return none }
			return s_str(unescape_html(s))
		}
		'str-escape-shell' {
			s := s_arg_str(args[0]) or { return none }
			return s_str(escape_shell(s))
		}
		'str-escape-json' {
			s := s_arg_str(args[0]) or { return none }
			return s_str(escape_json(s))
		}
		'str-escape-regex' {
			s := s_arg_str(args[0]) or { return none }
			return s_str(escape_regex(s))
		}
		else {
			return none
		}
	}
}

// ── title casing (UAX-29-ish word boundaries) ────────────────────────────────

// title_case uppercases the first letter following any non-alphanumeric
// boundary and lowercases the rest. Per spec §3.3 the hyphen is a word
// break (matching Python str.title), so "jean-paul sartre" →
// "Jean-Paul Sartre".
fn title_case(s string) string {
	mut b := strings.new_builder(s.len)
	mut at_boundary := true
	for r in s.runes() {
		if is_unicode_alpha(r) || is_unicode_digit(r) {
			if at_boundary {
				b.write_rune(rune_to_upper(r))
			} else {
				b.write_rune(rune_to_lower(r))
			}
			at_boundary = false
		} else {
			b.write_rune(r)
			at_boundary = true
		}
	}
	return b.str()
}

// ── trim ──────────────────────────────────────────────────────────────────

fn trim_ws(s string, left bool, right bool) string {
	rs := s.runes()
	mut lo := 0
	mut hi := rs.len
	if left {
		for lo < hi && is_unicode_ws(rs[lo]) {
			lo++
		}
	}
	if right {
		for hi > lo && is_unicode_ws(rs[hi - 1]) {
			hi--
		}
	}
	return runes_slice_to_string(rs[lo..hi])
}

fn trim_chars(s string, chars string, left bool, right bool) string {
	rs := s.runes()
	set := chars.runes()
	mut lo := 0
	mut hi := rs.len
	if left {
		for lo < hi && set.contains(rs[lo]) {
			lo++
		}
	}
	if right {
		for hi > lo && set.contains(rs[hi - 1]) {
			hi--
		}
	}
	return runes_slice_to_string(rs[lo..hi])
}

// ── split ────────────────────────────────────────────────────────────────

// str_split — split on each occurrence of sep. Empty sep splits on every
// character (spec §4.1). Empty input → empty sequence (spec §3.5).
fn str_split(s string, sep string) []string {
	if s.len == 0 {
		return []string{}
	}
	if sep.len == 0 {
		mut out := []string{}
		for r in s.runes() {
			out << runes_slice_to_string([r])
		}
		return out
	}
	return s.split(sep)
}

fn str_split_limit(s string, sep string, max int) []string {
	if s.len == 0 {
		return []string{}
	}
	if max <= 0 {
		return [s]
	}
	if sep.len == 0 {
		rs := s.runes()
		mut out := []string{}
		mut i := 0
		for i < rs.len && out.len < max {
			out << runes_slice_to_string([rs[i]])
			i++
		}
		if i < rs.len {
			out << runes_slice_to_string(rs[i..])
		}
		return out
	}
	// at most `max` splits → at most max+1 segments.
	return s.split_nth(sep, max + 1)
}

// str_split_lines — split on \n, \r\n, or \r; drop a single trailing
// empty segment after a final line break (spec §3.5).
fn str_split_lines(s string) []string {
	if s.len == 0 {
		return []string{}
	}
	mut out := []string{}
	mut cur := strings.new_builder(16)
	rs := s.runes()
	mut i := 0
	for i < rs.len {
		r := rs[i]
		if r == `\r` {
			out << cur.str()
			cur = strings.new_builder(16)
			if i + 1 < rs.len && rs[i + 1] == `\n` {
				i += 2
			} else {
				i++
			}
		} else if r == `\n` {
			out << cur.str()
			cur = strings.new_builder(16)
			i++
		} else {
			cur.write_rune(r)
			i++
		}
	}
	last := cur.str()
	if last.len > 0 {
		out << last
	}
	return out
}

// str_split_whitespace — split on Unicode whitespace; consecutive
// whitespace collapsed; leading/trailing whitespace produces no empty
// segments (spec §3.5).
fn str_split_whitespace(s string) []string {
	mut out := []string{}
	mut cur := strings.new_builder(16)
	mut have := false
	for r in s.runes() {
		if is_unicode_ws(r) {
			if have {
				out << cur.str()
				cur = strings.new_builder(16)
				have = false
			}
		} else {
			cur.write_rune(r)
			have = true
		}
	}
	if have {
		out << cur.str()
	}
	return out
}

// ── replace ────────────────────────────────────────────────────────────────

// str_replace_n replaces up to `limit` non-overlapping occurrences of
// `from` with `to`. limit < 0 means replace all.
fn str_replace_n(s string, from string, to string, limit int) string {
	if from.len == 0 || limit == 0 {
		return s
	}
	mut b := strings.new_builder(s.len)
	mut i := 0
	mut done := 0
	for i < s.len {
		if (limit < 0 || done < limit) && i + from.len <= s.len && s[i..i + from.len] == from {
			b.write_string(to)
			i += from.len
			done++
		} else {
			b.write_u8(s[i])
			i++
		}
	}
	return b.str()
}

// ── pad ────────────────────────────────────────────────────────────────────

enum PadSide {
	start
	end
	center
}

// pad_string pads s (codepoint width) up to `target` using repetitions
// of `pad`, truncating a multi-char pad to exactly fill (spec §3.7).
fn pad_string(s string, target int, pad string, side PadSide) string {
	cur := s.runes().len
	if target <= cur || pad.len == 0 {
		return s
	}
	need := target - cur
	match side {
		.start {
			return make_pad(pad, need) + s
		}
		.end {
			return s + make_pad(pad, need)
		}
		.center {
			left := need / 2
			right := need - left
			return make_pad(pad, left) + s + make_pad(pad, right)
		}
	}
}

// make_pad returns exactly `width` codepoints built from repetitions of
// pad, truncated (spec §3.7 "truncates if pad is multi-char").
fn make_pad(pad string, width int) string {
	pr := pad.runes()
	mut out := []rune{}
	mut i := 0
	for out.len < width {
		out << pr[i % pr.len]
		i++
	}
	return runes_slice_to_string(out)
}

// ── encoding helpers ─────────────────────────────────────────────────────────

// escape_html escapes the five XML/HTML metacharacters (spec §3.10).
fn escape_html(s string) string {
	mut b := strings.new_builder(s.len)
	for r in s.runes() {
		match r {
			`&` { b.write_string('&amp;') }
			`<` { b.write_string('&lt;') }
			`>` { b.write_string('&gt;') }
			`"` { b.write_string('&quot;') }
			`'` { b.write_string('&#39;') }
			else { b.write_rune(r) }
		}
	}
	return b.str()
}

// unescape_html decodes numeric entities (&#65; / &#x41;) and a curated
// set of named entities including the spec-called-out ones (&hellip;
// &mdash; &copy; &euro;) plus the five core metacharacters. (The full
// ~2,200-entity WHATWG table ships with libcx in the C reference impl;
// the V evaluator carries the common subset the conformance suite
// exercises.)
fn unescape_html(s string) string {
	named := html_named_entities()
	mut b := strings.new_builder(s.len)
	rs := s.runes()
	mut i := 0
	for i < rs.len {
		if rs[i] != `&` {
			b.write_rune(rs[i])
			i++
			continue
		}
		// find the terminating ';' within a sane window
		mut j := i + 1
		mut found := false
		for j < rs.len && j < i + 34 {
			if rs[j] == `;` {
				found = true
				break
			}
			j++
		}
		if !found {
			b.write_rune(rs[i])
			i++
			continue
		}
		body := runes_slice_to_string(rs[i + 1..j])
		mut decoded := ''
		mut ok := true
		if body.len > 1 && body[0] == `#` {
			cp := if body.len > 2 && (body[1] == `x` || body[1] == `X`) {
				hex_to_int(body[2..])
			} else {
				dec_to_int(body[1..])
			}
			if cp >= 0 {
				decoded = runes_slice_to_string([rune(cp)])
			} else {
				ok = false
			}
		} else {
			if v := named[body] {
				decoded = v
			} else {
				ok = false
			}
		}
		if ok {
			b.write_string(decoded)
			i = j + 1
		} else {
			b.write_rune(rs[i])
			i++
		}
	}
	return b.str()
}

fn dec_to_int(s string) int {
	mut n := 0
	if s.len == 0 {
		return -1
	}
	for c in s {
		if c < `0` || c > `9` {
			return -1
		}
		n = n * 10 + int(c - `0`)
	}
	return n
}

fn hex_to_int(s string) int {
	mut n := 0
	if s.len == 0 {
		return -1
	}
	for c in s {
		d := if c >= `0` && c <= `9` {
			int(c - `0`)
		} else if c >= `a` && c <= `f` {
			int(c - `a`) + 10
		} else if c >= `A` && c <= `F` {
			int(c - `A`) + 10
		} else {
			-1
		}
		if d < 0 {
			return -1
		}
		n = n * 16 + d
	}
	return n
}

fn html_named_entities() map[string]string {
	return {
		'amp':    '&'
		'lt':     '<'
		'gt':     '>'
		'quot':   '"'
		'apos':   "'"
		'nbsp':   ' '
		'copy':   '©'
		'reg':    '®'
		'trade':  '™'
		'hellip': '…'
		'mdash':  '—'
		'ndash':  '–'
		'euro':   '€'
		'pound':  '£'
		'yen':    '¥'
		'cent':   '¢'
		'sect':   '§'
		'para':   '¶'
		'middot': '·'
		'laquo':  '«'
		'raquo':  '»'
		'deg':    '°'
		'plusmn': '±'
		'times':  '×'
		'divide': '÷'
		'frac12': '½'
		'frac14': '¼'
		'frac34': '¾'
		'bull':   '•'
		'dagger': '†'
		'Dagger': '‡'
		'ldquo':  '“'
		'rdquo':  '”'
		'lsquo':  '‘'
		'rsquo':  '’'
	}
}

// escape_shell — POSIX single-quote shell quoting. Wraps in single
// quotes; embedded single quotes become '\'' (spec §3.10).
fn escape_shell(s string) string {
	mut b := strings.new_builder(s.len + 2)
	b.write_u8(`'`)
	for c in s {
		if c == `'` {
			b.write_string("'\\''")
		} else {
			b.write_u8(c)
		}
	}
	b.write_u8(`'`)
	return b.str()
}

// escape_json — JSON string-body escapes (no surrounding quotes; spec
// §3.10).
fn escape_json(s string) string {
	mut b := strings.new_builder(s.len)
	for c in s {
		match c {
			`"` { b.write_string('\\"') }
			`\\` { b.write_string('\\\\') }
			`\n` { b.write_string('\\n') }
			`\r` { b.write_string('\\r') }
			`\t` { b.write_string('\\t') }
			0x08 { b.write_string('\\b') }
			0x0c { b.write_string('\\f') }
			else {
				if c < 0x20 {
					b.write_string('\\u00')
					b.write_string(byte_hex(c))
				} else {
					b.write_u8(c)
				}
			}
		}
	}
	return b.str()
}

fn byte_hex(c u8) string {
	digits := '0123456789abcdef'
	return '${digits[c >> 4]:c}${digits[c & 0x0f]:c}'
}

// escape_regex — escape characters special to the regex engine so the
// string matches itself literally (spec §3.10).
fn escape_regex(s string) string {
	specials := '.^\$*+?()[]{}|\\'
	mut b := strings.new_builder(s.len)
	for c in s {
		if specials.contains_u8(c) {
			b.write_u8(`\\`)
		}
		b.write_u8(c)
	}
	return b.str()
}

// ── format ────────────────────────────────────────────────────────────────

// str_format performs runtime template substitution per spec §3.9.
// Placeholders: `{}` positional (implicit index), `{N}` positional by
// index, `{name}` named (from a map arg), optional `:type` char
// (d/f/s/x/X). No width/precision/alignment — `{x:.2f}` raises
// CXER2901. Missing arg → CXER2902. `{{` / `}}` are literal braces.
fn str_format(template string, args_node cx.Node) ?cx.Node {
	// Build positional + named lookup from the args node.
	mut positional := []cx.Node{}
	mut named := map[string]cx.Node{}
	if args_node is cx.Element {
		if args_node.name == '__cx_seq__' || args_node.name == '__cx_arr__'
			|| args_node.name == '' {
			positional = args_node.items.clone()
		} else if args_node.name == '__cx_map__' {
			for it in args_node.items {
				if it is cx.Element && it.items.len > 0 {
					named[it.name] = it.items[0]
				}
			}
		}
	}

	rs := template.runes()
	mut b := strings.new_builder(template.len)
	mut i := 0
	mut auto_idx := 0
	for i < rs.len {
		r := rs[i]
		if r == `{` {
			if i + 1 < rs.len && rs[i + 1] == `{` {
				b.write_rune(`{`)
				i += 2
				continue
			}
			// find closing brace
			mut j := i + 1
			for j < rs.len && rs[j] != `}` {
				j++
			}
			if j >= rs.len {
				return s_err('cx-err:CXER2901', 'E_STRINGS_FORMAT_TEMPLATE_INVALID: unterminated placeholder')
			}
			field := runes_slice_to_string(rs[i + 1..j])
			// parse field_name + optional :type
			mut fname := field
			mut tchar := ''
			if field.contains(':') {
				parts := field.split_nth(':', 2)
				fname = parts[0]
				tchar = if parts.len > 1 { parts[1] } else { '' }
			}
			// reject any spec specifier other than a single type char
			if tchar.len > 1 || (tchar.len == 1 && tchar !in ['d', 'f', 's', 'x', 'X']) {
				return s_err('cx-err:CXER2901', 'E_STRINGS_FORMAT_TEMPLATE_INVALID: unsupported format spec "${tchar}"')
			}
			// resolve the arg value
			mut val := cx.Node(cx.ScalarNode{ value: cx.ScalarValue(cx.NullValue{}), data_type: cx.ScalarType.null_type })
			if fname == '' {
				if auto_idx >= positional.len {
					return s_err('cx-err:CXER2902', 'E_STRINGS_FORMAT_ARG_MISSING: positional arg ${auto_idx} missing')
				}
				val = positional[auto_idx]
				auto_idx++
			} else if is_all_digits(fname) {
				idx := dec_to_int(fname)
				if idx < 0 || idx >= positional.len {
					return s_err('cx-err:CXER2902', 'E_STRINGS_FORMAT_ARG_MISSING: positional arg ${fname} missing')
				}
				val = positional[idx]
			} else {
				val = named[fname] or {
					return s_err('cx-err:CXER2902', 'E_STRINGS_FORMAT_ARG_MISSING: named arg "${fname}" missing')
				}
			}
			rendered, errcode := format_value(val, tchar)
			if errcode != '' {
				return s_err(errcode, 'E_STRINGS_FORMAT: ${rendered}')
			}
			b.write_string(rendered)
			i = j + 1
		} else if r == `}` {
			if i + 1 < rs.len && rs[i + 1] == `}` {
				b.write_rune(`}`)
				i += 2
				continue
			}
			return s_err('cx-err:CXER2901', 'E_STRINGS_FORMAT_TEMPLATE_INVALID: unmatched "}"')
		} else {
			b.write_rune(r)
			i++
		}
	}
	return s_str(b.str())
}

fn is_all_digits(s string) bool {
	if s.len == 0 {
		return false
	}
	for c in s {
		if c < `0` || c > `9` {
			return false
		}
	}
	return true
}

// format_value renders a single CX scalar according to the optional type
// char. Returns (rendered, errcode); errcode is '' on success or a CXER
// code on type/value incompatibility. No type char → default rendering.
fn format_value(n cx.Node, tchar string) (string, string) {
	if n is cx.ScalarNode {
		v := n.value
		match tchar {
			'', 's' {
				return scalar_plain(v), ''
			}
			'd' {
				match v {
					i64 { return v.str(), '' }
					f64 { return i64(v).str(), '' }
					else { return '{:d} requires int', 'cx-err:CXER2903' }
				}
			}
			'f' {
				match v {
					i64 { return f64(v).str(), '' }
					f64 { return v.str(), '' }
					else { return '{:f} requires number', 'cx-err:CXER2903' }
				}
			}
			'x' {
				match v {
					i64 { return int_to_hex(v, false), '' }
					else { return '{:x} requires int', 'cx-err:CXER2903' }
				}
			}
			'X' {
				match v {
					i64 { return int_to_hex(v, true), '' }
					else { return '{:X} requires int', 'cx-err:CXER2903' }
				}
			}
			else {
				return 'unsupported type char', 'cx-err:CXER2901'
			}
		}
	}
	return 'non-scalar arg', 'cx-err:CXER2903'
}

fn scalar_plain(v cx.ScalarValue) string {
	match v {
		string { return v }
		i64 { return v.str() }
		f64 { return v.str() }
		bool { return v.str() }
		cx.NullValue { return 'null' }
	}
}

fn int_to_hex(v i64, upper bool) string {
	mut n := v
	mut neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	if n == 0 {
		return '0'
	}
	digits := if upper { '0123456789ABCDEF' } else { '0123456789abcdef' }
	mut out := []u8{}
	for n > 0 {
		out << digits[n % 16]
		n /= 16
	}
	out.reverse_in_place()
	mut s := out.bytestr()
	if neg {
		s = '-' + s
	}
	return s
}
