module code

// predicate_migrate.v — the #110 predicate-surface cutover sweep: rewrite
// the RETIRED CXPath predicate sublanguage (grammar [132]–[134]) to the
// homoiconic prefix form ([159]).
//
//   [@a=v]            → [= $_@a v]        (any of = != < <= > >=)
//   [$_@a OP v]       → [OP $_@a v]
//   [$_position OP x] → [OP $_position x] (likewise $_last)
//   [last()]          → [= $_position $_last]
//   [count(*)]        → [> [$count $_/*] 0]
//   [count(*) OP N]   → [OP [$count $_/*] N]
//   [A and B], [A or B] over the atoms above
//                     → [and A' B'] / [or A' B'] (operands bracketed)
//
// The operator-free notation atoms (`[N]`, `[@name]`, `[@!name]`,
// `[name]`, `[@name::T]`) and every already-canonical body are left
// byte-identical.
//
// DESIGN — same discipline as let_collapse.v (#361): character-anchored
// byte surgery, never regex, and fail-closed. A predicate-shaped bracket
// is one whose `[` is byte-adjacent to a path step (previous byte is a
// name character, `]`, `*`, or a `$`-binding path); its body is matched
// against the CLOSED retired-template set above. A body that looks
// retired but does not fit any template is a hard per-file error (manual
// fix), never a silent skip. ORACLE: the rewritten file must parse as a
// CX program (prog_canon); any mis-fire rejects the whole file unchanged.

struct PredEdit {
	from int    // byte offset of body start (after '['), inclusive
	to   int    // byte offset of body end (at ']'), exclusive
	repl string // replacement body
}

// migrate_predicates rewrites every retired predicate body in a CX
// program source, or returns src unchanged when none are present.
pub fn migrate_predicates(src string) !string {
	edits := scan_pred_edits(src)!
	if edits.len == 0 {
		return src
	}
	mut out := src
	for w := edits.len - 1; w >= 0; w-- {
		e := edits[w]
		out = out[..e.from] + e.repl + out[e.to..]
	}
	// Fail-closed oracle: the rewritten text must parse as a CX program.
	prog_canon(out) or {
		return error('migrate-predicates: rewrite no longer parses as a program (refusing to emit): ${err}')
	}
	return out
}

// scan_pred_edits walks the source with a quote/comment-aware cursor,
// finds predicate-shaped brackets, and produces the retired-template
// rewrites. Errors on a retired-looking body that fits no template.
fn scan_pred_edits(src string) ![]PredEdit {
	return scan_pred_edits_mode(src, false)!
}

// scan_pred_edits_mode — `lenient` mode (fence/island scanning) logs and
// skips an unmappable body instead of failing the whole scan: .cxd raw
// blocks legitimately embed non-CX text. The conformance lanes are the
// semantic backstop — a genuinely retired predicate in a PROGRAM island
// that slips a lenient scan still fails its lane at parse time.
fn scan_pred_edits_mode(src string, lenient bool) ![]PredEdit {
	mut edits := []PredEdit{}
	s := src.bytes()
	mut i := 0
	for i < s.len {
		c := s[i]
		// Skip string literals (\'..\' and ".." with backslash escapes).
		if c == `"` || c == `'` {
			q := c
			i++
			for i < s.len && s[i] != q {
				if s[i] == `\\` && i + 1 < s.len {
					i += 2
					continue
				}
				i++
			}
			i++
			continue
		}
		// Skip `[# … #]` raw blocks verbatim (block comments / raw text) —
		// their contents (apostrophes, brackets) must not perturb the
		// quote/bracket state.
		if c == `[` && i + 1 < s.len && s[i + 1] == `#` {
			i += 2
			for i + 1 < s.len && !(s[i] == `#` && s[i + 1] == `]`) {
				i++
			}
			i += 2
			continue
		}
		// Skip `#` line comments (start of line or after whitespace).
		if c == `#` && (i == 0 || s[i - 1] == ` ` || s[i - 1] == `\t` || s[i - 1] == `\n`) {
			for i < s.len && s[i] != `\n` {
				i++
			}
			continue
		}
		if c == `[` && i > 0 && is_pred_anchor_byte(s[i - 1]) {
			body_from := i + 1
			body_to := match_bracket(s, i) or {
				return error('migrate-predicates: unbalanced bracket at byte ${i}')
			}
			body := src[body_from..body_to]
			if repl := rewrite_retired_body(body) {
				if repl != body {
					edits << PredEdit{ from: body_from, to: body_to, repl: repl }
				}
			} else {
				if lenient {
					eprintln('migrate-predicates: SKIPPED island body `${body.trim_space()}`: ${err}')
				} else {
					return error('migrate-predicates: predicate body `${body.trim_space()}` looks retired but fits no rewrite template — fix manually: ${err}')
				}
			}
			// continue scanning INSIDE the body too (nested predicates).
			i = body_from
			continue
		}
		i++
	}
	return edits
}

// is_pred_anchor_byte reports whether a byte can END a path step — the
// byte-adjacency rule that distinguishes `step[pred]` from a separate
// bracket operand ([131]/[135]).
fn is_pred_anchor_byte(b u8) bool {
	return (b >= `a` && b <= `z`) || (b >= `A` && b <= `Z`)
	    || (b >= `0` && b <= `9`) || b == `_` || b == `-`
	    || b == `]` || b == `*`
}

// match_bracket returns the offset of the `]` matching the `[` at
// `open`, respecting nested brackets and quoted strings.
fn match_bracket(s []u8, open int) ?int {
	mut depth := 0
	mut i := open
	for i < s.len {
		c := s[i]
		if c == `[` && i + 1 < s.len && s[i + 1] == `#` {
			i += 2
			for i + 1 < s.len && !(s[i] == `#` && s[i + 1] == `]`) {
				i++
			}
			i += 2
			continue
		}
		if c == `"` || c == `'` {
			q := c
			i++
			for i < s.len && s[i] != q {
				if s[i] == `\\` && i + 1 < s.len {
					i += 2
					continue
				}
				i++
			}
			i++
			continue
		}
		if c == `[` {
			depth++
		} else if c == `]` {
			depth--
			if depth == 0 {
				return i
			}
		}
		i++
	}
	return none
}

// ── retired-template recognizer / rewriter ────────────────────────────

// rewrite_retired_body maps ONE predicate body through the retired-
// template table. Returns the body unchanged when it is not a retired
// form (notation atoms, canonical prefix bodies, slices, directives).
// Errors when the body is retired-shaped but unmappable.
fn rewrite_retired_body(body string) !string {
	t := body.trim_space()
	if t.len == 0 {
		return body
	}
	// Fast outs: canonical/notation shapes are never touched.
	// - directive / fused prefix form / nested element: starts with `?`,
	//   a reserved operator token, or `[`.
	// - binding / path EBV: starts with `$` and carries no infix tail.
	// - notation atoms: INT, @name, @!name, @name::T, bare step name.
	if t.starts_with('?') || t.starts_with('[') {
		return body
	}
	if is_retired_free(t) {
		return body
	}
	// Top-level infix `or` / `and` split (or = lowest precedence).
	if parts := split_top_level_word(t, 'or') {
		return rejoin_connective('or', parts)!
	}
	if parts := split_top_level_word(t, 'and') {
		return rejoin_connective('and', parts)!
	}
	// Single retired atom → prefix body (unbracketed, fused form).
	return rewrite_retired_atom_body(t)!
}

// is_retired_free reports whether the body contains none of the retired
// markers (infix comparison outside quotes, paren-call, infix
// connectives) — such bodies are already canonical and stay untouched.
fn is_retired_free(t string) bool {
	s := t.bytes()
	// A body opening with a reserved word/symbol operator or `$fn ` is a
	// fused form; its INTERIOR may legitimately contain `=` (named args,
	// nested attr syntax is gone, but attr constructors `name=`)…
	// Conservative rule: fused/branded openers are canonical.
	for w in ['and ', 'or ', 'not ', 'cast ', 'union ', 'intersect ', 'except ',
		'= ', '!= ', '< ', '<= ', '> ', '>= ', '+ ', '- ', '* ', '/ '] {
		if t.starts_with(w) {
			return true
		}
	}
	if t.starts_with('$') {
		// `$…` EBV or fused call — retired only when an infix tail
		// follows the leading binding/path token.
		return !has_top_level_infix_tail(s)
	}
	mut i := 0
	mut has_marker := false
	for i < s.len {
		c := s[i]
		if c == `"` || c == `'` {
			q := c
			i++
			for i < s.len && s[i] != q {
				if s[i] == `\\` && i + 1 < s.len {
					i += 2
					continue
				}
				i++
			}
			i++
			continue
		}
		if c == `=` || c == `<` || c == `>` || c == `(` {
			// `::` type annotations pass (@name::T); `!=` caught via `=`.
			has_marker = true
			break
		}
		if (c == `a` || c == `o`) && i > 0 && s[i - 1] == ` ` {
			rest := t[i..]
			if rest.starts_with('and ') || rest.starts_with('or ') {
				has_marker = true
				break
			}
		}
		i++
	}
	return !has_marker
}

// has_top_level_infix_tail reports whether a `$…`-leading body carries
// an infix operator / connective after its first whitespace gap.
fn has_top_level_infix_tail(s []u8) bool {
	mut i := 0
	// consume the leading binding/path token (no spaces inside).
	for i < s.len && s[i] != ` ` && s[i] != `\t` {
		i++
	}
	for i < s.len && (s[i] == ` ` || s[i] == `\t`) {
		i++
	}
	if i >= s.len {
		return false
	}
	c := s[i]
	if c == `=` || c == `<` || c == `>` || c == `!` {
		return true
	}
	rest := s[i..].bytestr()
	return rest.starts_with('and ') || rest.starts_with('or ')
}

// split_top_level_word splits `t` on the FIRST top-level ` word ` hit
// (outside quotes/brackets), returning the two sides; none when absent.
fn split_top_level_word(t string, word string) ?([]string) {
	s := t.bytes()
	needle := ' ${word} '
	mut i := 0
	mut depth := 0
	for i < s.len {
		c := s[i]
		if c == `"` || c == `'` {
			q := c
			i++
			for i < s.len && s[i] != q {
				if s[i] == `\\` && i + 1 < s.len {
					i += 2
					continue
				}
				i++
			}
			i++
			continue
		}
		if c == `[` || c == `(` {
			depth++
		} else if c == `]` || c == `)` {
			depth--
		} else if depth == 0 && c == ` ` && i + needle.len <= s.len
		   && t[i..i + needle.len] == needle {
			return [t[..i], t[i + needle.len..]]
		}
		i++
	}
	return none
}

// rejoin_connective rewrites `A <word> B` into the fused prefix
// connective `word A' B'` where each operand becomes a BRACKETED
// canonical expression.
fn rejoin_connective(word string, parts []string) !string {
	left := rewrite_operand_expr(parts[0].trim_space())!
	right := rewrite_operand_expr(parts[1].trim_space())!
	return '${word} ${left} ${right}'
}

// rewrite_operand_expr maps one infix operand to a bracketed canonical
// expression (operand position inside a fused connective).
fn rewrite_operand_expr(t string) !string {
	// Nested connective (right-associative split already applied by
	// caller order: or → and).
	if parts := split_top_level_word(t, 'or') {
		inner := rejoin_connective('or', parts)!
		return '[${inner}]'
	}
	if parts := split_top_level_word(t, 'and') {
		inner := rejoin_connective('and', parts)!
		return '[${inner}]'
	}
	body := rewrite_retired_atom_body(t) or {
		// Not a retired atom: existence tests & already-canonical
		// operands get wrapped/kept.
		if t.starts_with('@!') {
			return '[not [\$exists \$_@${t[2..]}]]'
		}
		if t.starts_with('@') && is_plain_name(t[1..]) {
			return '[\$exists \$_@${t[1..]}]'
		}
		if t.starts_with('[') {
			return t
		}
		return error('operand `${t}` fits no template')
	}
	return '[${body}]'
}

// rewrite_retired_atom_body maps one retired ATOM to its prefix body
// (fused form, unbracketed). Errors when it fits no template.
fn rewrite_retired_atom_body(t string) !string {
	// `last()` → `= $_position $_last`
	if t == 'last()' {
		return '= \$_position \$_last'
	}
	// `count(*)` [OP N]
	if t.starts_with('count(') {
		rest := t[6..].trim_space()
		if rest.starts_with('*)') {
			tail := rest[2..].trim_space()
			if tail.len == 0 {
				return '> [\$count \$_/*] 0'
			}
			op, rhs := split_leading_op(tail) or {
				return error('count(*) tail `${tail}` fits no template')
			}
			return '${op} [\$count \$_/*] ${rhs}'
		}
		return error('paren-call `${t}` fits no template')
	}
	// `@name OP value` / `@name` handled at is_retired_free; here the
	// compare form:
	if t.starts_with('@') {
		mut j := 1
		s := t.bytes()
		for j < s.len && is_name_byte(s[j]) {
			j++
		}
		if j == 1 {
			return error('malformed attribute test `${t}`')
		}
		name := t[1..j]
		tail := t[j..].trim_space()
		if tail.len == 0 {
			return t // bare existence — notation, untouched
		}
		op, rhs := split_leading_op(tail) or {
			return error('attribute body `${t}` fits no template')
		}
		return '${op} \$_@${name} ${rhs}'
	}
	// `$_@name OP v` / `$_position OP x` / `$_last OP x` / `$binding OP v`
	if t.starts_with('$') {
		mut j := 0
		s := t.bytes()
		for j < s.len && s[j] != ` ` && s[j] != `\t` {
			j++
		}
		lhs := t[..j]
		tail := t[j..].trim_space()
		if tail.len == 0 {
			return t // plain EBV — canonical
		}
		op, rhs := split_leading_op(tail) or {
			return error('binding body `${t}` fits no template')
		}
		return '${op} ${lhs} ${rhs}'
	}
	return error('body `${t}` fits no template')
}

// split_leading_op peels a leading comparison operator off `tail`,
// returning (op, rhs). none when tail does not start with one.
fn split_leading_op(tail string) ?(string, string) {
	for op in ['!=', '<=', '>=', '=', '<', '>'] {
		if tail.starts_with(op) {
			rhs := tail[op.len..].trim_space()
			if rhs.len == 0 {
				return none
			}
			return op, rhs
		}
	}
	return none
}

fn is_name_byte(b u8) bool {
	return (b >= `a` && b <= `z`) || (b >= `A` && b <= `Z`)
	    || (b >= `0` && b <= `9`) || b == `_` || b == `-`
}

fn is_plain_name(t string) bool {
	if t.len == 0 {
		return false
	}
	for b in t.bytes() {
		if !is_name_byte(b) {
			return false
		}
	}
	return true
}

// ── fence / fixture wrappers (mirror let_collapse) ───────────────────

// migrate_predicates_md rewrites retired predicates inside ```cx fences
// of a markdown file; every byte outside the fence contents is verbatim.
pub fn migrate_predicates_md(src string) !string {
	mut froms := []int{}
	mut tos := []int{}
	mut repl := []string{}
	mut off := 0
	mut in_cx := false
	mut content_from := 0
	for off <= src.len {
		line_start := off
		mut line_end := off
		for line_end < src.len && src[line_end] != `\n` {
			line_end++
		}
		line := src[line_start..line_end]
		trimmed := line.trim_space()
		if !in_cx {
			if trimmed.starts_with('```') && trimmed.trim_left('`').trim_space() == 'cx' {
				in_cx = true
				content_from = if line_end < src.len { line_end + 1 } else { src.len }
			}
		} else if trimmed.starts_with('```') {
			in_cx = false
			body := if line_start > content_from { src[content_from..line_start - 1] } else { '' }
			migrated := migrate_fence_body(body) or {
				eprintln('migrate-predicates: SKIPPED unmigratable cx fence: ${err}')
				body
			}
			if migrated != body {
				froms << content_from
				tos << if line_start > content_from { line_start - 1 } else { content_from }
				repl << migrated
			}
		}
		if line_end >= src.len {
			break
		}
		off = line_end + 1
	}
	if repl.len == 0 {
		return src
	}
	mut out := src
	for w := repl.len - 1; w >= 0; w-- {
		out = out[..froms[w]] + repl[w] + out[tos[w]..]
	}
	return out
}

// migrate_fence_body applies the edit scan without the whole-program
// oracle (fences are often single snippets, not complete programs) —
// each fence must still lex bracket-balanced or it is skipped loudly.
fn migrate_fence_body(body string) !string {
	edits := scan_pred_edits_mode(body, true)!
	if edits.len == 0 {
		return body
	}
	mut out := body
	for w := edits.len - 1; w >= 0; w-- {
		e := edits[w]
		out = out[..e.from] + e.repl + out[e.to..]
	}
	return out
}

// migrate_predicates_cxd rewrites retired predicates in a .cxd fixture
// document. Fixture program sources live inside `[#…#]` raw blocks
// (and, for binding-API fixtures, inside double-quoted strings within
// those blocks), so the pass is island-aware: each raw-block interior
// is scanned directly, then its quoted-string islands are scanned too
// (exact-splice — a string containing escapes is left alone). Bytes
// outside raw blocks are untouched.
pub fn migrate_predicates_cxd(src string) !string {
	s := src.bytes()
	mut froms := []int{}
	mut tos := []int{}
	mut repl := []string{}
	mut i := 0
	for i + 1 < s.len {
		if s[i] == `[` && s[i + 1] == `#` {
			from := i + 2
			mut j := from
			for j + 1 < s.len && !(s[j] == `#` && s[j + 1] == `]`) {
				j++
			}
			if j + 1 >= s.len {
				break
			}
			interior := src[from..j]
			mut out := migrate_fence_body(interior)!
			out = migrate_string_islands(out)!
			if out != interior {
				froms << from
				tos << j
				repl << out
			}
			i = j + 2
			continue
		}
		i++
	}
	if repl.len == 0 {
		return src
	}
	mut out := src
	for w := repl.len - 1; w >= 0; w-- {
		out = out[..froms[w]] + repl[w] + out[tos[w]..]
	}
	return out
}

// migrate_string_islands applies the retired-template scan to the
// content of double/single-quoted strings (binding-API call fixtures
// quote their select paths). Escape-bearing strings are skipped — the
// splice window must be the exact raw bytes between the delimiters.
fn migrate_string_islands(src string) !string {
	s := src.bytes()
	mut froms := []int{}
	mut tos := []int{}
	mut repl := []string{}
	mut i := 0
	for i < s.len {
		c := s[i]
		if c == `"` || c == `'` {
			q := c
			from := i + 1
			mut j := from
			mut has_escape := false
			for j < s.len && s[j] != q {
				if s[j] == `\\` {
					has_escape = true
					j += 2
					continue
				}
				j++
			}
			if j >= s.len {
				break
			}
			if !has_escape && j > from {
				interior := src[from..j]
				out := migrate_fence_body(interior) or { interior }
				if out != interior {
					froms << from
					tos << j
					repl << out
				}
			}
			i = j + 1
			continue
		}
		i++
	}
	if repl.len == 0 {
		return src
	}
	mut out := src
	for w := repl.len - 1; w >= 0; w-- {
		out = out[..froms[w]] + repl[w] + out[tos[w]..]
	}
	return out
}
