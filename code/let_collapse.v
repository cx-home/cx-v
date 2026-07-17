module code

import cx

// let_collapse.v — the #361 idiom sweep: collapse cascading nested `[?let]`
// chains into the flat multi-binding form. Flat `[?let]` IS let* (later
// bindings see earlier ones, spec/code.md §8.5), and eval_let treats the LAST
// positional slot as the body, so whenever an inner `[?let]` is the outer's
// entire body the transform is semantics-preserving:
//
//   [?let [= $a 1] [?let [= $b 2] BODY]]  →  [?let [= $a 1] [= $b 2] BODY]
//
// DESIGN — token-anchored byte surgery, never regex (the standing rule for CX
// syntax migration) and never a parse→re-emit round trip: the program LEXER
// discards comments (`# …`, `[; … ]`), so re-emitting through the program
// emitter would delete every comment in the file. Instead cx.tokenize gives
// the full token stream with byte offsets; collapse sites are located by
// bracket matching over that stream, and the edits are three kinds of
// disjoint byte deletions — the inner `[?let` opener span, the inner
// closing `]`, and (for tidiness) the excess leading indentation of the
// lines the collapse pulls up. Everything outside those bytes — comments,
// strings, formatting — is preserved verbatim. Chains collapse in ONE pass:
// each link contributes its own disjoint opener/closer deletions.
//
// FAIL-CLOSED ORACLE: the same textual transform is applied to the program's
// canonical (comment-free, deterministically formatted) form, and both
// results must parse to the SAME canonical program. A mis-fired edit — one
// that ate a bracket, fired inside a string, or disagreed about a site
// because of surrounding comments — diverges the two canonical forms and the
// whole file is rejected unchanged. (The conformance/suite gates are the
// semantic backstop on top.)

struct LetEdit {
	from int // byte offset, inclusive
	to   int // byte offset, exclusive
}

// collapse_nested_lets returns `src` with every cascading-let site collapsed,
// or an error when src does not parse as a program or the verification
// oracle rejects the rewrite. Returns src unchanged (no error) when there is
// nothing to collapse.
pub fn collapse_nested_lets(src string) !string {
	canon0 := prog_canon(src) or {
		return error('collapse-lets: input does not parse as a CX program')
	}
	out1 := collapse_lets_pass(src)!
	// Second pass: program ISLANDS inside string literals — `[fn-doc
	// [example """…"""]]` snippets are the documentation surface the
	// anti-idiom self-propagates from, and `[?def]` bodies re-parse their
	// raw source at call time. Only strings whose decoded token text is an
	// EXACT source substring (no escapes involved) are spliced; everything
	// else is left alone. The end oracle validates these rewrites too (its
	// string-token recursion re-applies the transform to the expected side).
	out := collapse_string_islands(out1)!
	if out == src {
		return src
	}
	// Oracle leg 1: the rewritten text must still be a program.
	canon_out := prog_canon(out) or {
		return error('collapse-lets: rewrite no longer parses as a program (refusing to emit)')
	}
	// Oracle leg 2: the rewrite's canonical form must be TOKEN-identical to
	// the same textual transform applied to the ORIGINAL's canonical form.
	// The emitter renders a binding clause / body identically at any nesting
	// depth, so canonical(nested) minus the inner `[?let`/`]` tokens IS the
	// token stream of canonical(flat). Comparison happens at the TOKEN level
	// (kind+text), not by re-parsing the canonical text: whitespace
	// differences are irrelevant, and — decisively — the canonical call
	// surface `name:member(args)` is not itself re-parse-stable in binding
	// position, so a text-level reparse comparison rejects perfectly good
	// files. A structural mis-edit (eaten bracket, string damage, site
	// asymmetry) still diverges the token streams and fails the file closed.
	canon_t := collapse_lets_pass(canon0)!
	toks_out := cx.tokenize(canon_out) or {
		return error('collapse-lets: rewrite canonical form does not lex (refusing to emit)')
	}
	toks_exp := cx.tokenize(canon_t) or {
		return error('collapse-lets: transformed canonical form does not lex (refusing to emit)')
	}
	verify_collapse_tokens(toks_exp, toks_out, 0)!
	return out
}

// verify_collapse_tokens compares the expected and actual canonical token
// streams. When two STRING tokens differ, the comparison descends: `[?def]`
// bodies live in the AST as verbatim raw-source strings (canonical renders
// them `[?def :raw-source "…"]`), so the source-level rewrite legitimately
// changes those strings — the descent re-applies the transform to the
// EXPECTED side's (decoded) content and compares the two contents token-wise,
// recursively. A string difference that is NOT a collapsed program (or any
// other token difference) fails the file closed. Depth-capped defensively.
fn verify_collapse_tokens(exp []cx.ProgramToken, got []cx.ProgramToken, depth int) ! {
	if depth > 8 {
		return error('collapse-lets: verification recursion too deep (refusing to emit)')
	}
	if exp.len != got.len {
		return error('collapse-lets: verification mismatch (token count ${exp.len} vs ${got.len}) (refusing to emit)')
	}
	for w in 0 .. exp.len {
		if exp[w].kind != got[w].kind {
			return error('collapse-lets: verification mismatch at token ${w} (kind) (refusing to emit)')
		}
		if exp[w].text == got[w].text {
			continue
		}
		if exp[w].kind != .string_lit {
			return error('collapse-lets: verification mismatch at token ${w} ("${exp[w].text}" vs "${got[w].text}") (refusing to emit)')
		}
		// Differing strings: valid only if the difference IS the collapse —
		// i.e. transforming the expected content yields the got content
		// (token-wise, recursively). Some def raw-source captures are not
		// independently lexable (the body boundary can split a quote-pairing
		// context — e.g. the `"…" word "…"` attribute-alternation idiom), so
		// when lexing is impossible the fallback is a byte-level check that
		// the got content is the exp content with deletions drawn ONLY from
		// the transform's edit alphabet (`[?let` openers, `]`, spaces):
		// nothing can be rewritten, reordered, or inserted.
		exp_t := collapse_lets_pass(exp[w].text) or {
			if deletion_only_match(exp[w].text, got[w].text) {
				continue
			}
			return error('collapse-lets: string content mismatch (expected side untransformable) (refusing to emit)')
		}
		exp_toks := cx.tokenize(exp_t) or {
			return error('collapse-lets: string content mismatch (expected side does not lex) (refusing to emit)')
		}
		got_toks := cx.tokenize(got[w].text) or {
			return error('collapse-lets: string content mismatch (actual side does not lex) (refusing to emit)')
		}
		verify_collapse_tokens(exp_toks, got_toks, depth + 1)!
	}
}

// collapse_lets_pass performs one full textual pass: locate every collapse
// site in the token stream and apply all (disjoint) deletions.
fn collapse_lets_pass(src string) !string {
	toks := cx.tokenize(src)!
	if toks.len == 0 {
		return src
	}
	// Bracket matching over the [-family. lparen/lbrace nest independently
	// but share the one stack: each closer must match its opener's family,
	// which also guards against applying edits to malformed streams.
	// NOTE the lexer's directive encoding: `[?name` is ONE token — kind
	// `.directive_name`, text = the bare name, pos at the `[` — so the
	// directive opener is a bracket OPENER in its own right (the parser's
	// depth walks treat it identically), and its byte span is
	// `[?` + name = pos.offset .. pos.offset + 2 + text.len.
	mut match_idx := []int{len: toks.len, init: -1}
	mut stack := []int{}
	for i, t in toks {
		match t.kind {
			.lbrack, .ldirective, .directive_name, .lparen, .lbrace {
				stack << i
			}
			.rbrack, .rparen, .rbrace {
				if stack.len == 0 {
					return src // malformed; leave untouched
				}
				oi := stack.pop()
				ok := (t.kind == .rbrack
					&& (toks[oi].kind == .lbrack || toks[oi].kind == .ldirective
					|| toks[oi].kind == .directive_name))
					|| (t.kind == .rparen && toks[oi].kind == .lparen)
					|| (t.kind == .rbrace && toks[oi].kind == .lbrace)
				if !ok {
					return src // family mismatch; leave untouched
				}
				match_idx[oi] = i
			}
			else {}
		}
	}
	if stack.len != 0 {
		return src
	}
	mut edits := []LetEdit{}
	mut dedent_by_line := map[int]int{}
	for i, t in toks {
		if t.kind != .directive_name || t.text != 'let' {
			continue
		}
		closer := match_idx[i]
		if closer < 0 {
			continue
		}
		// Top-level children of this let: token index of each item start.
		children := let_child_items(toks, match_idx, i + 1, closer)
		if children.len == 0 {
			continue
		}
		last := children[children.len - 1]
		// The body (last child) must itself be a `[?let …]`.
		if toks[last].kind != .directive_name || toks[last].text != 'let' {
			continue
		}
		// Every preceding child must be a `[= …]` binding clause. Positionally
		// the collapse would preserve even a malformed child's meaning
		// (eval_let's binding-vs-body split is purely positional and
		// concatenation keeps every child's position class), but a let whose
		// non-binding first child survives to CANONICAL form re-parses
		// through parse_let_body's `[`-first-child gate — i.e. such programs
		// are not canonical-round-trip-stable and the oracle cannot vouch
		// for them. Well-formed-only keeps the oracle sound.
		mut all_bindings := true
		for ci in 0 .. children.len - 1 {
			cidx := children[ci]
			if toks[cidx].kind != .lbrack || cidx + 1 >= toks.len
				|| toks[cidx + 1].kind != .eq {
				all_bindings = false
				break
			}
		}
		if !all_bindings {
			continue
		}
		inner_closer := match_idx[last]
		if inner_closer < 0 {
			continue
		}
		// Same check for the INNER let's binding prefix (its last child — the
		// body — may be any expression).
		inner_children := let_child_items(toks, match_idx, last + 1, inner_closer)
		if inner_children.len == 0 {
			continue
		}
		mut inner_ok := true
		for ci in 0 .. inner_children.len - 1 {
			cidx := inner_children[ci]
			if toks[cidx].kind != .lbrack || cidx + 1 >= toks.len
				|| toks[cidx + 1].kind != .eq {
				inner_ok = false
				break
			}
		}
		if !inner_ok {
			continue
		}
		// Site accepted. Delete the inner opener (the single `[?let` token
		// spans `[?` + name, plus the single following space when present,
		// so `[?let [= …` collapses to `[= …` and not ` [= …`) and the
		// inner closing `]`.
		mut open_to := toks[last].pos.offset + 2 + toks[last].text.len
		if open_to < src.len && src[open_to] == ` ` {
			open_to++
		}
		edits << LetEdit{
			from: toks[last].pos.offset
			to:   open_to
		}
		edits << LetEdit{
			from: toks[inner_closer].pos.offset
			to:   toks[inner_closer].pos.offset + 1
		}
		// Tidiness: dedent the pulled-up lines by the indentation delta
		// between the inner and outer openers, so collapsed chains read as
		// the flat idiom instead of a staircase. Only leading SPACES on
		// lines that (a) start strictly after the inner opener's line,
		// (b) start before the inner closer, and (c) do not start inside a
		// string/raw token, are touched. Requests are accumulated per line
		// and merged AFTER the site loop: in a chain, the innermost lines
		// receive one delta from every enclosing site, and the merged total
		// is exactly the cumulative dedent that lines them up with the
		// outermost binding column. Any slip is caught by the oracle
		// (indentation inside a string/raw literal changes the canonical
		// program form).
		delta := toks[last].pos.col - t.pos.col
		if delta > 0 {
			collect_dedents(src, toks[last].pos, toks[inner_closer].pos.offset, delta, mut
				dedent_by_line)
		}
	}
	if edits.len == 0 {
		return src
	}
	// Materialise the merged per-line dedents as ordinary deletions (capped
	// by the spaces actually present, skipping lines that begin inside a
	// multi-line string/raw token).
	for line_start, delta in dedent_by_line {
		if offset_inside_multiline_token(toks, line_start) {
			continue
		}
		mut n := 0
		for n < delta && line_start + n < src.len && src[line_start + n] == ` ` {
			n++
		}
		if n > 0 {
			edits << LetEdit{
				from: line_start
				to:   line_start + n
			}
		}
	}
	return apply_deletions(src, mut edits)
}

// collect_dedents adds `delta` to every qualifying line-start between the
// inner opener and the inner closer (merged per line by the caller's map).
fn collect_dedents(src string, inner_open cx.Position, inner_close_off int, delta int, mut acc map[int]int) {
	mut off := inner_open.offset
	for off < src.len && src[off] != `\n` {
		off++
	}
	for off < src.len && off < inner_close_off {
		line_start := off + 1
		if line_start >= src.len || line_start >= inner_close_off {
			break
		}
		acc[line_start] = acc[line_start] + delta
		off = line_start
		for off < src.len && src[off] != `\n` {
			off++
		}
	}
}

// let_child_items returns the token index of each top-level item between
// `from` (first token after the let's name) and `closer` (the let's matching
// rbrack), skipping over nested bracket groups.
fn let_child_items(toks []cx.ProgramToken, match_idx []int, from int, closer int) []int {
	mut items := []int{}
	mut j := from
	for j < closer {
		items << j
		k := toks[j].kind
		if k == .lbrack || k == .ldirective || k == .directive_name || k == .lparen
			|| k == .lbrace {
			mj := match_idx[j]
			if mj < 0 || mj >= closer {
				return items // malformed / unmatched inside; caller checks shapes
			}
			j = mj + 1
		} else {
			// Atom item. Absorb the token runs that the expression grammar
			// binds into one expr, so an item is never split into fragments
			// that would land in the "binding prefix" slice: `$` + name,
			// qname continuations `:member` (the canonical emitter renders
			// `[$journal:read …]` as `journal:read(…)`), then any ADJACENT
			// call-paren group. Adjacency by byte offset mirrors the call
			// surface; a space-separated `( … )` / ` :label` is a distinct
			// item and stays one.
			if k == .dollar && j + 1 < closer && toks[j + 1].kind == .ident
				&& toks[j + 1].pos.offset == token_end(toks[j]) {
				j += 2
			} else {
				j++
			}
			// qname tail: ident ( ':' ident )* — all adjacent.
			for j + 1 < closer && toks[j].kind == .colon
				&& toks[j].pos.offset == token_end(toks[j - 1])
				&& toks[j + 1].kind == .ident
				&& toks[j + 1].pos.offset == token_end(toks[j]) {
				j += 2
			}
			for j < closer && toks[j].kind == .lparen
				&& toks[j].pos.offset == token_end(toks[j - 1]) {
				mj := match_idx[j]
				if mj < 0 || mj >= closer {
					return items
				}
				j = mj + 1
			}
		}
		// A postfix `!` / `?` immediately after an item belongs to it.
		for j < closer && (toks[j].kind == .bang || toks[j].kind == .qmark) {
			j++
		}
	}
	return items
}

// token_end returns the byte offset one past a token's SOURCE span. For the
// directive opener the span is `[?` + name; for other multi-byte tokens the
// text length is the span length except string/raw spans — which never
// precede an adjacency check here (a call-paren cannot be adjacent to a
// string in the grammar), so text.len is sufficient.
fn token_end(t cx.ProgramToken) int {
	if t.kind == .directive_name {
		return t.pos.offset + 2 + t.text.len
	}
	return t.pos.offset + t.text.len
}

// offset_inside_multiline_token reports whether `off` falls strictly inside
// (or in the shadow of) a string/raw span — the multi-line token kinds whose
// interior a dedent must never touch. A string token's `text` is not a
// reliable SOURCE-span length (quotes/escapes), so the containment test is
// deliberately conservative: if the last token starting at-or-before `off`
// is a string/raw span and `off` lies strictly after its start but before
// the NEXT token's start, the line is skipped. That shadow includes any
// whitespace/comments trailing the literal — skipping a dedent there is
// merely cosmetic, while dedenting inside a literal would change program
// meaning (and be rejected wholesale by the oracle).
fn offset_inside_multiline_token(toks []cx.ProgramToken, off int) bool {
	for w, t in toks {
		start := t.pos.offset
		if start >= off {
			return false // tokens are in source order; past it
		}
		if t.kind == .string_lit || t.kind == .data_span {
			next_start := if w + 1 < toks.len { toks[w + 1].pos.offset } else { 2147483647 }
			if off > start && off < next_start {
				return true
			}
		}
	}
	return false
}

// apply_deletions splices all edits (deletions) out of src. Edits must be
// pairwise disjoint; they are applied in descending offset order.
fn apply_deletions(src string, mut edits []LetEdit) string {
	edits.sort(a.from > b.from)
	// Disjointness guard: overlapping edits mean a logic error upstream —
	// bail out unchanged rather than emit a corrupted splice (the oracle
	// would also catch it, but never rely on one net).
	for w in 1 .. edits.len {
		if edits[w].to > edits[w - 1].from {
			return src
		}
	}
	mut out := src
	for e in edits {
		out = out[..e.from] + out[e.to..]
	}
	return out
}

// collapse_nested_lets_md rewrites cascading-let sites inside the ```cx
// fenced blocks of a Markdown document (spec/docs surfaces). Fence
// detection is line-structural; the block CONTENT goes through the same
// token-anchored transform. A block that parses as a full program gets the
// complete oracle (collapse_nested_lets); a partial snippet that does not
// parse standalone still gets the tokenize-level transform, whose
// balanced-bracket / disjoint-edit guards leave anything questionable
// untouched.
pub fn collapse_nested_lets_md(src string) !string {
	// Byte-span splicing, not split/join reconstruction: only the CONTENT
	// region of each ```cx fence is replaced; every byte outside — prose,
	// other fences, trailing blank lines — stays verbatim (a join-based
	// rebuild silently dropped a spec file's final empty line).
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
			collapsed := collapse_nested_lets(body) or {
				collapse_lets_pass(body) or {
					// Unlexable ```cx fence: report it — a silently-skipped
					// block is how invalid `;`-annotated doc examples hid
					// their cascades from the first sweep.
					if body.contains('?let') {
						eprintln('collapse-lets: SKIPPED unlexable cx fence (contains ?let): ${err}')
					}
					body
				}
			}
			if collapsed != body {
				froms << content_from
				tos << if line_start > content_from { line_start - 1 } else { content_from }
				repl << collapsed
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

// deletion_only_match reports whether `got` equals `exp` after deleting only
// bytes the collapse transform is allowed to remove: whole `[?let` opener
// sequences, `]` closers, and spaces. Runs of a deletable byte are consumed
// as a unit (got may keep at most as many as exp had — deletions only), which
// resolves the match-vs-delete ambiguity without backtracking.
fn deletion_only_match(exp string, got string) bool {
	mut i := 0
	mut j := 0
	for i < exp.len {
		// `[?let` in exp that got does not have at this point: deletable unit.
		if i + 5 <= exp.len && exp[i..i + 5] == '[?let'
			&& !(j + 5 <= got.len && got[j..j + 5] == '[?let') {
			i += 5
			continue
		}
		c := exp[i]
		if c == ` ` || c == `]` {
			// consume the whole run on both sides; got's run must not exceed exp's
			mut ei := i
			for ei < exp.len && exp[ei] == c {
				ei++
			}
			mut gj := j
			for gj < got.len && got[gj] == c {
				gj++
			}
			if gj - j > ei - i {
				return false
			}
			i = ei
			j = gj
			continue
		}
		if j >= got.len || got[j] != c {
			return false
		}
		i++
		j++
	}
	return j == got.len
}

// collapse_string_islands rewrites cascading-let sites inside string
// literals whose content is embedded CX source (doc examples, def bodies
// quoted in fixtures). Safety gate: the token's DECODED text must equal the
// raw source bytes between the quote delimiters exactly — any escape
// sequence breaks that equality and the string is skipped — so the splice
// window is known precisely and the rewrite (pure deletions) cannot create
// a delimiter. Content that does not tokenize, or has no sites, passes
// through untouched.
fn collapse_string_islands(src string) !string {
	toks := cx.tokenize(src)!
	mut froms := []int{}
	mut tos := []int{}
	mut repl := []string{}
	for t in toks {
		if t.kind != .string_lit || t.text.len == 0 {
			continue
		}
		if !t.text.contains('?let') {
			continue
		}
		off := t.pos.offset
		if off >= src.len {
			continue
		}
		q := src[off]
		if q != `"` && q != `'` {
			continue
		}
		mut delim := 1
		if off + 2 < src.len && src[off + 1] == q && src[off + 2] == q {
			delim = 3
		}
		content_from := off + delim
		content_to := content_from + t.text.len
		if content_to + delim > src.len {
			continue
		}
		if src[content_from..content_to] != t.text {
			continue // escapes in play; decoded != raw — skip
		}
		mut delim_ok := true
		for d in 0 .. delim {
			if src[content_to + d] != q {
				delim_ok = false
				break
			}
		}
		if !delim_ok {
			continue
		}
		collapsed := collapse_lets_pass(t.text) or { continue }
		if collapsed == t.text {
			continue
		}
		froms << content_from
		tos << content_to
		repl << collapsed
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

// collapse_nested_lets_cxd applies the collapse to every `[in-code [#…#]]`
// raw PROGRAM block of a .cxd conformance-fixture document, leaving every
// other byte of the file verbatim — `[in-cx …]` blocks carry the case's input
// DOCUMENT (which parse/AST expectations echo byte-for-byte, so a `[?let`
// appearing there is test DATA and must not move), and the `[out-…]` blocks
// are the expected outputs. The .cxd container itself is located via the same
// token stream (raw spans are single `data_span` tokens carrying exact
// offsets), so no text matching is involved.
pub fn collapse_nested_lets_cxd(src string) !string {
	toks := cx.tokenize(src)!
	mut edits_from := []int{}
	mut edits_to := []int{}
	mut repl := []string{}
	for i, t in toks {
		// shape: `[` `in-code` `[#…#]`
		if t.kind != .data_span || i < 2 {
			continue
		}
		if toks[i - 1].kind != .ident || toks[i - 1].text != 'in-code' {
			continue
		}
		if toks[i - 2].kind != .lbrack {
			continue
		}
		raw := t.text // includes the `[#` … `#]` delimiters
		if raw.len < 4 || !raw.starts_with('[#') || !raw.ends_with('#]') {
			continue
		}
		body := raw[2..raw.len - 2]
		collapsed := collapse_nested_lets(body) or {
			// A fixture program that deliberately does not parse (error-case
			// fixtures) is left untouched.
			continue
		}
		if collapsed == body {
			continue
		}
		edits_from << t.pos.offset
		edits_to << t.pos.offset + raw.len
		repl << '[#' + collapsed + '#]'
	}
	if repl.len == 0 {
		return src
	}
	mut out := src
	for w := repl.len - 1; w >= 0; w-- {
		out = out[..edits_from[w]] + repl[w] + out[edits_to[w]..]
	}
	return out
}
