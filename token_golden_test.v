module cx

// token_golden_test.v — golden token-stream tests for the cx-native data
// tokenizer (Phase 2 of the cxparse unification, trust harness §5.5). As each
// reader migrates to token-emitting form (lex_*), a golden case here asserts the
// exact (kind, byte range, source slice) so the lexer is independently trusted —
// not just validated transitively through `parse`.
//
// In-module (`module cx`) so it can drive the private Parser + lex_* readers.

// helper: lex one name token at the start of `src` and return it.
fn lex_one_name(src string) ?Token {
	mut p := new_parser(src)
	return p.lex_name()
}

fn test_lex_name_basic() {
	t := lex_one_name('hello world') or {
		assert false, 'expected a name token'
		return
	}
	assert t.kind == .name
	assert t.pos.offset == 0
	assert t.pos.line == 1
	assert t.pos.col == 1
	assert t.end == 5
	mut p := new_parser('hello world')
	assert p.src[t.pos.offset..t.end].bytestr() == 'hello'
}

// Data-mode names FOLD `.` and `:` (is_name_char) — the pinned name-char fork.
fn test_lex_name_folds_dot_and_colon() {
	t := lex_one_name('a.b:c rest') or {
		assert false, 'expected a name token'
		return
	}
	assert t.kind == .name
	assert t.end == 5 // 'a.b:c'
	mut p := new_parser('a.b:c rest')
	assert p.src[t.pos.offset..t.end].bytestr() == 'a.b:c'
}

// A glued `::` type-label separator STOPS the name run (so `port::u16` →
// name `port`). A single `:` is still consumed (above).
fn test_lex_name_stops_at_glued_double_colon() {
	t := lex_one_name('port::u16') or {
		assert false, 'expected a name token'
		return
	}
	assert t.end == 4 // 'port', not 'port::u16'
	mut p := new_parser('port::u16')
	assert p.src[t.pos.offset..t.end].bytestr() == 'port'
}

// Empty run (cursor at a non-name byte) → none.
fn test_lex_name_empty_is_none() {
	if _ := lex_one_name('  x') {
		assert false, 'leading space is not a name start; expected none'
	}
}

// The legacy read_name API must return the interned span byte-identically —
// proves the delegation (read_name -> lex_name -> intern) is behavior-stable.
fn test_read_name_delegates_identically() {
	mut p := new_parser('alpha.beta:gamma tail')
	got := p.read_name() or {
		assert false, 'read_name should succeed'
		return
	}
	assert got == 'alpha.beta:gamma'
}

// helper: lex one value_run at the start of `src`.
fn lex_one_value(src string) ?Token {
	mut p := new_parser(src)
	return p.lex_value_run()
}

fn slice(src string, t Token) string {
	mut p := new_parser(src)
	return p.src[t.pos.offset..t.end].bytestr()
}

fn test_lex_value_run_basic_terminators() {
	// terminated by whitespace
	t1 := lex_one_value('8080 next') or {
		assert false, 'expected value_run'
		return
	}
	assert t1.kind == .value_run
	assert slice('8080 next', t1) == '8080'
	// terminated by `]`
	t2 := lex_one_value('1.5]') or {
		assert false, 'expected value_run'
		return
	}
	assert slice('1.5]', t2) == '1.5'
}

// A balanced `[...]` opened mid-token absorbs embedded whitespace and `]`
// until depth returns to zero (the `:enum=[v1 v2 v3]` atomicity rule).
fn test_lex_value_run_absorbs_balanced_brackets() {
	src := ':enum=[v1 v2 v3] tail'
	t := lex_one_value(src) or {
		assert false, 'expected value_run'
		return
	}
	assert slice(src, t) == ':enum=[v1 v2 v3]'
}

// Quote regions inside a bracket stay atomic (predicate args like
// `//x[name='foo']`).
fn test_lex_value_run_quote_inside_bracket() {
	src := "x[name='a b']y"
	t := lex_one_value(src) or {
		assert false, 'expected value_run'
		return
	}
	assert slice(src, t) == "x[name='a b']"
}

// `[?` introduces a program form and breaks the run — at the start it yields
// an empty run (none).
fn test_lex_value_run_directive_breaks() {
	if _ := lex_one_value('[?foo bar]') {
		assert false, 'leading [? must not start a value_run'
	}
}

// read_token delegates byte-identically.
fn test_read_token_delegates_identically() {
	mut p := new_parser(':enum=[v1 v2 v3] tail')
	got := p.read_token() or {
		assert false, 'read_token should succeed'
		return
	}
	assert got == ':enum=[v1 v2 v3]'
}

// lex_raw_span: content is the bytes between `[#` and `#]`, verbatim (no escapes).
fn test_lex_raw_span_basic() {
	src := '[#<a> & b#] rest'
	mut p := new_parser(src)
	p.advance() // consume '['
	t := p.lex_raw_span() or {
		assert false, 'expected raw span'
		return
	}
	assert t.kind == .raw_span
	assert p.src[t.pos.offset..t.end].bytestr() == '<a> & b'
}

// A lone `#` not followed by `]` is content.
fn test_lex_raw_span_lone_hash_is_content() {
	src := '[#a#b#]z'
	mut p := new_parser(src)
	p.advance() // consume '['
	t := p.lex_raw_span() or {
		assert false, 'expected raw span'
		return
	}
	assert p.src[t.pos.offset..t.end].bytestr() == 'a#b'
}

// ── Token cursor (token_cursor.v) ────────────────────────────────────────────

// tok_peek_kind classifies leading bytes into a structural kind without consuming
// or allocating. One case per branch of the classifier.
fn test_tok_peek_kind_structural() {
	cases := {
		']x':     CxTokenKind.rbrack
		',a':     CxTokenKind.comma
		'=v':     CxTokenKind.eq
		'&ent;':  CxTokenKind.amp
		'(a, b)': CxTokenKind.lparen
		')tail':  CxTokenKind.rparen
		'{k: v}': CxTokenKind.lbrace
		'}tail':  CxTokenKind.rbrace
		'[child': CxTokenKind.lbrack
		'[?call': CxTokenKind.ldirective
		'[#raw#]': CxTokenKind.raw_span
		'[|block': CxTokenKind.block_span
		"'one'":   CxTokenKind.quote_run
		'"one"':   CxTokenKind.quote_run
		"'''triple'''": CxTokenKind.triple_span
		'"""triple"""': CxTokenKind.triple_span
		'*merge': CxTokenKind.star
		'#id':    CxTokenKind.hash
		'::T':    CxTokenKind.double_colon
		':atom':  CxTokenKind.colon
		'8080]':  CxTokenKind.value_run
		'bareword': CxTokenKind.value_run
	}
	for src, want in cases {
		p := new_parser(src)
		got := p.tok_peek_kind()
		assert got == want, 'tok_peek_kind(${src}) = ${got}, want ${want}'
	}
	// empty input → eof.
	pe := new_parser('')
	assert pe.tok_peek_kind() == .eof
}

// tok_peek_kind is non-destructive: position is unchanged after a peek.
fn test_tok_peek_kind_does_not_consume() {
	p := new_parser('[child]')
	before := p.pos
	_ := p.tok_peek_kind()
	assert p.pos == before
}

// Adjacency: a glued `name[...]` is adjacent; a spaced `name [...]` is not. This
// is the significant-whitespace `had_ws == !tok_adjacent_to_prev()` reconstruction.
fn test_tok_adjacent_glued_vs_spaced() {
	// glued: after consuming the name, the next token starts where it ended.
	mut pg := new_parser('name[x]')
	_ := pg.tok_name() or {
		assert false, 'expected name'
		return
	}
	assert pg.tok_adjacent_to_prev(), 'name[x] — `[` must be adjacent to name'
	// spaced: a whitespace skip moves pos past prev_tok_end.
	mut ps := new_parser('name [x]')
	_ := ps.tok_name() or {
		assert false, 'expected name'
		return
	}
	ps.skip_ws()
	assert !ps.tok_adjacent_to_prev(), 'name [x] — `[` must NOT be adjacent (had_ws)'
}

// Before any consume, nothing is adjacent (prev_tok_end == 0). After a leading ws
// skip the cursor is at a non-zero offset, so adjacency is false.
fn test_tok_adjacent_initial_state() {
	mut p := new_parser('  x')
	p.skip_ws()
	assert !p.tok_adjacent_to_prev()
}

// The consume helpers advance prev_tok_end to the post-token offset and return the
// shared lex_* boundaries unchanged.
fn test_tok_consume_helpers_track_end() {
	// tok_value over a whitespace-delimited run.
	mut pv := new_parser('8080 next')
	tv := pv.tok_value() or {
		assert false, 'expected value'
		return
	}
	assert tv.kind == .value_run
	assert pv.src[tv.pos.offset..tv.end].bytestr() == '8080'
	assert pv.prev_tok_end == pv.pos
	assert pv.pos == 4
	// tok_raw_span (cursor at the opening `[`).
	mut pr := new_parser('[#<a> & b#] rest')
	tr := pr.tok_raw_span() or {
		assert false, 'expected raw span'
		return
	}
	assert tr.kind == .raw_span
	assert pr.src[tr.pos.offset..tr.end].bytestr() == '<a> & b'
	assert pr.prev_tok_end == pr.pos // past the closing `#]`
	assert pr.peek() == ` `
	// tok_sigil consumes one byte and carries the canonical sigil text.
	mut psg := new_parser(']tail')
	ts := psg.tok_sigil(.rbrack)
	assert ts.kind == .rbrack
	assert ts.text == ']'
	assert psg.pos == 1
	assert psg.prev_tok_end == 1
}

// tok_save/tok_restore is lookahead-only: a peek that ran a lex_* reader then
// rewound leaves position byte-identical and does NOT touch prev_tok_end.
fn test_tok_save_restore_is_lookahead_only() {
	mut p := new_parser('alpha beta')
	p.prev_tok_end = 7 // sentinel: a prior (hypothetical) consume
	snap := p.tok_save()
	_ := p.lex_name() or {
		assert false, 'expected name'
		return
	}
	assert p.pos == 5 // advanced by the lookahead
	p.tok_restore(snap)
	assert p.pos == 0
	assert p.line == 1
	assert p.col == 1
	assert p.prev_tok_end == 7 // untouched by lookahead
}
