module main

import cx

// Tests for the binary AST decoder (bin_to_doc) and the round-trip
// pair emit_ast_bin → bin_to_doc. Closes audit finding CB-1 by
// enabling in-memory binary-AST traversal without CX-text round-trips.

// ── emit_ast_bin → bin_to_doc round-trip ─────────────────────────────────────

fn test_ast_bin_round_trip_basic() {
	doc := cx.parse('[server host=localhost port=8080]') or { panic(err) }
	bytes := cx.emit_ast_bin(doc)
	doc2 := cx.bin_to_doc(bytes) or { panic('decode: ${err}') }
	root := doc2.root() or { panic('no root') }
	assert root.name == 'server'
	assert root.attr('host') == 'localhost'
	assert root.attr('port') == '8080'
}

fn test_ast_bin_round_trip_nested() {
	src := '[config
  [server host=localhost port=8080]
  [database name=app pool=10]
]'
	doc := cx.parse(src) or { panic(err) }
	bytes := cx.emit_ast_bin(doc)
	doc2 := cx.bin_to_doc(bytes) or { panic(err) }
	root := doc2.root() or { panic('no root') }
	assert root.name == 'config'
	assert root.items.len == 2
}

fn test_ast_bin_preserves_attributes() {
	doc := cx.parse('[item count=42 ratio=1.5 active=true name=test]') or { panic(err) }
	bytes := cx.emit_ast_bin(doc)
	doc2 := cx.bin_to_doc(bytes) or { panic(err) }
	root := doc2.root() or { panic('no root') }
	assert root.attr('count') == '42'
	assert root.attr('ratio') == '1.5'
	assert root.attr('active') == 'true'
	assert root.attr('name') == 'test'
}

fn test_ast_bin_round_trip_scalar_body() {
	doc := cx.parse('[count 42]') or { panic(err) }
	bytes := cx.emit_ast_bin(doc)
	doc2 := cx.bin_to_doc(bytes) or { panic(err) }
	root := doc2.root() or { panic('no root') }
	s := root.scalar() or { panic('not scalar') }
	if s is i64 { assert s == 42 } else { assert false, 'expected i64' }
}

fn test_ast_bin_round_trip_comments_preserved() {
	src := '[a [- a comment -] [b]]'
	doc := cx.parse(src) or { panic(err) }
	bytes := cx.emit_ast_bin(doc)
	doc2 := cx.bin_to_doc(bytes) or { panic(err) }
	root := doc2.root() or { panic('no root') }
	mut found_comment := false
	for n in root.items {
		if n is cx.CommentNode { found_comment = true }
	}
	assert found_comment, 'comments must round-trip through binary AST'
}

// ── Decoder rejects malformed input ──────────────────────────────────────────

fn test_ast_bin_rejects_truncated_size() {
	bytes := [u8(0x01), 0x00]
	if _ := cx.bin_to_doc(bytes) {
		assert false, 'should reject truncated size header'
	} else {
		assert err.msg().contains('short')
	}
}

fn test_ast_bin_rejects_size_exceeds_input() {
	bytes := [u8(100), 0, 0, 0, 1, 0, 0, 0]
	if _ := cx.bin_to_doc(bytes) {
		assert false, 'should reject mismatched size'
	} else {
		assert err.msg().contains('exceeds')
	}
}

fn test_ast_bin_rejects_wrong_version() {
	// Versions 1-5 are accepted (v0.6.0: 4 for fragment plumbing, 5 for
	// grammar v3.5 nodes + BracketBody attr body tail). Use a value
	// outside that set so the test stays a real reject-test.
	mut bytes := []u8{}
	bytes << [u8(5), 0, 0, 0]
	bytes << u8(99)
	bytes << [u8(0), 0, 0, 0]
	if _ := cx.bin_to_doc(bytes) {
		assert false, 'should reject unsupported version'
	} else {
		assert err.msg().contains('version')
	}
}

// ── v5 (grammar v3.5) round-trip ─────────────────────────────────────────────

fn test_ast_bin_v5_interpolation_round_trip() {
	// [?=EXPR] survives ast_bin emit/decode.
	src := '[greeting Hello [?= user.name ] !]'
	doc := cx.parse(src) or { panic(err) }
	bytes := cx.emit_ast_bin(doc)
	doc2 := cx.bin_to_doc(bytes) or { panic('decode: ${err}') }
	root := doc2.root() or { panic('no root') }
	mut found := false
	for n in root.items {
		if n is cx.InterpolationNode {
			found = true
			assert n.expr.contains('user.name')
		}
	}
	assert found, 'InterpolationNode must round-trip through ast_bin v5'
}

fn test_ast_bin_v5_eval_directive_round_trip() {
	// `[?Name [arg, arg, arg]]` post-ADR-0017 uniform shape survives
	// ast_bin emit/decode. EvalDirective.items holds a single ArrayNode
	// per ADR 0017 §D6.
	src := '[?for [v, items, [body @v]]]'
	doc := cx.parse(src) or { panic(err) }
	bytes := cx.emit_ast_bin(doc)
	doc2 := cx.bin_to_doc(bytes) or { panic('decode: ${err}') }
	mut found := false
	for n in doc2.elements {
		if n is cx.EvalDirectiveNode {
			found = true
			assert n.name == 'for'
			assert n.items.len == 1
			arg := n.items[0]
			assert arg is cx.ArrayNode
			arr := arg as cx.ArrayNode
			assert arr.items.len == 3
		}
	}
	for n in doc2.prolog {
		if n is cx.EvalDirectiveNode {
			found = true
			assert n.name == 'for'
		}
	}
	assert found, 'EvalDirectiveNode must round-trip through ast_bin'
}

fn test_ast_bin_v5_attr_body_round_trip() {
	// BracketBody attribute value `name=[BodyItem*]` (grammar [55c])
	// survives ast_bin v5+ encoding. Post-ADR-0017, BracketBody no
	// longer appears on EvalDirective attributes (§D7 drops the
	// `:then=…/:else=…` slot convention) but remains a valid attribute
	// value form on regular Elements.
	src := '[product spec=[length 10] notes=[size large]]'
	doc := cx.parse(src) or { panic(err) }
	bytes := cx.emit_ast_bin(doc)
	doc2 := cx.bin_to_doc(bytes) or { panic('decode: ${err}') }
	mut nodes := []cx.Node{}
	nodes << doc2.prolog
	nodes << doc2.elements
	mut found_then := false
	mut found_else := false
	for n in nodes {
		if n is cx.Element {
			for a in n.attrs {
				if a.name == 'spec' {
					if body := a.body { assert body.len > 0; found_then = true }
				}
				if a.name == 'notes' {
					if body := a.body { assert body.len > 0; found_else = true }
				}
			}
		}
	}
	assert found_then, 'BracketBody attr `spec` must round-trip through ast_bin'
	assert found_else, 'BracketBody attr `notes` must round-trip through ast_bin'
}
