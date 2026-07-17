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
	src := '[a [; a comment ] [b]]'
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
	// Versions 1-5 are accepted (4 for fragment plumbing, 5 for
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
	// `[?Name ['arg', arg, arg]]` uniform shape survives
	// ast_bin emit/decode. EvalDirective.items holds a single ArrayNode.
	// The leading array item is quoted: a bare-name leading item is reserved
	// for the element head (3a / lexicon §collections [L83]).
	src := "[?for ['v', items, [body @v]]]"
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

fn test_node_valued_attribute_rejected() {
	// GR-NODE-ATTR (DECISION-NA, ruling 1a 2026-06-05): the retired grammar [55c]
	// BracketBody attribute-value form `name=[BodyItem*]` put an element node in
	// attribute position, which D2 (attributes are scalar-only) forbids. It is now
	// a hard parse error (E211, a data-parse code per cxdm.md §11; NOT the program
	// CXER0240 = AWAIT_ALL_FAILED) rather than a silently-accepted node attribute.
	src := '[product spec=[length 10] notes=[size large]]'
	if _ := cx.parse(src) {
		assert false, 'node-valued attribute `spec=[…]` must be rejected (D2 scalar-only)'
	} else {
		assert err.msg().contains('cx-err:E211'), 'reject must carry E211: ${err.msg()}'
	}
	// #396 owner ruling 1b (2026-07-13): the pipe-block form is retired too —
	// attributes have ONE value channel, a scalar. The hash-raw form stays as
	// the sole bracket-opened escape hatch and yields the CONTENT as a STRING
	// scalar (no Attribute.body — that channel is gone).
	raw := cx.parse("[product note=[# raw <b> #]]") or {
		panic('raw-text attribute value must still parse: ${err}')
	}
	assert raw.elements.len == 1
	rel := raw.elements[0] as cx.Element
	assert rel.attrs.len == 1
	assert cx.scalar_value_str_public(rel.attrs[0].value) == ' raw <b> '
	if _ := cx.parse('[product note=[| block |]]') {
		assert false, 'pipe-block attribute value must be rejected (D2 scalar-only, #396 ruling 1b)'
	} else {
		assert err.msg().contains('cx-err:E211'), 'reject must carry E211: ${err.msg()}'
	}
}
