module main

import cx
import code

// v0.8.0 DATA↔PROGRAM SEAM CLOSURE.
//
// `cx <file>` defaults to EVAL (the program reading; CLI-default=eval). The
// program reader previously FORKED from / REJECTED three pure-DATA
// constructs, so the new default could mishandle valid data files:
//   - `[#…#]` raw text was wrongly eaten as a block comment and DISCARDED
//     (a spec-conformance bug vs code.md §1.3 / lexicon [L2]/[L3]),
//   - `&…;` entity / `&#…;` char references hit the lexer's unexpected-char
//     catch-all,
//   - `[!…]` declarations + `[!DOCTYPE …]` were rejected (`!` in expression
//     position).
//
// Closure adds ONE `node_lit` ProgramLiteralKind: the program lexer captures
// the data-construct SPAN as a `data_span` token and the parser delegates to
// the proven data reader (`cx.parse_data_node`), carrying the parsed
// `cx.Node`. Eval returns it as-is. The "data = a program that evaluates to
// itself" invariant therefore holds BY CONSTRUCTION — the program (eval)
// reading of these constructs IS the data reading.
//
// `[-` (block-comment-vs-subtraction) stays a by-design fork (out of scope,
// like SEQ-NEST).

// data_read renders the DATA reading of src (what `cx --from=cx --to=cx`
// produces): parse as data, emit canonical CX.
fn data_read(src string) string {
	doc := cx.parse(src) or { panic('data parse failed: ${err}') }
	return cx.emit_cx(doc).trim_space()
}

// eval_read renders the PROGRAM (eval) reading of src (what `cx <file>`
// produces by default): parse as a program, evaluate, render to CX.
fn eval_read(src string) string {
	return code.eval_code('', src, 'cx') or { panic('eval failed: ${err}') }.trim_space()
}

// ── 1. parse_data_node returns the right node kind for each construct ─────────

fn test_parse_data_node_raw() {
	n := cx.parse_data_node('[# hello #]') or {
		assert false, 'parse_data_node failed: ${err}'
		return
	}
	assert n is cx.RawTextNode, 'expected RawTextNode'
	assert (n as cx.RawTextNode).value == ' hello ', 'raw value mismatch: "${(n as cx.RawTextNode).value}"'
}

fn test_parse_data_node_entity() {
	n := cx.parse_data_node('&amp;') or {
		assert false, 'parse_data_node failed: ${err}'
		return
	}
	assert n is cx.EntityRefNode, 'expected EntityRefNode'
	assert (n as cx.EntityRefNode).name == 'amp'
}

fn test_parse_data_node_charref() {
	n := cx.parse_data_node('&#65;') or {
		assert false, 'parse_data_node failed: ${err}'
		return
	}
	// A char reference resolves to text (codepoint 65 = 'A').
	assert n is cx.TextNode, 'expected TextNode'
	assert (n as cx.TextNode).value == 'A'
}

fn test_parse_data_node_entity_decl() {
	n := cx.parse_data_node("[!ENTITY x 'y']") or {
		assert false, 'parse_data_node failed: ${err}'
		return
	}
	assert n is cx.EntityDeclNode, 'expected EntityDeclNode'
}

fn test_parse_data_node_doctype() {
	n := cx.parse_data_node('[!DOCTYPE foo]') or {
		assert false, 'parse_data_node failed: ${err}'
		return
	}
	assert n is cx.DoctypeDecl, 'expected DoctypeDecl'
	assert (n as cx.DoctypeDecl).name == 'foo'
}

fn test_parse_data_node_rejects_trailing() {
	if _ := cx.parse_data_node('[# a #] [# b #]') {
		assert false, 'expected error on two-node input'
	}
}

// ── 2. The program lexer/parser builds a node_lit literal ─────────────────────

fn test_program_parse_node_lit() {
	prog := cx.parse_program('[# raw #]') or {
		assert false, 'program parse failed: ${err}'
		return
	}
	lit := prog.body as cx.ProgramLiteral
	assert lit.kind == .node_lit, 'expected node_lit, got ${lit.kind}'
	assert lit.str_val == '[# raw #]', 'verbatim span not preserved: "${lit.str_val}"'
	carried := lit.node or {
		assert false, 'node_lit carries no node'
		return
	}
	assert carried is cx.RawTextNode
}

// ── 3. The SEAM: eval reading == data reading for valid placements ───────────
//
// Raw text and entity references are valid ELEMENT-BODY content; declarations
// and DOCTYPE are valid as STANDALONE (prolog-position) nodes. For every one
// of these the eval reading must equal the data reading byte-for-byte.

fn test_seam_raw_in_body() {
	src := '[doc [# r #]]'
	assert eval_read(src) == data_read(src), 'raw-in-body seam: eval="${eval_read(src)}" data="${data_read(src)}"'
}

fn test_seam_entity_in_body() {
	src := '[p &amp;]'
	assert eval_read(src) == data_read(src), 'entity-in-body seam: eval="${eval_read(src)}" data="${data_read(src)}"'
}

fn test_seam_two_raws_in_body() {
	src := '[doc [# a #] [# b #]]'
	assert eval_read(src) == data_read(src), 'two-raws seam: eval="${eval_read(src)}" data="${data_read(src)}"'
}

fn test_seam_raw_standalone() {
	src := '[# hi #]'
	assert eval_read(src) == data_read(src), 'raw-standalone seam: eval="${eval_read(src)}" data="${data_read(src)}"'
}

fn test_seam_entity_standalone() {
	src := '&amp;'
	assert eval_read(src) == data_read(src), 'entity-standalone seam: eval="${eval_read(src)}" data="${data_read(src)}"'
}

fn test_seam_entity_decl_standalone() {
	src := "[!ENTITY x 'y']"
	assert eval_read(src) == data_read(src), 'entity-decl seam: eval="${eval_read(src)}" data="${data_read(src)}"'
}

fn test_seam_element_decl_standalone() {
	src := '[!ELEMENT a EMPTY]'
	assert eval_read(src) == data_read(src), 'element-decl seam: eval="${eval_read(src)}" data="${data_read(src)}"'
}

fn test_seam_doctype_standalone() {
	src := '[!DOCTYPE foo]'
	assert eval_read(src) == data_read(src), 'doctype seam: eval="${eval_read(src)}" data="${data_read(src)}"'
}

fn test_seam_doctype_with_internal_subset() {
	src := "[!DOCTYPE foo [ [!ENTITY x 'y'] ]]"
	assert eval_read(src) == data_read(src), 'doctype-subset seam: eval="${eval_read(src)}" data="${data_read(src)}"'
}

fn test_seam_decl_quote_with_bracket() {
	// A `]` inside a quoted literal must NOT close the `[!…]` span early
	// (the lexer skips quoted literals while tracking bracket depth).
	src := "[!ENTITY x 'a]b']"
	assert eval_read(src) == data_read(src), 'decl-]-in-string seam: eval="${eval_read(src)}" data="${data_read(src)}"'
}

// ── 4. The original bug: raw text is no longer DISCARDED by eval ──────────────

fn test_raw_no_longer_discarded() {
	// Before the fix, `cx file.cx` (eval) returned `[doc]` (raw eaten as a
	// comment). It must now preserve the raw text.
	assert eval_read('[doc [# r #]]') == '[doc [# r #]]'
}

// ── 5. `[--…--]` stays a comment (NOT captured as a data_span) ────────────────

fn test_semicolon_block_comment() {
	// `[; … ]` is the block comment and is skipped by the lexer; the
	// surrounding element evaluates with the comment elided.
	assert eval_read('[doc [; a comment ] 1]') == '[doc 1]'
}
