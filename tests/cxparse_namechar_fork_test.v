module main

import cx
import code

// cxparse_namechar_fork_test — pins the ONE deliberate name-char mode fork and
// proves the DATA path is an equivalent realization of lexicon [L11].
//
// `is_name_start` is byte-identical across both parsers and is shared with no
// behavior change. The CONTINUATION rule genuinely differs by mode and stays
// two named predicates (each defined once — that is not duplication, it is the
// mode boundary N1 admits):
//   • DATA   `cx.is_name_char`  — folds `.` and `:` into the name token
//                                  (dotted names + `prefix:local` QNames).
//   • PROGRAM `cx.is_ident_part` — excludes `.`/`:` (the program lexer emits
//                                  them as their own tokens: path step / colon).
//
// [L11] describes `:` as its own token that the parser FOLDS into a QName. The
// scannerless data path has no token stream; it realizes the SAME fold by
// accepting `:` mid-name. This is the RATIFIED end-state (the single-tokenizer
// flip was ruled architecturally unsound — PLAN §4.3), NOT a way-point. The
// equivalence is observable, so this test pins it directly:
// `[svg:rect]` folds to one element AND renders BARE (a regression that dropped
// `:` from `is_name_char` without re-adding it everywhere would quote the QName
// — the bijection break this fork guards against), while `[a:b:c]` is rejected.

fn test_name_start_is_shared_and_ascii() {
	for b in [u8(`a`), `z`, `A`, `Z`, `_`] {
		assert cx.is_name_start(b)
	}
	for b in [u8(`0`), `9`, `-`, `.`, `:`, ` `, `[`] {
		assert !cx.is_name_start(b)
	}
}

fn test_data_namechar_folds_dot_and_colon() {
	assert cx.is_name_char(`.`)
	assert cx.is_name_char(`:`)
	assert cx.is_name_char(`-`)
	assert cx.is_name_char(`0`)
	assert cx.is_name_char(`a`)
}

fn test_program_ident_part_excludes_dot_and_colon() {
	assert !cx.is_ident_part(`.`)
	assert !cx.is_ident_part(`:`)
	assert cx.is_ident_part(`-`)
	assert cx.is_ident_part(`0`)
	assert cx.is_ident_part(`a`)
}

fn test_program_lexer_splits_dotted_name() {
	// Behavioral consequence of `is_ident_part`: the program lexer breaks `a.b`
	// at the dot, so it yields strictly more tokens than the gap-free `ab`.
	dotted := cx.tokenize('a.b') or { panic('tokenize a.b: ${err}') }
	plain := cx.tokenize('ab') or { panic('tokenize ab: ${err}') }
	assert dotted.len > plain.len
}

fn test_data_parser_admits_dotted_name() {
	// Behavioral consequence of `is_name_char`: a dotted element name parses as
	// a single data element.
	doc := cx.parse('[a.b hello]') or { panic('data parse [a.b hello]: ${err}') }
	assert doc.elements.len == 1
}

fn test_qname_folds_to_one_element_and_renders_bare() {
	// [L11] realization: `prefix:local` folds into ONE element name on the data
	// path, and the canonical renderer prints it BARE (not quoted). This is the
	// bijection-critical observable the fork guards: a regression that dropped
	// `:` from `is_name_char` without re-adding the fold at the renderer would
	// emit `'svg:rect'`, breaking CX⇄XML round-tripping.
	doc := cx.parse('[svg:rect x=1]') or { panic('data parse [svg:rect x=1]: ${err}') }
	assert doc.elements.len == 1
	rendered := code.render_canonical(doc.elements[0])
	assert rendered.contains('svg:rect')
	assert !rendered.contains("'svg:rect'")
}

fn test_double_colon_qname_rejected() {
	// At most one `:` per [L11]: `a:b:c` is not a valid QName.
	if _ := cx.parse('[a:b:c]') {
		assert false, '[a:b:c] must be rejected as an invalid QName'
	}
}
