module code

import cx

// program_fmt.v — program-faithful source formatting for `cx fmt` + the LSP
// (#118). The data formatter (cx.cx_text_fmt) re-emits through the DATA emitter,
// which is lossless for data but REWRITES program surface ([= $x …], [$call],
// [?directive]) into the data `(…)` form — silently destroying a program file on
// save. fmt_source routes each file to the correct formatter, verified, and is
// FAIL-CLOSED: it never emits text that changes the file's meaning.
//
// Everything parses as both data and program, so the discriminator is semantic,
// not syntactic. We use the program emitter's deterministic, position-free output
// (program_node_to_source) as a canonical PROGRAM form and compare:
//   - data-format the source (d);
//   - if d has the SAME canonical program form as the source, the data format
//     preserved the program reading → use d (genuine data, or a program the data
//     formatter happens to preserve). Data files always hit this branch (the data
//     formatter is lossless, so src and d share one program reading);
//   - otherwise the data format changed the program's meaning → it is a real
//     program: format it FAITHFULLY via the program emitter, but only if that
//     emitter is a fixed point on it (round-trip-stable); else leave it untouched.

// fmt_source formats CX source text safely: lossless for data, faithful for
// programs, never corrupting.
pub fn fmt_source(input string) !string {
	mut cf_src := ''
	if prog := cx.parse_program(input) {
		cf_src = program_node_to_source(prog.body)
	} else {
		// Not a program under this reading. Unambiguous PROGRAM intent stays
		// fail-loud — the #11 eval-boundary rule, mirrored here at the fmt
		// boundary (#391; before this, `cx fmt` silently reformatted a broken
		// program as a data document whenever it happened to parse as data,
		// while `cx run` on the same bytes failed loud): a failure after the
		// parser committed to a program construct, or a data reading that
		// carries a REGISTERED `[?directive]`. Unlike eval, the
		// `unknown_directive` flag does NOT gate the fmt fallback: an
		// unregistered `[?name]` is how every data-layer prolog decl reads to
		// the program parser (`[?cx version=…]`, custom PIs), and losslessly
		// formatting such a document as data is exactly fmt's job — eval
		// fails loud there because *evaluating* one as self-echoing data
		// would bury the diagnostic. Everything else is pure data.
		no_data_fallback := if err is cx.ParseError {
			err.program_committed
		} else {
			false
		}
		if no_data_fallback || data_reading_has_program_directive(input) {
			return err
		}
		return cx.cx_text_fmt(input)!
	}
	// It parses as a program. Try the data formatter and check it preserved the
	// program reading — at the AST level, not just the emitted text (#400):
	// the program emitter proved NON-INJECTIVE once (two different ASTs, one
	// spelling), so canonical-text equality alone can bless a meaning change.
	shape_src := prog_shape(input) or { '' }
	if d := cx.cx_text_fmt(input) {
		if cf_d := prog_canon(d) {
			if cf_d == cf_src && prog_shape(d) or { '' } == shape_src {
				return d // data format preserved meaning (data, or a safe program)
			}
		}
	}
	// The data formatter would change the program's meaning → format faithfully.
	return faithful_program_fmt(input, cf_src, shape_src)
}

// prog_shape is a position-insensitive structural fingerprint of `input`'s
// program AST — V's generated struct rendering with every `pos: Position{…}`
// payload blanked (a source parse and a canonical-text reparse legitimately
// differ ONLY there). Two texts with equal shapes parse to structurally
// identical programs; unequal shapes mean a formatter output changed the
// meaning even if it re-emits the same canonical text (#400's failure mode:
// the retired `:label` colon-slot spelling was a TEXT fixed point whose
// reparse held bare atoms where the source held match clauses).
fn prog_shape(input string) ?string {
	prog := cx.parse_program(input) or { return none }
	s := prog.body.str()
	mut out := []u8{cap: s.len}
	mut i := 0
	for i < s.len {
		// Position renders as `Position{` … `}` with only scalar fields —
		// no nested braces — so skipping to the next `}` is exact.
		if i + 9 <= s.len && s[i..i + 9] == 'Position{' {
			for i < s.len && s[i] != `}` {
				i++
			}
			i++ // consume '}'
			continue
		}
		out << s[i]
		i++
	}
	return out.bytestr()
}

// prog_canon returns the canonical program-source form of `input` (the program
// emitter's deterministic, position-free rendering of its program AST), or none
// when `input` does not parse as a program.
fn prog_canon(input string) ?string {
	prog := cx.parse_program(input) or { return none }
	return program_node_to_source(prog.body)
}

// faithful_program_fmt returns the canonical program form `cf_src` only if the
// program emitter is round-trip-stable on it (re-parsing + re-emitting yields the
// same text — the emitter's fixed-point / faithfulness guarantee). If the emitter
// cannot faithfully round-trip this program, the original source is returned
// UNCHANGED — fmt must never emit a surface that changes meaning (#118).
fn faithful_program_fmt(input string, cf_src string, shape_src string) string {
	cf2 := prog_canon(cf_src) or { return input }
	if cf2 != cf_src {
		return input
	}
	// Text fixed point alone is NOT meaning preservation (#400): require the
	// canonical text to REPARSE to the same position-insensitive AST shape as
	// the source. A non-injective emitter output (same spelling, different
	// AST) now fails closed to the original text instead of shipping a
	// program that evaluates differently — or not at all.
	shape_out := prog_shape(cf_src) or { return input }
	if shape_src != '' && shape_out != shape_src {
		return input
	}
	return cf_src
}
