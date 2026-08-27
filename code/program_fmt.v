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
//     formatter happens to preserve);
//   - otherwise the data format changed the program's meaning → it is a real
//     program: format it FAITHFULLY via the program emitter, but only if that
//     emitter is a fixed point on it (round-trip-stable); else leave it untouched.
//
// #967 correction: an older version of this note claimed "data files always hit
// the first branch (the data formatter is lossless, so src and d share one
// program reading)". MEASURED FALSE. The data emitter's canonical quoting rule
// drops quotes the bare image re-reads identically — in the DATA reading. In the
// PROGRAM reading a bare body word is a CALL: `[name "demo"]` holds a
// string_lit, `[name demo]` holds a ProgramCall. So a plain data document with a
// quoted string reaches the second branch, and before this fix that branch — the
// program lane, whose parser drops comments — deleted every comment in the file.
// The second branch now fails closed on a comment-bearing source instead.

// fmt_source formats CX source text safely: lossless for data, faithful for
// programs, never corrupting.
//
// The returned text is UNTERMINATED. That is a total contract of this entry
// point, not a per-lane courtesy: every caller supplies the final newline
// (`cx fmt`'s println, the LSP whole-document edit), so a lane that hands back
// a terminated string adds one line to the file on every pass.
//
// #980 — the fail-closed lanes did exactly that. `faithful_program_fmt`
// returns the SOURCE when the program emitter cannot prove a faithful round
// trip, and it returned the source BYTES, trailing newline and all; the
// second pass then re-fails-closed on text carrying one more newline than the
// first, unbounded (corpus/rosetta/21-fetch-csv-validate.cx: 57 → 58 → 59
// lines) and formatting.md §7 idempotence failed by a growing blank line.
// The comment lane below had already met this obligation locally with its own
// `trim_right`; normalizing at the boundary instead makes every lane —
// including any added later — inherit it, and leaves each lane free to reason
// about meaning rather than about terminators.
pub fn fmt_source(input string) !string {
	return fmt_source_lane(input)!.trim_right('\n')
}

// fmt_source_lane is fmt_source's lane selection. It may return terminated
// text (the fail-closed lanes return the source verbatim); fmt_source owns the
// termination contract for all of them.
fn fmt_source_lane(input string) !string {
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
	//
	// #967 / R-A7 — but the faithful PROGRAM lane is not lossless, and
	// `cx fmt` is specified as the LOSSLESS canonical formatter (cli.md:107 /
	// :209; canonical.md §1.2 makes comments exactly what separates lossless
	// from strict canonical). `cx.parse_program` discards CommentNode
	// outright, so `program_node_to_source` has nothing to re-emit and the
	// lane returns a canonical program text with every comment DELETED —
	// silent user data loss in the command the LSP calls on save.
	//
	// The lossless CX emitter the data lane uses is therefore the ONLY lane
	// that ever emits a comment-bearing document; when its output has just
	// been shown to change this file's meaning, there is no lossless
	// canonical form to emit, so fmt fails closed on the SOURCE — the same
	// answer faithful_program_fmt gives when it cannot verify a round trip.
	// Unchanged text is lossless, re-parses, and is a fixed point; a
	// comment-stripped canonicalization is none of those. Comment-free
	// sources are untouched by this branch and keep the program lane.
	if data_reading_carries_comment(input) {
		return input
	}
	return faithful_program_fmt(input, cf_src, shape_src)
}

// data_reading_carries_comment reports whether the DATA reading of `input`
// retains at least one comment node. The data reader is the authority here:
// it is the only reader in the tree that keeps comments (the program reader
// drops them at parse), and a lexical `#` scan would count hashes inside
// strings, raw blocks and table cells. A source with no data reading has no
// comment inventory to protect — the program lane is then the only lane.
fn data_reading_carries_comment(input string) bool {
	doc := cx.parse(input) or { return false }
	for c in doc.prolog {
		if node_carries_comment(c) {
			return true
		}
	}
	for e in doc.elements {
		if node_carries_comment(e) {
			return true
		}
	}
	return false
}

fn node_carries_comment(n cx.Node) bool {
	if n is cx.CommentNode {
		return true
	}
	if n is cx.Element {
		for it in n.items {
			if node_carries_comment(it) {
				return true
			}
		}
		return false
	}
	if n is cx.DocumentNode {
		for c in n.prolog {
			if node_carries_comment(c) {
				return true
			}
		}
		for c in n.elements {
			if node_carries_comment(c) {
				return true
			}
		}
		return false
	}
	if n is cx.EvalDirectiveNode {
		for it in n.items {
			if node_carries_comment(it) {
				return true
			}
		}
		return false
	}
	return false
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
