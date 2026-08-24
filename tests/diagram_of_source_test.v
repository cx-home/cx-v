// diagram_of_source_test.v — the #889 byte-identity pin for the
// caller-facing entry (RULED DRW3-1 deliverable B;
// ledger/rulings_2026_08_20_diagram_wave3.md).
//
// The owner's requirement: `[$diagram:of-source $src $format]` "must
// produce byte-identical output to the CLI path for the same input
// (pin it), and the CLI should route through it rather than keeping a
// second lift — one path, no twin."
//
// This pins BOTH halves:
//
//   * the CLI path — `render_diagram(src, fmt)`, which is what
//     `cx diagram` and `cx eval --target=…` reach through
//     `code.eval_code` — and
//   * a CX PROGRAM's own call, evaluated end-to-end through the
//     engine: `[?lib 'cx-stdlib/diagram'] [$diagram:of-source …]`.
//
// The program hands its render back base64-encoded so the comparison
// is over BYTES, not over the value renderer's quoting/escaping.

module main

import encoding.base64
import cx
import code
import platform as _

const of_source_pins = [
	'[greet]',
	'[?if [> \$x 0] [then [pos]] [else [neg]]]',
	'[?for [in \$u //users/user] [yield \$u]]',
	'[?pipe (1, 2) through=[?fn (\$x) [* \$x 2]]]',
	'[user id=1 name=\'ada\']',
]

fn render_via_cx_program(src string, format string, detail string) !string {
	prog := "[?lib 'cx-stdlib/diagram' as=diagram]\n" +
		"[?lib 'cx-stdlib/bytes' as=bytes]\n" +
		'[$bytes:to-base64 [$bytes:from-string-utf8 [$diagram:of-source ${cx_string_literal(src)} "${format}" detail="${detail}"]]]'
	out := code.eval_code('', prog, 'text')!
	// A string result renders quoted; base64 carries no quote bytes.
	trimmed := out.trim_space().trim("'")
	return base64.decode_str(trimmed)
}

// cx_string_literal quotes a CX source string for embedding in a CX
// program: double quotes, backslash-escaped.
fn cx_string_literal(s string) string {
	return '"' + s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n') + '"'
}

fn test_of_source_matches_the_cli_render_byte_for_byte() {
	mut failures := []string{}
	for src in of_source_pins {
		// The CLI path (cmd/diagram.v → eval_code → render_diagram),
		// which routes THROUGH of-source since #889. `mermaid` with no
		// detail suffix is the DR-11 `min` rung — the same default
		// `of-source` carries. (`dot` is not a CLI target: `cx diagram`
		// takes mermaid|svg|png, so the DOT comparison below is against
		// the module's own image path instead.)
		cli := code.render_diagram(src, 'mermaid') or {
			failures << 'render_diagram(mermaid) on ${src}: ${err}'
			continue
		}
		via := render_via_cx_program(src, 'mermaid', 'min') or {
			failures << 'of-source(mermaid) on ${src}: ${err}'
			continue
		}
		if cli != via {
			failures << 'BYTE DIVERGENCE mermaid on ${src}\n--- cli ---\n${cli}\n--- of-source ---\n${via}'
		}
		// DOT: of-source's internal lift must agree with the seam's
		// image path byte-for-byte (the vector goldens pin that path).
		prog := cx.parse_program(src) or {
			failures << 'parse ${src}: ${err}'
			continue
		}
		seam_dot := code.render_dot_cx(prog) or {
			failures << 'render_dot_cx on ${src}: ${err}'
			continue
		}
		via_dot := render_via_cx_program(src, 'dot', 'min') or {
			failures << 'of-source(dot) on ${src}: ${err}'
			continue
		}
		if seam_dot != via_dot {
			failures << 'BYTE DIVERGENCE dot on ${src}\n--- seam ---\n${seam_dot}\n--- of-source ---\n${via_dot}'
		}
	}
	if failures.len > 0 {
		for f in failures {
			println(f)
		}
	}
	assert failures.len == 0
}

fn test_of_source_detail_rungs_reach_the_same_bytes_as_the_format_suffix() {
	src := '[?pipe (1, 2) through=[?fn (\$x) [* \$x 2]]]'
	for detail in ['min', 'compact', 'full'] {
		cli := code.render_diagram(src, 'mermaid:${detail}') or {
			assert false, 'render_diagram(mermaid:${detail}): ${err}'
			return
		}
		via := render_via_cx_program(src, 'mermaid', detail) or {
			assert false, 'of-source(mermaid, ${detail}): ${err}'
			return
		}
		assert cli == via, 'detail rung ${detail} diverged:\n--- cli ---\n${cli}\n--- of-source ---\n${via}'
	}
}

// RULED: D910-1 (#910) — the ingress's guarded DATA fallback. A pure-data
// document the PROGRAM reading refuses (but the DATA reading accepts, with
// no registered directive) lifts as data, so `cx diagram` and the
// code-diagram ERD lane render it instead of a token-level error / the
// empty placeholder. The source below carries the data-only idioms that
// made the shipped examples/config.cx undiagrammable: a bare URL and a
// bare filesystem path in prose bodies. (The third original idiom, the
// SPACED `::T` annotation, was retired by RULED: TA-1 #911 — it now
// refuses loudly in BOTH readings, so it can no longer carry a fallback.)
fn test_data_document_takes_the_ingress_fallback() {
	src := '[server host=0.0.0.0
  [origins https://example.com]
  [file /var/log/app.log]]'
	// The program reading refuses it (the deliberate reader difference)…
	if _ := cx.parse_program(src) {
		assert false, 'expected the program reading to refuse the data-idiom source'
	}
	// …and the diagram render now succeeds via the data lift.
	out := code.render_diagram(src, 'mermaid') or {
		assert false, 'D910-1 fallback did not render: ${err.msg()}'
		return
	}
	assert out.starts_with('%%cx:'), 'embed-source metadata missing'
	assert out.contains('flowchart TD'), 'expected a flowchart render, got: ${out}'
	// eval_code's diagram arm (the `cx diagram` CLI path) reaches the
	// same bytes — one lift path, no twin.
	cli := code.eval_code('', src, 'mermaid') or {
		assert false, 'eval_code mermaid on a data doc: ${err.msg()}'
		return
	}
	assert cli == out, 'CLI path diverged from render_diagram'
	// The code-diagram ERD lane is no longer the EMPTY placeholder.
	erd := code.code_diagram(src) or {
		assert false, 'code-diagram on a data doc: ${err.msg()}'
		return
	}
	assert erd.contains('server {'), 'expected a populated erDiagram, got: ${erd}'
}

fn test_d910_fallback_guards_keep_program_intent_fail_loud() {
	// A source BOTH readings refuse keeps the verbatim ingress [err].
	if _ := code.render_diagram('[?if [ unbalanced', 'mermaid') {
		assert false, 'expected refusal for a source both readings refuse'
	}
	// A broken source whose DATA reading carries a registered
	// [?directive] is unambiguous PROGRAM intent — no fallback (the
	// eval_code guard, shared by the ingress).
	if _ := code.render_diagram('[?modify $doc [set count 1] [append item]]', 'mermaid') {
		assert false, 'expected refusal for a program-shaped source'
	}
}

// RULED: DGF-1 (#912) — eval_code (the `cx diagram` CLI path) matches
// diagram targets on the BASE format and passes the FULL string through to
// render_diagram, which owns the detail suffix (parse_diagram_format). The
// rungs the layer below already implements (of-source, the wasm export, the
// gates) now reach the CLI. One pin per rung, on the program arm AND the
// D910-1 data-fallback arm.
fn test_dgf1_cli_path_takes_the_detail_rungs() {
	src := '[user name=alice role=admin tenant=acme]'
	for rung in ['mermaid', 'mermaid:min', 'mermaid:compact', 'mermaid:full'] {
		want := code.render_diagram(src, rung) or {
			assert false, 'render_diagram(${rung}): ${err.msg()}'
			return
		}
		got := code.eval_code('', src, rung) or {
			assert false, 'eval_code(${rung}): ${err.msg()}'
			return
		}
		assert got == want, 'CLI path diverged from render_diagram on ${rung}'
	}
	// The suffix genuinely reaches the detail engine — the full rung carries
	// the attrs the min rung omits.
	minr := code.eval_code('', src, 'mermaid') or {
		assert false, 'eval_code(mermaid): ${err.msg()}'
		return
	}
	full := code.eval_code('', src, 'mermaid:full') or {
		assert false, 'eval_code(mermaid:full): ${err.msg()}'
		return
	}
	assert full != minr, 'the :full suffix did not change the render'
	assert full.contains('tenant'), 'expected the full rung to carry attrs'
}

fn test_dgf1_data_fallback_arm_takes_the_detail_rungs() {
	// A pure-data source the PROGRAM reading refuses (bare URL + bare path,
	// the D910-1 idioms — deliberately NOT the spaced ::T, which is TA-1's
	// migration target) renders the suffixed rung through the same fallback.
	src := '[server [origins https://example.com] [file /var/log/app.log]]'
	if _ := cx.parse_program(src) {
		assert false, 'expected the program reading to refuse the data-idiom source'
	}
	want := code.render_diagram(src, 'mermaid:full') or {
		assert false, 'render_diagram fallback (mermaid:full): ${err.msg()}'
		return
	}
	got := code.eval_code('', src, 'mermaid:full') or {
		assert false, 'eval_code fallback (mermaid:full): ${err.msg()}'
		return
	}
	assert got == want, 'fallback arm diverged from render_diagram on mermaid:full'
}

// RULED: D913-1 (#913) — a document with NO program structure renders its
// ELEMENT TREE in every format: elements as nodes on the min|compact|full
// label ladder, containment as edges. Before this the DOT walk emitted ZERO
// nodes for such documents (an 8pt empty canvas from `cx diagram
// --format=svg`, exit 0 — the #910 silent-degradation class one lane over)
// and the flowchart collapsed the whole document to the start→…→result
// envelope. Directive renders stay byte-identical (the golden lanes pin it).
fn test_d913_data_doc_renders_its_element_tree() {
	src := '[server host=0.0.0.0
  [origins https://example.com]
  [file /var/log/app.log]]'
	mm := code.render_diagram(src, 'mermaid') or {
		assert false, 'mermaid tree render: ${err.msg()}'
		return
	}
	assert mm.contains('n1["[server'), 'expected the root element node, got: ${mm}'
	assert mm.contains('n1 --> n2'), 'expected a containment edge, got: ${mm}'
	assert !mm.contains('(["start"])'), 'a data doc must not render the program envelope: ${mm}'
	assert !mm.contains('["…"]'), 'the collapsed ellipsis leaf must be gone: ${mm}'
	// The DOT text (the svg/png stdin) carries the same tree.
	dot := render_via_cx_program(src, 'dot', 'min') or {
		assert false, 'of-source dot: ${err.msg()}'
		return
	}
	assert dot.contains('digraph CX {'), 'dot header: ${dot}'
	assert dot.contains('n1 [label="[server'), 'expected the root DOT node, got: ${dot}'
	assert dot.contains('n1 -> n2;'), 'expected a containment edge, got: ${dot}'
	// The detail rung reaches the DOT text (DGF-1 plumbing + D913-1 labels).
	full := render_via_cx_program(src, 'dot', 'full') or {
		assert false, 'of-source dot full: ${err.msg()}'
		return
	}
	assert full.contains('@host='), 'expected attr chips on the full DOT rung, got: ${full}'
}

fn test_d913_multi_form_program_renders_its_forms() {
	// cx:block descends in BOTH walks: a multi-form program renders its
	// chained forms instead of one `…` leaf (mermaid) / an empty canvas
	// (dot). The single-form goldens pin that nothing else moved.
	src := '[?let [= \$x 1] \$x]\n[?let [= \$y 2] \$y]'
	dot := render_via_cx_program(src, 'dot', 'min') or {
		assert false, 'of-source dot multi-form: ${err.msg()}'
		return
	}
	assert dot.contains('[label="[?let]"];'), 'expected directive nodes in the DOT text, got: ${dot}'
	mm := code.render_diagram(src, 'mermaid') or {
		assert false, 'mermaid multi-form: ${err.msg()}'
		return
	}
	assert !mm.contains('n3["…"]'), 'the collapsed block leaf must be gone: ${mm}'
}

fn test_of_source_refuses_an_unknown_format() {
	// Through the CLI surface (render_diagram's own format check) …
	if _ := code.render_diagram('[greet]', 'gif') {
		assert false, 'expected a refusal for an unknown format'
	} else {
		assert err.msg().contains('not recognised'), 'unexpected message: ${err.msg()}'
	}
	// … and through the module entry a CX program calls.
	out := code.eval_code('', "[?lib 'cx-stdlib/diagram' as=diagram]\n[\$diagram:of-source \"[greet]\" \"gif\"]",
		'text') or {
		assert false, 'of-source gif: ${err}'
		return
	}
	assert out.contains('CXER0100'), 'expected a CXER0100 err value, got: ${out}'
	assert out.contains('not recognised'), 'expected the format refusal, got: ${out}'
}
