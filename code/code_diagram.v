module code

// code_diagram.v — the playground's CFG / ERD / SEQ diagram surface.
//
// WAVE 3 of the diagram port (#889, RULED DRW3-1 —
// ledger/rulings_2026_08_20_diagram_wave3.md; design letter
// spec/02-working/diagram_renderer_cx.md, DR-1a/DR-9a). The emitter is
// now a CX program: `cx-stdlib/diagram`'s `code-diagram` entry
// (stdlib/diagram.cx §9), reached through the module seam. The 3,219
// lines of V that produced this Mermaid text — the source-text patches,
// the auto-detect classifier, the CFG basic-block emitter and its
// def-subgraph scope machinery, the ERD containment walker, the SEQ
// actor/activation emitter, and the min/full level layers — are
// DELETED, not wrapped: DR-9a is cutover-first, no permanent twin.
//
// What remains here is the level vocabulary and three thin entry
// points; nothing in this file produces a byte of diagram text.
//
// Bit-for-bit: vcx/tests/code_diagram_golden_test.v pins 282 goldens
// (94 sources × 3 levels) captured from the V emitter before the
// cutover; the CX renderer matches every one byte-for-byte. The pin
// corpus has grown since the cutover — every addition under a named
// ledger ruling, the goldens themselves never rewritten (#1032 /
// RULED: SEQ-3/SEQ-4 added the let-bound-spine SEQ pair).

// DiagramLevel controls the verbosity of `cx_code_diagram` output.
// Three rungs: `min` strips to shape-only; `compact` is the default
// and preserves the §D3/§D4/§D13 baselines; `full` adds INPUT/OUTPUT
// terminals, source spans, binding-resolution bridges, and step-back
// rules.
pub enum CodeDiagramLevel {
	min
	compact
	full
}

// parse_code_diagram_level maps a string ("min" / "compact" / "full")
// to the enum. Empty / unknown defaults to `.compact` per D12.6
// "default-on-unspecified".
pub fn parse_code_diagram_level(s string) CodeDiagramLevel {
	match s {
		'min' { return .min }
		'full' { return .full }
		'compact' { return .compact }
		else { return .compact }
	}
}

// code_diagram is the top-level entry point: parses `source`,
// classifies code-vs-data (data → ERD, sequence-shape code → SEQ,
// other code → CFG), and emits the Mermaid representation at the
// `.compact` rung.
pub fn code_diagram(source string) !string {
	return code_diagram_with_level(source, .compact)!
}

// code_diagram_with_level is the level-aware entry point (D12.6) and
// the ONE path into the renderer: `cx code-diagram`, the wasm export
// `cx_code_diagram_with_level`, and the golden gate all arrive here.
//
// Empty source classifies as data and yields the placeholder
// `erDiagram`. A source the parser refuses degrades to a
// kind-appropriate placeholder header — the CX module owns both
// behaviors (the text-level classification is part of the port).
pub fn code_diagram_with_level(source string, level CodeDiagramLevel) !string {
	return code_diagram_cx(source, code_diagram_level_str(level))!
}

// code_diagram_level_str is the level enum's wire spelling — the string
// the CX module's own `$level` parameter takes.
pub fn code_diagram_level_str(level CodeDiagramLevel) string {
	return match level {
		.min { 'min' }
		.compact { 'compact' }
		.full { 'full' }
	}
}

// effect_graph_with_level — the `effects` VIEW (RULED: DGX-1,
// ledger/rulings_2026_08_21_diagram_capabilities.md).
//
// The second subject this subcommand can render: not the program's
// control flow or its data shape, but WHAT IT CAN DO — which of
// `security.md` §2's nine capabilities the source reaches, through
// which call path, and which only under a branch. The auditor's view:
// "grant this program `net` and it can reach these three calls."
//
// It is a VIEW, not a format: `--view=effects` selects the subject,
// `--level` still selects the rung. `--view=auto` (the default) is the
// ERD/CFG/SEQ auto-detection this subcommand has always performed, byte
// for byte.
//
// Honesty is normative (DGX-1c): a dynamic `[?eval]`, an unresolvable
// callee, a dynamic element name, an unreadable `[?lib]`, or a
// non-literal `[?with-caps]` deny renders as an UNKNOWN edge at every
// rung. A capability graph that quietly under-reports is worse than
// none.
pub fn effect_graph_with_level(source string, level CodeDiagramLevel) !string {
	return effect_graph_cx(source, code_diagram_level_str(level))!
}
