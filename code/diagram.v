module code

import cx as _

// ── Phase 4: diagram renderer ───────────────────────────────────────────────
//
// Reference renderer for the visualization targets per spec/code.md
// §10.1 + §10.1.2. Three formats are supported (svg / png / mermaid);
// html and markdown stay Phase-4-gated.
//
// THE RENDERER IS A CX PROGRAM (#758, RULED DR-1…DR-11 2026-08-20 —
// ledger/rulings_2026_08_20_diagram_renderer.md; module spec
// spec/03-approved/std-lib/diagram.md). After wave 2 this file holds
// NO renderer logic at all: every byte of Mermaid, DOT, SVG and PNG
// output, both dot-less envelopes, both metadata splices, the PNG
// CRC-32, and all three reverse-parse extractors live in
// `cx-stdlib/diagram` (stdlib/diagram.cx). The graphviz hop is the
// module's one impure surface — `[$process-run ["dot" "-T…"] …]`
// under the `subprocess` capability with the `dot` allowlist entry
// (DR-2a) — so the V pair `shell_dot` / `import_os_execute` is
// deleted, not wrapped, and this file no longer imports `os`.
//
// What remains here is the format-string surface and the dispatch to
// the engine seam (vcx/code/diagram_cx_seam.v).
//
// Round-trip contract (gate 9, "hybrid embed-source"): each rendered
// output carries the original program source as base64-encoded metadata
// (Mermaid leading `%%cx:<base64>%%` comment; SVG `<metadata><cx:source>`
// block; PNG tEXt chunk keyed `cx-source`). `reverse_parse_diagram`
// strips the visual layer and recovers the source verbatim — a parse of
// the recovered source MUST be structurally equal to the original
// program AST.

pub fn render_diagram(source_text string, format string) !string {
	out, _ := render_diagram_counted(source_text, format, false)!
	return out
}

// diagram_render_steps is render_diagram with the render's WORK COUNT:
// the number of eval steps (eval_node entries — the F4 evaluation
// budget's own counter, S6.2) the render cost. Same call, same bytes.
//
// Its consumer is the DR-6 performance gate (#893, RULED: ISW-1). A
// wall-clock budget on a shared build machine measures the neighbours'
// `clang` as much as it measures this renderer — the 55ms that opened
// #893 was recorded with five agents compiling, and the same gate passes
// at ~17ms on a quiet box. Eval steps are a property of the program and
// the module and of nothing else: identical on every machine, under every
// load, in every run. A LINEARITY bound over them is a real regression
// tripwire where a time assertion can only report the machine's mood —
// the trade `parse_amplification_test.v` made for LIM-2.
pub fn diagram_render_steps(source_text string, format string) !(string, u64) {
	return render_diagram_counted(source_text, format, true)!
}

// render_diagram_counted is the ONE render entry both of the above share,
// so the instrumented form cannot drift from the shipped one.
fn render_diagram_counted(source_text string, format string, count_steps bool) !(string, u64) {
	// `format` may optionally encode a detail level via a `:` suffix
	// (e.g. `mermaid:compact`, `mermaid:full`, `mermaid:min`). Bare
	// `mermaid` defaults to `min` to preserve pre-detail-level
	// rendering for clients that haven't migrated (DR-11a rungs).
	// The §10.1.2 admission check (CXER0281) is the module's sealed
	// rules table for ALL THREE formats — wave 2 retired the second
	// copy this file used to carry for svg/png.
	base, detail := parse_diagram_format(format)
	if base != 'mermaid' && base != 'svg' && base != 'png' {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: "diagram format '${format}' not recognised (accepted: mermaid[:detail], svg, png)"
		}
	}
	detail_s := match detail {
		.min { 'min' }
		.compact { 'compact' }
		.full { 'full' }
	}
	return render_of_source_cx_counted(source_text, base, detail_s, count_steps)!
}

// DiagramDetail controls how much element-shape information appears
// in Mermaid node labels. Defaults to `.min` (legacy behaviour:
// element name only); the playground passes `.compact` (name +
// first 2 attrs + (+N more)) or `.full` (name + all attrs).
pub enum DiagramDetail {
	min     // element name only — `[user]` / `[user …]` when non-empty
	compact // name + up to 2 attrs + (+K more attrs) — `[user @id=1 @name='a' (+2)]`
	full    // name + all attrs — `[user @id=1 @name='a' @role='admin' @tenant='acme']`
}

// parse_diagram_format splits `format` on `:` and returns (base, detail).
// Unknown / missing suffix → `.min` (legacy behaviour).
fn parse_diagram_format(format string) (string, DiagramDetail) {
	if !format.contains(':') {
		return format, DiagramDetail.min
	}
	parts := format.split(':')
	base := parts[0]
	suffix := if parts.len > 1 { parts[1] } else { '' }
	detail := match suffix {
		'compact' { DiagramDetail.compact }
		'full'    { DiagramDetail.full }
		else      { DiagramDetail.min }
	}
	return base, detail
}

// reverse_parse_diagram extracts the embedded CX source from a
// previously-rendered diagram and returns it. Used by gate-9
// round-trip tests: render(prog, fmt) → reverse_parse_diagram →
// parse → assert structural equality vs original prog. The
// extractors for all three formats are cx-stdlib/diagram pure CX.
pub fn reverse_parse_diagram(rendered string, format string) !string {
	return extract_diagram_source_cx(rendered, format)!
}
