module code

import cx
import strings

// ── Output rendering (Phase 3.11) ───────────────────────────────────────────
//
// `render` turns a CX-program evaluation result (a `cx.Node`) into the
// caller's requested output format. The supported targets are listed
// in `spec/audits/code_abi_v1.md §3.1` (resolved at D5):
//
//   text (default) — newline-joined canonical-form per top-level item
//   cx             — single canonical-form CX document
//   json           — AST-JSON shape (spec/audits/code_abi_v1.md §3.1)
//   yaml / xml     — Document-wrapped emit via vcx/cx/emitter_*.v
//   csv / tsv      — sequence-of-records → header + rows, CXER0100
//                    when the result shape is not tabular
//   html / markdown / svg / mermaid       — Phase 4-gated (reference renderer)
//
// json/yaml/xml/csv/tsv reuse the canonical emitters already living in
// the cx module — the program-result Node is normalised into either an
// AST-JSON value directly (for json) or a `cx.Document` (for yaml/xml)
// before delegating.

const cx_slot_prefix = '__cx_slot:'
const cx_seq_name = '__cx_seq__'
const cx_arr_name = '__cx_arr__'
const cx_map_name = '__cx_map__'

// redaction_marker is the `cxdm.md §12.2` secret-redaction string. A
// secret value (`__cx_secret__` wrapper, `eval.v`) renders as this marker
// — never the underlying value — at every output boundary. The marker is
// a plain string (not a typed node) for format-portability across CX /
// JSON / XML / YAML / CSV (§12.5).
const redaction_marker = '‹redacted›'

// redacted_scalar returns the string ScalarNode that replaces a secret at
// an output boundary on the structured (JSON / YAML / XML / CSV)
// normalization paths.
fn redacted_scalar() cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(redaction_marker)
		data_type: .string_type
	}
}

// redact_secrets deep-walks a program-result node and replaces every
// `__cx_secret__` wrapper (cxdm.md §12) with the redaction marker. The
// canonical / text / cx renderer redacts intrinsically inside
// render_element(_to); this pass is the equivalent for the structured
// normalizers (render_json / render_yaml / render_xml / render_delimited),
// which build their own node/Document shapes and never route through
// render_element. It is also reused by the log + err-build boundaries.
// Best-effort single-pass projection (§12.2): the wrapper is dropped and
// the marker substituted; non-secret nodes pass through unchanged.
fn redact_secrets(n cx.Node) cx.Node {
	match n {
		cx.Element {
			if n.name == secret_marker_name {
				return redacted_scalar()
			}
			// D5: a `[?meta]` wrapper is an inert side-band — for the
			// structured normalizers (JSON / YAML / TOML / MD) it projects
			// to its inner value (the annotation has no native equivalent
			// there; XML preserves it losslessly via `<cx:meta>` elsewhere).
			if n.name == meta_marker_name {
				return if n.items.len >= 1 { redact_secrets(n.items[0]) } else { redacted_scalar() }
			}
			mut items := []cx.Node{cap: n.items.len}
			for it in n.items {
				items << redact_secrets(it)
			}
			return cx.Element{
				name:  n.name
				attrs: n.attrs
				items: items
				meta:  n.meta
				table: n.table
			}
		}
		cx.SequenceNode {
			return cx.SequenceNode{ items: n.items.map(redact_secrets(it)) }
		}
		cx.ArrayNode {
			return cx.ArrayNode{ items: n.items.map(redact_secrets(it)) }
		}
		cx.MapNode {
			mut entries := []cx.MapEntry{cap: n.entries.len}
			for e in n.entries {
				entries << cx.MapEntry{
					key_type:  e.key_type
					key_value: e.key_value
					value:     redact_secrets(e.value)
				}
			}
			return cx.MapNode{ entries: entries }
		}
		else {
			return n
		}
	}
}

// render selects the renderer keyed by `target` and produces the
// program output as a string. Empty / NULL target defaults to "text"
// per `spec/audits/code_abi_v1.md §3.1`.
pub fn render(n cx.Node, target string) !string {
	// A function value is opaque and has no faithful data round-trip;
	// reaching this serialization boundary raises CXER0291
	// (E_FN_NOT_SERIALIZABLE, §8.6).
	if n is cx.Element && n.name == closure_sentinel_name {
		return EvalError{
			code:    'cx-err:CXER0291'
			message: 'a function value is not serialisable (cx-err:CXER0291 E_FN_NOT_SERIALIZABLE)'
		}
	}
	t := if target == '' { 'text' } else { target }
	match t {
		'text', 'cx' { return render_canonical(n) }
		'json'       { return render_json(n) }
		'yaml'       { return render_yaml(n) }
		'xml'        { return render_xml(n) }
		'csv'        { return render_delimited(n, ',')! }
		'tsv'        { return render_delimited(n, '\t')! }
		'svg', 'mermaid', 'png' {
			// Diagram targets are routed BEFORE result evaluation by
			// `eval_code` (they render the program AST + source,
			// not the result). If we reach `render` here, the caller
			// invoked us directly on a result Node — surface a
			// clear "use eval_code with target=…" message.
			return EvalError{
				code:    'cx-err:CXER0001'
				message: "output target '${t}' must be requested through eval_code (renders program AST + source for round-trip)"
			}
		}
		'html', 'markdown' {
			return EvalError{
				code:    'cx-err:CXER0001'
				message: "output target '${t}' requires the reference renderer (Phase 4 follow-up); not yet implemented"
			}
		}
		else {
			return EvalError{
				code:    'cx-err:CXER0100'
				message: "unknown output target '${t}' (accepted: text, cx, json, yaml, xml, csv, tsv, html, markdown, svg, mermaid)"
			}
		}
	}
}

// render_canonical is the text/cx renderer. The two targets produce
// the same output at Phase 3.11 — both are canonical CX. They diverge
// once richer formatting lands (text gets unquoted-when-possible scalar
// rendering; cx stays strictly canonical).
pub fn render_canonical(n cx.Node) string {
	return render_node(n)
}

fn render_node(n cx.Node) string {
	match n {
		cx.TextNode {
			return n.value
		}
		cx.ScalarNode {
			return render_scalar(n)
		}
		cx.Element {
			return render_element(n)
		}
		cx.SequenceNode { return cx.cx_emit_sequence_inline(n, true) }
		cx.ArrayNode    { return cx.cx_emit_array_inline(n, true) }
		cx.MapNode      { return cx.cx_emit_map_inline(n, true) }
		cx.IteratorNode {
			// materialize to Sequence at the host
			// boundary. Force-pull via iterate() so the memo is
			// fully populated before paren-comma render. Each item
			// is rendered through `render_node` recursively so nested
			// cx_seq_name / cx_arr_name markers (produced by
			// combinators like `[?zip]` / `[?enumerate]` /
			// `[?chunks]` / `[?partition]`) render in their canonical
			// paren / bracket forms rather than as raw element heads.
			items := iterate(n)
			mut parts := []string{cap: items.len}
			for it in items {
				parts << render_node(it)
			}
			return '(${parts.join(', ')})'
		}
		// DATA↔PROGRAM seam: an embedded pure-DATA node value (from a `node_lit`
		// literal) renders through the data CX emitter so `cx file.cx` (eval)
		// matches `cx --from=cx --to=cx file.cx` (data) byte-for-byte.
		cx.RawTextNode, cx.EntityRefNode, cx.DoctypeDecl, cx.EntityDeclNode,
		cx.ElementDeclNode, cx.AttlistDeclNode, cx.NotationDeclNode,
		cx.PEReferenceNode, cx.ConditionalSectNode, cx.DocumentNode {
			return cx.cx_emit_node_str(n, true)
		}
		else {
			return '<${n}>'
		}
	}
}

// render_node_to writes the canonical rendering of `n` directly to
// `b`. Functionally identical to `render_node(n)` but avoids
// allocating intermediate strings — the streaming path in
// `StreamCtx.emit_node` calls this to keep the per-yield render
// hot-loop free of per-attribute / per-child string-concat
// allocations (§11.6 gate 15 throughput).
pub fn render_node_to(mut b strings.Builder, n cx.Node) {
	match n {
		cx.TextNode {
			b.write_string(n.value)
		}
		cx.ScalarNode {
			render_scalar_to(mut b, n)
		}
		cx.Element {
			render_element_to(mut b, n)
		}
		cx.SequenceNode { b.write_string(cx.cx_emit_sequence_inline(n, true)) }
		cx.ArrayNode    { b.write_string(cx.cx_emit_array_inline(n, true)) }
		cx.MapNode      { b.write_string(cx.cx_emit_map_inline(n, true)) }
		cx.IteratorNode {
			// materialize to Sequence at the host
			// boundary. Force-pull via iterate() so the memo is
			// fully populated before paren-comma render. Recursive
			// per-item render keeps nested marker-named elements
			// (paren / bracket) canonical.
			items := iterate(n)
			b.write_string('(')
			for i, it in items {
				if i > 0 { b.write_string(', ') }
				render_node_to(mut b, it)
			}
			b.write_string(')')
		}
		// DATA↔PROGRAM seam: render embedded pure-DATA node values via the data
		// CX emitter (see render_node above).
		cx.RawTextNode, cx.EntityRefNode, cx.DoctypeDecl, cx.EntityDeclNode,
		cx.ElementDeclNode, cx.AttlistDeclNode, cx.NotationDeclNode,
		cx.PEReferenceNode, cx.ConditionalSectNode, cx.DocumentNode {
			b.write_string(cx.cx_emit_node_str(n, true))
		}
		else {
			b.write_string('<')
			b.write_string('${n}')
			b.write_string('>')
		}
	}
}

fn render_scalar_to(mut b strings.Builder, n cx.ScalarNode) {
	// atoms (data_type == .atom_type) carry their name in the
	// string ScalarValue but MUST render as `:name`, not as a quoted
	// string. Without this branch program output emits `"ok"` for `:ok`
	// and breaks round-trip through `cx eval` / playground.
	if n.data_type == .atom_type {
		if n.value is string {
			b.write_string(':')
			b.write_string(n.value as string)
			return
		}
	}
	// bigint scalars carry their digits as a string value but are NUMERIC —
	// render bare (no quotes), matching the data emitter's cx_scalar so the
	// program result and the canonical-CX emitter agree. A bare over-i64
	// integer re-parses back to bigint (D-H auto-promotion), so this is
	// lossless.
	if n.data_type == .bigint_type {
		if n.value is string {
			b.write_string(n.value as string)
			return
		}
	}
	// duration / period scalars carry their verbatim CX form (`1h30m`, `3mo`)
	// as a string but render BARE — they are typed temporal spans, not strings.
	if n.data_type == .duration_type || n.data_type == .period_type {
		if n.value is string {
			b.write_string(n.value as string)
			return
		}
	}
	v := n.value
	match v {
		string {
			if looks_like_duration_value(v) {
				b.write_string(v)
			} else {
				// Delegate to the render-side quote-style chooser
				// (prefers `"…"` over `'…'` to match the long-
				// standing programs-render contract). Without this
				// a $-bound source containing `name="Foo"` would be
				// naively wrapped in `"...name="Foo"..."` and break
				// re-parse.
				b.write_string(choose_render_quote(v))
			}
		}
		i64    { b.write_string(v.str()) }
		f64    { b.write_string(v.str()) }
		bool   { b.write_string(v.str()) }
		cx.NullValue { b.write_string('null') }
	}
}

// attr_needs_typed_render reports whether an attribute carries a type the
// value-only path can't render losslessly — an atom (needs the `:` sigil)
// or a non-auto-recoverable scalar type (sized int / decimal / bigint /
// bytes, needs the glued `::T` annotation). Such attributes defer to the
// shared `cx.cx_attr_scalar` so the eval / gate renderer agrees with the
// canonical-CX emitter (D3). Untyped, auto-recoverable, and reference
// attributes keep their existing value-only rendering. (D3)
fn attr_needs_typed_render(a cx.Attribute) bool {
	if a.is_ref {
		return false
	}
	dt := a.data_type() or { return false }
	if dt == 'atom' {
		return true
	}
	return !(cx.type_name_is_auto_recoverable(dt) || dt == 'string')
}

fn render_attr_value_to(mut b strings.Builder, v cx.ScalarValue) {
	match v {
		string {
			if looks_like_duration_value(v) {
				b.write_string(v)
			} else if needs_quoted_attr(v) {
				b.write_string(choose_render_quote(v))
			} else {
				b.write_string(v)
			}
		}
		i64    { b.write_string(v.str()) }
		f64    { b.write_string(v.str()) }
		bool   { b.write_string(v.str()) }
		cx.NullValue { b.write_string('null') }
	}
}

fn render_element_to(mut b strings.Builder, n cx.Element) {
	// Secret redaction (cxdm.md §12.2): a `__cx_secret__` wrapper emits
	// the redaction marker, never the underlying value. Handled here (and
	// in render_element) so EVERY canonical/text/cx path redacts — direct
	// render_canonical callers (gate, store, format/canonical, §9.2
	// stringification) and iterator-materialized items included.
	if n.name == secret_marker_name {
		b.write_string(choose_render_quote(redaction_marker))
		return
	}
	// D5: a `[?meta]` wrapper renders transparently as its inner value —
	// the annotation is an inert side-band, invisible to CX/text output.
	if n.name == meta_marker_name {
		if n.items.len >= 1 {
			render_node_to(mut b, n.items[0])
		}
		return
	}
	// `:table` block — delegate to the cx-module emitter (see render_element).
	if _ := n.table_opt() {
		b.write_string(cx.cx_emit_node_str(n, false))
		return
	}
	if n.name == '' {
		for i, it in n.items {
			if i > 0 { b.write_string('\n') }
			render_node_to(mut b, it)
		}
		return
	}
	if n.name == cx_seq_name {
		b.write_string('(')
		for i, it in n.items {
			if i > 0 { b.write_string(', ') }
			render_node_to(mut b, it)
		}
		b.write_string(')')
		return
	}
	if n.name == cx_arr_name {
		b.write_string('[')
		for i, it in n.items {
			if i > 0 { b.write_string(', ') }
			render_node_to(mut b, it)
		}
		b.write_string(']')
		return
	}
	if n.name == cx_map_name {
		// `__cx_map__` element: child items are entry elements with
		// name=key, items=[value]. Emit as `{k: v, k: v}`.
		b.write_string('{')
		mut first := true
		for it in n.items {
			if it is cx.Element {
				if !first { b.write_string(', ') }
				first = false
				b.write_string(it.name)
				b.write_string(': ')
				if it.items.len > 0 {
					render_node_to(mut b, it.items[0])
				}
			}
		}
		b.write_string('}')
		return
	}
	// §9 / decision (a): typed-array body canonical render.
	if rendered := try_render_array_element(n) {
		b.write_string(rendered)
		return
	}
	b.write_string('[')
	b.write_string(n.name)
	// emit ElementMeta (anchor / merge / id / data_type) so the
	// `text`/`cx` render targets round-trip canonical-CX attribute
	// syntax (e.g. `[section :id "intro"]`). Without this, modify
	// pipelines that preserve `el.meta` through spine copies emit
	// truncated output where `:id intro` collapses to a bare scalar
	// child. Mirrors `cx_build_meta` in `vcx/cx/emitter_cx.v`.
	if a := n.anchor()    { b.write_string(' &'); b.write_string(a) }
	if m := n.merge()     { b.write_string(' *'); b.write_string(m) }
	if id := n.id()       { b.write_string(' #'); b.write_string(id) }
	if dt := n.data_type() { b.write_string('::'); b.write_string(dt) }
	for a in n.attrs {
		b.write_string(' ')
		// D3: an atom or a non-auto-recoverable typed attribute carries a
		// `:`-sigil / glued `::T` surface — delegate to the single source of
		// truth so both renderers agree. Untyped / auto-recoverable / ref
		// attributes keep the existing value-only path (no churn).
		if attr_needs_typed_render(a) {
			b.write_string(cx.cx_attr_scalar(a))
			continue
		}
		b.write_string(a.name)
		b.write_string('=')
		render_attr_value_to(mut b, a.value)
	}
	for it in n.items {
		if it is cx.Element && it.name.starts_with(cx_slot_prefix) {
			b.write_string(' :')
			b.write_string(it.name[cx_slot_prefix.len..])
			b.write_string(' ')
			if it.items.len > 0 {
				render_body_item_to(mut b, it.items[0])
			}
		} else {
			b.write_string(' ')
			render_body_item_to(mut b, it)
		}
	}
	b.write_string(']')
}

// render_body_item_to renders a child node of an Element body.
//
// Unlike `render_node_to` (used for top-level results and structural
// emit), bare TextNode values appearing as element-body items render
// through `choose_render_quote` so they emit with a quote wrapper —
// matching the long-standing programs-render convention that string
// scalars in body position are always quoted (`[label "Click me"]`
// rather than `[label Click me]`). Without this branch a TextNode
// produced by the CX parser (which collapses `[label "Click me"]`
// into Element{TextNode{"Click me"}}) would render as the bareword
// form on the way out of `cx eval`, causing a visual round-trip
// regression vs the source quote shape — observed in fixtures
// `program-modify-007-rename` and `program-modify-008-append-child`
// (2026-05-23 task #43).
//
// The cx-data parser treats `[label "Click me"]` and `[label Click
// me]` as equivalent at the data level (both yield TextNode value
// "Click me"); the canonical-CX emitter likewise drops unneeded
// quotes via `cx_quote_text_if_needed`. The programs renderer is
// stricter — it preserves the quoted-string surface so consumers can
// distinguish a TextNode arising from a quoted source from one that
// was produced by program construction.
//
// Whitespace-only TextNodes (used internally for separator hygiene
// inside mixed-content elements) render via the canonical path so we
// do not noise up the output with `" "` markers.
fn render_body_item_to(mut b strings.Builder, n cx.Node) {
	if n is cx.TextNode {
		if n.value.trim_space() == '' {
			b.write_string(n.value)
			return
		}
		b.write_string(choose_render_quote(n.value))
		return
	}
	// A discrete date/datetime scalar in body position (a typed-list item, e.g.
	// `[ds 2024-01-15 2024-02-20]`) renders BARE — its value re-auto-types to a
	// date on round-trip, whereas the generic render_scalar would quote it (a
	// date's value is carried as a string), which would re-parse as a string and
	// LOSE the date type. Matches render_array_scalar_item's drop-annotation form.
	if n is cx.ScalarNode {
		if (n.data_type == .date_type || n.data_type == .datetime_type) && n.value is string {
			b.write_string(n.value as string)
			return
		}
	}
	// A `name==''` sequence wrapper (the multi-value shape produced by a
	// nested `[?for]` comprehension) renders newline-joined at top level,
	// but inside a named element's body that form is non-round-trippable.
	// In body position it serialises as a paren sequence `(a, b, c)` —
	// the canonical sequence-value form (program-conc-018).
	if n is cx.Element && n.name == '' {
		b.write_string('(')
		for i, it in n.items {
			if i > 0 { b.write_string(', ') }
			render_node_to(mut b, it)
		}
		b.write_string(')')
		return
	}
	render_node_to(mut b, n)
}

fn render_scalar(n cx.ScalarNode) string {
	// atoms render with leading `:` from the wrapper's
	// data_type; see render_scalar_to for the rationale.
	if n.data_type == .atom_type {
		if n.value is string {
			return ':' + (n.value as string)
		}
	}
	// bigint renders bare (numeric); see render_scalar_to for the rationale.
	if n.data_type == .bigint_type {
		if n.value is string {
			return n.value as string
		}
	}
	// duration / period render bare (typed temporal spans, not strings).
	if n.data_type == .duration_type || n.data_type == .period_type {
		if n.value is string {
			return n.value as string
		}
	}
	v := n.value
	match v {
		string {
			if looks_like_duration_value(v) {
				return v
			}
			return choose_render_quote(v)
		}
		i64    { return v.str() }
		f64    { return v.str() }
		bool   { return v.str() }
		cx.NullValue { return 'null' }
	}
}

// choose_render_quote picks a quote style for a string scalar in
// programs-render output. The programs-render contract prefers `"…"`
// over `'…'` (the canonical-CX cx_choose_quote prefers single first;
// matching that would churn every existing fixture's out_text). The
// rules: prefer double; fall back to single when the string contains
// `"`; fall back to triple-single when both; fall back to triple-
// double when even triples collide. Empty / quote-free strings get
// double-quote wrap to keep the existing fixture shape.
fn choose_render_quote(s string) string {
	// Quoting hierarchy per spec/core/canonical.md §2.3 (bare > single >
	// double; triple is multiline-only):
	//   - no `'`             → single-quoted (the default quoting form)
	//   - has `'`, no `"`    → double-quoted (the apostrophe needs no escape)
	//   - has both `'` & `"` → single-quoted with `\'` escape (the
	//                          disambiguating tiebreak, line 130; the `"`
	//                          needs no escape inside `'…'`)
	// Triple-quoting is RESERVED for values with literal newlines or
	// consecutive whitespace (line 131) — NOT for escape-avoidance — and is
	// emitted by the multiline path, not here.
	has_double := s.contains('"')
	has_single := s.contains("'")
	// Minimal backslash re-escape (cx.cx_escape_quoted) so the rendered scalar
	// round-trips through the data parser's lenient escape decode — shared with
	// the canonical-CX emitter (no two-copy drift). The both-quotes branch's
	// `'`→`\'` escape is subsumed by the delimiter-escape pass.
	if !has_single { return "'" + cx.cx_escape_quoted(s, `'`) + "'" }
	if !has_double { return '"' + cx.cx_escape_quoted(s, `"`) + '"' }
	return "'" + cx.cx_escape_quoted(s, `'`) + "'"
}

// ── §9 / decision (a): canonical array-body render ─────────────────────────
//
// A typed-array element body (`data_type` `T[]`, all-scalar items) renders
// per lexicon.ebnf §9 (D1): drop the REDUNDANT `::T[]`
// annotation and use the minimal array SIGNAL.
//   - int/float/bool/date/datetime (auto-array on whitespace): drop the
//     annotation, whitespace-separated, items as bare literals (dates emit
//     UNQUOTED so they re-auto-type to date, not string);
//   - string (whitespace would be prose): drop the annotation, COMMA-
//     separated, items bare-when-safe (quoted only when a bare token would
//     re-parse as a non-string / split / be ambiguous);
//   - a SINGLE non-string scalar would re-parse as a scalar, so its array-
//     ness has no whitespace signal → keep `::T[]` (a string singleton uses
//     the trailing-comma form instead);
//   - non-recoverable element types (sized ints, decimal, bigint, bytes,
//     atom, f16) and the empty array keep `::T[]` (type not inferrable).
// Heterogeneous bodies are an ArrayNode child (data_type none), not this
// path — they render as a nested array literal `[head [a, b, c]]` (D1, 1b).
// The drop/comma/trailing decision lives in `cx.array_render_plan` so this
// renderer and the canonical-CX emitter share one rule (no two-copy drift).

// needs_quote_string_item reports whether a string item of a comma array
// must be quoted to round-trip as a string (would otherwise split, re-parse
// as a non-string scalar, or carry a reserved leading sigil).
fn needs_quote_string_item(s string) bool {
	if s.len == 0 { return true }
	for c in s {
		if c == ` ` || c == `\t` || c == `\n` || c == `\r` || c == `,`
			|| c == `[` || c == `]` || c == `(` || c == `)` || c == `{`
			|| c == `}` || c == `'` || c == `"` || c == `&` {
			return true
		}
	}
	if cx.cx_would_autotype(s) { return true }
	if s[0] == `@` || s[0] == `:` || s[0] == `#` { return true }
	return false
}

// render_array_scalar_item renders one item of a typed-array body. The
// explicit `::T[]` head pins the element type, so a bare-eligible string item
// stays BARE (`[tags::string[] admin user]`) — it is quoted only when the bare
// form would split or re-type. Dates/datetimes emit unquoted. This mirrors the
// cx-module data emitter (cx_emit_array_item) so `cx fmt` / `cx canonical` and
// the program renderer produce identical canonical text for a typed array.
// (`drop_ann` is retained in the signature for the shared array_render_plan
// contract; the plan now always keeps the annotation.)
fn render_array_scalar_item(s cx.ScalarNode, string_item bool, drop_ann bool) string {
	if s.data_type == .date_type || s.data_type == .datetime_type {
		if s.value is string {
			return s.value as string
		}
	}
	if string_item && s.value is string {
		v := s.value as string
		if needs_quote_string_item(v) {
			return choose_render_quote(v)
		}
		return v
	}
	return render_scalar(s)
}

// try_render_array_element renders a typed-array element body per decision
// (a), or returns none when `n` is not an all-scalar typed array (the caller
// falls through to the generic element render).
fn try_render_array_element(n cx.Element) ?string {
	dt := n.data_type() or { return none }
	if !dt.ends_with('[]') { return none }
	if n.attrs.len > 0 { return none }
	base := dt#[..-2]
	mut scalars := []cx.ScalarNode{}
	for it in n.items {
		if it is cx.ScalarNode {
			scalars << it
		} else {
			return none
		}
	}
	cnt := scalars.len
	drop_ann, use_comma, trailing := cx.array_render_plan(base, cnt)
	mut s := '[${n.name}'
	if a := n.anchor() { s += ' &${a}' }
	if m := n.merge()  { s += ' *${m}' }
	if id := n.id()    { s += ' #${id}' }
	if !drop_ann { s += '::${dt}' }
	if cnt > 0 {
		sep := if use_comma { ', ' } else { ' ' }
		mut parts := []string{cap: cnt}
		for sc in scalars {
			parts << render_array_scalar_item(sc, base == 'string', drop_ann)
		}
		s += ' ' + parts.join(sep)
		if trailing { s += ',' }
	}
	s += ']'
	return s
}

fn render_element(n cx.Element) string {
	// Secret redaction (cxdm.md §12.2) — see render_element_to.
	if n.name == secret_marker_name {
		return choose_render_quote(redaction_marker)
	}
	// D5: a `[?meta]` wrapper renders transparently as its inner value.
	if n.name == meta_marker_name {
		return if n.items.len >= 1 { render_node(n.items[0]) } else { '' }
	}
	// A `:table` block carries its rows/cols in the pooled `table` field,
	// NOT in `items` — this code-module element renderer has no table-block
	// production, so delegate to the cx-module emitter (the same one `cx
	// canonical` / `--to=cx` use), which renders the full
	// `[name [table[col::T …]] rows]` form. Without this, a table that
	// evaluates to itself rendered as a bare `[name::table]` (rows dropped).
	if _ := n.table_opt() {
		return cx.cx_emit_node_str(n, false)
	}
	// Top-level program output wrapper (name=''): join items with
	// newlines. This matches the `[?for]` shape where the program
	// returns multiple values.
	if n.name == '' {
		mut lines := []string{cap: n.items.len}
		for it in n.items {
			lines << render_node(it)
		}
		return lines.join('\n')
	}
	// Sequence literal `(a, b, c)`.
	if n.name == cx_seq_name {
		mut parts := []string{cap: n.items.len}
		for it in n.items {
			parts << render_node(it)
		}
		return '(${parts.join(', ')})'
	}
	// Array literal `[a, b, c]`.
	if n.name == cx_arr_name {
		mut parts := []string{cap: n.items.len}
		for it in n.items {
			parts << render_node(it)
		}
		return '[${parts.join(', ')}]'
	}
	// Map literal `{k: v, k: v}`. The `__cx_map__`
	// marker carries map entries as child elements (name=key,
	// items=[value]) per the program-side eval_map representation.
	if n.name == cx_map_name {
		mut parts := []string{cap: n.items.len}
		for it in n.items {
			if it is cx.Element {
				val_str := if it.items.len > 0 {
					render_node(it.items[0])
				} else { '' }
				parts << '${it.name}: ${val_str}'
			}
		}
		return '{${parts.join(', ')}}'
	}
	// §9 / decision (a): typed-array body canonical render.
	if rendered := try_render_array_element(n) {
		return rendered
	}
	// Named element. Attributes carry on the head; items render in
	// order, distinguishing labeled-slot children (name prefixed by
	// `__cx_slot:LABEL`) from positional items.
	mut s := '[${n.name}'
	// emit ElementMeta (anchor / merge / id / data_type) so the
	// `text`/`cx` render targets round-trip canonical-CX attribute
	// syntax — see render_element_to for rationale.
	if a := n.anchor()    { s += ' &${a}' }
	if m := n.merge()     { s += ' *${m}' }
	if id := n.id()       { s += ' #${id}' }
	if dt := n.data_type() { s += '::${dt}' }
	for a in n.attrs {
		if attr_needs_typed_render(a) {
			s += ' ${cx.cx_attr_scalar(a)}'
			continue
		}
		s += ' ${a.name}='
		s += render_attr_value(a.value)
	}
	for it in n.items {
		if it is cx.Element && it.name.starts_with(cx_slot_prefix) {
			label := it.name[cx_slot_prefix.len..]
			body := if it.items.len > 0 {
				render_body_item(it.items[0])
			} else { '' }
			s += ' :${label} ${body}'
		} else {
			s += ' ' + render_body_item(it)
		}
	}
	s += ']'
	return s
}

// render_body_item is the non-streaming counterpart to
// `render_body_item_to` — see that function's doc for the round-trip
// quoting rationale.
fn render_body_item(n cx.Node) string {
	if n is cx.TextNode {
		if n.value.trim_space() == '' {
			return n.value
		}
		return choose_render_quote(n.value)
	}
	// Discrete date/datetime scalar → bare (round-trips as a date); see
	// render_body_item_to for the rationale.
	if n is cx.ScalarNode {
		if (n.data_type == .date_type || n.data_type == .datetime_type) && n.value is string {
			return n.value as string
		}
	}
	// A `name==''` sequence wrapper (the multi-value shape produced by a
	// nested `[?for]` comprehension) renders newline-joined at top level,
	// but inside a named element's body that form is non-round-trippable.
	// In body position it serialises as a paren sequence `(a, b, c)` —
	// the canonical sequence-value form (program-conc-018).
	if n is cx.Element && n.name == '' {
		mut parts := []string{cap: n.items.len}
		for it in n.items {
			parts << render_node(it)
		}
		return '(${parts.join(', ')})'
	}
	return render_node(n)
}

fn render_attr_value(v cx.ScalarValue) string {
	match v {
		string {
			if looks_like_duration_value(v) {
				return v
			}
			if needs_quoted_attr(v) {
				return choose_render_quote(v)
			}
			return v
		}
		i64    { return v.str() }
		f64    { return v.str() }
		bool   { return v.str() }
		cx.NullValue { return 'null' }
	}
}

// is_program_safe_bare_attr reports whether `s` can be emitted as an
// UNQUOTED attribute value and survive a PROGRAM re-parse unchanged.
//
// The eval-result renderer's output is re-read by the program reader (the
// `data evaluates to itself` seam — `cx --xml`, `cx eval` piping all parse
// their input as a program). A bare attribute value must therefore lex as a
// single value token the program reader admits: a name-start-led run of
// ident parts, with `:` (the only mid-run fold — QName, lexicon [L70]:
// `urn:example`, `svg:rect`).
//
// Everything else is NOT expressible bare in program source and breaks the
// re-parse: a leading digit makes `1-doc` lex as `1` `-` `doc`; a `.` is its
// own path-step token so `pkg.mod` lexes as `pkg` `.` `mod`…; `/` is a path step
// (`America/New_York` lexes as `America` `/` `New_York`); and any non-ASCII
// byte (em-dash `—`, emoji `✅`, accented prose) or structural ASCII symbol
// is rejected ("unexpected character"). All such values MUST be quoted.
fn is_program_safe_bare_attr(s string) bool {
	if s.len == 0 { return false }
	mut i := 0
	for {
		// Each `:`-separated segment must be a non-empty ident: name-start
		// then ident-parts. This admits `urn:example` / `svg:rect` (QName)
		// but rejects `chrono::NaiveDate` — the glued `::` is the
		// type-annotation token, not a QName separator.
		if i >= s.len || !cx.is_name_start(s[i]) { return false }
		i++
		for i < s.len && cx.is_ident_part(s[i]) { i++ }
		if i == s.len { return true }
		if s[i] == `:` {
			i++
			continue
		}
		return false
	}
	return true
}

fn needs_quoted_attr(s string) bool {
	if s.len == 0 { return true }
	// Only a program-safe bare ident/QName may be emitted unquoted; every
	// other value (whitespace, brackets, quotes, digit-led `1-doc`, dotted
	// dotted `pkg.mod`, non-ASCII `—`/`✅`, structural symbols) must be quoted or the
	// program re-parse fails. This is the eval-result renderer feeding a
	// PROGRAM reader, which is STRICTER than the lenient data reader the
	// canonical emitter (`cx_quote_attr_if_needed`) targets — the divergence
	// is intentional and preserves the `data evaluates to itself` invariant.
	if !is_program_safe_bare_attr(s) { return true }
	// A bare value that auto-types (true / false / null / number / date) must
	// also be quoted to preserve string-ness on re-parse (canonical.md §2.3).
	// (`@id` refs and `:NAME` atoms are already excluded above — neither
	// starts with a name-start char.)
	if cx.cx_would_autotype(s) { return true }
	return false
}

fn looks_like_duration_value(s string) bool {
	for suf in ['us', 'ms', 's', 'm', 'h'] {
		if s.ends_with(suf) {
			prefix := s[..s.len - suf.len]
			if prefix.len == 0 { continue }
			mut all_digit := true
			for c in prefix {
				if !(c >= `0` && c <= `9`) {
					all_digit = false
					break
				}
			}
			if all_digit { return true }
		}
	}
	return false
}

// ── JSON (AST-JSON shape) ───────────────────────────────────────────────────
//
// Emits the canonical AST-JSON encoding of the program result. The
// program-result conventions (anon top-level wrapper, `__cx_seq__` /
// `__cx_arr__` collection markers, `__cx_map__` map marker,
// `__cx_slot:LABEL` labelled-child children) are flattened into the
// AST shape:
//
//   • anon wrapper with multiple items   → JSON array of items
//   • anon wrapper with one item         → that item's JSON shape
//   • `__cx_seq__` / `__cx_arr__`      → JSON array of items
//   • `__cx_map__`                      → JSON object keyed by entry name
//   • named Element                      → AST-JSON element shape
//     (slot children flattened as `:label` body slots in the items list)
//   • ScalarNode                         → AST-JSON scalar shape
//   • TextNode                           → AST-JSON text shape
//
// Strings, numbers, bools, null are emitted as their JSON-native form
// inside the AST-JSON `"value"` field — the existing `emit_ast_json_*`
// helpers handle that path.

fn render_json(n cx.Node) string {
	// Redact secrets before normalizing (cxdm.md §12.2) — the AST-JSON
	// path never routes through render_element's intrinsic backstop.
	return node_to_ast_json(redact_secrets(n))
}

fn node_to_ast_json(n cx.Node) string {
	match n {
		cx.Element {
			return element_to_ast_json(n)
		}
		cx.TextNode {
			return '{"type":"Text","value":${json_str(n.value)}}'
		}
		cx.ScalarNode {
			return scalar_node_to_ast_json(n)
		}
		else {
			// Unhandled node types — render as JSON null with a type
			// annotation so callers can detect the gap without it being
			// silently swallowed.
			return 'null'
		}
	}
}

// element_to_ast_json renders an Element using the AST-JSON shape, with
// the program-result conventions flattened (anon wrapper, collection
// markers, labelled slots, map marker).
fn element_to_ast_json(e cx.Element) string {
	// Top-level program output wrapper — array of items (or single item
	// when there's exactly one).
	if e.name == '' {
		if e.items.len == 1 {
			return node_to_ast_json(e.items[0])
		}
		return ast_json_array(e.items)
	}
	// Collection markers — render as JSON arrays / objects.
	if e.name == cx_seq_name || e.name == cx_arr_name {
		return ast_json_array(e.items)
	}
	if e.name == cx_map_name {
		return ast_json_map(e.items)
	}
	// Named element — emit AST-JSON shape directly. Labelled slots are
	// represented by child elements whose name starts with
	// `__cx_slot:`; we preserve them as items but rewrite the synthetic
	// name to keep the JSON wire-form readable.
	clean := flatten_slots(e)
	return cx.emit_ast_json_element(clean)
}

fn scalar_node_to_ast_json(s cx.ScalarNode) string {
	dt := scalar_type_label(s.data_type)
	v := scalar_value_to_json(s.value)
	return '{"type":"Scalar","dataType":"${dt}","value":${v}}'
}

fn scalar_type_label(t cx.ScalarType) string {
	return match t {
		.int_type      { 'int' }
		.float_type    { 'float' }
		.bool_type     { 'bool' }
		.null_type     { 'null' }
		.string_type   { 'string' }
		.date_type     { 'date' }
		.datetime_type { 'datetime' }
		.bytes_type    { 'bytes' }
		.decimal_type  { 'decimal' }
		.bigint_type   { 'bigint' }
		.duration_type { 'duration' }
		.period_type   { 'period' }
		.atom_type     { 'atom' }
	}
}

fn scalar_value_to_json(v cx.ScalarValue) string {
	match v {
		i64          { return v.str() }
		f64          {
			s := v.str()
			if s.contains('.') || s.contains('e') || s.contains('n') {
				return s
			}
			return '${s}.0'
		}
		bool         { return if v { 'true' } else { 'false' } }
		cx.NullValue { return 'null' }
		string       { return json_str(v) }
	}
}

fn ast_json_array(items []cx.Node) string {
	parts := items.map(node_to_ast_json(it))
	return '[${parts.join(',')}]'
}

fn ast_json_map(entries []cx.Node) string {
	mut parts := []string{cap: entries.len}
	for entry in entries {
		if entry is cx.Element {
			key := entry.name
			val := if entry.items.len == 1 {
				node_to_ast_json(entry.items[0])
			} else if entry.items.len == 0 {
				'null'
			} else {
				ast_json_array(entry.items)
			}
			parts << '${json_str(key)}:${val}'
		}
	}
	return '{${parts.join(',')}}'
}

// flatten_slots returns an Element-equivalent whose labelled-slot child
// elements (name prefixed with `__cx_slot:LABEL`) are renamed to the
// label so downstream AST-JSON emitters don't leak the synthetic
// prefix into the wire form. Other children pass through unchanged.
fn flatten_slots(e cx.Element) cx.Element {
	mut new_items := []cx.Node{cap: e.items.len}
	for it in e.items {
		if it is cx.Element && it.name.starts_with(cx_slot_prefix) {
			label := it.name[cx_slot_prefix.len..]
			new_items << cx.Element{
				name:  label
				attrs: it.attrs
				items: it.items
			}
		} else {
			new_items << it
		}
	}
	return cx.Element{
		name:  e.name
		attrs: e.attrs
		items: new_items
		meta:  e.meta
		table: e.table
	}
}

fn json_str(s string) string {
	mut result := '"'
	for b in s.bytes() {
		match b {
			`"`  { result += '\\"' }
			`\\` { result += '\\\\' }
			`\n` { result += '\\n' }
			`\r` { result += '\\r' }
			`\t` { result += '\\t' }
			else {
				if b < 0x20 {
					result += '\\u${b:04x}'
				} else {
					result += b.ascii_str()
				}
			}
		}
	}
	result += '"'
	return result
}

// ── YAML (Document-wrapped) ────────────────────────────────────────────────
//
// Wraps the program result in a `cx.Document` (lifting an anon
// top-level wrapper into a multi-element doc, or wrapping a single
// Element / ScalarNode in a synthetic `result` element) and calls
// `cx.emit_yaml` from the cx module.

fn render_yaml(n cx.Node) string {
	// Redact secrets before lifting to a Document (cxdm.md §12.2).
	doc := node_to_doc(redact_secrets(n))
	return cx.emit_yaml(doc)
}

// ── XML (Document-wrapped) ─────────────────────────────────────────────────

fn render_xml(n cx.Node) string {
	// D5: XML is the one structured target that preserves `[?meta]`
	// annotations losslessly — rewrite the inert `__cx_meta__` wrappers
	// into reserved `<cx:meta>` elements BEFORE redaction/lifting (the
	// other targets drop the annotation via redact_secrets). Redact
	// secrets before lifting to a Document (cxdm.md §12.2).
	doc := node_to_doc(redact_secrets(meta_to_xml_element(n)))
	return cx.emit_xml(doc)
}

// cx_meta_xml_name is the reserved XML element a `[?meta]` annotation
// serializes to (D5 / conversions.md §2.1).
const cx_meta_xml_name = 'cx:meta'

// meta_to_xml_element rewrites program-layer `[?meta]` wrappers
// (`__cx_meta__`) into a reserved `cx:meta` element for the XML target:
// `<cx:meta><cx:map>…annotation…</cx:map>INNER</cx:meta>`. The annotation
// map (a `__cx_map__` marker) becomes a cx-native MapNode and the inner
// value is marker-normalized via `flatten_node`, so the result emits and
// XML↔XML round-trips losslessly. Non-meta elements pass through with
// their children rewritten in place; non-element nodes are returned as-is.
fn meta_to_xml_element(n cx.Node) cx.Node {
	if n is cx.Element {
		if n.name == meta_marker_name {
			inner := if n.items.len >= 1 {
				flatten_node(n.items[0])
			} else {
				cx.Node(cx.TextNode{})
			}
			map_node := if n.items.len >= 2 && n.items[1] is cx.Element
				&& (n.items[1] as cx.Element).name == cx_map_name {
				map_marker_to_node(n.items[1] as cx.Element)
			} else {
				cx.Node(cx.MapNode{})
			}
			return cx.Element{
				name:  cx_meta_xml_name
				items: [map_node, inner]
			}
		}
		return cx.Element{
			...n
			items: n.items.map(meta_to_xml_element(it))
		}
	}
	return n
}

// node_to_doc lifts a program-result Node into a `cx.Document` so the
// existing cx-module emitters can consume it. The flattening rules
// match the program-result conventions described above on the JSON
// path; collection markers are mapped to cx-native SequenceNode /
// ArrayNode / MapNode.
//
// Both YAML and XML routes wrap top-level collection markers in a
// synthetic `result` element. YAML needs the wrapper (sem_document
// filters non-Element top-level nodes); XML used to take a hoisted
// bare-collection shape to dodge an emit_xml_inline_node SequenceNode-
// swallow bug, but commit 154beb61 fixed the emitter to handle nested
// collections correctly, so both targets now share one shape.
fn node_to_doc(n cx.Node) cx.Document {
	mut elements := []cx.Node{}
	match n {
		cx.Element {
			if n.name == '' {
				for it in n.items {
					elements << lift_to_top_level(it)
				}
			} else if n.name == cx_seq_name || n.name == cx_arr_name
			          || n.name == cx_map_name {
				elements << lift_to_top_level(n)
			} else {
				elements << flatten_slots(n)
			}
		}
		cx.ScalarNode {
			elements << cx.Element{
				name:  'result'
				items: [cx.Node(n)]
			}
		}
		cx.TextNode {
			elements << cx.Element{
				name:  'result'
				items: [cx.Node(n)]
			}
		}
		else {
			elements << cx.Element{ name: 'result' }
		}
	}
	return cx.Document{ elements: elements }
}

// lift_to_top_level converts a Node into a form suitable to live in
// `Document.elements`. Bare ScalarNode / TextNode get wrapped in an
// `item` element. Collection markers are rewritten into the cx-native
// SequenceNode / ArrayNode / MapNode and wrapped in a `result` element.
fn lift_to_top_level(n cx.Node) cx.Node {
	if n is cx.Element {
		if n.name == cx_seq_name {
			return cx.Element{
				name:  'result'
				items: [cx.Node(cx.SequenceNode{
					items: n.items.map(flatten_node(it))
				})]
			}
		}
		if n.name == cx_arr_name {
			return cx.Element{
				name:  'result'
				items: [cx.Node(cx.ArrayNode{
					items: n.items.map(flatten_node(it))
				})]
			}
		}
		if n.name == cx_map_name {
			return cx.Element{
				name:  'result'
				items: [map_marker_to_node(n)]
			}
		}
		return flatten_slots(n)
	}
	if n is cx.ScalarNode || n is cx.TextNode {
		return cx.Element{
			name:  'item'
			items: [n]
		}
	}
	return n
}

// flatten_node recursively rewrites collection markers and labelled
// slots inside a node tree so the canonical-form emitters see
// cx-native types. Used by lift_to_top_level when projecting a marker
// into a SequenceNode / ArrayNode item list.
fn flatten_node(n cx.Node) cx.Node {
	if n is cx.Element {
		if n.name == cx_seq_name {
			return cx.Node(cx.SequenceNode{
				items: n.items.map(flatten_node(it))
			})
		}
		if n.name == cx_arr_name {
			return cx.Node(cx.ArrayNode{
				items: n.items.map(flatten_node(it))
			})
		}
		if n.name == cx_map_name {
			return map_marker_to_node(n)
		}
		return flatten_slots(n)
	}
	return n
}

// map_marker_to_node converts a `__cx_map__` element (entries are
// child elements whose name is the key and whose body is the value)
// into a cx-native MapNode. All keys are typed as `string_type`; this
// matches the program evaluator's evaluation rule (`eval_map` only
// produces string-typed keys per `vcx/code/eval.v`).
fn map_marker_to_node(e cx.Element) cx.Node {
	mut entries := []cx.MapEntry{cap: e.items.len}
	for it in e.items {
		if it is cx.Element {
			val := if it.items.len == 1 {
				flatten_node(it.items[0])
			} else if it.items.len == 0 {
				cx.Node(cx.ScalarNode{
					data_type: .null_type
					value:     cx.ScalarValue(cx.NullValue{})
				})
			} else {
				// Multi-item map values render as a sequence so the
				// emitters render a well-formed nested value.
				cx.Node(cx.SequenceNode{
					items: it.items.map(flatten_node(it))
				})
			}
			entries << cx.MapEntry{
				key_type:  .string_type
				key_value: cx.ScalarValue(it.name)
				value:     val
			}
		}
	}
	return cx.Node(cx.MapNode{ entries: entries })
}

// ── CSV / TSV (sequence-of-records) ────────────────────────────────────────
//
// Only renders when the result shape is a sequence-of-elements with
// uniform names (the canonical "row" shape). Header order follows
// first-occurrence of attribute / scalar-body-key across the row set.
// Anything else falls back to a CXER0100 with a clear "shape not
// tabular" message — no faked output.

fn render_delimited(n cx.Node, delim string) !string {
	// A `:table` block carries its rows/cols in the `table` field; the
	// record-shape row extractor below doesn't understand it, so delegate a
	// table node to the cx-module delimited emitter — the SAME path (and
	// options) `cx --to=csv` / `--from=cx --to=csv` use, so eval and convert
	// emit byte-identical output for a pure-data table.
	if n is cx.Element {
		if _ := n.table_opt() {
			mut topts := cx.default_emit_options()
			topts.delimiter = delim[0]
			return cx.emit_delimited(cx.Document{ elements: [cx.Node(n)] }, topts)
		}
	}
	// Redact secrets before tabular extraction (cxdm.md §12.2).
	rows := extract_rows(redact_secrets(n)) or {
		return EvalError{
			code:    'cx-err:CXER0100'
			message: 'csv/tsv: result shape is not a sequence of records (${err.msg()})'
		}
	}
	if rows.len == 0 {
		return ''
	}
	// Collect header keys in first-occurrence order across all rows.
	mut headers := []string{}
	mut seen := map[string]bool{}
	for row in rows {
		for a in row.attrs {
			if !seen[a.name] {
				seen[a.name] = true
				headers << a.name
			}
		}
	}
	mut lines := []string{cap: rows.len + 1}
	lines << headers.map(escape_delim_field(it, delim)).join(delim)
	for row in rows {
		mut cells := []string{cap: headers.len}
		for h in headers {
			cells << escape_delim_field(row_attr_value(row, h), delim)
		}
		lines << cells.join(delim)
	}
	return lines.join('\n')
}

// extract_rows inspects a result Node and returns the list of "row"
// Elements when the shape is a uniform sequence-of-records. Returns
// an error otherwise. Accepted shapes:
//   • `__cx_seq__` / `__cx_arr__` of same-named Elements
//   • anon top-level wrapper of same-named Elements
//   • single Element whose body is a `__cx_seq__` / `__cx_arr__` of
//     same-named Elements (the common `[ok :rows (…)]` shape)
fn extract_rows(n cx.Node) ![]cx.Element {
	candidates := collect_row_candidates(n) or { return error(err.msg()) }
	if candidates.len == 0 {
		return error('no records in result')
	}
	first_name := candidates[0].name
	for r in candidates {
		if r.name != first_name {
			return error('records have heterogeneous names: ${first_name} vs ${r.name}')
		}
	}
	return candidates
}

fn collect_row_candidates(n cx.Node) ![]cx.Element {
	if n is cx.Element {
		if n.name == '' || n.name == cx_seq_name || n.name == cx_arr_name {
			return collect_elements(n.items)
		}
		// Single Element with a single seq/arr body item — peek through.
		if n.items.len == 1 {
			child := n.items[0]
			if child is cx.Element
			   && (child.name == cx_seq_name || child.name == cx_arr_name) {
				return collect_elements(child.items)
			}
		}
		// Single record on its own — degenerate one-row table.
		return [n]
	}
	return error('top-level result is not an element / sequence')
}

fn collect_elements(items []cx.Node) ![]cx.Element {
	mut out := []cx.Element{cap: items.len}
	for it in items {
		if it is cx.Element {
			if it.name.starts_with(cx_slot_prefix) {
				return error('row contains a labelled-slot child — not tabular')
			}
			out << it
		} else {
			return error('row is not an element')
		}
	}
	return out
}

fn row_attr_value(row cx.Element, key string) string {
	for a in row.attrs {
		if a.name == key {
			return scalar_value_text(a.value)
		}
	}
	return ''
}

fn scalar_value_text(v cx.ScalarValue) string {
	match v {
		string       { return v }
		i64          { return v.str() }
		f64          { return v.str() }
		bool         { return v.str() }
		cx.NullValue { return '' }
	}
}

fn escape_delim_field(s string, delim string) string {
	needs_quote := s.contains(delim) || s.contains('\n') || s.contains('\r')
		|| s.contains('"')
	if !needs_quote {
		return s
	}
	return '"${s.replace('"', '""')}"'
}
