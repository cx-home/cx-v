module cx

import strings
import os

// ── cx: self-host module ──────────────────────────────────────────────────────
//
// Per ADR 0023 §D1 and spec/modules/cx.md §1: the cx: namespace ships
// at v0.7.0 with all three tiers (Must / Should / Nice). This file
// implements the Must tier (DD1–DD10) plus the dispatch entry points
// for the Should / Nice tiers that DD13–DD22 will fill in.
//
// All Must-tier functions wrap an already-shipped V-core API:
//   cx:parse       → cx.parse (vcx/cx/parser.v:152)
//   cx:serialize   → cx_emit_cx_value_text (this file; thin wrap of emit_cx)
//   cx:canonical   → cx.cx_text_canonical (vcx/cx/tooling.v:42)
//   cx:hash        → cx.cx_text_hash (vcx/cx/tooling.v:53)
//   cx:diff        → cx.cx_text_diff (vcx/cx/diff.v:68) + diff_render_json + re-parse
//   cx:to-format   → cx.to_xml / to_json / to_yaml / to_toml / to_md / to_csv / to_tsv / to_psv / to_cx
//   cx:from-format → cx.from_xml / json_to_cx / yaml_to_cx / toml_to_cx / from_md / from_csv / from_tsv / from_psv / parse
//   cx:equal       → cx.cx_text_eq (vcx/cx/tooling.v:62) — semantic canonical equality
//   cx:select      → CXPath compile-then-evaluate (uses existing eval_path machinery)
//
// cx:patch is 🚧 at this row — the diff data model exists (vcx/cx/diff.v
// Change struct + ChangeKind enum) but a path-resolving AST mutator
// over CXLValue does not. The ADR 0023 budget was 1 session for DD6;
// honest accounting puts patch closer to 2-3 sessions given the AST
// shape mutation challenges in V's structural-enum-based Node type.
// DD6 carries the 🚧 mark; cx_patch raises cx-err:CXER0022 with a
// "not yet implemented" message that EE5 / DD11 work can grow into
// when an evaluator pass that needs patch surfaces.
//
// All Must-tier functions are Pure per spec/modules/cx.md §1.1. The
// EE1 catalog already records the per-function purity; EE4 enforcement
// reads through the catalog without inspecting the filter dispatch.

// ── EE4. [?cx pure-only] enforcement ─────────────────────────────────────────
//
// Per ADR 0023 §D5: under [?cx pure-only], calls to functions whose
// EE1-catalog purity is ReadOnly or SideEffect raise cx-err:CXER0040.
// fn:trace is the one documented exemption (XQuery 4.0 standard;
// load-bearing for pure-document debuggability — spec/modules/log.md
// §3 codifies this as the one carve-out).
//
// Split-on-colon convention: filter names like 'cx:hash' / 'log:info'
// split to ns='cx' / 'log', local='hash' / 'info'. Bare names like
// 'upper' / 'sum' are treated as ns='fn' (XQuery 4.0 standard
// library namespace). Unknown modules pass through without
// enforcement — the dispatch will raise a different error
// downstream (filter-not-in-set), keeping CXER0040 narrowly meaning
// "purity violation under pure-only" rather than "unknown function."

fn check_purity_gate(env &CXLEnv, fn_name string) ! {
	if !env.pure_only { return }
	// fn:trace exemption — XQuery 4.0 C17 + spec/modules/log.md §3.
	// Bare 'trace' (the XQuery shape) and explicit 'fn:trace' both
	// route here; both are exempt.
	if fn_name == 'trace' || fn_name == 'fn:trace' { return }
	// cx:eval / cx:render — M2 collision (spec/modules/cx.md §2.2).
	// Distinct error code (CXER0042) instead of the generic CXER0040
	// because the rejection carries spec-level "eval is unconditionally
	// refused under pure-only" semantics, not just a determinism mismatch.
	if fn_name == 'cx:eval' || fn_name == 'cx:render' {
		return error('cx-err:CXER0042\x1F${fn_name} is incompatible with [?cx pure-only] (mitigation M2)\x1F')
	}
	ns, local := purity_split_ns(fn_name)
	spec := function_spec(ns, local) or { return }  // unknown ns → no gate at v0.7.0
	if spec.purity == .pure_fn { return }
	purity_str := purity_label(spec.purity)
	return error('cx-err:CXER0040\x1F${purity_str} function "${fn_name}" called under [?cx pure-only]\x1F')
}

// check_activation_gate refuses calls to functions whose module is
// .on_declaration and has not been activated via [?cx use-module=...].
// At v0.7.0 every registered module is .always so the gate never
// fires; the framework is in place for v0.8.0 BaseX modules
// (file:, http:, hash:, random:, etc.) which will be on_declaration
// per ADR 0023 §D3. Unknown namespaces pass through (downstream
// "filter not in CXL set" owns that error).
fn check_activation_gate(env &CXLEnv, fn_name string) ! {
	ns, _ := purity_split_ns(fn_name)
	mod := module_spec(ns) or { return }
	if mod.activation == .always { return }
	if ns in env.declared_modules { return }
	return error('cx-err:CXER0032\x1Fmodule "${ns}" requires [?cx use-module=${ns}] before "${fn_name}" can be called\x1F')
}

fn purity_split_ns(name string) (string, string) {
	idx := name.index(':') or { return 'fn', name }
	return name[..idx], name[idx + 1..]
}

// cxl_value_to_cx_text serializes a CXLValue back to CX source text.
// Used by cx:serialize, cx:canonical, cx:hash, cx:diff, and the
// cx:to-format dispatch.
//
// Strategy:
//   * Empty sequence → empty string
//   * Single Element item → that element emitted as a one-element Document
//   * Single TextNode / ScalarNode / CommentNode / PINode item → wrap
//     in a synthetic root and emit (preserves quoting / type tagging)
//   * Single CXLScalar (atomic typed scalar) → emit its lexical form
//   * Multiple items or other CXLItem kinds → wrap in synthetic
//     #document Element and emit
//
// Scalars produce their canonical text form (e.g. CXLScalar{string,
// "hello"} → "hello", CXLScalar{int, 42} → "42"). CXLFunction and
// ArrayNode/MapNode use the readable-sentinel form per item_to_text;
// callers that pass functions to cx:serialize get the sentinel
// `[function arity=N]` rather than an error, consistent with cx's
// permissive coercion model.
fn cxl_value_to_cx_text(v CXLValue) string {
	if v.len == 0 { return '' }
	// Fast path: single Element item — emit directly as a document.
	if v.len == 1 {
		it := v[0]
		match it {
			Element {
				doc := Document{ elements: [Node(it)] }
				return emit_cx(doc)
			}
			CXLScalar {
				return scalar_value_str(it.value)
			}
			TextNode, ScalarNode, CommentNode, PINode, CXDirectiveNode,
			ArrayNode, MapNode {
				doc := Document{ elements: [Node(it)] }
				return emit_cx(doc)
			}
			CXLFunction {
				return '[function arity=${it.params.len}]'
			}
		}
	}
	// Multi-item sequence — wrap in synthetic document. Items that
	// aren't Node-compatible (CXLScalar, CXLFunction) fall back to
	// their item_to_text rendering to keep output well-formed.
	mut nodes := []Node{cap: v.len}
	for it in v {
		match it {
			Element { nodes << Node(it) }
			TextNode, ScalarNode, CommentNode, PINode, CXDirectiveNode,
			ArrayNode, MapNode { nodes << Node(it) }
			CXLScalar {
				nodes << Node(TextNode{ value: scalar_value_str(it.value) })
			}
			CXLFunction {
				nodes << Node(TextNode{ value: '[function arity=${it.params.len}]' })
			}
		}
	}
	doc := Document{ elements: nodes }
	return emit_cx(doc)
}

// cx_text_to_cxl_value parses CX source text and wraps the result as
// a CXLValue. Used by cx:parse and cx:from-format. Mirrors
// cxl_seq_from_doc but operates on a fresh parse rather than the
// evaluator's input document.
fn cx_text_to_cxl_value(text string) !CXLValue {
	doc := parse(text)!
	if doc.elements.len == 1 && doc.elements[0] is Element {
		return [CXLItem(doc.elements[0] as Element)]
	}
	if doc.elements.len == 0 {
		return CXLValue([]CXLItem{})
	}
	root := Element{ name: '#document', items: doc.elements }
	return [CXLItem(root)]
}

// ── DD1. cx:parse(text) → cx-value ─────────────────────────────────────────────

fn filter_cx_parse(args []CXLValue) !CXLValue {
	if args.len < 1 { return error('cx-err:CXER0020\x1Fcx:parse expects 1 argument (text)\x1F') }
	text := value_to_string(args[0])
	return cx_text_to_cxl_value(text) or {
		return error('cx-err:CXER0020\x1Fcx:parse malformed source: ${err.msg()}\x1F')
	}
}

// ── DD2. cx:serialize(value) → text ────────────────────────────────────────────

fn filter_cx_serialize(args []CXLValue) !CXLValue {
	if args.len < 1 { return error('cx-err:CXER0021\x1Fcx:serialize expects 1 argument (value)\x1F') }
	text := cxl_value_to_cx_text(args[0])
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(text) })]
}

// ── DD3. cx:canonical(value) → text in canonical form ─────────────────────────

fn filter_cx_canonical(args []CXLValue) !CXLValue {
	if args.len < 1 { return error('cx-err:CXER0021\x1Fcx:canonical expects 1 argument (value)\x1F') }
	source := cxl_value_to_cx_text(args[0])
	if source == '' {
		return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue('') })]
	}
	canonical := cx_text_canonical(source) or {
		return error('cx-err:CXER0021\x1Fcx:canonical failed: ${err.msg()}\x1F')
	}
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(canonical) })]
}

// ── DD4. cx:hash(value) → SHA-256 hex of strict canonical bytes ────────────────

fn filter_cx_hash(args []CXLValue) !CXLValue {
	if args.len < 1 { return error('cx-err:CXER0021\x1Fcx:hash expects 1 argument (value)\x1F') }
	source := cxl_value_to_cx_text(args[0])
	if source == '' {
		// Hash of the empty document is the canonical empty form's hash.
		// cx_text_hash handles this directly via cx_text_canonical.
	}
	digest := cx_text_hash(source) or {
		return error('cx-err:CXER0021\x1Fcx:hash failed: ${err.msg()}\x1F')
	}
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(digest) })]
}

// ── DD5. cx:diff(a, b) → cx-value (diff doc) ──────────────────────────────────

fn filter_cx_diff(args []CXLValue) !CXLValue {
	if args.len < 2 {
		return error('cx-err:CXER0021\x1Fcx:diff expects 2 arguments (a, b)\x1F')
	}
	src_a := cxl_value_to_cx_text(args[0])
	src_b := cxl_value_to_cx_text(args[1])
	changes := cx_text_diff(src_a, src_b) or {
		return error('cx-err:CXER0021\x1Fcx:diff failed: ${err.msg()}\x1F')
	}
	// Render as JSON, then re-parse as cx-value so callers can pipe
	// the diff through CXPath / map: / array: operations. The JSON
	// form is the data-bearing representation per spec/modules/cx.md
	// §1.1 + ADR 0012; unified / summary text forms are caller-side
	// concerns via fn:serialize-json on the result.
	json_str := diff_render_json(changes)
	cx_src := json_to_cx(json_str) or {
		return error('cx-err:CXER0021\x1Fcx:diff render failed: ${err.msg()}\x1F')
	}
	return cx_text_to_cxl_value(cx_src) or {
		return error('cx-err:CXER0021\x1Fcx:diff re-parse failed: ${err.msg()}\x1F')
	}
}

// ── DD6. cx:patch(value, diff) → cx-value ────────────────────────────────
//
// Apply a diff doc (sequence of `[item kind=... path=... before=...
// after=...]` records per cx:diff) to a cx-value. See vcx/cx/patch.v
// for the path resolver + per-kind handlers.
//
// CXER0022 surfaces on: path-not-found, unknown kind, before-value
// mismatch, malformed diff shape. Per spec/modules/cx.md §4 this is
// the "diff cannot apply to value (conflict)" error.
fn filter_cx_patch(args []CXLValue) !CXLValue {
	if args.len < 2 {
		return error('cx-err:CXER0022\x1Fcx:patch expects 2 arguments (value, diff)\x1F')
	}
	value := args[0]
	diff_v := args[1]
	changes := extract_patch_changes(diff_v) or {
		return error('cx-err:CXER0022\x1Fcx:patch diff doc malformed: ${err.msg()}\x1F')
	}
	return patch_value(value, changes) or {
		return error(err.msg())
	}
}

// ── DD7. cx:to-format(value, fmt) → text ──────────────────────────────────────

fn filter_cx_to_format(args []CXLValue) !CXLValue {
	if args.len < 2 {
		return error('cx-err:CXER0023\x1Fcx:to-format expects 2 arguments (value, fmt)\x1F')
	}
	fmt_str := value_to_string(args[1]).to_lower()
	source := cxl_value_to_cx_text(args[0])
	out := match fmt_str {
		'cx' {
			source
		}
		'xml' {
			to_xml(source) or {
				return error('cx-err:CXER0024\x1Fcx:to-format xml failed: ${err.msg()}\x1F')
			}
		}
		'json' {
			to_json(source) or {
				return error('cx-err:CXER0024\x1Fcx:to-format json failed: ${err.msg()}\x1F')
			}
		}
		'yaml' {
			to_yaml(source) or {
				return error('cx-err:CXER0024\x1Fcx:to-format yaml failed: ${err.msg()}\x1F')
			}
		}
		'toml' {
			to_toml(source) or {
				return error('cx-err:CXER0024\x1Fcx:to-format toml failed: ${err.msg()}\x1F')
			}
		}
		'md', 'markdown' {
			to_md(source) or {
				return error('cx-err:CXER0024\x1Fcx:to-format md failed: ${err.msg()}\x1F')
			}
		}
		'csv' {
			to_csv(source) or {
				return error('cx-err:CXER0024\x1Fcx:to-format csv failed: ${err.msg()}\x1F')
			}
		}
		'tsv' {
			to_tsv(source) or {
				return error('cx-err:CXER0024\x1Fcx:to-format tsv failed: ${err.msg()}\x1F')
			}
		}
		'psv' {
			to_psv(source) or {
				return error('cx-err:CXER0024\x1Fcx:to-format psv failed: ${err.msg()}\x1F')
			}
		}
		else {
			return error('cx-err:CXER0023\x1Fcx:to-format unknown format "${fmt_str}" (use cx|xml|json|yaml|toml|md|csv|tsv|psv)\x1F')
		}
	}
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(out) })]
}

// ── DD9. cx:equal(a, b) → boolean (semantic, canonical-aware) ─────────────────
//
// Distinct from fn:deep-equal (XQuery 4.0 standard, atomic-level
// comparison). cx:equal canonicalizes both sides via cx_text_canonical
// before comparison — attribute order and presentation-only
// differences collapse; semantic equality is the property the function
// exposes. Both arguments must be serializable cx-values; CXLFunction
// arguments yield false (function values have no canonical form at
// v0.7.0).

fn filter_cx_equal(args []CXLValue) !CXLValue {
	if args.len < 2 {
		return error('cx-err:CXER0021\x1Fcx:equal expects 2 arguments (a, b)\x1F')
	}
	src_a := cxl_value_to_cx_text(args[0])
	src_b := cxl_value_to_cx_text(args[1])
	eq := cx_text_eq(src_a, src_b) or {
		return error('cx-err:CXER0021\x1Fcx:equal failed: ${err.msg()}\x1F')
	}
	return [CXLItem(CXLScalar{ data_type: .bool_type, value: ScalarValue(eq) })]
}

// ── DD10. cx:select(value, path) → sequence (runtime CXPath) ──────────────────
//
// Compile a CXPath string at runtime and evaluate it against the given
// cx-value. The compile-time [?= EXPR] interpolation uses the same
// CXPath engine but binds at parse time; cx:select enables data-
// driven query construction where the path is itself an expression.
//
// Implementation: swap env.context to args[0], evaluate the path
// string as a CXPath expression (eval_expr handles the path-vs-
// literal-vs-comparison disambiguation), restore env.context. The
// path argument must be a string scalar; non-string types are
// atomized via value_to_string per cx's permissive coercion model.

// ── DD15. cx:anchors(value) → sequence of QName ──────────────────────────────
//
// Walks every element in the value, collecting non-empty `anchor`
// metadata into a deduplicated sequence of string scalars. Returns
// the empty sequence when no anchors are present (or the value is
// empty / non-element).
fn filter_cx_anchors(args []CXLValue) !CXLValue {
	if args.len < 1 { return CXLValue([]CXLItem{}) }
	mut seen := map[string]bool{}
	mut out := []CXLItem{}
	collect_anchors_from_value(args[0], mut seen, mut out)
	return CXLValue(out)
}

fn collect_anchors_from_value(v CXLValue, mut seen map[string]bool, mut out []CXLItem) {
	for it in v {
		if it is Element {
			collect_anchors_from_node(it as Element, mut seen, mut out)
		}
	}
}

fn collect_anchors_from_node(el Element, mut seen map[string]bool, mut out []CXLItem) {
	if a := el.anchor {
		if a != '' && a !in seen {
			seen[a] = true
			out << CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(a) })
		}
	}
	for child in el.items {
		if child is Element {
			collect_anchors_from_node(child as Element, mut seen, mut out)
		}
	}
}

// ── DD16. cx:ids(value) → sequence of string ─────────────────────────────────

fn filter_cx_ids(args []CXLValue) !CXLValue {
	if args.len < 1 { return CXLValue([]CXLItem{}) }
	mut seen := map[string]bool{}
	mut out := []CXLItem{}
	collect_ids_from_value(args[0], mut seen, mut out)
	return CXLValue(out)
}

fn collect_ids_from_value(v CXLValue, mut seen map[string]bool, mut out []CXLItem) {
	for it in v {
		if it is Element {
			collect_ids_from_node(it as Element, mut seen, mut out)
		}
	}
}

fn collect_ids_from_node(el Element, mut seen map[string]bool, mut out []CXLItem) {
	if id := el.id {
		if id != '' && id !in seen {
			seen[id] = true
			out << CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(id) })
		}
	}
	for child in el.items {
		if child is Element {
			collect_ids_from_node(child as Element, mut seen, mut out)
		}
	}
}

// ── DD17. cx:references(value) → sequence of map { id, source-path } ─────────
//
// Each entry maps the referenced ID string to the source-path location
// expressed as a CXPath-ish element name (full CXPath path generation
// arrives with the v0.7.x include/anchor work). source-path is best-
// effort at v0.7.0; the contract is the (id, source-path) tuple shape,
// not the exact path syntax.
fn filter_cx_references(args []CXLValue) !CXLValue {
	if args.len < 1 { return CXLValue([]CXLItem{}) }
	mut out := []CXLItem{}
	collect_refs_from_value(args[0], '', mut out)
	return CXLValue(out)
}

fn collect_refs_from_value(v CXLValue, parent_path string, mut out []CXLItem) {
	for it in v {
		if it is Element {
			collect_refs_from_node(it as Element, parent_path, mut out)
		}
	}
}

fn collect_refs_from_node(el Element, parent_path string, mut out []CXLItem) {
	path := if parent_path == '' { el.name } else { '${parent_path}/${el.name}' }
	for a in el.attrs {
		if a.is_ref {
			ref_id := scalar_value_str(a.value)
			entry := MapNode{
				entries: [
					MapEntry{
						key_type:   .string_type
						key_value:  ScalarValue('id')
						value:      Node(ScalarNode{ data_type: .string_type, value: ScalarValue(ref_id) })
					},
					MapEntry{
						key_type:   .string_type
						key_value:  ScalarValue('source-path')
						value:      Node(ScalarNode{ data_type: .string_type, value: ScalarValue('${path}/@${a.name}') })
					},
				]
			}
			out << CXLItem(entry)
		}
	}
	if br := el.body_ref {
		entry := MapNode{
			entries: [
				MapEntry{
					key_type:   .string_type
					key_value:  ScalarValue('id')
					value:      Node(ScalarNode{ data_type: .string_type, value: ScalarValue(br) })
				},
				MapEntry{
					key_type:   .string_type
					key_value:  ScalarValue('source-path')
					value:      Node(ScalarNode{ data_type: .string_type, value: ScalarValue(path) })
				},
			]
		}
		out << CXLItem(entry)
	}
	for child in el.items {
		if child is Element {
			collect_refs_from_node(child as Element, path, mut out)
		}
	}
}

// ── DD20. cx:strip-comments(value) → cx-value ────────────────────────────────

fn filter_cx_strip_comments(args []CXLValue) !CXLValue {
	if args.len < 1 { return CXLValue([]CXLItem{}) }
	mut out := []CXLItem{}
	for it in args[0] {
		if it is CommentNode { continue }
		if it is Element {
			out << CXLItem(strip_comments_from_element(it as Element))
		} else {
			out << it
		}
	}
	return CXLValue(out)
}

fn strip_comments_from_element(el Element) Element {
	mut new_items := []Node{cap: el.items.len}
	for child in el.items {
		if child is CommentNode { continue }
		if child is Element {
			new_items << Node(strip_comments_from_element(child as Element))
		} else {
			new_items << child
		}
	}
	return Element{
		name:      el.name
		anchor:    el.anchor
		merge:     el.merge
		data_type: el.data_type
		attrs:     el.attrs
		items:     new_items
		id:        el.id
		body_ref:  el.body_ref
	}
}

// ── DD21. cx:strip-attrs(value, pattern) → cx-value ──────────────────────────
//
// Removes attributes whose name matches `pattern`. v0.7.0 uses simple
// glob-ish matching: `*` matches zero or more chars, exact otherwise.
// Full RE2-pattern matching (per spec/modules/cx.md §1.3) arrives with
// the cx:strip-attrs-regex follow-up; v0.7.0 covers the
// "strip every attribute named X" and "strip every attribute starting
// with prefix-*" use cases that motivated the function.
fn filter_cx_strip_attrs(args []CXLValue) !CXLValue {
	if args.len < 2 {
		return error('cx-err:CXER0031\x1Fcx:strip-attrs expects 2 arguments (value, pattern)\x1F')
	}
	pattern := value_to_string(args[1])
	if pattern == '' {
		return error('cx-err:CXER0031\x1Fcx:strip-attrs pattern is empty\x1F')
	}
	mut out := []CXLItem{}
	for it in args[0] {
		if it is Element {
			out << CXLItem(strip_attrs_from_element(it as Element, pattern))
		} else {
			out << it
		}
	}
	return CXLValue(out)
}

fn strip_attrs_from_element(el Element, pattern string) Element {
	mut new_attrs := []Attribute{cap: el.attrs.len}
	for a in el.attrs {
		if attr_name_matches_pattern(a.name, pattern) { continue }
		new_attrs << a
	}
	mut new_items := []Node{cap: el.items.len}
	for child in el.items {
		if child is Element {
			new_items << Node(strip_attrs_from_element(child as Element, pattern))
		} else {
			new_items << child
		}
	}
	return Element{
		name:      el.name
		anchor:    el.anchor
		merge:     el.merge
		data_type: el.data_type
		attrs:     new_attrs
		items:     new_items
		id:        el.id
		body_ref:  el.body_ref
	}
}

fn attr_name_matches_pattern(name string, pattern string) bool {
	if pattern == '*' { return true }
	if pattern.ends_with('*') && !pattern.starts_with('*') {
		prefix := pattern[..pattern.len - 1]
		return name.starts_with(prefix)
	}
	if pattern.starts_with('*') && !pattern.ends_with('*') {
		suffix := pattern[1..]
		return name.ends_with(suffix)
	}
	if pattern.starts_with('*') && pattern.ends_with('*') {
		inner := pattern[1..pattern.len - 1]
		return name.contains(inner)
	}
	return name == pattern
}

// ── DD22. cx:pretty-print(value, options?) → text ────────────────────────────
//
// Wraps emit_cx (lossless, indented form). Options at v0.7.0 are
// advisory — emit_cx produces the canonical pretty form per
// spec/cx_text.md. Future options (indent, max-line-length, sort-
// attrs, strip-comments) land alongside the pretty-print engine's
// width control work.
fn filter_cx_pretty_print(args []CXLValue) !CXLValue {
	if args.len < 1 {
		return error('cx-err:CXER0021\x1Fcx:pretty-print expects at least 1 argument (value)\x1F')
	}
	source := cxl_value_to_cx_text(args[0])
	pretty := cx_text_fmt(source) or {
		return error('cx-err:CXER0021\x1Fcx:pretty-print failed: ${err.msg()}\x1F')
	}
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(pretty) })]
}

// ── DD14. cx:validate(value, schema) → diagnostic sequence ───────────────────
//
// Wraps the cxs schema validator (vcx/cx/schema.v / cabi.v cx_validate).
// Each diagnostic becomes a MapNode with `level` + `message` + `path`
// keys; full diagnostic-payload mapping (per spec/schema.md §10)
// matures alongside the v0.7.0 conformance suite. Empty diagnostic
// sequence ⇔ valid value.
fn filter_cx_validate(args []CXLValue) !CXLValue {
	if args.len < 2 {
		return error('cx-err:CXER0021\x1Fcx:validate expects 2 arguments (value, schema)\x1F')
	}
	doc_src := cxl_value_to_cx_text(args[0])
	schema_src := cxl_value_to_cx_text(args[1])
	doc := parse(doc_src) or {
		return error('cx-err:CXER0020\x1Fcx:validate doc parse failed: ${err.msg()}\x1F')
	}
	report := validate(doc, schema_src, ValidateOptions{}) or {
		return error('cx-err:CXER0021\x1Fcx:validate schema failed: ${err.msg()}\x1F')
	}
	mut out := []CXLItem{}
	for d in report.diagnostics {
		sev_str := match d.severity {
			.info           { 'info' }
			.warn           { 'warn' }
			.error_severity { 'error' }
		}
		entry := MapNode{
			entries: [
				MapEntry{
					key_type:  .string_type
					key_value: ScalarValue('code')
					value:     Node(ScalarNode{ data_type: .string_type, value: ScalarValue(d.code) })
				},
				MapEntry{
					key_type:  .string_type
					key_value: ScalarValue('level')
					value:     Node(ScalarNode{ data_type: .string_type, value: ScalarValue(sev_str) })
				},
				MapEntry{
					key_type:  .string_type
					key_value: ScalarValue('message')
					value:     Node(ScalarNode{ data_type: .string_type, value: ScalarValue(d.message) })
				},
			]
		}
		out << CXLItem(entry)
	}
	return CXLValue(out)
}

// ── DD11. cx:eval(source, context, options?) — gated sandboxed eval ──────────
//
// Per ADR 0023 §D6 (M1–M5) and the §M5 amendment (options-map third
// argument). v0.7.0 ships all five mitigations + sandboxed evaluation
// over a context map:
//
//   M1 (allow-eval gate)         ✅ — CXER0041 (caller's env)
//   M2 (pure-only collision)     ✅ — CXER0042 (dispatch + parse-time)
//   M3 (sandboxed by context)    ✅ — fresh bindings/defs in sandbox;
//                                     caller's ?def/?fn/?let scope is NOT
//                                     inherited. Only the context-map
//                                     keys are visible in the fragment
//   M4 (module pass-through)     ✅ — CXER0043; fragment's [?cx
//                                     use-module=...] may NOT name a
//                                     module the caller did not activate
//   M5 (recursion-depth + origin) ✅ — CXER0044; options-map carries
//                                      max-depth + origin-uri/line/col;
//                                      $err:eval-origin binding plumbed
//                                      through parse_cx_error / eval_try
//
// The eval pipeline materializes the fragment's output text in a fresh
// builder, then re-parses it as a cx-value (per ADR 0023 §D1). The
// re-parse step is what makes cx:eval distinct from cx:render — the
// render variant returns the raw text scalar without re-parsing.
//
// What's inherited vs sandboxed:
//   INHERITED  : input doc, context value, output target/strict, log:
//                config + stack, hook seat, security caps (call_depth /
//                sequence_len), test_mode, declared_modules,
//                allow_eval (so nested cx:eval works), max_eval_depth
//   SANDBOXED  : bindings (start empty; populated only from ctx map),
//                defs (start empty — caller's ?def NOT visible),
//                eval_depth (+= 1), out (fresh builder),
//                stream_cb (always none — eval produces a value, not
//                a stream; caller drains the resulting value).

fn filter_cx_eval(args []CXLValue, mut env CXLEnv) !CXLValue {
	if args.len < 2 {
		return error('cx-err:CXER0021\x1Fcx:eval expects 2 or 3 arguments (source, context, options?)\x1F')
	}
	source := value_to_string(args[0])
	ctx_value := args[1]
	options := if args.len >= 3 { ?CXLValue(args[2]) } else { ?CXLValue(none) }
	text := cx_eval_engine(source, ctx_value, options, mut env) or {
		return cx_eval_attach_origin(err.msg(), options)
	}
	// Re-parse the fragment output → cx-value (per ADR 0023 §D1).
	// Empty output → empty sequence. Output that's valid cx text
	// (`[name attrs body]` shape) → that parsed cx-value. Output that
	// is plain text or scalar (`hello`, `42`) → wrapped as a string
	// scalar — the eval's output bytes ARE the value bytes.
	if text == '' { return CXLValue([]CXLItem{}) }
	if v := cx_text_to_cxl_value(text) {
		return v
	}
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(text) })]
}

// DD12. cx:render(template, context) → text — sugar over cx:eval +
// cx:serialize. Same gate set; output is the raw rendered text without
// the cx:eval re-parse step.
fn filter_cx_render(args []CXLValue, mut env CXLEnv) !CXLValue {
	if args.len < 2 {
		return error('cx-err:CXER0021\x1Fcx:render expects 2 or 3 arguments (template, context, options?)\x1F')
	}
	source := value_to_string(args[0])
	ctx_value := args[1]
	options := if args.len >= 3 { ?CXLValue(args[2]) } else { ?CXLValue(none) }
	text := cx_eval_engine(source, ctx_value, options, mut env) or {
		return cx_eval_attach_origin(err.msg(), options)
	}
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(text) })]
}

// cx_eval_engine runs the gated sandboxed eval pipeline shared by
// cx:eval and cx:render. Returns the raw output text; callers choose
// whether to re-parse to a cx-value (cx:eval) or wrap as a string
// scalar (cx:render).
fn cx_eval_engine(source string, ctx_value CXLValue, options ?CXLValue, mut env CXLEnv) !string {
	// M2 — pure-only collision (dispatch-time fallback if the parse-
	// time hoist in apply_program_config didn't fire — eg. if the
	// caller is itself an evaluator using the engine directly).
	if env.pure_only {
		return error('cx-err:CXER0042\x1Fcx:eval is incompatible with [?cx pure-only] (mitigation M2)\x1F')
	}
	// M1 — allow-eval gate.
	if !env.allow_eval {
		return error('cx-err:CXER0041\x1Fcx:eval requires [?cx allow-eval=true] at document head (mitigation M1)\x1F')
	}
	// M5 — recursion-depth check. options-map's "max-depth" overrides
	// env.max_eval_depth per-call.
	mut effective_max := env.max_eval_depth
	if opts := options {
		if max_override := lookup_int_in_map(opts, 'max-depth') {
			if max_override > 0 { effective_max = max_override }
		}
	}
	if env.eval_depth >= effective_max {
		return error('cx-err:CXER0044\x1Fcx:eval recursion depth ${env.eval_depth} exceeded max ${effective_max} (mitigation M5)\x1F')
	}
	// Parse the fragment source. Parse failure is treated as a
	// cx:parse-class error (CXER0020) because the input is cx text.
	prog_doc := parse(source) or {
		return error('cx-err:CXER0020\x1Fcx:eval source parse failed: ${err.msg()}\x1F')
	}
	// M4 — module pass-through restrictive. Vet the fragment's prolog
	// for [?cx use-module=...] directives. Any module not in the
	// caller's declared_modules set raises CXER0043.
	check_eval_module_widening(prog_doc, env)!
	// Build M3 sandbox. Fresh bindings + defs. Context map (args[1])
	// populates initial bindings. Everything else inherits.
	mut sandbox := CXLEnv{
		input:             env.input
		target:            env.target
		strict:            env.strict
		context:           env.context
		bindings:          map[string]CXLValue{}   // M3: caller's ?for/?let/?with NOT visible
		defs:              map[string]TemplateDef{} // M3: caller's ?def NOT visible
		out:               strings.new_builder(256)
		stream_cb:         none                     // eval produces a value; no streaming
		flush_after_bytes: 0
		call_depth:        0
		max_call_depth:    env.max_call_depth
		max_sequence_len:  env.max_sequence_len
		hook:              env.hook
		log_level:         env.log_level
		log_format:        env.log_format
		log_output:        env.log_output
		test_mode:         env.test_mode
		log_context_stack: env.log_context_stack.clone()
		pure_only:         env.pure_only
		declared_modules:  env.declared_modules.clone()
		allow_eval:        env.allow_eval
		max_eval_depth:    effective_max
		eval_depth:        env.eval_depth + 1
	}
	// Pre-populate context-map keys into sandbox bindings (M3 — the
	// fragment sees only these names as bound variables, plus whatever
	// it defines itself via ?def / ?for / ?let).
	if ctx_value.len > 0 {
		ctx_item := ctx_value[0]
		if ctx_item is MapNode {
			for entry in (ctx_item as MapNode).entries {
				key := scalar_value_str(entry.key_value)
				if key == '' { continue }
				sandbox.bindings[key] = node_to_cxl_value(entry.value)
			}
		}
	}
	// Apply fragment's own prolog (output-target, log-*, allow-eval,
	// use-module additions are no-ops since we vetted no widening
	// above, etc.).
	apply_program_config(prog_doc, mut sandbox)!
	// Evaluate.
	for n in prog_doc.prolog { eval_node(n, mut sandbox)! }
	for n in prog_doc.elements { eval_node(n, mut sandbox)! }
	return sandbox.out.str()
}

// check_eval_module_widening walks the fragment's prolog and raises
// CXER0043 if it activates any module the caller has not activated
// (mitigation M4 per spec/modules/cx.md §2.4).
fn check_eval_module_widening(prog Document, env &CXLEnv) ! {
	for n in prog.prolog {
		if n is CXDirectiveNode {
			for a in n.attrs {
				if a.name == 'use-module' {
					v := scalar_value_str(a.value)
					for name in v.split(',') {
						trimmed := name.trim_space()
						if trimmed == '' { continue }
						if trimmed in env.declared_modules { continue }
						return error('cx-err:CXER0043\x1Fcx:eval fragment widens module set: "${trimmed}" not in caller\'s active modules (mitigation M4)\x1F')
					}
				}
			}
		}
	}
}

// node_to_cxl_value converts a single AST Node (the value side of a
// MapEntry, used by cx:eval's context-map population) into the
// CXLValue shape the binding scope expects. Most node kinds wrap
// into a single-item sequence; SequenceNode flattens into multiple
// items.
fn node_to_cxl_value(n Node) CXLValue {
	match n {
		Element          { return [CXLItem(n)] }
		ScalarNode       { return [CXLItem(CXLScalar{ data_type: n.data_type, value: n.value })] }
		TextNode         { return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(n.value) })] }
		ArrayNode        { return [CXLItem(n)] }
		MapNode          { return [CXLItem(n)] }
		CommentNode      { return [CXLItem(n)] }
		PINode           { return [CXLItem(n)] }
		CXDirectiveNode  { return [CXLItem(n)] }
		SequenceNode     {
			mut out := []CXLItem{}
			for it in n.items {
				inner := node_to_cxl_value(it)
				for x in inner { out << x }
			}
			return CXLValue(out)
		}
		else { return CXLValue([]CXLItem{}) }
	}
}

// cx_eval_attach_origin enriches a cx-err: error message with the
// $err:eval-origin payload extracted from the options-map (origin-uri,
// origin-line, origin-col). The payload format is a compact JSON-ish
// fragment carried in a 4th \x1F-separated field of the cx-err: prefix
// string. parse_cx_error decodes it; eval_try binds it as
// $err:eval-origin in the catch handler.
//
// When the options map lacks origin keys, the payload is the synthetic
// form `{"synthetic":true,"eval-depth":N}` per ADR 0023 §M5.
fn cx_eval_attach_origin(msg string, options ?CXLValue) IError {
	uri := if opts := options { lookup_string_in_map(opts, 'origin-uri') or { '' } } else { '' }
	line := if opts := options { lookup_int_in_map(opts, 'origin-line') or { 0 } } else { 0 }
	col := if opts := options { lookup_int_in_map(opts, 'origin-col') or { 0 } } else { 0 }
	mut payload := ''
	if uri != '' || line > 0 || col > 0 {
		payload = '{"uri":"${escape_origin_string(uri)}","line":${line},"column":${col}}'
	} else {
		payload = '{"synthetic":true}'
	}
	// If the error is already a cx-err: structured form, append the
	// origin as a 4th field. Otherwise wrap as a CXER0000 generic.
	mut s := msg
	if s.starts_with('cxl: ') { s = s[5..] }
	if s.starts_with('cx-err:') {
		// Check existing field count; if origin already present, leave
		// untouched (nested cx:eval may have set its own origin already).
		us := u8(0x1f).ascii_str()
		parts := s['cx-err:'.len..].split(us)
		if parts.len >= 4 {
			return error(msg)
		}
		// Pad to 3 fields, then append origin as 4th.
		code := if parts.len >= 1 { parts[0] } else { 'CXER0000' }
		desc := if parts.len >= 2 { parts[1] } else { '' }
		value := if parts.len >= 3 { parts[2] } else { '' }
		return error('cx-err:${code}\x1F${desc}\x1F${value}\x1F${payload}')
	}
	return error('cx-err:CXER0000\x1F${s}\x1F\x1F${payload}')
}

fn escape_origin_string(s string) string {
	mut b := strings.new_builder(s.len + 4)
	for c in s {
		match c {
			`"`  { b.write_string('\\"') }
			`\\` { b.write_string('\\\\') }
			`\n` { b.write_string('\\n') }
			`\r` { b.write_string('\\r') }
			else { b.write_u8(c) }
		}
	}
	return b.str()
}

// lookup_int_in_map extracts an integer-valued entry from a MapNode
// carried in a single-item CXLValue. Used for cx:eval's options-map
// third argument. Returns none when the value is missing, the
// container isn't a map, or the entry's value isn't integer-typed.
fn lookup_int_in_map(v CXLValue, key string) ?int {
	if v.len == 0 { return none }
	it := v[0]
	if it !is MapNode { return none }
	mn := it as MapNode
	for entry in mn.entries {
		if scalar_value_str(entry.key_value) == key {
			val_node := entry.value
			if val_node is ScalarNode {
				sv := val_node.value
				if sv is i64 { return int(sv as i64) }
			}
			if val_node is TextNode {
				return val_node.value.int()
			}
		}
	}
	return none
}

// lookup_string_in_map extracts a string-valued entry from a MapNode
// carried in a single-item CXLValue. Used for cx:eval's options-map
// origin-uri key.
fn lookup_string_in_map(v CXLValue, key string) ?string {
	if v.len == 0 { return none }
	it := v[0]
	if it !is MapNode { return none }
	mn := it as MapNode
	for entry in mn.entries {
		if scalar_value_str(entry.key_value) == key {
			val_node := entry.value
			if val_node is ScalarNode {
				return scalar_value_str(val_node.value)
			}
			if val_node is TextNode {
				return val_node.value
			}
		}
	}
	return none
}

// ── DD13 / DD18 / DD19 — Should/Nice-tier engines ────────────────────────────
//
// schema-of (DD13): cxs schema inference over the value — see
// filter_cx_schema_of below.
//
// resolve-includes (DD18): wraps the V-core resolve_includes_doc
// engine (GG1 row at v0_7_0_status.md, spec/include.md §1-§8) — see
// filter_cx_resolve_includes below.
//
// merge (DD19): three-policy semantic merge over anchor-aware ASTs —
// see merge_values / merge_elements below.

// DD13 (ADR 0023 §D1 Should tier): infer a cxs schema from a
// cx-value. Walks the element tree gathering per-name attribute and
// child-element observations, rolls up cardinalities and dataType
// unions, emits a cxs document per spec/schema.md §2.
//
// v0.7.0 scope:
//   * Type declarations for every unique element name reachable
//     from the root, in first-seen order.
//   * `[body :elem]` for elements with element children only;
//     `[body :<scalar-type>]` for single-Scalar bodies (using the
//     dataType union when instances differ — falling back to :string);
//     `[body :string]` for text-only bodies; `[body :mixed]` for
//     elements with both text and element children.
//   * `[attr <name> :<type>]` per attribute. `:req` set when the
//     attribute appears on every instance; `:opt` (omitted from
//     output) when at least one instance lacks it.
//   * `[elem <name> :card='<min>..<max>']` per child element. Min /
//     max derived from per-instance counts across all parent
//     instances. Max=='*' when ≥ 2 occurrences observed; max=='1'
//     when ≤ 1 across all instances. Min=='0' when at least one
//     parent instance lacks the child; Min=='1' otherwise.
//
// Out of scope for v0.7.0 (filed for v0.7.x extension):
//   * `[check ...]` constraint inference (range / pattern / enum)
//   * Anchor / merge inheritance rolled into the schema shape
//   * Open / strict / closed schema-mode inference (always emits
//     open per spec §9 default; users tighten manually)
//   * Cross-instance type unions beyond a fall-through to :string
fn filter_cx_schema_of(args []CXLValue) !CXLValue {
	if args.len < 1 {
		return error('cx-err:CXER0021\x1Fcx:schema-of expects 1 argument (value)\x1F')
	}
	// Find the root element. The value may be a single Element item,
	// a multi-item sequence (synthetic #document), or an empty value.
	v := args[0]
	if v.len == 0 {
		return error('cx-err:CXER0021\x1Fcx:schema-of: empty cx-value has no schema\x1F')
	}
	mut root_el := ?Element(none)
	if v.len == 1 {
		first := v[0]
		if first is Element {
			root_el = first
		}
	}
	if root_el == none {
		// Multi-item or non-Element value: synthesize a #document
		// root and infer its schema (this matches how cx_text_to_cxl_value
		// wraps multi-item docs).
		mut items := []Node{cap: v.len}
		for it in v {
			match it {
				Element { items << Node(it) }
				TextNode, ScalarNode, CommentNode, PINode, CXDirectiveNode,
				ArrayNode, MapNode { items << Node(it) }
				else {}
			}
		}
		root_el = ?Element(Element{ name: '#document', items: items })
	}
	root := root_el or {
		return error('cx-err:CXER0021\x1Fcx:schema-of: value did not project to an Element\x1F')
	}
	mut state := SchemaInferState{
		order:    []
		per_name: map[string]ElementShape{}
	}
	walk_for_schema(root, mut state)
	doc_text := emit_inferred_schema(root.name, state)
	mut schema_doc := parse(doc_text) or {
		return error('cx-err:CXER0021\x1Fcx:schema-of internal emit/parse mismatch: ${err.msg()}\x1F')
	}
	// Return the schema document's top-level nodes as a sequence
	// CXLValue. Multi-item return surfaces through cxl_value_to_cx_text
	// as a `[#document ...]`-shaped wrapper at re-emission time when
	// callers chain through cx:serialize / cx:canonical; the schema-of
	// directive lives in `doc.prolog` (parser parks CXDirectiveNode at
	// top level there per is_prolog_node_type).
	mut items := []CXLItem{cap: schema_doc.prolog.len + schema_doc.elements.len}
	for n in schema_doc.prolog {
		match n {
			CXDirectiveNode { items << CXLItem(n) }
			else {}
		}
	}
	for n in schema_doc.elements {
		match n {
			Element { items << CXLItem(n) }
			else {}
		}
	}
	if items.len == 1 {
		return CXLValue(items)
	}
	return CXLValue(items)
}

// SchemaInferState accumulates per-element-name observations across a
// walk of the input value.
struct SchemaInferState {
mut:
	order    []string  // first-seen element names (for stable output order)
	per_name map[string]ElementShape
}

// ElementShape records observations across all instances of a single
// element name encountered during the walk.
struct ElementShape {
mut:
	instance_count int
	// attrs[name] → AttrShape; tracks dataType union + how many
	// instances carry this attribute (compared against instance_count
	// to decide :req vs :opt).
	attrs map[string]AttrShape
	// child_count_per_instance[name] → list of per-instance counts;
	// post-walk we derive [min, max] from min/max across the list.
	// Missing entries imply 0 for that instance.
	child_counts map[string]ChildCardSummary
	// First-seen child order (for stable output)
	child_order []string
	// Body-shape observations.
	has_text_body     bool  // saw at least one TextNode in items
	has_scalar_body   bool  // saw at least one ScalarNode in items
	has_element_child bool  // saw at least one Element in items
	scalar_types_seen map[string]bool  // union of scalar dataTypes
}

struct AttrShape {
mut:
	present_in_count int
	types_seen       map[string]bool
}

struct ChildCardSummary {
mut:
	instances_with_count int  // # parent instances that had ≥1 of this child
	min_count            int  // min count observed across instances that had ≥1
	max_count            int
}

fn walk_for_schema(el Element, mut state SchemaInferState) {
	if el.name !in state.per_name {
		state.order << el.name
		state.per_name[el.name] = ElementShape{
			attrs:             map[string]AttrShape{}
			child_counts:      map[string]ChildCardSummary{}
			child_order:       []
			scalar_types_seen: map[string]bool{}
		}
	}
	mut shape := state.per_name[el.name]
	shape.instance_count++
	// Attrs.
	for a in el.attrs {
		mut as_shape := shape.attrs[a.name] or { AttrShape{ types_seen: map[string]bool{} } }
		as_shape.present_in_count++
		type_label := if dt := a.data_type {
			scalar_type_name(dt)
		} else {
			// No explicit dataType — infer from the value's runtime type.
			scalar_type_name(scalar_type_of(a.value))
		}
		as_shape.types_seen[type_label] = true
		shape.attrs[a.name] = as_shape
	}
	// Children: count per-name within this instance, walk recursively.
	mut per_inst_counts := map[string]int{}
	for it in el.items {
		match it {
			Element {
				per_inst_counts[it.name] = (per_inst_counts[it.name] or { 0 }) + 1
				if it.name !in shape.child_counts && it.name !in shape.child_order {
					shape.child_order << it.name
				}
				shape.has_element_child = true
				walk_for_schema(it, mut state)
			}
			TextNode {
				if it.value.trim_space() != '' {
					shape.has_text_body = true
				}
			}
			ScalarNode {
				shape.has_scalar_body = true
				shape.scalar_types_seen[scalar_type_name(it.data_type)] = true
			}
			else {}
		}
	}
	// Roll per-instance child counts into the summary.
	for child_name, n in per_inst_counts {
		mut summary := shape.child_counts[child_name] or { ChildCardSummary{} }
		summary.instances_with_count++
		if summary.min_count == 0 || n < summary.min_count {
			summary.min_count = n
		}
		if n > summary.max_count {
			summary.max_count = n
		}
		shape.child_counts[child_name] = summary
	}
	state.per_name[el.name] = shape
}

fn emit_inferred_schema(root_name string, state SchemaInferState) string {
	mut sb := strings.new_builder(256)
	sb.write_string('[?cx schema-of ${root_name}]\n')
	for tn in state.order {
		shape := state.per_name[tn]
		sb.write_string('[${tn}\n')
		// Body shape.
		body_shape := infer_body_shape(shape)
		sb.write_string('  [body :${body_shape}]\n')
		// Attrs in source order (recovered by iterating the first
		// instance's attr names — but we have lost that here, so use
		// map iteration). For stable output we sort attr names
		// alphabetically.
		mut attr_names := []string{}
		for n in shape.attrs.keys() {
			attr_names << n
		}
		attr_names.sort()
		for an in attr_names {
			as_shape := shape.attrs[an]
			type_label := single_type_label(as_shape.types_seen)
			required := as_shape.present_in_count == shape.instance_count
			req_marker := if required { ' :req' } else { '' }
			sb.write_string('  [attr ${an} :${type_label}${req_marker}]\n')
		}
		// Child elements in first-seen order.
		for cn in shape.child_order {
			summary := shape.child_counts[cn]
			min_label := if summary.instances_with_count < shape.instance_count {
				'0'
			} else if summary.min_count <= 0 {
				'0'
			} else {
				'1'
			}
			max_label := if summary.max_count > 1 { '*' } else { '1' }
			sb.write_string("  [elem ${cn} :card='${min_label}..${max_label}']\n")
		}
		sb.write_string(']\n')
	}
	return sb.str()
}

fn infer_body_shape(shape ElementShape) string {
	if shape.has_element_child && (shape.has_text_body || shape.has_scalar_body) {
		return 'mixed'
	}
	if shape.has_element_child {
		return 'elem'
	}
	if shape.has_scalar_body {
		return single_type_label(shape.scalar_types_seen)
	}
	if shape.has_text_body {
		return 'string'
	}
	// Empty body — emit as :elem (most permissive of the empty cases).
	return 'elem'
}

fn single_type_label(types map[string]bool) string {
	if types.len == 0 { return 'string' }
	if types.len == 1 {
		for k, _ in types { return k }
	}
	// Union of multiple scalar types collapses to :string at v0.7.0
	// (cxs has no union-type syntax at v0.6.0+; spec/schema.md §3
	// enumerates the single-type-per-attribute discipline).
	return 'string'
}

// DD18 (ADR 0023 §D1 Should tier): programmatic include resolution
// over an already-parsed cx-value. Wraps the V-core `resolve_includes_doc`
// engine (GG1 row at spec/v0_7_0_status.md, semantics per
// spec/include.md §1-§8).
//
// Pipeline: serialize the input cx-value → re-parse as a Document
// (cheap; cx:resolve-includes is a Should-tier convenience) → run
// resolve_includes_doc against the supplied root → re-emit elements
// as a CXLValue.
//
// Error code mapping per spec/modules/cx.md §4:
//   E901 (absolute path)     → CXER0029 (traversal-rejected)
//   E902 (escapes root)      → CXER0029 (traversal-rejected)
//   E903 (URL-scheme path)   → CXER0029 (traversal-rejected)
//   E904 (cycle)             → CXER0027 (include-cycle)
//   E905 (depth)             → CXER0027 (include-cycle — depth bound)
//   E906 / E907 / E908 / E909 → CXER0028 (include-not-found / I/O)
//   E910 / E911              → CXER0028 (include-not-found — invalid content)
fn filter_cx_resolve_includes(n EvalDirectiveNode, mut env CXLEnv) !CXLValue {
	slots := arg_array_slots(n)!
	if slots.len < 2 {
		return error('cx-err:CXER0028\x1Fcx:resolve-includes expects 2 arguments (value, root)\x1F')
	}
	value := eval_slot_to_value(slots[0], mut env)!
	// Root extracted via slot_to_expr so absolute paths containing `/`
	// survive past the slot evaluator's expression heuristic (mirrors
	// cx:select pattern). Trim surrounding string-literal quotes.
	mut root := slot_to_expr(slots[1]) or {
		return error('cx-err:CXER0029\x1Fcx:resolve-includes root slot must be a text expression: ${err.msg()}\x1F')
	}
	root = root.trim_space()
	if root.len >= 2 && root[0] == `'` && root[root.len - 1] == `'` {
		root = root[1..root.len - 1]
	} else if root.len >= 2 && root[0] == `"` && root[root.len - 1] == `"` {
		root = root[1..root.len - 1]
	}
	if root == '' {
		return error('cx-err:CXER0029\x1Fcx:resolve-includes root argument is empty\x1F')
	}
	mut abs_root := root
	if !os.is_abs_path(abs_root) {
		abs_root = os.abs_path(abs_root)
	}
	abs_root = os.real_path(abs_root)
	// Build a Document directly from the CXLValue rather than
	// round-tripping through cxl_value_to_cx_text → parse — the text
	// emitter drops CXDirective children in body position, which
	// loses our [?cx include=...] payload before resolution runs.
	mut doc := cxl_value_to_doc(value)
	opts := ResolveIncludeOpts{
		root:          abs_root
		max_depth:     max_include_depth_default
		current_file:  abs_root
		include_stack: []
	}
	resolve_includes_doc(mut doc, opts) or {
		msg := err.msg()
		// Map E-codes to CXER codes per the spec/modules/cx.md §4
		// dispatch table.
		code := if msg.contains('E904') || msg.contains('E905') {
			'CXER0027'
		} else if msg.contains('E901') || msg.contains('E902') || msg.contains('E903') {
			'CXER0029'
		} else {
			'CXER0028'
		}
		return error('cx-err:${code}\x1Fcx:resolve-includes: ${msg}\x1F')
	}
	// Re-emit doc.elements as a CXLValue.
	if doc.elements.len == 1 && doc.elements[0] is Element {
		return [CXLItem(doc.elements[0] as Element)]
	}
	if doc.elements.len == 0 {
		return CXLValue([]CXLItem{})
	}
	root_synth := Element{ name: '#document', items: doc.elements }
	return [CXLItem(root_synth)]
}

// cxl_value_to_doc projects a CXLValue back to a Document for
// AST-level passes (notably resolve_includes_doc). Unlike
// cxl_value_to_cx_text → parse, this preserves CXDirective children
// in element body position, which the text emitter drops.
fn cxl_value_to_doc(v CXLValue) Document {
	mut nodes := []Node{cap: v.len}
	for it in v {
		match it {
			Element { nodes << Node(it) }
			TextNode, ScalarNode, CommentNode, PINode, CXDirectiveNode,
			ArrayNode, MapNode { nodes << Node(it) }
			CXLScalar {
				nodes << Node(TextNode{ value: scalar_value_str(it.value) })
			}
			CXLFunction {
				nodes << Node(TextNode{ value: '[function arity=${it.params.len}]' })
			}
		}
	}
	return Document{ elements: nodes }
}

// DD19 (ADR 0023 §D1 Nice tier): three-policy semantic merge of two
// cx-values. Implements the "last-wins" / "first-wins" /
// "error-on-conflict" attribute-collision policies described in
// spec/modules/cx.md §1.3.
//
// Merge semantics at v0.7.0:
//   - Empty a → return b; empty b → return a
//   - Both single-Element same-name → merge attrs (policy-resolved) +
//     concat-merge items by name (same-name children merge recursively;
//     unmatched children from a precede unmatched children from b)
//   - Otherwise (mixed shapes / different names / multi-item sequences)
//     → concat (item-by-item; no cross-item merge)
//
// Anchor/IDREF cross-resolution is documented in spec/identity.md but
// requires the canonical-form anchor-resolver follow-up; v0.7.0 covers
// the by-name + by-position cases that the Nice-tier rubric calls out.
fn filter_cx_merge(args []CXLValue) !CXLValue {
	if args.len < 2 {
		return error('cx-err:CXER0030\x1Fcx:merge expects 2 or 3 arguments (a, b, policy?)\x1F')
	}
	policy := if args.len >= 3 { value_to_string(args[2]).to_lower() } else { 'last-wins' }
	if policy !in ['last-wins', 'first-wins', 'error-on-conflict'] {
		return error('cx-err:CXER0030\x1Fcx:merge unknown policy "${policy}" (use last-wins | first-wins | error-on-conflict)\x1F')
	}
	merged := merge_values(args[0], args[1], policy)!
	return merged
}

fn merge_values(a CXLValue, b CXLValue, policy string) !CXLValue {
	if a.len == 0 { return b }
	if b.len == 0 { return a }
	// Single-Element + Single-Element same name → element merge
	if a.len == 1 && b.len == 1 {
		ai, bi := a[0], b[0]
		if ai is Element && bi is Element {
			ae := ai as Element
			be := bi as Element
			if ae.name == be.name {
				merged := merge_elements(ae, be, policy)!
				return [CXLItem(merged)]
			}
		}
	}
	// Mixed shapes / multi-item / disjoint names → concat
	mut out := []CXLItem{cap: a.len + b.len}
	for it in a { out << it }
	for it in b { out << it }
	return CXLValue(out)
}

fn merge_elements(a Element, b Element, policy string) !Element {
	// Attribute merge — collision per policy.
	mut attrs := []Attribute{cap: a.attrs.len + b.attrs.len}
	mut seen := map[string]int{}  // name → index in attrs
	for at in a.attrs {
		seen[at.name] = attrs.len
		attrs << at
	}
	for at in b.attrs {
		if idx := seen[at.name] {
			_ := idx
			// Collision — resolve per policy.
			match policy {
				'last-wins'         { attrs[seen[at.name]] = at }
				'first-wins'        {}  // keep a's value
				'error-on-conflict' {
					return error('cx-err:CXER0030\x1Fcx:merge attribute collision on "${at.name}" under error-on-conflict policy\x1F')
				}
				else {}
			}
		} else {
			seen[at.name] = attrs.len
			attrs << at
		}
	}
	// Item merge — same-name children merge recursively; unique-name
	// children pass through in their source order (a first, then b).
	mut items := []Node{cap: a.items.len + b.items.len}
	mut b_consumed := map[int]bool{}
	for ai_idx, ai in a.items {
		_ := ai_idx
		if ai is Element {
			ae := ai as Element
			// Find first matching same-name unconsumed Element in b.
			mut matched := -1
			for bi_idx, bi in b.items {
				if bi_idx in b_consumed { continue }
				if bi is Element {
					if (bi as Element).name == ae.name {
						matched = bi_idx
						break
					}
				}
			}
			if matched >= 0 {
				bn := b.items[matched] as Element
				merged_child := merge_elements(ae, bn, policy)!
				items << Node(merged_child)
				b_consumed[matched] = true
				continue
			}
		}
		items << ai
	}
	for bi_idx, bi in b.items {
		if bi_idx in b_consumed { continue }
		items << bi
	}
	// Anchor / merge / id / body_ref / table / lang_resolved — at v0.7.0
	// the result inherits a's identity tokens (anchor / id) since the
	// "first declared" wins on identity per spec/identity.md. Merge ref
	// is dropped on the result (a merged element is no longer a merge
	// reference itself).
	return Element{
		name:          a.name
		anchor:        a.anchor
		merge:         a.merge
		data_type:     a.data_type
		attrs:         attrs
		items:         items
		id:            a.id
		body_ref:      a.body_ref
		table:         a.table
		local:         a.local
		ns_uri:        a.ns_uri
		lang_resolved: a.lang_resolved
	}
}

// filter_cx_select takes the raw EvalDirectiveNode so it can extract
// slot[1]'s textual form before the standard slot evaluator would
// re-interpret strings like '@name' or '/foo' as CXPath expressions
// against the OUTER context. The path-string semantics of cx:select
// demands the literal slot text, not its pre-evaluated form.
fn filter_cx_select(n EvalDirectiveNode, mut env CXLEnv) !CXLValue {
	slots := arg_array_slots(n)!
	if slots.len < 2 {
		return error('cx-err:CXER0026\x1Fcx:select expects 2 arguments (value, path)\x1F')
	}
	// Slot 0 is evaluated through the standard slot pipeline — it
	// participates in nested directive composition, captures, etc.
	value := eval_slot_to_value(slots[0], mut env)!
	// Slot 1 is the path string; extracted via slot_to_expr so that
	// quoted-string literals like '@name' survive intact. slot_to_expr
	// already trims whitespace.
	path := slot_to_expr(slots[1]) or {
		return error('cx-err:CXER0026\x1Fcx:select path slot must be a text expression: ${err.msg()}\x1F')
	}
	if path == '' {
		return error('cx-err:CXER0026\x1Fcx:select path is empty\x1F')
	}
	saved_ctx := env.context
	env.context = value
	result := eval_expr(path, mut env) or {
		env.context = saved_ctx
		return error('cx-err:CXER0026\x1Fcx:select malformed path "${path}": ${err.msg()}\x1F')
	}
	env.context = saved_ctx
	return result
}

// ── DD8. cx:from-format(text, fmt) → cx-value ─────────────────────────────────

fn filter_cx_from_format(args []CXLValue) !CXLValue {
	if args.len < 2 {
		return error('cx-err:CXER0023\x1Fcx:from-format expects 2 arguments (text, fmt)\x1F')
	}
	text := value_to_string(args[0])
	fmt_str := value_to_string(args[1]).to_lower()
	cx_src := match fmt_str {
		'cx' {
			text
		}
		'xml' {
			from_xml(text) or {
				return error('cx-err:CXER0025\x1Fcx:from-format xml parse failed: ${err.msg()}\x1F')
			}
		}
		'json' {
			json_to_cx(text) or {
				return error('cx-err:CXER0025\x1Fcx:from-format json parse failed: ${err.msg()}\x1F')
			}
		}
		'yaml' {
			yaml_to_cx(text) or {
				return error('cx-err:CXER0025\x1Fcx:from-format yaml parse failed: ${err.msg()}\x1F')
			}
		}
		'toml' {
			toml_to_cx(text) or {
				return error('cx-err:CXER0025\x1Fcx:from-format toml parse failed: ${err.msg()}\x1F')
			}
		}
		'md', 'markdown' {
			from_md(text) or {
				return error('cx-err:CXER0025\x1Fcx:from-format md parse failed: ${err.msg()}\x1F')
			}
		}
		'csv' {
			from_csv(text) or {
				return error('cx-err:CXER0025\x1Fcx:from-format csv parse failed: ${err.msg()}\x1F')
			}
		}
		'tsv' {
			from_tsv(text) or {
				return error('cx-err:CXER0025\x1Fcx:from-format tsv parse failed: ${err.msg()}\x1F')
			}
		}
		'psv' {
			from_psv(text) or {
				return error('cx-err:CXER0025\x1Fcx:from-format psv parse failed: ${err.msg()}\x1F')
			}
		}
		else {
			return error('cx-err:CXER0023\x1Fcx:from-format unknown format "${fmt_str}" (use cx|xml|json|yaml|toml|md|csv|tsv|psv)\x1F')
		}
	}
	return cx_text_to_cxl_value(cx_src) or {
		return error('cx-err:CXER0025\x1Fcx:from-format result re-parse failed: ${err.msg()}\x1F')
	}
}
