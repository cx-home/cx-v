module code

import cx

// Homoiconic dynamic construction — computed names + quasiquote + tree-eval.
// Spec: spec/core/code.md §6.4.2–§6.4.4; spec/modules/cx.md §3.4.
//
// Three pillars:
//   1. Computed names — [?element]/[?attr]/[?entry]/[?name] (name coercion §6.4.2.1).
//   2. Quasiquote     — [?quote]/[?unquote]/[?splice] (eager, two-color hygiene §6.4.3).
//   3. Tree-eval      — [?eval] / cx:eval-tree, reusing the cx:eval sandbox (§6.4.4).
//
// The quoted value is a CXDM data tree: a cx.ProgramNode is *lifted* to a cx.Node
// tree (program_node_to_data_q) and *lowered* back (data_to_program_node) for
// [?eval] — there is no parse step, so CXER4100 is structurally unreachable
// (the §0.1 thesis).
//
// NOTE (V cgen): the lift functions build children via explicit `wrap_cx` /
// `wrap_cx_attr` / `<<` appends, NEVER inline `[fn()!]` array literals — the
// latter trips V's type_default_impl recursion on the recursive cx.Node
// sumtype (cgen.v:10636 "maximum levels of nesting").

const dc_ok_sentinel_name = '__cx_dc_ok__'

fn is_err_node(n cx.Node) bool {
	return is_err_value(n)
}

fn empty_seq_node() cx.Node {
	return cx.Node(cx.Element{ name: seq_marker_name })
}

fn is_empty_seq_node(n cx.Node) bool {
	if n is cx.ScalarNode {
		return n.value is cx.NullValue
	}
	if n is cx.Element {
		if n.name == seq_marker_name || n.name == arr_marker_name
		   || n.name == map_marker_name || n.name == '' {
			return n.items.len == 0
		}
	}
	return false
}

fn seq_items(n cx.Node) ([]cx.Node, bool) {
	if n is cx.Element {
		if n.name == seq_marker_name || n.name == arr_marker_name || n.name == '' {
			return n.items, true
		}
	}
	return []cx.Node{}, false
}

fn coerce_computed_name(v cx.Node, position string) cx.Node {
	if is_empty_seq_node(v) {
		if position == 'rename' {
			return mk_err('cx-err:CXER0236', '[rename] name must be non-empty')
		}
		return empty_seq_node()
	}
	mut name := ''
	mut is_scalar := false
	mut scalar_is_string_or_atom := false
	if v is cx.ScalarNode {
		sv := v.value
		match sv {
			string {
				is_scalar = true
				name = sv
				scalar_is_string_or_atom = true
			}
			else {
				is_scalar = true
				name = cx.scalar_value_str_public(sv)
				scalar_is_string_or_atom = false
			}
		}
	} else if v is cx.TextNode {
		is_scalar = true
		name = v.value
		scalar_is_string_or_atom = true
	}
	if !is_scalar {
		return mk_err('cx-err:CXER0235', 'computed ${position} name must be a scalar')
	}
	if position == 'entry' {
		return cx.Node(cx.ScalarNode{ value: cx.ScalarValue(name), data_type: cx.ScalarType.string_type })
	}
	name = name.trim_space()
	if !scalar_is_string_or_atom || !is_valid_atom_name(name)
	   || name == 'true' || name == 'false' || name == 'null' {
		return mk_err('cx-err:CXER0236', 'computed ${position} name "${name}" is not a valid NCName')
	}
	return cx.Node(cx.ScalarNode{ value: cx.ScalarValue(name), data_type: cx.ScalarType.string_type })
}

fn coerce_entry_key(v cx.Node) (string, cx.Node, bool) {
	coerced := coerce_computed_name(v, 'entry')
	if is_err_node(coerced) {
		return '', coerced, true
	}
	if coerced is cx.ScalarNode {
		k := coerced.value
		if k is string {
			return k, empty_seq_node(), false
		}
	}
	return '', empty_seq_node(), false
}

fn eval_dc_body_items(prog_items []cx.ProgramNode, mut items []cx.Node, mut cx_attrs []cx.Attribute, mut env MatchEnv) !cx.Node {
	for it in prog_items {
		if it is cx.ProgramDirective {
			match it.name {
				'attr' {
					if it.slots.len != 2 {
						return EvalError{ code: 'cx-err:CXER0100', message: '[?attr] requires NAME and VALUE' }
					}
					name_raw := eval_node(it.slots[0].value, mut env)!
					if is_err_node(name_raw) {
						return name_raw
					}
					name_node := coerce_computed_name(name_raw, 'attr')
					if is_err_node(name_node) {
						return name_node
					}
					if is_empty_seq_node(name_node) {
						continue
					}
					val_node := eval_node(it.slots[1].value, mut env)!
					if is_err_node(val_node) {
						return val_node
					}
					aname := (name_node as cx.ScalarNode).value as string
					sv, dt := construction_attr_value(aname, it.slots[1].value, val_node)!
					cx_attrs << cx.new_attribute(aname, sv, cx.AttributeMeta{ data_type: dt })
					continue
				}
				'splice' {
					grafted := eval_splice_value(it, mut env)!
					if is_err_node(grafted) {
						return grafted
					}
					gitems, is_seq := seq_items(grafted)
					if is_seq {
						for g in gitems {
							items << g
						}
					} else if is_empty_seq_node(grafted) {
					} else {
						items << grafted
					}
					continue
				}
				'unquote' {
					uv := eval_unquote_value(it, mut env)!
					if is_err_node(uv) {
						return uv
					}
					if is_empty_seq_node(uv) {
						continue
					}
					items << uv
					continue
				}
				else {}
			}
		}
		val := eval_node(it, mut env)!
		// #853 (owner ruling 2026-08-18, "2a") — element construction is
		// OPERAND-CONSUMING for propagation, per code.md §6.4.1 /
		// §9.2: a positional child that EVALUATES to an [err …] propagates
		// instead of being adopted as a child. Before this, a refusal spliced
		// into a document had stopped being a refusal — it no longer
		// short-circuited and `[?match … [case [err …] …]]` could not see it,
		// because by then it was a node in a tree. #853 caught it as a 200 OK
		// with `<err code="…">` serialized into a page.
		//
		// THE DISCRIMINATOR IS THE POSITION, NOT THE VALUE — the same
		// principle as the [?quote] hole half (@ 58df73d5). A SOURCE-LITERAL
		// `[err …]` element is data and stays data, so err-shaped documents
		// remain expressible; keying on "is this value an err" would have
		// passed the headline case and silently made them inexpressible.
		//
		// The position test is the literal HEAD NAME: a `[err …]` written in
		// source is a ProgramLiteral whose name is `err`, and it BUILDS that
		// element. Every other item — a call, a binding read, a directive, a
		// computed-name construction, or a nested literal element whose own
		// construction propagated — is an operand, so an err result
		// propagates. That last case is what makes propagation TRANSITIVE:
		// `[section [div [$concat …]]]` propagates from `div` and then from
		// `section`, so a refusal cannot come to rest at any depth.
		if is_err_node(val) && !is_literal_err_head(it) {
			return val
		}
		items << val
	}
	return dc_ok_sentinel()
}

// is_literal_err_head reports whether a body item is a SOURCE-LITERAL
// `[err …]` element — the one child position whose err-shaped value is DATA
// rather than a propagating refusal (code.md §6.4.1, "the discriminator is
// POSITION, not value"). A computed-name construction is deliberately NOT
// covered: a computed name is itself a computation, so it is an operand
// position like any other.
@[inline]
fn is_literal_err_head(it cx.ProgramNode) bool {
	if it is cx.ProgramLiteral {
		return it.name == 'err' && it.name_expr == none
	}
	return false
}

fn dc_ok_sentinel() cx.Node {
	return cx.Node(cx.Element{ name: dc_ok_sentinel_name })
}

fn is_dc_ok_sentinel(n cx.Node) bool {
	if n is cx.Element {
		return n.name == dc_ok_sentinel_name
	}
	return false
}

fn eval_unquote_value(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	if d.slots.len != 1 {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?unquote] requires one EXPR' }
	}
	v := eval_node(d.slots[0].value, mut env)!
	if is_err_node(v) {
		return v
	}
	items, is_seq := seq_items(v)
	if is_seq {
		if items.len == 0 {
			return empty_seq_node()
		}
		if items.len == 1 {
			return items[0]
		}
		return mk_err('cx-err:CXER0237', '[?unquote] yielded a ${items.len}-item sequence')
	}
	return v
}

fn eval_splice_value(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	if d.slots.len != 1 {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?splice] requires one EXPR' }
	}
	return eval_node(d.slots[0].value, mut env)!
}

// eval_computed_attr — a standalone [?attr] outside attribute position is a
// structural misuse (CXER0100); eval_dc_body_items intercepts the valid case.
fn eval_computed_attr(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	return EvalError{ code: 'cx-err:CXER0100', message: '[?attr …] is valid only in attribute position (inside an element body)' }
}

// eval_computed_entry — a standalone [?entry] outside a `{…}` map is a misuse;
// eval_map intercepts the valid case.
fn eval_computed_entry(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	return EvalError{ code: 'cx-err:CXER0100', message: '[?entry …] is valid only inside a `{…}` map literal' }
}

// eval_name_misplaced — standalone [?name] is only meaningful in a [set-attr] /
// [rename] name slot, where eval_modify resolves it.
fn eval_name_misplaced(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	return EvalError{ code: 'cx-err:CXER0100', message: '[?name …] is valid only in a [set-attr] / [rename] name slot' }
}

// eval_unquote_misplaced — a top-level [?unquote] outside a [?quote] is a misuse.
fn eval_unquote_misplaced(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	return EvalError{ code: 'cx-err:CXER0100', message: '[?unquote …] is valid only inside a [?quote …]' }
}

// eval_splice_misplaced — a top-level [?splice] outside a multi-sibling slot.
fn eval_splice_misplaced(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	return EvalError{ code: 'cx-err:CXER0100', message: '[?splice …] is valid only in a multi-sibling slot (element body, sequence, map-entry list)' }
}

// eval_quote evaluates `[?quote FORM]` (§6.4.3): build FORM's CXDM tree
// unevaluated, except [?unquote]/[?splice] holes (resolved here, eagerly, at
// the quote site). The result is a data tree suitable for [?eval].
fn eval_quote(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	if d.slots.len != 1 {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?quote] requires exactly one FORM' }
	}
	// #853 — a HOLE's `[err]` propagates railway-style, per §6.4.3.1:
	// "holes are evaluated once, left-to-right, at quote-eval time; a hole's
	// `[err]` propagates railway-style (§9.2) then."
	//
	// It did not. The lift resolved each hole through eval_unquote_value /
	// eval_splice_value — which do surface the err — and then appended that
	// value to the tree under construction like any other child. The result
	// was a document with a refusal buried in it: 200 OK with
	// `<err code="…">` serialized into the page, unmatchable by
	// `[?match … [case [err …] …]]` because by then it was a node in a tree.
	//
	// This also restores §6.4.3's stated equivalence — "building with
	// [?quote]+holes and building imperatively with
	// [?element]/[?attr]/[?entry] produce the SAME tree". The imperative path
	// already aborted on a hole err (eval_dc_body_items' [?attr]/[?splice]/
	// [?unquote] arms); only the quote path disagreed.
	//
	// WHAT IS DELIBERATELY UNCHANGED: a plain positional child that evaluates
	// to an err is still CONTAINED (`[a [err …]]`), and a literal `[err …]`
	// written inside a quoted form is still data. Element construction is
	// data-building, not a railway — see the note in eval_dc_body_items. The
	// carrier below records only what a HOLE produced, so the two cases cannot
	// be confused: the discriminator is the POSITION, not the value.
	mut hole_err := []cx.Node{}
	lifted := quote_form(d.slots[0].value, mut env, mut hole_err)!
	if hole_err.len > 0 {
		return hole_err[0]
	}
	return lifted
}

// note_hole_err records the FIRST err a [?quote] hole produced. Returns true
// when `v` was an err, so the caller can stop grafting it. The lift keeps
// walking rather than unwinding: holes are specified to evaluate
// left-to-right, and the first err is the one that propagates.
@[inline]
fn note_hole_err(v cx.Node, mut hole_err []cx.Node) bool {
	if is_err_node(v) {
		if hole_err.len == 0 {
			hole_err << v
		}
		return true
	}
	return false
}

// quote_form lifts a cx.ProgramNode to its CXDM data image, resolving holes. A
// bare $x (cx.ProgramBinding with no path) becomes an inert <cx:var> data node
// (two-color rule §6.4.3.2).
fn quote_form(node cx.ProgramNode, mut env MatchEnv, mut hole_err []cx.Node) !cx.Node {
	if node is cx.ProgramDirective {
		if node.name == 'unquote' {
			uv := eval_unquote_value(node, mut env)!
			note_hole_err(uv, mut hole_err)
			return uv
		}
		if node.name == 'splice' {
			return EvalError{ code: 'cx-err:CXER0100', message: '[?splice] is valid only in a multi-sibling slot, not a single quoted value' }
		}
	}
	return program_node_to_data_q(node, mut env, mut hole_err)!
}

fn resolve_name_subform(d cx.ProgramDirective, position string, mut env MatchEnv) !cx.Node {
	if d.slots.len != 1 {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?name] requires one NAME-EXPR' }
	}
	v := eval_node(d.slots[0].value, mut env)!
	if is_err_node(v) {
		return v
	}
	return coerce_computed_name(v, position)
}

// ── cx.ProgramNode → CXDM data (lift, quote-time) ──────────────────────────────

// program_node_to_data_q lifts a cx.ProgramNode to its CXDM data image at quote
// time, resolving [?unquote]/[?splice] holes nested anywhere inside. Bare $x
// (no path) becomes an inert <cx:var> data node. The tag convention mirrors
// the program-XML codec so the data tree round-trips and [?eval] lowers it
// back (data_to_program_node). Inline `[call()!]` array literals are avoided
// throughout (they trip V's type_default_impl recursion for the recursive
// cx.Node sumtype) — children are built via explicit `<<` appends.
fn program_node_to_data_q(node cx.ProgramNode, mut env MatchEnv, mut hole_err []cx.Node) !cx.Node {
	if node is cx.ProgramLiteral {
		return literal_to_data_q(node, mut env, mut hole_err)!
	}
	if node is cx.ProgramBinding {
		if node.path.len == 0 {
			// I1 row 9 (L78): a bare $x lowers to the authorable HOLE node
			// — canonical spelling `$x` — so quoted trees carry plain CX
			// text and Tier-1 addresses. (The former <cx:var> image died on
			// re-parse, E210 — cx-094 pinned that death.)
			return cx.Node(cx.HoleNode{ name: node.name })
		}
		return mk_cx_expr(node)
	}
	if node is cx.ProgramDirective {
		if node.name == 'unquote' {
			uv := eval_unquote_value(node, mut env)!
			note_hole_err(uv, mut hole_err)
			return uv
		}
		if node.name == 'splice' {
			sp := eval_splice_value(node, mut env)!
			note_hole_err(sp, mut hole_err)
			return sp
		}
		mut kids := []cx.Node{}
		for s in node.slots {
			if s.kind == .labeled {
				inner := program_node_to_data_q(s.value, mut env, mut hole_err)!
				kids << wrap_cx(('cx:' + s.label), inner)
			} else {
				if s.value is cx.ProgramDirective && (s.value as cx.ProgramDirective).name == 'splice' {
					sp := eval_splice_value(s.value as cx.ProgramDirective, mut env)!
					if note_hole_err(sp, mut hole_err) {
						continue
					}
					sitems, is_seq := seq_items(sp)
					if is_seq {
						for it in sitems {
							kids << it
						}
						continue
					}
					kids << sp
					continue
				}
				kids << program_node_to_data_q(s.value, mut env, mut hole_err)!
			}
		}
		return mk_cx_node(('cx:' + node.name), '', kids)
	}
	return mk_cx_expr(node)
}

fn literal_to_data_q(l cx.ProgramLiteral, mut env MatchEnv, mut hole_err []cx.Node) !cx.Node {
	if l.kind == .int_lit {
		return mk_cx_scalar('cx:int', i64(l.int_val).str())
	}
	if l.kind == .float_lit {
		return mk_cx_scalar('cx:float', l.flt_val.str())
	}
	if l.kind == .bool_lit {
		return mk_cx_scalar('cx:bool', l.bool_val.str())
	}
	if l.kind == .string_lit {
		return mk_cx_scalar('cx:str', l.str_val)
	}
	if l.kind == .atom_lit {
		return mk_cx_scalar('cx:atom', l.str_val)
	}
	if l.kind == .duration_lit {
		return mk_cx_scalar('cx:dur', l.dur_val)
	}
	if l.kind == .cx_element {
		return element_to_data_q(l, mut env, mut hole_err)!
	}
	if l.kind == .sequence_lit {
		return mk_cx_node('cx:seq', '', wrap_items_q(l.items, mut env, mut hole_err)!)
	}
	if l.kind == .array_lit {
		return mk_cx_node('cx:arr', '', wrap_items_q(l.items, mut env, mut hole_err)!)
	}
	if l.kind == .block {
		return mk_cx_node('cx:block', '', wrap_items_q(l.items, mut env, mut hole_err)!)
	}
	if l.kind == .node_lit {
		// Quoting an embedded pure-DATA construct yields that data node verbatim.
		return l.node or {
			return EvalError{ code: 'cx-err:CXER0001', message: 'node_lit literal carries no node' }
		}
	}
	// map_lit
	mut entries := []cx.Node{}
	for i, v in l.items {
		key := if i < l.keys.len { l.keys[i] } else { '' }
		inner := program_node_to_data_q(v, mut env, mut hole_err)!
		entries << wrap_cx_attr('entry', 'key', key, inner)
	}
	return mk_cx_node('cx:map', '', entries)
}

// wrap_items_q wraps each quoted item in an <item> element. A [?splice] hole
// expands into multiple siblings (each wrapped), so a spliced sequence inside a
// quoted (…)/[…]/block grafts as several items, not one nested sequence (§6.4.3).
fn wrap_items_q(prog_items []cx.ProgramNode, mut env MatchEnv, mut hole_err []cx.Node) ![]cx.Node {
	mut out := []cx.Node{}
	for it in prog_items {
		if it is cx.ProgramDirective && it.name == 'splice' {
			sp := eval_splice_value(it, mut env)!
			sitems, is_seq := seq_items(sp)
			if is_seq {
				for s in sitems {
					out << wrap_cx('item', s)
				}
			} else if is_empty_seq_node(sp) {
				// () → graft nothing
			} else {
				out << wrap_cx('item', sp)
			}
			continue
		}
		inner := program_node_to_data_q(it, mut env, mut hole_err)!
		out << wrap_cx('item', inner)
	}
	return out
}

// lift_quoted_items lifts a list of quoted body items to CXDM data kids,
// expanding [?splice] holes into siblings: each sequence item is grafted in
// order, () grafts nothing, and a non-sequence value grafts as a single node
// (§6.4.3). All other items ([?unquote], plain forms) lift to one node via
// program_node_to_data_q. This mirrors the splice handling in the directive-slot
// loop so element bodies and slot lists expand splice consistently.
fn lift_quoted_items(prog_items []cx.ProgramNode, mut env MatchEnv, mut hole_err []cx.Node) ![]cx.Node {
	mut out := []cx.Node{}
	for it in prog_items {
		if it is cx.ProgramDirective && it.name == 'splice' {
			sp := eval_splice_value(it, mut env)!
			if note_hole_err(sp, mut hole_err) {
				continue
			}
			sitems, is_seq := seq_items(sp)
			if is_seq {
				for s in sitems {
					out << s
				}
			} else if is_empty_seq_node(sp) {
				// () → graft nothing
			} else {
				out << sp
			}
			continue
		}
		if it is cx.ProgramDirective && it.name == 'unquote' {
			// [?unquote ()] removes the slot (absence), mirroring the
			// [?element]-construction path (eval_dc_body_items); a non-empty
			// value injects as one node.
			uv := eval_unquote_value(it, mut env)!
			if note_hole_err(uv, mut hole_err) {
				continue
			}
			if is_empty_seq_node(uv) {
				continue
			}
			out << uv
			continue
		}
		out << program_node_to_data_q(it, mut env, mut hole_err)!
	}
	return out
}

fn element_to_data_q(l cx.ProgramLiteral, mut env MatchEnv, mut hole_err []cx.Node) !cx.Node {
	if op_name := operator_xml_names[l.name] {
		kids := lift_quoted_items(l.items, mut env, mut hole_err)!
		return mk_cx_node_attr('cx:op', 'name', op_name, kids)
	}
	if name_e := l.name_expr {
		mut kids := []cx.Node{}
		name_inner := program_node_to_data_q(name_e, mut env, mut hole_err)!
		kids << wrap_cx('cx:name', name_inner)
		for a in l.attrs {
			av := program_node_to_data_q(a.value, mut env, mut hole_err)!
			kids << wrap_cx_attr('cx:attr', 'name', a.name, av)
		}
		kids << lift_quoted_items(l.items, mut env, mut hole_err)!
		return mk_cx_node('cx:element', '', kids)
	}
	mut kids := []cx.Node{}
	for a in l.attrs {
		av := program_node_to_data_q(a.value, mut env, mut hole_err)!
		kids << wrap_cx_attr('cx:attr', 'name', a.name, av)
	}
	kids << lift_quoted_items(l.items, mut env, mut hole_err)!
	return mk_cx_node(l.name, '', kids)
}

// mk_cx_node builds a cx.Element with the given tag, optional text body, and
// children (appended explicitly — no array-literal default generation).
fn mk_cx_node(tag string, text string, children []cx.Node) cx.Node {
	mut items := []cx.Node{}
	if text != '' {
		items << cx.Node(cx.TextNode{ value: text })
	}
	for ch in children {
		items << ch
	}
	return cx.Node(cx.Element{ name: tag, items: items })
}

// mk_cx_node_attr is mk_cx_node plus a single XML attribute.
fn mk_cx_node_attr(tag string, attr_name string, attr_val string, children []cx.Node) cx.Node {
	mut items := []cx.Node{}
	for ch in children {
		items << ch
	}
	mut attrs := []cx.Attribute{}
	attrs << cx.Attribute{ name: attr_name, value: cx.ScalarValue(attr_val) }
	return cx.Node(cx.Element{ name: tag, items: items, attrs: attrs })
}

// wrap_cx wraps a single child node in a <tag>…</tag> element.
fn wrap_cx(tag string, child cx.Node) cx.Node {
	mut items := []cx.Node{}
	items << child
	return cx.Node(cx.Element{ name: tag, items: items })
}

// wrap_cx_attr wraps a single child in a <tag attr="val">…</tag> element.
fn wrap_cx_attr(tag string, attr_name string, attr_val string, child cx.Node) cx.Node {
	mut items := []cx.Node{}
	items << child
	mut attrs := []cx.Attribute{}
	attrs << cx.Attribute{ name: attr_name, value: cx.ScalarValue(attr_val) }
	return cx.Node(cx.Element{ name: tag, items: items, attrs: attrs })
}

// mk_cx_scalar builds a scalar value node `<cx:KIND>text</cx:KIND>`.
fn mk_cx_scalar(tag string, text string) cx.Node {
	mut items := []cx.Node{}
	items << cx.Node(cx.TextNode{ value: text })
	return cx.Node(cx.Element{ name: tag, items: items })
}

// mk_cx_expr is the bijective escape hatch: a <cx:expr> node carrying the
// canonical source of a cx.ProgramNode (lowered by re-parse — the source is the
// codec's own emission, not user input, so no user-facing CXER4100 surface).
fn mk_cx_expr(node cx.ProgramNode) cx.Node {
	return mk_cx_scalar('cx:expr', program_node_to_source(node))
}

// ── CXDM data → cx.ProgramNode (lower, eval-time) ──────────────────────────────

// data_to_program_node lowers a quoted CXDM data tree back to a cx.ProgramNode
// (the inverse of program_node_to_data_q). No text parse for the structural
// forms; the <cx:expr> hatch re-parses the codec's own source.
fn data_to_program_node(n cx.Node) !cx.ProgramNode {
	if n is cx.ScalarNode {
		return scalar_node_to_program(n)
	}
	if n is cx.TextNode {
		return cx.ProgramNode(cx.ProgramLiteral{ kind: .string_lit, str_val: n.value, pos: cx.Position{} })
	}
	if n is cx.Element {
		return element_data_to_program(n)!
	}
	if n is cx.HoleNode {
		// I1 row 9 (L78): the authorable hole lowers back to a bare
		// binding reference — [?eval] of a quoted tree resolves it in the
		// eval-site environment.
		return cx.ProgramNode(cx.ProgramBinding{ name: n.name, pos: cx.Position{} })
	}
	return error('tree-eval: cannot lower this node kind to code')
}

fn scalar_node_to_program(n cx.ScalarNode) cx.ProgramNode {
	v := n.value
	if v is i64 {
		return cx.ProgramNode(cx.ProgramLiteral{ kind: .int_lit, int_val: v, pos: cx.Position{} })
	}
	if v is f64 {
		return cx.ProgramNode(cx.ProgramLiteral{ kind: .float_lit, flt_val: v, pos: cx.Position{} })
	}
	if v is bool {
		return cx.ProgramNode(cx.ProgramLiteral{ kind: .bool_lit, bool_val: v, pos: cx.Position{} })
	}
	if v is string {
		if n.data_type == cx.ScalarType.atom_type {
			return cx.ProgramNode(cx.ProgramLiteral{ kind: .atom_lit, str_val: v, pos: cx.Position{} })
		}
		return cx.ProgramNode(cx.ProgramLiteral{ kind: .string_lit, str_val: v, pos: cx.Position{} })
	}
	return cx.ProgramNode(cx.ProgramLiteral{ kind: .sequence_lit, pos: cx.Position{} })
}

fn element_text(e cx.Element) string {
	mut s := ''
	for it in e.items {
		if it is cx.TextNode {
			s += it.value
		}
	}
	return s
}

fn element_children(e cx.Element) []cx.Node {
	mut out := []cx.Node{}
	for it in e.items {
		if it is cx.TextNode {
			continue
		}
		out << it
	}
	return out
}

fn first_child(e cx.Element) !cx.Node {
	for it in e.items {
		if it is cx.TextNode {
			continue
		}
		return it
	}
	return error('tree-eval: expected a child node')
}

fn element_data_to_program(e cx.Element) !cx.ProgramNode {
	if !e.name.starts_with('cx:') {
		mut attrs := []cx.ProgramAttr{}
		mut items := []cx.ProgramNode{}
		for ch in element_children(e) {
			if ch is cx.Element && ch.name == 'cx:attr' {
				aname := cx_attr_name(ch) or { return error('tree-eval: <cx:attr> missing name') }
				av := data_to_program_node(cx_attr_value(ch))!
				attrs << cx.ProgramAttr{ name: aname, value: av }
			} else {
				items << data_to_program_node(ch)!
			}
		}
		return cx.ProgramNode(cx.ProgramLiteral{ kind: .cx_element, name: e.name, attrs: attrs, items: items, pos: cx.Position{} })
	}
	local := e.name[3..]
	if local == 'int' {
		return cx.ProgramNode(cx.ProgramLiteral{ kind: .int_lit, int_val: element_text(e).i64(), pos: cx.Position{} })
	}
	if local == 'float' {
		return cx.ProgramNode(cx.ProgramLiteral{ kind: .float_lit, flt_val: element_text(e).f64(), pos: cx.Position{} })
	}
	if local == 'bool' {
		return cx.ProgramNode(cx.ProgramLiteral{ kind: .bool_lit, bool_val: element_text(e) == 'true', pos: cx.Position{} })
	}
	if local == 'str' {
		return cx.ProgramNode(cx.ProgramLiteral{ kind: .string_lit, str_val: element_text(e), pos: cx.Position{} })
	}
	if local == 'atom' {
		return cx.ProgramNode(cx.ProgramLiteral{ kind: .atom_lit, str_val: element_text(e), pos: cx.Position{} })
	}
	if local == 'dur' {
		return cx.ProgramNode(cx.ProgramLiteral{ kind: .duration_lit, dur_val: element_text(e), pos: cx.Position{} })
	}
	if local == 'var' {
		return cx.ProgramNode(cx.ProgramBinding{ name: element_text(e), pos: cx.Position{} })
	}
	if local == 'expr' {
		prog := cx.parse_program(element_text(e))!
		return prog.body
	}
	if local == 'op' {
		op_name := cx_elem_attr(e, 'name') or { return error('tree-eval: <cx:op> missing name') }
		sym := operator_symbol_for(op_name) or { return error('tree-eval: <cx:op> unknown op ${op_name}') }
		mut items := []cx.ProgramNode{}
		for ch in element_children(e) {
			items << data_to_program_node(ch)!
		}
		return cx.ProgramNode(cx.ProgramLiteral{ kind: .cx_element, name: sym, items: items, pos: cx.Position{} })
	}
	if local == 'seq' {
		return cx.ProgramNode(cx.ProgramLiteral{ kind: .sequence_lit, items: unwrap_items(e)!, pos: cx.Position{} })
	}
	if local == 'arr' {
		return cx.ProgramNode(cx.ProgramLiteral{ kind: .array_lit, items: unwrap_items(e)!, pos: cx.Position{} })
	}
	if local == 'block' {
		return cx.ProgramNode(cx.ProgramLiteral{ kind: .block, items: unwrap_items(e)!, pos: cx.Position{} })
	}
	if local == 'map' {
		mut keys := []string{}
		mut vals := []cx.ProgramNode{}
		mut decls := []string{}
		for ch in element_children(e) {
			if ch is cx.Element && ch.name == 'entry' {
				k := cx_elem_attr(ch, 'key') or { '' }
				keys << k
				// RULED: MSS-4 (#917): decl-kind marks a declaration-only
				// entry — no value node (value ABSENT).
				if dk := cx_elem_attr(ch, 'decl-kind') {
					vals << cx.ProgramNode(cx.ProgramLiteral{ kind: .string_lit })
					decls << dk
					continue
				}
				vals << data_to_program_node(first_child(ch)!)!
				decls << ''
			}
		}
		return cx.ProgramNode(cx.ProgramLiteral{ kind: .map_lit, keys: keys, items: vals, decl_kinds: decls, pos: cx.Position{} })
	}
	if local == 'element' {
		mut name_expr := cx.ProgramNode(cx.ProgramLiteral{ kind: .string_lit, pos: cx.Position{} })
		mut has_name := false
		mut attrs := []cx.ProgramAttr{}
		mut items := []cx.ProgramNode{}
		for ch in element_children(e) {
			if ch is cx.Element && ch.name == 'cx:name' {
				name_expr = data_to_program_node(first_child(ch)!)!
				has_name = true
			} else if ch is cx.Element && ch.name == 'cx:attr' {
				aname := cx_attr_name(ch) or { return error('tree-eval: <cx:attr> missing name') }
				av := data_to_program_node(cx_attr_value(ch))!
				attrs << cx.ProgramAttr{ name: aname, value: av }
			} else {
				items << data_to_program_node(ch)!
			}
		}
		if !has_name {
			return error('tree-eval: <cx:element> missing <cx:name>')
		}
		return cx.ProgramNode(cx.ProgramLiteral{ kind: .cx_element, name: '', name_expr: name_expr, attrs: attrs, items: items, pos: cx.Position{} })
	}
	// Directive `<cx:NAME>` when NAME is a directive name.
	if cx.is_directive_name(local) {
		mut slots := []cx.ProgramSlot{}
		for ch in element_children(e) {
			if ch is cx.Element && ch.name.starts_with('cx:')
			   && !cxdm_is_value_tag(ch.name[3..]) && !cx.is_directive_name(ch.name[3..]) {
				label := ch.name[3..]
				slots << cx.ProgramSlot{ kind: .labeled, label: label, value: data_to_program_node(first_child(ch)!)! }
			} else {
				slots << cx.ProgramSlot{ kind: .positional, value: data_to_program_node(ch)! }
			}
		}
		return cx.ProgramNode(cx.ProgramDirective{ name: local, slots: slots, pos: cx.Position{} })
	}
	return error('tree-eval: unrecognized <${e.name}> in code tree')
}

fn unwrap_items(e cx.Element) ![]cx.ProgramNode {
	mut out := []cx.ProgramNode{}
	for ch in element_children(e) {
		if ch is cx.Element && ch.name == 'item' {
			out << data_to_program_node(first_child(ch)!)!
		} else {
			out << data_to_program_node(ch)!
		}
	}
	return out
}

fn cx_elem_attr(e cx.Element, name string) ?string {
	for a in e.attrs {
		if a.name == name {
			return cx.scalar_value_str_public(a.value)
		}
	}
	return none
}

fn cx_attr_name(e cx.Element) ?string {
	return cx_elem_attr(e, 'name')
}

fn cx_attr_value(e cx.Element) cx.Node {
	for it in e.items {
		if it is cx.TextNode {
			continue
		}
		return it
	}
	return empty_seq_node()
}

fn cxdm_is_value_tag(local string) bool {
	return local in ['int', 'float', 'bool', 'str', 'atom', 'dur', 'var', 'expr',
		'call', 'op', 'seq', 'arr', 'map', 'block', 'wildcard', 'slice', 'slice-access',
		'for-comp', 'pattern', 'element', 'name', 'attr', 'entry', 'key']
}

// ── [?eval] / cx:eval-tree — tree-eval (§6.4.4) ─────────────────────────────

const tree_eval_default_depth = 8

// eval_tree evaluates `[?eval TREE [context MAP]? [opts MAP]?]` (§6.4.4):
// evaluate a CXDM value as code with NO parse step. Reuses the cx:eval sandbox.
fn eval_tree(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	if d.slots.len == 0 {
		return EvalError{ code: 'cx-err:CXER0100', message: '[?eval] requires a TREE expression' }
	}
	tree_val := eval_node(d.slots[0].value, mut env)!
	if is_err_node(tree_val) {
		return tree_val
	}
	mut ctx := map[string]cx.Node{}
	mut max_depth := tree_eval_default_depth
	for i := 1; i < d.slots.len; i++ {
		s := d.slots[i]
		if s.kind != .labeled {
			continue
		}
		if s.label == 'context' {
			cv := eval_node(s.value, mut env)!
			ctx = map_value_to_bindings(cv)
		} else if s.label == 'opts' {
			ov := eval_node(s.value, mut env)!
			md, has_md := map_get_int(ov, 'max-depth')
			if has_md {
				max_depth = md
			}
		}
	}
	return run_tree_eval(tree_val, ctx, max_depth, mut env)!
}

// eval_tree_fn is the function-call form of tree-eval — cx:eval-tree per
// spec/modules/cx.md §3.4, the dual of the [?eval] directive. Args are
// positional: ($tree $context::map=$nil $opts::map=$nil). Reuses the shared
// run_tree_eval engine (capability gate + shared depth counter + context
// isolation), so [?eval TREE [context MAP] [opts {…}]] and
// cx:eval-tree($tree $context $opts) are observably identical.
fn eval_tree_fn(args []cx.Node, mut env MatchEnv) !cx.Node {
	if args.len == 0 {
		return EvalError{ code: 'cx-err:CXER0100', message: 'cx:eval-tree requires a TREE argument' }
	}
	tree_val := args[0]
	if is_err_node(tree_val) {
		return tree_val
	}
	mut ctx := map[string]cx.Node{}
	if args.len > 1 {
		// $context defaults to $nil (empty context); map_value_to_bindings
		// yields {} for a nil/non-map value.
		ctx = map_value_to_bindings(args[1])
	}
	mut max_depth := tree_eval_default_depth
	if args.len > 2 {
		md, has_md := map_get_int(args[2], 'max-depth')
		if has_md {
			max_depth = md
		}
	}
	return run_tree_eval(tree_val, ctx, max_depth, mut env)!
}

// run_tree_eval is the shared tree-eval engine (used by [?eval] and
// cx:eval-tree). Checks the eval capability, builds an isolated context env,
// enforces the shared depth counter, lowers the tree (no parse step), evaluates.
fn run_tree_eval(tree_val cx.Node, ctx map[string]cx.Node, max_depth int, mut env MatchEnv) !cx.Node {
	if !cap_allowed('eval') {
		return mk_err('cx-err:CXER0271', 'eval capability denied — tree-eval requires the `eval` capability (run with --allow-eval)')
	}
	if is_empty_seq_node(tree_val) {
		return empty_seq_node()
	}
	if tree_val is cx.ScalarNode {
		return tree_val
	}
	if tree_val is cx.TextNode {
		return tree_val
	}
	has_state := env.state != unsafe { nil }
	if has_state && env.state.eval_depth >= max_depth {
		return mk_err('cx-err:CXER4114', 'tree-eval recursion depth exceeded (max-depth=${max_depth})')
	}
	prog := data_to_program_node(tree_val) or {
		return mk_err('cx-err:CXER0238', 'tree-eval: tree node not evaluable as code in its position')
	}
	// A construction sub-form ([?attr]/[?entry]/[?name]/[?unquote]/[?splice])
	// is valid only nested inside a constructor; as the top-level eval target
	// it is non-evaluable-in-position (§6.4.6). Surface the tree-eval-specific
	// CXER0238 instead of letting the node's generic CXER0100 misuse escape.
	if prog is cx.ProgramDirective {
		if prog.name in ['attr', 'entry', 'name', 'unquote', 'splice'] {
			return mk_err('cx-err:CXER0238', 'tree-eval: [?${prog.name}] is not evaluable as code in this position')
		}
	}
	mut sub := new_env()
	sub.state = env.state
	for k, v in ctx {
		sub.bindings[k] = v
	}
	// §6.4.4 module non-widening (#808): capture the caller's `[?lib]` alias
	// set for the duration of the tree-eval, so eval_lib can refuse a lib the
	// caller did not have (CXER4113). NOT merely unenforced before this — the
	// sub-env shares `state`, and eval_lib registers into
	// state.module_table, so a `[?lib]` inside an evaluated tree WIDENED THE
	// CALLER'S OWN module table as a side effect. The depth-cap twin
	// (CXER4114, just above) was enforced; this half of the same sandbox rule
	// was not.
	//
	// Saved and restored rather than cleared, so a nested tree-eval narrows
	// against ITS caller and the outer one is unaffected on the way out.
	mut prev_allow := ?[]string(none)
	if has_state {
		if p := env.state.tree_eval_lib_allow {
			prev_allow = p.clone()
		}
		mut allowed := []string{}
		for alias, _ in env.state.module_table.alias_modules {
			allowed << alias
		}
		env.state.tree_eval_lib_allow = allowed
		env.state.eval_depth++
	}
	result := eval_node(prog, mut sub) or {
		if has_state {
			env.state.eval_depth--
			env.state.tree_eval_lib_allow = prev_allow
		}
		return err
	}
	if has_state {
		env.state.eval_depth--
		env.state.tree_eval_lib_allow = prev_allow
	}
	return result
}

// map_value_to_bindings flattens a `__cx_map__` value to a name → node map.
fn map_value_to_bindings(v cx.Node) map[string]cx.Node {
	mut out := map[string]cx.Node{}
	if v is cx.Element {
		if v.name == map_marker_name {
			for e in v.items {
				if e is cx.Element {
					if e.items.len > 0 {
						out[e.name] = e.items[0]
					}
				}
			}
		}
	}
	return out
}

// map_get_int reads an integer-valued key from a `__cx_map__` value.
fn map_get_int(v cx.Node, key string) (int, bool) {
	binds := map_value_to_bindings(v)
	val := binds[key] or { return 0, false }
	if val is cx.ScalarNode {
		iv := val.value
		if iv is i64 {
			return int(iv), true
		}
	}
	return 0, false
}
