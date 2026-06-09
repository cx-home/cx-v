module code

import cx

// region_export — the escape-safety deep-copy for scope-aware regions
// (see bench/parallel-alloc/INTEGRATION-DESIGN.md §5–§6).
//
// When a [?worker] body (or any region work unit) runs with the per-thread
// region active, its transient cx.Node structure is bump-allocated in the
// region block and becomes DANGLING the moment the scope exits and resets the
// block. Any value that must outlive the scope — the worker result, a value
// sent on a channel — must therefore be copied onto the GC heap BEFORE the
// reset. region_export is that total recursive copy.
//
// Mechanism: cx_region_suspend() turns region routing OFF for the calling
// thread (so every allocation made during the copy lands on GC_MALLOC), the
// tree is rebuilt structurally, then cx_region_resume() restores the prior
// state. The function self-guards on cx_region_is_active(): when the region is
// not active (the default build, where `-d cx_regions` is absent, or any code
// path outside a scope) it returns its argument unchanged with zero copying —
// so wiring a region_export call into an eval path is inert by default.
//
// What needs copying vs. what is shared:
//   - SCANNED allocations (the Node sum-type boxes, []Node / []Attribute /
//     []MapEntry / []AttDef / []TableColumn arrays, &ElementMeta, &TableData,
//     &IteratorNode) are routed into the region while active → they dangle →
//     they are rebuilt here.
//   - NOSCAN leaves (string `.str` buffers) ALWAYS go to GC_MALLOC even inside
//     a scope (the malloc hook only routes the scanned `malloc` path — see
//     allocation.c.v / INTEGRATION-DESIGN.md §3), so string contents are
//     already GC-owned and are SHARED, not re-copied. Scalar values (bool /
//     i64 / f64 / NullValue) are inline and copied by value.
//
// LIMITATION (initial [?worker] rollout): MatchNode / ModifyNode carry program
// -AST (ProgramNode) subtrees whose deep copy is a separate type hierarchy; a
// match/modify value freshly CONSTRUCTED inside a region scope is only
// shallow-reboxed here (its top box is rescued; in-body-built children are
// not). In practice match/modify values flow from the GC-owned program AST, so
// this is safe for those; returning a body-constructed one from a worker is
// out of scope until the [?async]/handler widening (§7.4). Likewise, a closure
// VALUE returned from a worker body snapshots its captured bindings in-scope —
// closures-as-results are not yet rescued (§6 open item). The corruption
// battery exercises data results (Element / scalars / collections), which are
// copied totally.

// region_export returns a GC-owned deep copy of `n` when a region scope is
// active on the calling thread, or `n` unchanged otherwise.
pub fn region_export(n cx.Node) cx.Node {
	if !cx_region_is_active() {
		return n
	}
	was := cx_region_suspend()
	out := export_node(n)
	cx_region_resume(was)
	return out
}

// export_node rebuilds one node. Caller guarantees the region is suspended, so
// every allocation below lands on the GC heap.
fn export_node(n cx.Node) cx.Node {
	match n {
		cx.Element {
			return cx.Element{
				name:  n.name
				attrs: export_attrs(n.attrs)
				items: export_nodes(n.items)
				meta:  export_element_meta(n.meta)
				table: export_table(n.table)
			}
		}
		cx.TextNode {
			return cx.Node(cx.TextNode{ value: n.value })
		}
		cx.ScalarNode {
			return cx.Node(cx.ScalarNode{ data_type: n.data_type, value: n.value })
		}
		cx.AliasNode {
			return cx.Node(cx.AliasNode{ name: n.name })
		}
		cx.CommentNode {
			return cx.Node(cx.CommentNode{ value: n.value, is_line: n.is_line })
		}
		cx.PINode {
			return cx.Node(cx.PINode{ target: n.target, data: n.data })
		}
		cx.XMLDeclNode {
			return cx.Node(cx.XMLDeclNode{
				version:    n.version
				encoding:   n.encoding
				standalone: n.standalone
			})
		}
		cx.CXDirectiveNode {
			return cx.Node(cx.CXDirectiveNode{
				attrs:  export_attrs(n.attrs)
				anchor: n.anchor
				items:  export_nodes(n.items)
			})
		}
		cx.EntityRefNode {
			return cx.Node(cx.EntityRefNode{ name: n.name })
		}
		cx.RawTextNode {
			return cx.Node(cx.RawTextNode{ value: n.value })
		}
		cx.BlockContentNode {
			return cx.Node(cx.BlockContentNode{ items: export_nodes(n.items) })
		}
		cx.EntityDeclNode {
			// def is `string | ExternalEntityDef` (strings only) — value copy.
			return cx.Node(cx.EntityDeclNode{ kind: n.kind, name: n.name, def: n.def })
		}
		cx.ElementDeclNode {
			return cx.Node(cx.ElementDeclNode{ name: n.name, contentspec: n.contentspec })
		}
		cx.AttlistDeclNode {
			// defs is []AttDef (strings only) — clone reallocates the backing
			// buffer onto GC; elements are value-copied (strings shared).
			return cx.Node(cx.AttlistDeclNode{ name: n.name, defs: n.defs.clone() })
		}
		cx.NotationDeclNode {
			return cx.Node(cx.NotationDeclNode{
				name:      n.name
				public_id: n.public_id
				system_id: n.system_id
			})
		}
		cx.PEReferenceNode {
			return cx.Node(cx.PEReferenceNode{ name: n.name })
		}
		cx.DoctypeDecl {
			return cx.Node(cx.DoctypeDecl{
				name:        n.name
				external_id: n.external_id
				int_subset:  export_nodes(n.int_subset)
			})
		}
		cx.ConditionalSectNode {
			return cx.Node(cx.ConditionalSectNode{ kind: n.kind, subset: export_nodes(n.subset) })
		}
		cx.InterpolationNode {
			return cx.Node(cx.InterpolationNode{ expr: n.expr })
		}
		cx.EvalDirectiveNode {
			return cx.Node(cx.EvalDirectiveNode{
				name:  n.name
				attrs: export_attrs(n.attrs)
				items: export_nodes(n.items)
			})
		}
		cx.SequenceNode {
			return cx.Node(cx.SequenceNode{ items: export_nodes(n.items) })
		}
		cx.ArrayNode {
			return cx.Node(cx.ArrayNode{ items: export_nodes(n.items) })
		}
		cx.MapNode {
			return cx.Node(cx.MapNode{ entries: export_map_entries(n.entries) })
		}
		cx.IteratorNode {
			// @[heap] + identity-by-pointer: rebuilding mints a fresh identity,
			// which is correct here — the region original is about to be reset,
			// so no surviving reference can compare against it (cx values are
			// trees, no aliasing). source_args + memo are recursively copied.
			return cx.Node(cx.IteratorNode{
				source_kind: n.source_kind
				source_args: export_nodes(n.source_args)
				memo:        export_nodes(n.memo)
				exhausted:   n.exhausted
				single_use:  n.single_use
			})
		}
		cx.MatchNode {
			// Shallow rebox — see LIMITATION at the top of this file.
			return cx.Node(n)
		}
		cx.ModifyNode {
			// Shallow rebox — see LIMITATION at the top of this file.
			return cx.Node(n)
		}
		cx.DocumentNode {
			// D7 — deep-copy the transparent document carrier onto the GC heap.
			mut dt := ?cx.DoctypeDecl(none)
			if d := n.doctype {
				exported := export_node(cx.Node(d))
				if exported is cx.DoctypeDecl {
					dt = exported
				}
			}
			return cx.Node(cx.DocumentNode{
				prolog:   export_nodes(n.prolog)
				doctype:  dt
				elements: export_nodes(n.elements)
			})
		}
	}
}

fn export_nodes(items []cx.Node) []cx.Node {
	mut out := []cx.Node{cap: items.len}
	for it in items {
		out << export_node(it)
	}
	return out
}

fn export_attrs(attrs []cx.Attribute) []cx.Attribute {
	mut out := []cx.Attribute{cap: attrs.len}
	for a in attrs {
		out << cx.Attribute{
			name:   a.name
			value:  a.value
			is_ref: a.is_ref
			meta:   export_attr_meta(a.meta)
		}
	}
	return out
}

fn export_attr_meta(m &cx.AttributeMeta) &cx.AttributeMeta {
	if isnil(m) {
		return unsafe { nil }
	}
	mut nb := ?[]cx.Node(none)
	if b := m.body {
		nb = export_nodes(b)
	}
	return &cx.AttributeMeta{
		data_type: m.data_type
		local:     m.local
		ns_uri:    m.ns_uri
		body:      nb
	}
}

fn export_element_meta(m &cx.ElementMeta) &cx.ElementMeta {
	if isnil(m) {
		return unsafe { nil }
	}
	return &cx.ElementMeta{
		anchor:        m.anchor
		merge:         m.merge
		data_type:     m.data_type
		id:            m.id
		body_ref:      m.body_ref
		lang_resolved: m.lang_resolved
		local:         m.local
		ns_uri:        m.ns_uri
	}
}

fn export_table(t &cx.TableData) &cx.TableData {
	if isnil(t) {
		return unsafe { nil }
	}
	mut rows := [][]cx.TableCellValue{cap: t.rows.len}
	for row in t.rows {
		mut nrow := []cx.TableCellValue{cap: row.len}
		for cell in row {
			nrow << export_cell(cell)
		}
		rows << nrow
	}
	return &cx.TableData{
		cols:         t.cols.clone()
		rows:         rows
		from_chunked: t.from_chunked
	}
}

// export_cell copies a table cell. Scalar variants are value-copied (strings
// shared); the collection-literal variants carry region Node trees and recurse.
fn export_cell(c cx.TableCellValue) cx.TableCellValue {
	match c {
		cx.ArrayNode {
			return cx.TableCellValue(cx.ArrayNode{ items: export_nodes(c.items) })
		}
		cx.MapNode {
			return cx.TableCellValue(cx.MapNode{ entries: export_map_entries(c.entries) })
		}
		cx.SequenceNode {
			return cx.TableCellValue(cx.SequenceNode{ items: export_nodes(c.items) })
		}
		else {
			// bool | i64 | f64 | string | NullValue — inline/noscan, share.
			return c
		}
	}
}

fn export_map_entries(entries []cx.MapEntry) []cx.MapEntry {
	mut out := []cx.MapEntry{cap: entries.len}
	for e in entries {
		out << cx.MapEntry{
			key_type:  e.key_type
			key_value: e.key_value
			value:     export_node(e.value)
		}
	}
	return out
}
