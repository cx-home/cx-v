module code

// planar_query.v — the Ring-1 half of the L99 quoted planar store query
// (store.md §6.2; W6 of the I5 stream-2 ledger): static slice-set
// extraction (the L100 which-sources walk) and the sandboxed executor.
// The Ring-2 orchestration (handle resolution, the authz-slice layer, the
// wire) lives in vcx/platform/stdlib_store.v; this file owns everything
// that is a pure function of the query TEXT plus the execution sandbox.
//
// The quoted comprehension arrives as `[cx:expr '<source>']` (the [?quote]
// lowering — quoted trees lower to plain authorable CX text), so the whole
// pipeline is string-as-source: parse → §7.8 membership → slice extraction
// → L96 rewrite → sandboxed evaluation. The plan address of the same
// source (cx:plan-address / code.md §7.9) is the caching identity.

import cx

// planar_query_source extracts the source text from a quoted-comprehension
// value: the `[cx:expr '<source>']` lowering (a one-string-child element).
// Returns none for any other shape (the caller's typed refusal).
pub fn planar_query_source(v cx.Node) ?string {
	if v is cx.Element {
		if v.name == 'cx:expr' && v.items.len == 1 {
			it := v.items[0]
			if it is cx.ScalarNode {
				sv := it.value
				if sv is string {
					return sv
				}
			}
			if it is cx.TextNode {
				return it.value
			}
		}
	}
	return none
}

// PlanarSliceRef is one extracted source slice: kind ('store'|'journal'),
// the handle's binding NAME (resolved against the caller's bindings by the
// Ring-2 layer), and the literal path/stream.
pub struct PlanarSliceRef {
pub:
	kind   string
	handle string
	path   string
}

// planar_extract_slices extracts the STATIC slice set from a planar member
// — the L100 which-sources consumer, authored on the ONE walk
// (for_comp_children): every [$store:source …] / [$journal:source …] call
// with its literal path. The §6.5.1 purity theorem makes this set exactly
// the query's read set (membership refuses every other effect). Errors:
// a non-literal path (the slice set must be static — the caller maps to
// CXER1709) or a non-bare-binding handle argument.
pub fn planar_extract_slices(n cx.ProgramNode) ![]PlanarSliceRef {
	mut out := []PlanarSliceRef{}
	planar_slices_walk(n, mut out)!
	// dedup (handle, path) pairs — one authz check per distinct slice.
	mut seen := map[string]bool{}
	mut dedup := []PlanarSliceRef{}
	for s in out {
		key := '${s.kind}\x00${s.handle}\x00${s.path}'
		if key in seen {
			continue
		}
		seen[key] = true
		dedup << s
	}
	return dedup
}

fn planar_slices_walk(n cx.ProgramNode, mut out []PlanarSliceRef) ! {
	match n {
		cx.Program {
			planar_slices_walk(n.body, mut out)!
		}
		cx.ProgramForComp {
			// the ONE walk: every child node of the comprehension exactly
			// once — clause sources/exprs, yield, yield-value.
			for item in cx.for_comp_children(n) {
				planar_slices_walk(item.node, mut out)!
			}
		}
		cx.ProgramCall {
			if n.name in planar_source_ref_names {
				kind := if n.name == 'store:source' { 'store' } else { 'journal' }
				if n.args.len < 2 {
					return error('a [\$${n.name}] source reference needs (handle, path)')
				}
				handle := n.args[0]
				if handle !is cx.ProgramBinding {
					return error('a [\$${n.name}] handle must be a bare enclosing-scope binding (code.md §7.8 point 3)')
				}
				hb := handle as cx.ProgramBinding
				if hb.path.len > 0 {
					return error('a [\$${n.name}] handle must be a bare binding (got a path expression)')
				}
				parg := n.args[1]
				mut path := ''
				if parg is cx.ProgramLiteral && parg.kind == .string_lit {
					path = parg.str_val
				} else if parg is cx.ProgramLiteral && parg.kind == .atom_lit {
					// journal streams may be spelled as atoms (:default)
					path = ':${parg.str_val}'
				} else {
					return error('the [\$${n.name}] path/stream must be a literal — the slice set is extracted statically, authorize-before-execute needs it (store.md §6.2)')
				}
				out << PlanarSliceRef{
					kind:   kind
					handle: hb.name
					path:   path
				}
				return
			}
			for a in n.args {
				planar_slices_walk(a, mut out)!
			}
		}
		cx.ProgramDirective {
			for s in n.slots {
				planar_slices_walk(s.value, mut out)!
			}
		}
		cx.ProgramLiteral {
			for it in n.items {
				planar_slices_walk(it, mut out)!
			}
			for s in n.slots {
				planar_slices_walk(s.value, mut out)!
			}
			for a in n.attrs {
				planar_slices_walk(a.value, mut out)!
			}
		}
		cx.ProgramPattern {
			for a in n.attrs {
				if v := a.value {
					planar_slices_walk(v, mut out)!
				}
			}
			for child in n.body {
				planar_slices_walk(child, mut out)!
			}
		}
		cx.ProgramSliceAccess {
			for ax in n.axes {
				if s := ax.start {
					planar_slices_walk(s, mut out)!
				}
				if s := ax.stop {
					planar_slices_walk(s, mut out)!
				}
				if s := ax.step {
					planar_slices_walk(s, mut out)!
				}
			}
		}
		else {}
	}
}

// planar_query_narrowed_caps — the L99 narrowed set: everything the pure
// fragment cannot legitimately need is denied for the query's dynamic
// extent. read/net stay — they are what source scans use; eval is denied
// INSIDE (membership already refuses [?eval] statically — this is the
// defense-in-depth layer).
const planar_query_narrowed_caps = ['write', 'env', 'clock', 'random', 'subprocess', 'eval',
	'secret-reveal']

// planar_query_execute runs a MEMBERSHIP-CHECKED planar comprehension in
// the L99 sandbox: the `eval` host capability gates entry (quoted code is
// dynamic execution — the shipped [?eval] posture), the narrowed cap set
// is installed for the dynamic extent, and the isolated environment
// receives ONLY `bindings` (the resolved source-ref handles — the purity
// theorem's "exactly its source set"). The stdlib store/journal modules
// are activated inside the sandbox (the source-ref verbs are the one
// effect surface the fragment is allowed). Returns the comprehension's
// own relation, or an err VALUE.
pub fn planar_query_execute(prog cx.ProgramNode, bindings map[string]cx.Node, mut env MatchEnv) cx.Node {
	if !cap_allowed('eval') {
		return mk_err('cx-err:CXER0271',
			'eval capability denied — the host-capability layer: a quoted planar query executes through the sandboxed [?eval] and requires the `eval` capability (run with --allow-eval)')
	}
	saved := caps_push_narrowed(planar_query_narrowed_caps)
	defer {
		caps_restore(saved)
	}
	mut sub := new_env()
	sub.state = env.state
	for k, v in bindings {
		sub.bindings[k] = v
	}
	// activate the source-ref modules in the sandbox (fresh env = no
	// [?lib] state; the source verbs are the fragment's one effect
	// surface).
	prelude := cx.parse_program("[?lib 'cx-stdlib/store'] [?lib 'cx-stdlib/journal']") or {
		return mk_err('cx-err:CXER0001', 'planar query sandbox: prelude parse failed: ${err.msg()}')
	}
	eval_node(prelude.body, mut sub) or {
		return mk_err('cx-err:CXER0001', 'planar query sandbox: prelude failed: ${err.msg()}')
	}
	body := if prog is cx.Program { prog.body } else { prog }
	result := eval_node(body, mut sub) or { return unwrap_guard_err(err) or { mk_err('cx-err:CXER0001',
		'planar query execution failed: ${err.msg()}') } }
	if is_err_value(result) {
		return result
	}
	// materialize the relation (a comprehension may return a lazy
	// iterator) into the SAME plain sequence shape the CXPath query verb
	// returns — one rendering convention, byte-parity with the wire path.
	return cx.Element{
		name:  seq_marker_name
		items: iterate(result)
	}
}
