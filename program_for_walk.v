module cx

// program_for_walk.v — THE [?for] traversal contract (stream-2 ruling L100,
// planar_algebra.md §2; issue #711 item 7).
//
// Every consumer that needs a comprehension's child nodes — purity, lint,
// extraction, shape inference, LSP surfaces, Tier-2 emission, diagrams —
// enumerates them THROUGH THIS ONE FUNCTION instead of hand-rolling the
// clause walk. The nine-plus duplicate walkers diverged exactly the way
// L100 predicted: the first consumer moved onto this contract (the purity
// checker) had been SKIPPING the `[yield-map K V]` VALUE node, so an impure
// expression in map-value position escaped the definition-time purity
// refusal entirely (probed live, stream-2 W2).
//
// The contract: every child ProgramNode of a ProgramForComp, exactly once,
// in surface order — per clause (source first, then expr), then the yield
// node, then the map-yield value node when present. Non-node clause payload
// (bind names, direction, par width) is deliberately NOT enumerated: it is
// clause METADATA, read from the clause row a consumer already holds via
// `clause_idx`.

// ForWalkRole — which slot of the comprehension a walked node occupies.
pub enum ForWalkRole {
	clause_source // a generator's source (clause_idx set)
	clause_expr   // a filter / binding / order-by / group-by / take etc. expression (clause_idx set)
	yield_node    // the yield body (clause_idx = -1)
	yield_value   // the [yield-map K V] value node (clause_idx = -1)
}

// ForWalkItem — one enumerated child node with its role.
pub struct ForWalkItem {
pub:
	role       ForWalkRole
	clause_idx int // index into f.clauses; -1 for the yield items
	node       ProgramNode
}

// for_comp_children enumerates every child node of the comprehension,
// exactly once, in surface order. THE single traversal (L100).
pub fn for_comp_children(f ProgramForComp) []ForWalkItem {
	mut out := []ForWalkItem{cap: f.clauses.len * 2 + 2}
	for i, c in f.clauses {
		if src := c.source {
			out << ForWalkItem{
				role:       .clause_source
				clause_idx: i
				node:       src
			}
		}
		if e := c.expr {
			out << ForWalkItem{
				role:       .clause_expr
				clause_idx: i
				node:       e
			}
		}
	}
	out << ForWalkItem{
		role:       .yield_node
		clause_idx: -1
		node:       f.yield
	}
	if yv := f.yield_value {
		out << ForWalkItem{
			role:       .yield_value
			clause_idx: -1
			node:       yv
		}
	}
	return out
}
