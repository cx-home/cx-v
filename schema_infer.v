module cx

// ── Corpus shape synthesis — `cx schema infer` (shape_inference.md §8,
// L68; stream 16 W3) ──────────────────────────────────────────────────
//
// Ring 0: documents in, a deterministic `.cxs` out. No evaluator.
//
// The join lattice (normative): identical→identical; int ⊔ float →
// float (the numeric family — the validator already accepts int where
// float is declared); decimal joins only decimal (stream 11's
// no-mixing rule); anything else → `[or …]` — inference NEVER widens
// to string. Observed attr absence → `[opt]`; observed child counts →
// `[card "M..N"]`; a body absent in some occurrences → `[opt]`.
//
// Determinism contract: the same corpus yields byte-identical output
// (attrs/elems/types sorted by name, or-members sorted, no timestamps),
// so the inferred schema's content-hash is a stable E2 identity.
// Emitted schemas are mode=open (they describe what was seen); sampling
// is full-corpus by default — bounded sampling is opt-in and records
// its provenance as a header attribute (identity-bearing, but corpus-
// determined, so the contract holds).

pub struct SchemaInferOpts {
pub mut:
	// 0 = full corpus (the default). N>0 = infer from the first N
	// documents only; the header records `sample="N/TOTAL"`.
	sample int
}

// InferShape is the recursive join accumulator: scalar members plus at
// most one joined shape per container axis. Containers join item-wise
// (arr ⊔ arr joins the items), never textually.
@[heap]
struct InferShape {
mut:
	scalars  []string
	has_list bool
	list_it  &InferShape = unsafe { nil }
	has_seq  bool
	seq_it   &InferShape = unsafe { nil }
	has_map  bool
	map_key  &InferShape = unsafe { nil }
	map_val  &InferShape = unsafe { nil }
}

fn (mut s InferShape) add_scalar(name string) {
	if name == '' {
		return
	}
	if name !in s.scalars {
		s.scalars << name
	}
	// int ⊔ float → float (the one collapsing join; decimal never
	// collapses — it stays its own member).
	if 'int' in s.scalars && 'float' in s.scalars {
		s.scalars = s.scalars.filter(it != 'int')
	}
}

fn (mut s InferShape) join_node(n Node) {
	match n {
		ScalarNode {
			s.add_scalar(scalar_type_name(n.data_type))
		}
		TextNode {
			s.add_scalar('string')
		}
		ArrayNode {
			if !s.has_list {
				s.has_list = true
				s.list_it = &InferShape{}
			}
			mut it := unsafe { s.list_it }
			for item in n.items {
				it.join_node(item)
			}
		}
		SequenceNode {
			if !s.has_seq {
				s.has_seq = true
				s.seq_it = &InferShape{}
			}
			mut it := unsafe { s.seq_it }
			for item in n.items {
				it.join_node(item)
			}
		}
		MapNode {
			if !s.has_map {
				s.has_map = true
				s.map_key = &InferShape{}
				s.map_val = &InferShape{}
			}
			mut mk := unsafe { s.map_key }
			mut mv := unsafe { s.map_val }
			for entry in n.entries {
				mk.add_scalar(scalar_type_name(entry.key_type))
				mv.join_node(entry.value)
			}
		}
		else {}
	}
}

fn (s &InferShape) is_empty() bool {
	return s.scalars.len == 0 && !s.has_list && !s.has_seq && !s.has_map
}

// render yields the type text for the joined shape: one member bare,
// several as a sorted `[or …]`. An empty shape (nothing observed —
// e.g. only empty arrays) renders `any`.
fn (s &InferShape) render() string {
	mut members := s.scalars.clone()
	if s.has_list {
		members << '[list ${s.list_it.render()}]'
	}
	if s.has_seq {
		members << '[seq ${s.seq_it.render()}]'
	}
	if s.has_map {
		members << '[map ${s.map_key.render()} ${s.map_val.render()}]'
	}
	if members.len == 0 {
		return 'any'
	}
	members.sort()
	if members.len == 1 {
		return members[0]
	}
	return '[or ${members.join(' ')}]'
}

struct InferAttrAcc {
mut:
	shape &InferShape = unsafe { nil }
	seen  int
}

struct InferTypeAcc {
mut:
	occurrences int
	attrs       map[string]InferAttrAcc
	child_min   map[string]int
	child_max   map[string]int
	body        &InferShape = unsafe { nil }
	body_seen   int
	has_kids    bool
}

// schema_infer synthesizes an open-mode `.cxs` schema from a corpus of
// documents. Every document's top-level elements must share ONE name —
// that name becomes `of=` (mixed roots are refused loudly; a corpus
// with two document kinds is two inference runs).
pub fn schema_infer(docs []Document, opts SchemaInferOpts) !string {
	if docs.len == 0 {
		return error('schema infer: empty corpus (no documents)')
	}
	total := docs.len
	take := if opts.sample > 0 && opts.sample < total { opts.sample } else { total }
	mut root := ''
	mut accs := map[string]&InferTypeAcc{}
	mut type_order := []string{}
	for di in 0 .. take {
		doc := docs[di]
		mut saw_root := false
		for n in doc.elements {
			if n is Element {
				if root == '' {
					root = n.name
				} else if n.name != root {
					return error('schema infer: mixed root elements — saw <${root}> and <${n.name}> (one corpus, one document kind; run infer per kind)')
				}
				saw_root = true
				infer_walk(n, mut accs, mut type_order)
			}
		}
		if !saw_root {
			return error('schema infer: document ${di + 1} has no root element')
		}
	}
	if root == '' {
		return error('schema infer: corpus has no root element')
	}
	// ── Emission (deterministic) ──
	mut sb := []string{}
	sample_attr := if take < total { ' sample="${take}/${total}"' } else { '' }
	sb << '[schema of=${root} mode=open${sample_attr}]'
	mut names := type_order.clone()
	names.sort()
	// Root first, the rest sorted.
	root_acc := accs[root] or { return error('schema infer: internal — root accumulator missing') }
	sb << infer_render_type(root, root_acc)
	for name in names {
		if name == root {
			continue
		}
		acc := accs[name] or { continue }
		sb << infer_render_type(name, acc)
	}
	return sb.join('\n') + '\n'
}

fn infer_walk(e Element, mut accs map[string]&InferTypeAcc, mut type_order []string) {
	if e.name !in accs {
		accs[e.name] = &InferTypeAcc{
			body: &InferShape{}
		}
		type_order << e.name
	}
	mut acc := accs[e.name] or { return }
	prior := acc.occurrences
	acc.occurrences++
	for a in e.attrs {
		if a.name !in acc.attrs {
			acc.attrs[a.name] = InferAttrAcc{
				shape: &InferShape{}
			}
		}
		mut aa := acc.attrs[a.name] or { continue }
		mut sh := unsafe { aa.shape }
		sh.add_scalar(infer_attr_type_name(a))
		aa.seen++
		acc.attrs[a.name] = aa
	}
	mut counts := map[string]int{}
	mut body_here := false
	for n in e.items {
		match n {
			Element {
				counts[n.name]++
				infer_walk(n, mut accs, mut type_order)
			}
			ScalarNode, TextNode, ArrayNode, SequenceNode, MapNode {
				mut b := unsafe { acc.body }
				b.join_node(n)
				body_here = true
			}
			else {}
		}
	}
	if counts.len > 0 {
		acc.has_kids = true
	}
	if body_here {
		acc.body_seen++
	}
	// Cardinality bookkeeping: names absent in this occurrence floor to
	// 0; names first seen after occurrence 1 also floor to 0.
	for name, c in counts {
		if name !in acc.child_max {
			acc.child_max[name] = c
			acc.child_min[name] = if prior > 0 { 0 } else { c }
		} else {
			if c > acc.child_max[name] {
				acc.child_max[name] = c
			}
			if c < acc.child_min[name] {
				acc.child_min[name] = c
			}
		}
	}
	for name, _ in acc.child_max {
		if name !in counts {
			acc.child_min[name] = 0
		}
	}
}

fn infer_attr_type_name(a Attribute) string {
	if dt := a.data_type() {
		st := scalar_type_from_name(dt) or { ScalarType.string_type }
		return scalar_type_name(st)
	}
	return match a.value {
		i64       { 'int' }
		f64       { 'float' }
		bool      { 'bool' }
		string    { 'string' }
		NullValue { 'null' }
	}
}

fn infer_render_type(name string, acc &InferTypeAcc) string {
	mut parts := []string{}
	mut attr_names := acc.attrs.keys()
	attr_names.sort()
	for an in attr_names {
		aa := acc.attrs[an] or { continue }
		req := if aa.seen == acc.occurrences { '[req]' } else { '[opt]' }
		parts << ' [attr ${an}::${aa.shape.render()} ${req}]'
	}
	mut child_names := acc.child_max.keys()
	child_names.sort()
	for cn in child_names {
		parts << ' [elem ${cn} [card "${acc.child_min[cn]}..${acc.child_max[cn]}"]]'
	}
	// A body rule only when body content was observed and the element
	// is not mixed-content (children + body — open mode covers it).
	if acc.body_seen > 0 && !acc.has_kids {
		req := if acc.body_seen == acc.occurrences { '[req]' } else { '[opt]' }
		parts << ' [body ${acc.body.render()} ${req}]'
	}
	if parts.len == 0 {
		return '[${name}]'
	}
	return '[${name}\n' + parts.join('\n') + ']'
}
