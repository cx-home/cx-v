module code

import cx
import crypto.sha256
import strings

// #79 — Tier-2 code identity (pre-Phase-1 floor).
//
// Tier-2 identity content-addresses CX *code* by the hash of its NORMALIZED
// AST, so two definitions collide iff they are the same computation up to
// (a) bound-variable renaming (alpha-equivalence), (b) comments/formatting,
// (c) the definition's own name, and (d) the names of the definitions it
// depends on (names are aliases — store §3.9). Distinct from and additional to
// Tier-1 (data) identity (canonical.md §1.4).
//
// Normalization `N` (spec/02-working/cxstore_code_identity_tier2.md §2):
//   1. Comments/formatting: the program AST carries no comment node, so
//      parse_program already discards them — comment/format insensitivity is
//      structural (proven by tests, not assumed).
//   2. Alpha-normalize binders → de Bruijn LEVELS: every binder introduces its
//      name at the next level; a bound read emits its level, a free read emits
//      its name verbatim. The def name is excluded.
//   3. Dependency-by-hash (Merkle-DAG): a free reference to a sibling
//      definition is emitted as that sibling's Tier-2 hash, so identity is
//      transitively complete and rename-independent for callees too.
//   4. Mutual recursion = one component: definitions in a dependency cycle are
//      hashed as a single SCC (intra-cycle references become positional `@sccK`
//      tokens), and each member's hash is `H(component-hash # position)`.
//
// IMPLEMENTATION: a read-only structural emitter (T2Emitter) walks the AST and
// writes a LENGTH-PREFIXED token stream (every variable-length field as
// `<len>:<bytes>`), so the encoding is injective over AST structure —
// structurally distinct defs can NEVER collide. An unhandled binder form only
// fails to collapse an alpha-variant (a missed dedup), never merges two
// different computations. (We do not reconstruct the AST and re-emit source: V
// cannot codegen struct-literal reconstruction of the recursive program AST.)
//
// PRE-PHASE-1 FLOOR: whole-program / def-blob content-addressing by normalized
// hash. No searchable / function-level index is built here (Phase-1+; #85/#86).

// cx_code_tier2_hash returns the lowercase hex SHA-256 of the normalized AST of
// a single `[?def …]` definition, with NO dependency resolution (free refs are
// emitted verbatim). Correct for leaf defs whose free references are language
// builtins; for defs that call sibling user definitions use
// cx_program_tier2_hashes (which resolves dependencies to hashes).
pub fn cx_code_tier2_hash(def_source string) !string {
	def := cx.parse_def(def_source)!
	stream, _ := normalize_def_node(def, map[string]bool{}, map[string]string{})!
	// I1 stream 19 (L31): Tier-2 addresses are tagged too — the caller's
	// 'code:' prefix composes on top: code:sha2-256:<hex>.
	return cx.cx_tag_address(cx.cx_default_hash_algo, sha256.sum256(stream.bytes()).hex())
}

// tier2_normalize_def returns the canonical normalized token stream of a single
// def's body (de Bruijn binders, def name excluded, no dependency resolution).
// Exposed for tests/inspection.
pub fn tier2_normalize_def(def_source string) !string {
	def := cx.parse_def(def_source)!
	stream, _ := normalize_def_node(def, map[string]bool{}, map[string]string{})!
	return stream
}

// cx_program_tier2_hashes computes the dependency-aware Tier-2 hash of every
// top-level `[?def …]` in a program, returned as alias-name → hash. References
// between sibling defs are resolved by hash (Merkle-DAG); mutual-recursion
// cycles are hashed as one strongly-connected component.
pub fn cx_program_tier2_hashes(program_source string) !map[string]string {
	prog := cx.parse_program(program_source)!
	mut order := []string{}
	mut defs := map[string]cx.DefNode{}
	collect_program_defs(prog.body, mut order, mut defs)!

	mut siblings := map[string]bool{}
	for n in order {
		siblings[n] = true
	}

	// Dependency edges: def → sibling defs it references (free refs only).
	mut edges := map[string][]string{}
	for n in order {
		_, refs := normalize_def_node(defs[n], siblings, map[string]string{})!
		// Self-edges (direct recursion) are kept — they force a cyclic SCC.
		mut seen := map[string]bool{}
		mut es := []string{}
		for r in refs {
			if r !in seen {
				seen[r] = true
				es << r
			}
		}
		edges[n] = es
	}

	// Tarjan SCC — emitted in reverse-topological order (dependencies first).
	mut t := Tarjan{
		edges: edges
	}
	for n in order {
		if n !in t.index {
			t.strongconnect(n)
		}
	}

	mut hashes := map[string]string{}
	for comp in t.out {
		cyclic := comp.len > 1 || (comp.len == 1 && comp[0] in edges[comp[0]])
		if !cyclic {
			n := comp[0]
			stream, _ := normalize_def_node(defs[n], siblings, hashes)!
			hashes[n] = cx.cx_tag_address(cx.cx_default_hash_algo, sha256.sum256(stream.bytes()).hex())
		} else {
			hash_scc(comp, siblings, defs, mut hashes)!
		}
	}
	return hashes
}

// ── Computation identity is PURE (F1'/A1, 2026-08-08) ────────────────────────
// The computation-identity relation (cx_code_tier2_hash, below) is Ring-1
// and store-free: it backs the [$cx:computation-id] claim
// (`computes-as:<algo>:<hex>`) and the xap-dist exports check. It is an
// index / recompute-and-compare relation, NEVER a storage key — code is
// stored as an OPAQUE document (put-blob, raw-byte identity) on Ring 2.

// hash_scc hashes a strongly-connected component (mutual recursion) as one
// unit, then derives each member's hash positionally.
fn hash_scc(comp []string, siblings map[string]bool, defs map[string]cx.DefNode, mut hashes map[string]string) ! {
	// Step A — placeholder bodies: intra-SCC refs collapse to a single token,
	// external deps already resolved to their hashes (present in `hashes`).
	mut placeholder := hashes.clone()
	for m in comp {
		placeholder[m] = '@scc'
	}
	mut membs := []SccMember{}
	for m in comp {
		body, _ := normalize_def_node(defs[m], siblings, placeholder)!
		membs << SccMember{
			name: m
			body: body
		}
	}
	// Step B — canonical, name-independent order by placeholder body.
	membs.sort(a.body < b.body)
	mut position := map[string]int{}
	for i, mb in membs {
		position[mb.name] = i
	}
	// Step C — positional bodies: each intra-SCC ref → its target's position.
	mut pos_deps := hashes.clone()
	for m in comp {
		pos_deps[m] = '@scc${position[m]}'
	}
	mut concat := strings.new_builder(256)
	for mb in membs {
		body, _ := normalize_def_node(defs[mb.name], siblings, pos_deps)!
		concat.write_string(body)
		concat.write_u8(0x1e) // record separator
	}
	comp_hash := sha256.sum256(concat.str().bytes()).hex()
	for m in comp {
		hashes[m] = cx.cx_tag_address(cx.cx_default_hash_algo, sha256.sum256('${comp_hash}#${position[m]}'.bytes()).hex())
	}
}

struct SccMember {
	name string
	body string
}

// collect_program_defs gathers top-level `[?def …]` directives in source order.
// cx_program_entry_computation_id resolves the F3(a) pushdown carriage's
// entry def in a fetched OPAQUE program document (S6 §4.3) and returns
// (entry_name, tagged_leaf_hash) — the SAME leaf-form computation identity
// the pure [$cx:computation-id] builtin answers, computed on the PARSED def
// (never re-emitted source: re-emission is not identity-safe for code, F1').
// The document must be a program of [?def]s ONLY — a top-level non-def form
// refuses here (the profile maps every refusal from this fn to CXER5025;
// defs-only also means fetching a document can never run load-time effects,
// so no capability question exists at fetch). entry='' resolves iff the
// program holds exactly one def.
pub fn cx_program_entry_computation_id(program_source string, entry string) !(string, string) {
	prog := cx.parse_program(program_source)!
	mut order := []string{}
	mut defs := map[string]cx.DefNode{}
	body := prog.body
	match body {
		cx.ProgramDirective {
			if body.name != 'def' {
				return error('the program document must hold [?def]s only (found [?${body.name}])')
			}
			add_def(body, mut order, mut defs)!
		}
		cx.ProgramLiteral {
			if body.kind != .block {
				return error('the program document must hold [?def]s only (found a ${body.kind} literal)')
			}
			for it in body.items {
				if it is cx.ProgramDirective && it.name == 'def' {
					add_def(it, mut order, mut defs)!
					continue
				}
				return error('the program document must hold [?def]s only (found a top-level non-def form)')
			}
		}
		else {
			return error('the program document must hold [?def]s only')
		}
	}
	if order.len == 0 {
		return error('the program document holds no [?def]')
	}
	mut name := entry
	if name == '' {
		if order.len > 1 {
			return error('entry= is required: the program document holds ${order.len} defs (${order.join(', ')})')
		}
		name = order[0]
	}
	def := defs[name] or {
		return error('entry `${name}` names no def in the program document (defs: ${order.join(', ')})')
	}
	stream, _ := normalize_def_node(def, map[string]bool{}, map[string]string{})!
	return name, cx.cx_tag_address(cx.cx_default_hash_algo, sha256.sum256(stream.bytes()).hex())
}

fn collect_program_defs(node cx.ProgramNode, mut order []string, mut defs map[string]cx.DefNode) ! {
	match node {
		cx.ProgramDirective {
			if node.name == 'def' {
				add_def(node, mut order, mut defs)!
			}
		}
		cx.ProgramLiteral {
			if node.kind == .block {
				for it in node.items {
					collect_program_defs(it, mut order, mut defs)!
				}
			}
		}
		else {}
	}
}

fn add_def(d cx.ProgramDirective, mut order []string, mut defs map[string]cx.DefNode) ! {
	raw := module_raw_source(d) or { return error('[?def] missing source for Tier-2 identity') }
	def := cx.parse_def(raw)!
	if def.name in defs {
		return error('Tier-2 identity: duplicate def `${def.name}`')
	}
	order << def.name
	defs[def.name] = def
}

// normalize_def_node returns the normalized token stream of a def's body plus
// the de-duplicated list of sibling references it makes. `siblings` is the set
// of program-level def names (drives ref recording); `deps` maps a sibling name
// to the token emitted in its place (its hash, or an `@sccK` placeholder).
fn normalize_def_node(def cx.DefNode, siblings map[string]bool, deps map[string]string) !(string, []string) {
	body_prog := cx.parse_program(def.body)!
	mut e := T2Emitter{
		siblings: siblings
		deps:     deps
		b:        strings.new_builder(128)
	}
	for p in def.params {
		e.scope << p.name
	}
	e.b.write_string('def:')
	e.b.write_string(def.params.len.str())
	// I1 row 13 (L28 / audit C2): arity-and-shape-bearing signature
	// fields JOIN the hash — two defs that cannot be called
	// interchangeably must not share an address. Per-param shape tokens:
	// named-param NAMES (part of the call contract — positional names
	// stay alpha-normalized via the binder stack), the rest-kind flag
	// (`($a $b)` vs `($a *$b)` collided pre-I1 — the live W-23 defect),
	// and default VALUES in canonicalized form (rule 5: the same
	// pipeline as the body tokens — never raw source). returns-type
	// contributes its STRICT-CANONICAL SOURCE TEXT bytes (rule 3 — the
	// one deliberate source-text exception, so the I5 TypeExpr parser
	// repair is identity-neutral). purity/scope stay OUT (deployment
	// metadata); every other clause or field is OUTSIDE Tier-2 —
	// EXCLUDED-BY-DEFAULT, closed list (rule 4).
	for p in def.params {
		e.b.write_u8(`p`)
		if p.is_named {
			e.b.write_u8(`n`)
			e.field(p.name)
		}
		if p.is_rest {
			e.b.write_u8(`*`)
		}
		if dv := p.default {
			e.b.write_u8(`=`)
			if dprog := cx.parse_program(dv) {
				e.emit(dprog.body)
			} else {
				e.field(dv)
			}
		}
	}
	if rt := def.returns_type_source {
		e.b.write_u8(`R`)
		e.field(t2_canonical_source(rt))
	}
	e.b.write_u8(`|`)
	e.emit(body_prog.body)
	return e.b.str(), e.refs
}

// t2_canonical_source normalizes a source-text-participating field (rule
// 3's returns-type) to its strict-canonical SOURCE bytes: surrounding
// whitespace trimmed, internal whitespace runs collapsed to one space —
// formatting-insensitive (approved property b) without ever reading the
// parsed slot.
fn t2_canonical_source(src string) string {
	mut out := []u8{cap: src.len}
	mut in_ws := false
	for c in src.trim_space().bytes() {
		if c == ` ` || c == `\t` || c == `\n` || c == `\r` {
			in_ws = true
			continue
		}
		if in_ws && out.len > 0 {
			out << ` `
		}
		in_ws = false
		out << c
	}
	return out.bytestr()
}

// T2Emitter walks the program AST read-only, emitting the normalized stream.
struct T2Emitter {
	siblings map[string]bool   // program def names (for ref recording)
	deps     map[string]string // sibling name → replacement token
mut:
	b     strings.Builder
	scope []string // de Bruijn binder stack (index = level)
	refs  []string // sibling references made by this def (may repeat)
}

fn (mut e T2Emitter) field(s string) {
	e.b.write_string(s.len.str())
	e.b.write_u8(`:`)
	e.b.write_string(s)
}

// ref_name emits a head/reference name, substituting a dependency hash token
// when the name is a resolved sibling, and recording the sibling reference.
fn (mut e T2Emitter) ref_name(name string) {
	if name in e.siblings {
		e.refs << name
	}
	if tok := e.deps[name] {
		e.b.write_u8(`D`)
		e.field(tok)
	} else {
		e.field(name)
	}
}

fn t2_level(scope []string, name string) ?int {
	mut i := scope.len - 1
	for i >= 0 {
		if scope[i] == name {
			return i
		}
		i--
	}
	return none
}

fn (mut e T2Emitter) emit_binding(n cx.ProgramBinding) {
	if lvl := t2_level(e.scope, n.name) {
		e.b.write_u8(`b`)
		e.b.write_string(lvl.str())
	} else {
		// free reference — may be a sibling dependency
		e.b.write_u8(`r`)
		e.ref_name(n.name)
	}
	// #769 audit: pattern-position bindings carry a type test (`$v::int`,
	// reachable through map patterns) and a rest-capture flag (`*$r`) —
	// both distinguish computations. Presence-marked: expression-position
	// bindings never carry either, so their bytes are unchanged.
	if n.type_test != '' {
		e.b.write_u8(`T`)
		e.field(n.type_test)
	}
	if n.is_rest {
		e.b.write_u8(`*`)
	}
	e.emit_path_steps(n.path)
}

// emit_path_steps writes a [135a] step run into the T2 preimage — shared
// by binding paths, the CRS-1 call-result postfix, and the PS-1 result
// postfix on every other bracketed value form (directives, for-comps,
// literals, slice literals). PRESENCE-MARKED by construction: a path-less
// node writes nothing here, so every pre-CRS-1/PS-1 preimage keeps its
// exact bytes, while `[$f $x]@v` and `[$f $x]` remain distinct
// computations (identity = pure function of canonical bytes,
// core/canonical.md §1).
fn (mut e T2Emitter) emit_path_steps(path []cx.ProgramPathStep) {
	for step in path {
		e.b.write_u8(`/`)
		e.b.write_string(step.kind.str())
		e.field(step.name)
		// #925 (PYE-1a/1b): a computed step's binding name is identity-
		// bearing — `$m.$k` and `$m.$j` are different programs. Presence-
		// marked so literal steps keep their exact preimage bytes.
		if step.computed_name != '' {
			e.b.write_u8(`C`)
			e.field(step.computed_name)
		}
		// [131b] kind test — PRESENCE-MARKED so the pre-existing
		// name-test spelling keeps its exact preimage bytes (a step
		// without a kind test writes nothing here, as before). Two kind
		// tests on the same axis differ only in this field, so it has to
		// be in the stream: `$x/text()` and `$x/element()` are not the
		// same query.
		if step.kind_test != .none {
			e.b.write_u8(`K`)
			e.b.write_string(step.kind_test.str())
		}
		for pred in step.predicates {
			e.b.write_u8(`[`)
			e.emit_predicate(pred)
			e.b.write_u8(`]`)
		}
	}
}

// t2_clause_meta writes one comprehension clause's metadata row: kind (IN
// the preimage via c.kind.str()), bind, and — #769 audit — the [order-by]
// DIRECTION, presence-marked so the implicit-asc spelling keeps its
// pre-fix bytes (explicit `asc` vs implicit is a missed dedup, which the
// contract allows; `asc` vs `desc` was a false merge, which it does not).
// par_width/par_max stay OUT deliberately: under the ruled ordered-
// reassembly theorem ([par] reassembles source order ALWAYS), [par 2] and
// [par 4] are the same computation.
fn (mut e T2Emitter) t2_clause_meta(c cx.ProgramForClause) {
	e.b.write_u8(`|`)
	e.b.write_string(c.kind.str())
	e.field(c.bind)
	if c.direction != '' {
		e.b.write_u8(`d`)
		e.field(c.direction)
	}
}

// emit_slice_axis writes one slice axis: kind, then presence-marked
// start/stop/step through the normal emit pipeline (de Bruijn binders apply,
// so alpha-equivalent bounds still collapse). #769 (RULED (a) 2026-08-10):
// the bounds distinguish computations, so they are IN the stream; the
// presence markers keep every bound-free encoding at its pre-fix bytes.
fn (mut e T2Emitter) emit_slice_axis(ax cx.SliceAxis) {
	e.b.write_u8(`|`)
	e.b.write_string(ax.kind.str())
	if s := ax.start {
		e.b.write_u8(`s`)
		e.emit(s)
	}
	if s := ax.stop {
		e.b.write_u8(`t`)
		e.emit(s)
	}
	if s := ax.step {
		e.b.write_u8(`p`)
		e.emit(s)
	}
}

fn (mut e T2Emitter) emit_predicate(p cx.ProgramPathPredicate) {
	e.b.write_string(p.kind.str())
	e.b.write_u8(`i`)
	e.b.write_string(p.int_index.str())
	e.field(p.attr_name)
	e.field(p.attr_op)
	// #769: attr_kind distinguishes `[@k]` from `[@!k]` (op is '' for both).
	// Marked only off the .existence default so position/expr predicates and
	// existence tests keep their pre-fix bytes.
	if p.attr_kind != .existence {
		e.b.write_u8(`k`)
		e.field(p.attr_kind.str())
	}
	// #772 rider: the type-test TYPE NAME distinguishes computations from
	// the same landing that makes eval honor it. Presence-marked.
	if p.type_name != '' {
		e.b.write_u8(`T`)
		e.field(p.type_name)
	}
	if av := p.attr_value {
		e.b.write_u8(`v`)
		e.emit(av)
	}
	if bd := p.body {
		e.b.write_u8(`e`)
		e.emit(bd)
	}
}

fn (mut e T2Emitter) emit(node cx.ProgramNode) {
	match node {
		cx.Program {
			e.emit(node.body)
		}
		cx.ProgramBinding {
			e.b.write_u8(`$`)
			e.emit_binding(node)
		}
		cx.ProgramCall {
			e.b.write_string('(c')
			e.ref_name(node.name)
			if node.fallible {
				e.b.write_u8(`?`)
			} else if node.must_succeed {
				e.b.write_u8(`!`)
			} else {
				e.b.write_u8(`.`)
			}
			e.b.write_string(node.args.len.str())
			for i, a in node.args {
				e.b.write_u8(` `)
				if i < node.arg_labels.len {
					e.field(node.arg_labels[i])
				} else {
					e.field('')
				}
				e.emit(a)
			}
			// CRS-1 call-result postfix — presence-marked (see
			// emit_path_steps): path-less calls keep their exact bytes.
			e.emit_path_steps(node.path)
			e.b.write_u8(`)`)
		}
		cx.ProgramLiteral {
			e.emit_literal(node)
			// PS-1 result postfix — presence-marked (see emit_path_steps):
			// step-less literals keep their exact bytes; `[a 1]/b` and
			// `[a 1]` are distinct computations.
			e.emit_path_steps(node.path)
		}
		cx.ProgramDirective {
			e.emit_directive(node)
			// PS-1 result postfix — presence-marked, as above.
			e.emit_path_steps(node.path)
		}
		cx.ProgramForComp {
			// W7 (L100 tail): the payload nodes ride THE ONE walk
			// (cx.for_comp_children) — the last identity-bearing traversal
			// retired onto the single contract. Clause METADATA (kind — IN
			// the preimage via c.kind.str() — and bind) is not enumerated by
			// the walk; it is emitted from the clause rows as each clause's
			// first payload node arrives, with metadata-only clauses (the
			// erased-hint kinds carry no source/expr) flushed in row order so
			// the stream stays byte-identical to the pre-retirement emission
			// (C9: a moved hash is a defect, never a blessing).
			e.b.write_string('(for')
			e.b.write_string(node.outer_form.str())
			e.b.write_string(node.yield_form.str())
			mut emitted := -1
			for item in cx.for_comp_children(node) {
				match item.role {
					.clause_source, .clause_expr {
						for emitted < item.clause_idx {
							emitted++
							e.t2_clause_meta(node.clauses[emitted])
						}
						e.b.write_u8(if item.role == .clause_source { `s` } else { `e` })
						e.emit(item.node)
					}
					.yield_node {
						for emitted < node.clauses.len - 1 {
							emitted++
							e.t2_clause_meta(node.clauses[emitted])
						}
						e.b.write_string('|y')
						e.emit(item.node)
					}
					.yield_value {
						e.b.write_u8(`v`)
						e.emit(item.node)
					}
				}
			}
			e.b.write_u8(`)`)
			// PS-1 result postfix — presence-marked (emit_path_steps).
			e.emit_path_steps(node.path)
		}
		cx.ProgramPattern {
			e.emit_pattern(node)
		}
		cx.ProgramSliceAccess {
			e.b.write_string('(sa')
			e.emit_binding(node.binding)
			e.b.write_string(node.axes.len.str())
			for ax in node.axes {
				e.emit_slice_axis(ax)
			}
			e.b.write_u8(`)`)
		}
		cx.ProgramSliceLiteral {
			e.b.write_string('(sl')
			e.b.write_string(node.axes.len.str())
			for ax in node.axes {
				e.emit_slice_axis(ax)
			}
			e.b.write_u8(`)`)
			// PS-1 result postfix — presence-marked (emit_path_steps).
			e.emit_path_steps(node.path)
		}
		cx.ProgramPathExpr {
			e.b.write_string('(px')
			e.b.write_string(node.leading.str())
			for s in node.steps {
				e.b.write_u8(`|`)
				e.b.write_string(s.axis.str())
				e.field(s.name)
				e.b.write_string(s.ns_kind.str())
				e.field(s.ns_prefix)
				// Presence-marked, same reason as the binding-path arm:
				// absent kind test → zero bytes → unmoved preimage.
				if s.kind_test != .none {
					e.b.write_u8(`K`)
					e.b.write_string(s.kind_test.str())
				}
				e.field(s.bind)
				for pred in s.predicates {
					e.b.write_u8(`[`)
					e.emit_predicate(pred)
					e.b.write_u8(`]`)
				}
			}
			e.b.write_u8(`)`)
		}
		cx.ProgramWildcard {
			e.b.write_string('(w')
			e.b.write_string(if node.deep { '1' } else { '0' })
			e.b.write_u8(`)`)
		}
	}
}

fn (mut e T2Emitter) emit_literal(l cx.ProgramLiteral) {
	e.b.write_string('(L')
	e.b.write_string(l.kind.str())
	match l.kind {
		.string_lit, .bigint_lit, .decimal_lit, .date_lit, .datetime_lit, .node_lit, .atom_lit {
			e.field(l.str_val)
		}
		.duration_lit, .period_lit {
			// #769 audit: these two kinds carry their payload in dur_val —
			// emitting str_val (always empty here) merged EVERY duration
			// and EVERY period. The kind tag above keeps the two families
			// distinct from each other.
			e.field(l.dur_val)
		}
		.int_lit {
			e.field(l.int_val.str())
		}
		.float_lit {
			e.field(l.flt_val.str())
		}
		.bool_lit {
			e.b.write_string(if l.bool_val { '1' } else { '0' })
		}
		.sequence_lit, .array_lit, .block {
			e.b.write_string(l.items.len.str())
			for it in l.items {
				e.b.write_u8(` `)
				e.emit(it)
			}
		}
		.map_lit {
			e.b.write_string(l.items.len.str())
			for i, it in l.items {
				e.b.write_u8(` `)
				if i < l.keys.len {
					e.field(l.keys[i])
				} else {
					e.field('')
				}
				// RULED: MSS-4 (#917): a declaration-only entry contributes
				// its `::T` kind to identity — never the inert placeholder
				// (a decl and a literal-null entry must not collide).
				if i < l.decl_kinds.len && l.decl_kinds[i] != '' {
					e.field('::' + l.decl_kinds[i])
					continue
				}
				e.emit(it)
			}
		}
		.cx_element {
			// head name is a reference (may be a sibling dependency call)
			e.ref_name(l.name)
			e.field(l.data_type)
			if ne := l.name_expr {
				e.b.write_u8(`n`)
				e.emit(ne)
			}
			e.b.write_u8(`a`)
			e.b.write_string(l.attrs.len.str())
			for a in l.attrs {
				e.b.write_u8(` `)
				e.field(a.name)
				e.emit(a.value)
			}
			e.b.write_u8(`i`)
			e.b.write_string(l.items.len.str())
			for it in l.items {
				e.b.write_u8(` `)
				e.emit(it)
			}
		}
	}
	e.b.write_u8(`)`)
}

fn (mut e T2Emitter) emit_directive(d cx.ProgramDirective) {
	match d.name {
		'fn' { e.emit_fn(d) }
		'let' { e.emit_let(d) }
		'match' { e.emit_match(d) }
		else { e.emit_generic_directive(d) }
	}
}

fn (mut e T2Emitter) emit_fn(d cx.ProgramDirective) {
	if d.slots.len < 2 || d.slots[0].value !is cx.ProgramLiteral {
		e.emit_generic_directive(d)
		return
	}
	params := d.slots[0].value as cx.ProgramLiteral
	saved := e.scope.len
	mut nparams := 0
	for it in params.items {
		if it is cx.ProgramBinding {
			e.scope << it.name
			nparams++
		}
	}
	e.b.write_string('(fn')
	e.b.write_string(nparams.str())
	for i := 1; i < d.slots.len; i++ {
		e.b.write_u8(` `)
		e.emit(d.slots[i].value)
	}
	e.b.write_u8(`)`)
	e.scope.trim(saved)
}

fn (mut e T2Emitter) emit_let(d cx.ProgramDirective) {
	if d.slots.len < 2 || d.slots[0].value !is cx.ProgramLiteral {
		e.emit_generic_directive(d)
		return
	}
	cl := d.slots[0].value as cx.ProgramLiteral
	if cl.items.len == 0 || cl.items[0] !is cx.ProgramBinding {
		e.emit_generic_directive(d)
		return
	}
	binder := cl.items[0] as cx.ProgramBinding
	e.b.write_string('(let')
	// value expression(s) in the OUTER scope
	for i := 1; i < cl.items.len; i++ {
		e.b.write_u8(` `)
		e.emit(cl.items[i])
	}
	e.b.write_u8(`|`)
	saved := e.scope.len
	e.scope << binder.name
	for i := 1; i < d.slots.len; i++ {
		e.b.write_u8(` `)
		e.emit(d.slots[i].value)
	}
	e.b.write_u8(`)`)
	e.scope.trim(saved)
}

fn (mut e T2Emitter) emit_match(d cx.ProgramDirective) {
	if d.slots.len < 3 {
		e.emit_generic_directive(d)
		return
	}
	e.b.write_string('(mat')
	e.emit(d.slots[0].value)
	mut i := 1
	for i < d.slots.len {
		if d.slots[i].value is cx.ProgramPattern && i + 1 < d.slots.len {
			e.b.write_u8(`|`)
			saved := e.scope.len
			binds := t2_pattern_binds(d.slots[i].value as cx.ProgramPattern)
			for bn in binds {
				e.scope << bn
			}
			e.emit_pattern(d.slots[i].value as cx.ProgramPattern)
			e.b.write_u8(`=`)
			e.emit(d.slots[i + 1].value)
			e.scope.trim(saved)
			i += 2
		} else {
			e.b.write_u8(`|`)
			e.emit(d.slots[i].value)
			i++
		}
	}
	e.b.write_u8(`)`)
}

fn (mut e T2Emitter) emit_generic_directive(d cx.ProgramDirective) {
	e.b.write_string('(d')
	e.field(d.name)
	e.b.write_string(d.slots.len.str())
	for s in d.slots {
		e.b.write_u8(` `)
		e.field(s.label)
		e.emit(s.value)
	}
	e.b.write_u8(`)`)
}

// t2_pattern_binds collects bound names a pattern introduces (head bind first,
// then body binds, recursively), outer-to-inner / left-to-right.
fn t2_pattern_binds(p cx.ProgramPattern) []string {
	mut out := []string{}
	if p.head.bind != '' {
		out << p.head.bind
	}
	for it in p.body {
		match it {
			cx.ProgramBinding {
				if it.name != '' && it.name != '_' {
					out << it.name
				}
			}
			cx.ProgramPattern {
				out << t2_pattern_binds(it)
			}
			else {}
		}
	}
	return out
}

fn (mut e T2Emitter) emit_pattern(p cx.ProgramPattern) {
	e.b.write_string('(p')
	e.b.write_string(p.head.kind.str())
	// A named head in result position is a call (parser yields a pattern for a
	// bracketed result form, e.g. a recursive `[odd-p …]` inside `[?match]`),
	// so a head naming a sibling def is a dependency — route through ref_name.
	if p.head.kind == .named {
		e.ref_name(p.head.value)
	} else {
		e.field(p.head.value)
	}
	if p.head.bind != '' {
		if lvl := t2_level(e.scope, p.head.bind) {
			e.b.write_u8(`b`)
			e.b.write_string(lvl.str())
		} else {
			e.b.write_u8(`r`)
			e.field(p.head.bind)
		}
	}
	if p.direct {
		e.b.write_u8(`D`)
	}
	for a in p.attrs {
		e.b.write_u8(`@`)
		e.b.write_string(a.kind.str())
		e.field(a.name)
		e.field(a.op)
		// #769: the comparison VALUE and the type-test TYPE NAME distinguish
		// computations (`@role="admin"` vs `@role="guest"`; `@x::int` vs
		// `@x::str`). Presence-marked: existence/absence attrs keep their
		// pre-fix bytes.
		if v := a.value {
			e.b.write_u8(`v`)
			e.emit(v)
		}
		if a.type_name != '' {
			e.b.write_u8(`T`)
			e.field(a.type_name)
		}
	}
	for it in p.body {
		e.b.write_u8(` `)
		match it {
			cx.ProgramBinding {
				if lvl := t2_level(e.scope, it.name) {
					e.b.write_string('\$b')
					e.b.write_string(lvl.str())
				} else {
					e.b.write_string('\$r')
					e.field(it.name)
				}
				// #769 audit: same presence-marked fields as emit_binding.
				if it.type_test != '' {
					e.b.write_u8(`T`)
					e.field(it.type_test)
				}
				if it.is_rest {
					e.b.write_u8(`*`)
				}
			}
			cx.ProgramPattern {
				e.emit_pattern(it)
			}
			else {
				e.field(it.type_name())
			}
		}
	}
	e.b.write_u8(`)`)
}

// ── Tarjan strongly-connected components ─────────────────────────────────────

struct Tarjan {
	edges map[string][]string
mut:
	index    map[string]int
	lowlink  map[string]int
	on_stack map[string]bool
	stack    []string
	idx      int
	out      [][]string // SCCs in reverse-topological order (dependencies first)
}

fn (mut t Tarjan) strongconnect(v string) {
	t.index[v] = t.idx
	t.lowlink[v] = t.idx
	t.idx++
	t.stack << v
	t.on_stack[v] = true
	for w in t.edges[v] {
		if w !in t.index {
			t.strongconnect(w)
			if t.lowlink[w] < t.lowlink[v] {
				t.lowlink[v] = t.lowlink[w]
			}
		} else if t.on_stack[w] {
			if t.index[w] < t.lowlink[v] {
				t.lowlink[v] = t.index[w]
			}
		}
	}
	if t.lowlink[v] == t.index[v] {
		mut comp := []string{}
		for {
			w := t.stack.pop()
			t.on_stack[w] = false
			comp << w
			if w == v {
				break
			}
		}
		t.out << comp
	}
}
