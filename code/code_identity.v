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
	return sha256.sum256(stream.bytes()).hex()
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
			hashes[n] = sha256.sum256(stream.bytes()).hex()
		} else {
			hash_scc(comp, siblings, defs, mut hashes)!
		}
	}
	return hashes
}

// ── Content-addressed code storage (pre-Phase-1 floor) ───────────────────────
//
// Code is stored in a DISTINCT namespace keyed by Tier-2 identity (never
// conflated with Tier-1 data docs — they use the `code:` key prefix), so
// alpha-/comment-/name-variants of the same definition dedup to a single stored
// object. This is "def-blob storage by normalized hash" — the whole-program /
// searchable index is Phase-1+ (#85/#86), not built here.

// cx_code_store_put_def stores `def_source` under its Tier-2 code identity hash,
// deduping variants to one object. Returns the Tier-2 hash (the lookup key).
// The first representative stored for a given identity wins (content-addressed
// puts are idempotent).
pub fn cx_code_store_put_def(mut ms MemStore, def_source string) !string {
	h := cx_code_tier2_hash(def_source)!
	key := 'code:${h}'
	// #128-A: store via the local-storage layer so code persists on EVERY local
	// backend — including the object-graph (cxpack) backend, which bypasses the
	// `docs` map (a direct `ms.docs[key]=…` would be silently dropped on persist).
	// The source is stored verbatim as a raw-leaf object (code does not data-parse).
	store_put_raw(mut ms, key, def_source)!
	return h
}

// cx_code_store_get_def returns the stored source for a Tier-2 code hash, or
// none if no definition of that identity has been stored.
pub fn cx_code_store_get_def(ms &MemStore, tier2_hash string) ?string {
	key := 'code:${tier2_hash}'
	if !store_doc_present(ms, key) {
		return none
	}
	return store_doc_text(ms, key) or { return none }
}

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
		hashes[m] = sha256.sum256('${comp_hash}#${position[m]}'.bytes()).hex()
	}
}

struct SccMember {
	name string
	body string
}

// collect_program_defs gathers top-level `[?def …]` directives in source order.
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
	e.b.write_u8(`|`)
	e.emit(body_prog.body)
	return e.b.str(), e.refs
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
	for step in n.path {
		e.b.write_u8(`/`)
		e.b.write_string(int(step.kind).str())
		e.field(step.name)
		for pred in step.predicates {
			e.b.write_u8(`[`)
			e.emit_predicate(pred)
			e.b.write_u8(`]`)
		}
	}
}

fn (mut e T2Emitter) emit_predicate(p cx.ProgramPathPredicate) {
	e.b.write_string(int(p.kind).str())
	e.b.write_u8(`i`)
	e.b.write_string(p.int_index.str())
	e.field(p.attr_name)
	e.field(p.attr_op)
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
			e.b.write_u8(`)`)
		}
		cx.ProgramLiteral {
			e.emit_literal(node)
		}
		cx.ProgramDirective {
			e.emit_directive(node)
		}
		cx.ProgramForComp {
			e.b.write_string('(for')
			e.b.write_string(int(node.outer_form).str())
			e.b.write_string(int(node.yield_form).str())
			for c in node.clauses {
				e.b.write_u8(`|`)
				e.b.write_string(int(c.kind).str())
				e.field(c.bind)
				if s := c.source {
					e.b.write_u8(`s`)
					e.emit(s)
				}
				if ex := c.expr {
					e.b.write_u8(`e`)
					e.emit(ex)
				}
			}
			e.b.write_string('|y')
			e.emit(node.yield)
			if yv := node.yield_value {
				e.b.write_u8(`v`)
				e.emit(yv)
			}
			e.b.write_u8(`)`)
		}
		cx.ProgramPattern {
			e.emit_pattern(node)
		}
		cx.ProgramSliceAccess {
			e.b.write_string('(sa')
			e.emit_binding(node.binding)
			e.b.write_string(node.axes.len.str())
			e.b.write_u8(`)`)
		}
		cx.ProgramSliceLiteral {
			e.b.write_string('(sl')
			e.b.write_string(node.axes.len.str())
			e.b.write_u8(`)`)
		}
		cx.ProgramPathExpr {
			e.b.write_string('(px')
			e.b.write_string(int(node.leading).str())
			for s in node.steps {
				e.b.write_u8(`|`)
				e.b.write_string(int(s.axis).str())
				e.field(s.name)
				e.b.write_string(int(s.ns_kind).str())
				e.field(s.ns_prefix)
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
	e.b.write_string(int(l.kind).str())
	match l.kind {
		.string_lit, .bigint_lit, .duration_lit, .period_lit, .date_lit, .datetime_lit,
		.node_lit, .atom_lit {
			e.field(l.str_val)
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
	e.b.write_string(int(p.head.kind).str())
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
		e.b.write_string(int(a.kind).str())
		e.field(a.name)
		e.field(a.op)
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
