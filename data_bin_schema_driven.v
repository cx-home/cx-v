module cx

import crypto.sha256
import strconv

// CXCol — schema-driven encoding (header flag bit 1) per
// spec/core/data-bin.md §3.13.
//
// Schema-driven encoding omits per-value type tags wherever the schema
// declares the value's type. Tag-omission is per-field: declared keys
// get typed-payload-only encoding; undeclared keys (under `open` mode)
// fall back to self-describing CXCol encoding so schema-driven and
// self-describing form coexist within a single document.
//
// This module ships:
//   - SchemaModel parsing (root type + body kind + per-attr types
//     + nested element types + `[?cx schema-mode <mode>]` directive)
// Schema content-hash: SHA-256 over
//     emit_data_bin(parse(schema_text)) (the strict-canonical CXCol
//     form of the parsed schema)
//   - Schema-driven encoder + decoder for the most common shapes:
//     elements with declared attrs, scalar bodies, and nested
//     declared elements
//   - Three schema-reference forms per §3.13.1: 0x10 content-hash,
//     0x11 inline schema (recursive CXCol blob), 0x12 hash + name hint
//
// Reader-side decode walks the schema cursor in lockstep with the
// data; undeclared scopes (open mode) fall through to self-describing
// reads. Closed mode rejects undeclared keys at emit time (`S012`)
// and unknown scopes at decode time (`D003`).

// ── Tags / constants ─────────────────────────────────────────────────────────

const cxcol_flags_schema_driven = u8(0x02)            // header flags bit 1

const tag_schema_ref_hash      = u8(0x10)
const tag_schema_ref_inline    = u8(0x11)
const tag_schema_ref_hash_name = u8(0x12)

// ── Schema model ─────────────────────────────────────────────────────────────

pub enum SchemaMode {
	open
	strict
	closed
}

// AttrRule carries every attribute-declaration constraint for one
// `[attr name::T [req] [default V] [range M N] [enum …] [pattern …]
// [min-length N] [max-length N]]` schema entry.
// `required` defaults to true per spec/schema.md §5.
pub struct AttrRule {
pub mut:
	type_name string
	required  bool = true
	has_def   bool
	def_value string
	pat       string    // RE2 pattern (S008 — checked by libcx-vendored RE2)
	enum_vals []string  // S007
	range_min string    // S006 — kept as raw text; the validator parses
	range_max string    //        per declared scalar type
	len_min   string    // S018
	len_max   string
	// attr-position fragment alias `[attr name *frag [clause …]]`.
	// At schema-load time the validator looks up `*frag` in
	// SchemaModel.frags and inlines the fragment body's kind + range +
	// enum + pat + len constraints into this AttrRule.  Site-local
	// clauses ([req] / [opt] / [default V]) take precedence over the
	// fragment.  Empty when no alias is referenced.
	alias_target string
	// (v1.1) — attribute-position container productions.
	// Same shape as BodyRule.item_kind / .key_kind. Attribute values
	// that are collection literals (`name=[a, b, c]` for arr, etc.)
	// validate against these.
	item_kind string
	key_kind  string
}

// ElemRule carries the cardinality + type-to-recurse-into for one
// `[elem name [card "M..N"]]` entry. `type_name`
// defaults to the child element's name (the conventional case).
pub struct ElemRule {
pub mut:
	type_name     string
	min           int = 1
	max           int = 1   // ignored when max_unbounded
	max_unbounded bool
}

// BodyRule carries the body-declaration constraints for one
// `[body kind [clause …]]` entry. `kind` is the
// body kind ('string', 'i32', 'elem', 'mixed', 'none', 'any',
// 'scalar', etc.).
pub struct BodyRule {
pub mut:
	declared  bool
	kind      string
	required  bool
	pat       string
	enum_vals []string
	range_min string
	range_max string
	len_min   string
	len_max   string
	// (v1.1) — container productions `arr[T]` / `seq[T]`
	// `map[K, V]`. When `kind` is 'arr' or 'seq', `item_kind` carries the
	// element kind ('u16', 'string', or a nested `arr[float]` / `map[…]`
	// expression). When `kind` is 'map', `key_kind` carries the key
	// type (atomic scalar, restricted to 'string')
	// and `item_kind` the value type. Recursive nesting (`arr[arr[float]]`,
	// `map[string, arr[u32]]`) is preserved verbatim and re-parsed at
	// validation time.
	item_kind string
	key_kind  string
}

// SchemaType describes one named type in the schema. The unified
// model is unified; it carries every constraint sigil the
// validator and the schema-driven encoder both need so neither side
// re-walks the schema AST.
//
// Container body kinds: elem / mixed / table / frag (have children).
// Scalar body kinds: string / i8..i64 / u8..u64 / f16..f64 / bool /
// date / datetime / time / bytes / decimal / bigint. 'any' and
// 'scalar' bypass body validation. 'none' requires an empty body.
pub struct SchemaType {
pub mut:
	name                string
	body                BodyRule
	attrs               map[string]AttrRule
	elems               map[string]ElemRule
	elems_order         []string  // declaration order — drives S015 child-order
	child_order_strict  bool      // [check ordering=strict] under this type
	// Top-level fragment alias `[type-name *frag]` (parsed by
	// the CX parser as `Element.merge = "frag"`). Resolution at schema-
	// load time inlines the fragment's body+attrs+elems+elems_order into
	// this SchemaType. Empty when no alias is referenced.
	alias_target        string
}

// SchemaModel is the parsed schema with mode + a registry of named
// types reachable from the root.
pub struct SchemaModel {
pub mut:
	mode  SchemaMode = SchemaMode.open
	root  string
	name  string // human-readable schema name from `[?cx schema-name '…']`
	types map[string]SchemaType
	src   string
	// Fragment registry per spec/schema.md §8. anchor name →
	// fragment definition. Sources: (a) anchor on a top-level type-decl
	// element (the type doubles as a fragment); (b) the standalone
	// `[?cx frag &name [body...]]` directive form. Populated during
	// parse_schema; consumed by resolve_aliases to inline fragment
	// declarations into referencing types and attrs.
	frags map[string]SchemaType
}

// parse_schema parses a `.cxs` schema source into a SchemaModel.
//
// The schema text is parsed via the standard CX parser (which now
// accepts positional directive args like `[?cx schema-of server]`).
// We then walk the AST extracting the root name from the schema-of
// directive, the mode from any schema-mode directive, and the per-
// type body / attr / elem declarations from each `[<type-name> ...]`
// element. Per, declarations carry the type via a
// `name::T` glued ascription in the first body TextNode and the
// constraints as `[clause …]` child Elements (`[req]`, `[default V]`,
// `[range M N]`, …).  See the §6.f section below.
pub fn parse_schema(schema_text string) !SchemaModel {
	doc := parse(schema_text) or {
		return error('S009: schema parse failure: ${err.msg()}')
	}
	mut sm := SchemaModel{ src: schema_text }
	// Pass 1 — directive application (schema-of / schema-mode /
	// schema-version) and standalone-fragment registration.
	for n in doc.prolog {
		if n is CXDirectiveNode {
			schema_directive_apply(n, mut sm)!
			register_frag_directive(n, mut sm)!
		}
	}
	for n in doc.elements {
		if n is Element {
			schema_directive_walk_for_mode(n, mut sm)!
		} else if n is CXDirectiveNode {
			schema_directive_apply(n, mut sm)!
			register_frag_directive(n, mut sm)!
		}
	}
	// Pass 2 — build type declarations and register anchored types as
	// fragments (an anchor on a type-decl element makes the type itself
	// a reusable fragment per spec/schema.md §8).
	for n in doc.elements {
		if n is Element {
			st := schema_type_from_element(n)!
			sm.types[st.name] = st
			if anc := n.anchor() {
				if anc in sm.frags {
					// Two fragments with the same name — schema-load fail.
					return error('S014: duplicate fragment anchor \'&${anc}\'')
				}
				sm.frags[anc] = st
			}
		}
	}
	if sm.root == '' && sm.types.len == 0 && sm.frags.len == 0 {
		return error('S009: schema has no schema-of directive and no type declarations (malformed)')
	}
	if sm.root == '' {
		// If no schema-of directive was present, default to the first
		// declared type. This keeps standalone fragment schemas usable.
		for k, _ in sm.types {
			sm.root = k
			break
		}
	}
	// Pass 3 — resolve fragment aliases (eager, schema-load time per
	// spec §10.1 step 1). Type-level aliases via DFS with cycle
	// detection (S016). Missing-anchor → S013. Attr-level aliases run
	// after type resolution (a fragment that's itself an anchored type
	// must be fully resolved before its body kind+constraints can be
	// inlined into a referencing attr).
	resolve_aliases(mut sm)!
	// S011 — default-value coercion check at schema-load time
	// (spec/schema.md §11). Runs *after* alias resolution because a
	// fragment may supply the declared type for the attr.
	for type_name, st in sm.types {
		for attr_name, ar in st.attrs {
			if ar.has_def && ar.type_name != '' {
				if !default_value_coerces(ar.def_value, ar.type_name) {
					return error('S011: default value \'${ar.def_value}\' for attribute \'${attr_name}\' on type \'${type_name}\' does not match declared type :${ar.type_name}')
				}
			}
		}
	}
	return sm
}

// register_frag_directive recognizes `[?cx frag &name [body T [clause …]]]`
// (spec/schema.md §8 standalone fragment form shape).
// The directive's first positional attr name must be `frag`; the
// directive carries the fragment anchor in `.anchor` and the fragment
// body declarations in `.items`.
fn register_frag_directive(d CXDirectiveNode, mut sm SchemaModel) ! {
	if d.attrs.len == 0 || d.attrs[0].name != 'frag' { return }
	anc := d.anchor or {
		return error('S009: `[?cx frag ...]` directive missing required `&anchor`')
	}
	if anc in sm.frags {
		return error('S014: duplicate fragment anchor \'&${anc}\'')
	}
	mut st := SchemaType{ name: anc }
	collect_decls(d.items, mut st)!
	sm.frags[anc] = st
}

// resolve_aliases inlines `*frag` references at schema-load time per
// spec §8 + §10.1 step 1.  Type-level aliases (`[type *frag]` parsed
// as Element.merge) run first via DFS with cycle detection.  Attr-
// level aliases (`[attr name *frag [clause …]]`) run after type
// resolution.
fn resolve_aliases(mut sm SchemaModel) ! {
	// Phase 1 — type-level aliases. DFS with three colors: 0 white
	// (unvisited), 1 grey (in progress), 2 black (resolved).
	mut state := map[string]int{}
	for k, _ in sm.types {
		if state[k] != 2 {
			resolve_type_alias_dfs(k, mut sm, mut state)!
		}
	}
	// Phase 2 — attr-level aliases. Each attr with a fragment alias
	// inlines the fragment body's kind+constraints into its AttrRule.
	type_keys := sm.types.keys()
	for tk in type_keys {
		mut attrs_copy := sm.types[tk].attrs.clone()
		for ak, ar in sm.types[tk].attrs {
			if ar.alias_target == '' { continue }
			frag := sm.frags[ar.alias_target] or {
				return error('S013: fragment alias `*${ar.alias_target}` on attribute `${ak}` of type `${tk}` references unknown fragment')
			}
			mut new_ar := ar
			inline_frag_into_attr(mut new_ar, frag)
			attrs_copy[ak] = new_ar
		}
		mut t := sm.types[tk]
		t.attrs = attrs_copy.clone()
		sm.types[tk] = t
	}
}

fn resolve_type_alias_dfs(name string, mut sm SchemaModel, mut state map[string]int) ! {
	state[name] = 1
	cur := sm.types[name] or { return }
	if cur.alias_target != '' {
		// Resolve the fragment owner first (if it's also a type with
		// pending aliases) so the inlined data is fully resolved.
		alias := cur.alias_target
		if alias in sm.types {
			if state[alias] == 1 {
				return error('S016: cyclic fragment reference detected at `${name}` → `*${alias}`')
			}
			if state[alias] != 2 {
				resolve_type_alias_dfs(alias, mut sm, mut state)!
			}
		}
		frag := sm.frags[alias] or {
			return error('S013: fragment alias `*${alias}` on type `${name}` references unknown fragment')
		}
		// Cycle on a directly self-referential fragment: the current
		// type's anchor IS its own alias_target. The DFS state on
		// `name` is grey at this point, so we don't catch it via the
		// state[alias] check above — explicit guard.
		if alias == name {
			return error('S016: cyclic fragment reference detected — type `${name}` aliases itself')
		}
		mut t := sm.types[name]
		merge_frag_into_type(mut t, frag)
		sm.types[name] = t
	}
	state[name] = 2
}

// merge_frag_into_type inlines a fragment's body / attrs / elems /
// elems_order / child_order_strict into the referencing type. The
// fragment's declarations fill any slot the referencing type left
// empty; existing declarations on the referencing type are NOT
// overwritten (spec §8 says "inline", referencing-site wins on
// conflict — least surprise).
fn merge_frag_into_type(mut st SchemaType, frag SchemaType) {
	if !st.body.declared && frag.body.declared {
		st.body = frag.body
	}
	for an, ar in frag.attrs {
		if an !in st.attrs { st.attrs[an] = ar }
	}
	for en, er in frag.elems {
		if en !in st.elems {
			st.elems[en] = er
			st.elems_order << en
		}
	}
	if !st.child_order_strict && frag.child_order_strict {
		st.child_order_strict = true
	}
}

// inline_frag_into_attr applies a fragment's body kind + constraints
// to a referencing AttrRule. Site-local flags (req/opt/def) on the
// referencing attr take precedence; the fragment supplies the type
// shape (kind, range, enum, pat, len). A single-step
// inlining; chained fragments resolve via Phase-1 type resolution.
fn inline_frag_into_attr(mut ar AttrRule, frag SchemaType) {
	if frag.body.declared {
		if ar.type_name == '' { ar.type_name = frag.body.kind }
		if ar.range_min == '' && ar.range_max == '' {
			ar.range_min = frag.body.range_min
			ar.range_max = frag.body.range_max
		}
		if ar.len_min == '' && ar.len_max == '' {
			ar.len_min = frag.body.len_min
			ar.len_max = frag.body.len_max
		}
		if ar.enum_vals.len == 0 { ar.enum_vals = frag.body.enum_vals.clone() }
		if ar.pat == '' { ar.pat = frag.body.pat }
	}
}

// default_value_coerces returns true when `raw` (the literal text from
// the `[default V]` clause) is a CX literal that matches the declared
// scalar type.  Used at schema-load time to enforce S011 fail-fast per
// spec/schema.md §11.
fn default_value_coerces(raw string, declared string) bool {
	s := strip_quotes(raw)
	match declared {
		'string', 's' { return true }
		'int', 'i8', 'i16', 'i32', 'i64', 'u8', 'u16', 'u32', 'u64' {
			_ := s.int()
			// V's .int() returns 0 silently on parse failure; verify by
			// re-stringifying. Empty s is rejected.
			if s == '' { return false }
			// A simple manual digit check (allow optional leading -).
			mut start := 0
			if s.len > 0 && (s[0] == `-` || s[0] == `+`) { start = 1 }
			if start >= s.len { return false }
			for i in start .. s.len {
				if s[i] < `0` || s[i] > `9` { return false }
			}
			return true
		}
		'float', 'f32', 'f64', 'f16' {
			if s == '' { return false }
			_ := strconv.atof64(s) or { return false }
			return true
		}
		'bool' { return s == 'true' || s == 'false' }
		'date', 'datetime', 'time', 'bytes', 'decimal', 'bigint' {
			// These ride a string-typed ScalarValue today; permissive
			// at schema-load. Tightening lands when a typed-scalar
			// fixture surfaces the looseness.
			return true
		}
		'any', 'scalar' { return true }
		else { return true }
	}
}

// directive_arg_text reads one positional directive argument as text.
// Bareword args are stored in the attr `name` (value empty); quoted
// args (e.g. `[?cx schema-name 'Book schema v1']`) are stored in `value`
// with an empty name. This normalizes both forms to their text.
fn directive_arg_text(a Attribute) string {
	if a.name != '' { return a.name }
	return a.str_value()
}

// schema_directive_apply consumes a `[?cx schema-of NAME]` /
// `[?cx schema-mode MODE]` / `[?cx schema-version VER]` directive
// (positional form). S020 fail-fasts on unsupported version.
fn schema_directive_apply(d CXDirectiveNode, mut sm SchemaModel) ! {
	if d.attrs.len == 0 { return }
	first := d.attrs[0].name
	match first {
		'schema-of' {
			if d.attrs.len >= 2 { sm.root = d.attrs[1].name }
		}
		'schema-name' {
			// Human-readable name; quoted positional arg lands in `value`
			// (empty name), bareword in `name`. Diagnostic-only per §2.
			if d.attrs.len >= 2 { sm.name = directive_arg_text(d.attrs[1]) }
		}
		'schema-mode' {
			if d.attrs.len >= 2 {
				mode := d.attrs[1].name
				sm.mode = match mode {
					'strict' { SchemaMode.strict }
					'closed' { SchemaMode.closed }
					else     { SchemaMode.open }
				}
			}
		}
		'schema-version' {
			if d.attrs.len >= 2 {
				ver := d.attrs[1].name
				if ver != '0.8' {
					return error('S020: schema-version \'${ver}\' is not supported (this implementation supports 0.8 only)')
				}
			}
		}
		else {}
	}
}

// schema_directive_walk_for_mode looks for `[?cx schema-mode ...]`
// directives that landed inside the document body (some authors put
// the mode directive after the schema-of). We honor them at parse
// time so the model reflects the final mode regardless of position.
fn schema_directive_walk_for_mode(e Element, mut sm SchemaModel) ! {
	for n in e.items {
		if n is CXDirectiveNode {
			schema_directive_apply(n, mut sm)!
		} else if n is Element {
			schema_directive_walk_for_mode(n, mut sm)!
		}
	}
}

// schema_type_from_element walks one type-declaration element and
// produces a SchemaType under the unified model. Recognized children:
//   [body kind [clause …]]               declares body kind / constraints
//   [attr name::T [clause …]]            declares an attribute
//   [elem name [clause …]]               declares a child element + cardinality
//   [check ordering=strict]              parent-level child-order policy (S015)
//   [<sub-type> ...]                     unrecognized; ignored at v0
//
// `[type-name *fragment-name]` (where the parser stores
// `*fragment-name` as `Element.merge`) records the fragment alias for
// later resolution by resolve_aliases. The merge field's normal CX
// "merge from anchor" semantics overlap exactly with the schema spec's
// "inline the fragment's declarations" semantics, so we reuse it.
//
// Returns an error on:
//   - duplicate `[attr <same-name> ...]` declarations on the same
//     type (S014).
fn schema_type_from_element(e Element) !SchemaType {
	// top-level `[type Name::T]` / `[type Name [decls…]]`
	// form.  The element name is the literal `type`; the actual type
	// name is in the first body token (with an optional `::T` body-
	// shape ascription).
	if e.name == 'type' {
		return schema_type_from_v0_8_type_decl(e)
	}
	mut st := SchemaType{ name: e.name }
	if mt := e.merge() {
		st.alias_target = mt
	}
	collect_decls(e.items, mut st)!
	return st
}

// schema_type_from_v0_8_type_decl handles the top-level
// `[type Name…]` form.  Three variants:
//
//   [type Name::T]                     ← scalar / composite body alias
//   [type Name::[composite …]]         ← composite-body alias
//   [type Name  [attr …] [elem …] …]   ← named record (attrs + elems)
//
// The Name lives in the first TextNode of the body; an optional `::T`
// after Name carries the body-shape ascription (scalar or composite).
// Constraint clauses directly under a `[type Name::T …]` declaration
// (e.g. `[req]`, `[range M N]`, `[pattern …]`) fold into the body rule.
fn schema_type_from_v0_8_type_decl(e Element) !SchemaType {
	name, type_str := split_v0_8_name_type(e)
	if name == '' {
		return error('S009: `[type ...]` declaration missing type name')
	}
	mut st := SchemaType{ name: name }
	if type_str != '' {
		// Body-shape alias — `[type ID::string]` / `[type Path::[list T]]`.
		apply_v0_8_type_str_to_body(type_str, mut st.body)
	}
	// Fold any body-level constraint clauses into the body rule.  attr /
	// elem / check children flow through collect_decls below.
	for n in e.items {
		if n is Element {
			if is_v0_8_clause_name(n.name) {
				apply_v0_8_clause_to_body(n, mut st.body)
			}
		}
	}
	collect_decls(e.items, mut st)!
	return st
}

// apply_v0_8_clause_to_body folds one constraint-clause child Element
// into the BodyRule (parallel to apply_v0_8_clause_to_attr but writing
// to the BodyRule slots).
fn apply_v0_8_clause_to_body(n Element, mut br BodyRule) {
	match n.name {
		'req' { br.required = true }
		'opt' { br.required = false }
		'min' { br.range_min = clause_payload_text(n) }
		'max' { br.range_max = clause_payload_text(n) }
		'range' {
			mn, mx := clause_payload_pair(n)
			br.range_min = mn
			br.range_max = mx
		}
		'min-length' { br.len_min = clause_payload_text(n) }
		'max-length' { br.len_max = clause_payload_text(n) }
		'len' {
			mn, mx := clause_payload_pair(n)
			br.len_min = mn
			br.len_max = mx
		}
		'pattern' { br.pat = clause_payload_text(n) }
		'enum' { br.enum_vals = clause_payload_list(n) }
		else {}
	}
}

// apply_v0_8_type_str_to_body resolves a body-shape ascription string
// (scalar bareword OR composite `[…]`) into a BodyRule.
fn apply_v0_8_type_str_to_body(typ string, mut br BodyRule) {
	t := typ.trim_space()
	if t == '' { return }
	br.declared = true
	if t.starts_with('[') && t.ends_with(']') && t.len >= 2 {
		inner := t[1..t.len - 1].trim_space()
		toks := split_ws_quote_bracket(inner)
		if toks.len == 0 { return }
		head := toks[0]
		match head {
			'enum' {
				br.kind = 'string'
				mut vals := []string{}
				for v in toks[1..] {
					vv := strip_quotes(v.trim_space())
					if vv != '' { vals << vv }
				}
				br.enum_vals = vals
			}
			'list', 'seq' {
				br.kind = 'arr'
				if toks.len > 1 { br.item_kind = toks[1..].join(' ') }
			}
			'map' {
				br.kind = 'map'
				if toks.len > 1 { br.key_kind = toks[1] }
				if toks.len > 2 { br.item_kind = toks[2..].join(' ') }
			}
			else {
				// Unknown / opaque composite — leave kind empty.
			}
		}
		if is_scalar_kind(br.kind) || is_container_collection_kind(br.kind) {
			br.required = true
		}
		return
	}
	br.kind = t
	if is_scalar_kind(br.kind) || is_container_collection_kind(br.kind) {
		br.required = true
	}
}

// collect_decls walks a list of items (from a type-decl element or a
// `[?cx frag &name ...]` directive) and populates the SchemaType's
// body/attrs/elems/elems_order/child_order_strict fields.
fn collect_decls(items []Node, mut st SchemaType) ! {
	mut elems_order := st.elems_order.clone()
	for n in items {
		if n is Element {
			match n.name {
				'body' {
					st.body = body_rule_from_element(n)
				}
				'attr' {
					ar := attr_rule_from_element(n)
					name := decl_name_from_element(n)
					if name != '' {
						if name in st.attrs {
							return error('S014: duplicate attribute declaration \'${name}\' on type \'${st.name}\'')
						}
						st.attrs[name] = ar
					}
				}
				'elem' {
					er := elem_rule_from_element(n)
					name := decl_name_from_element(n)
					if name != '' {
						if name !in st.elems {
							elems_order << name
						}
						st.elems[name] = er
					}
				}
				'check' {
					for a in n.attrs {
						if a.name == 'ordering' {
							v := scalar_value_str(a.value).trim_space()
							if v == 'strict' { st.child_order_strict = true }
						}
					}
				}
				else {}
			}
		}
	}
	st.elems_order = elems_order
}

// body_rule_from_element parses an body declaration of
// the shape `[body kind [clause …] …]` (bareword kind + clause-children).
// The legacy `[body :kind :flag …]` shape was removed in Drop 3.
fn body_rule_from_element(e Element) BodyRule {
	return body_rule_from_element_v0_8(e)
}

// parse_container_kind matches container productions
// `arr[T]` / `seq[T]` / `map[K, V]`. Returns (kind, key_kind,
// item_kind) on a match, none otherwise. The inner `[...]` payload is
// extracted with balanced-bracket awareness so nested productions
// (`arr[arr[float]]`) round-trip verbatim — the recursive parse runs
// at validation time, not schema-load time.
fn parse_container_kind(tok string) ?(string, string, string) {
	for prefix in ['arr', 'seq', 'map'] {
		if tok.len > prefix.len + 2 && tok[..prefix.len] == prefix && tok[prefix.len] == `[` && tok.ends_with(']') {
			inner := tok[prefix.len + 1..tok.len - 1]
			if prefix == 'map' {
				k, v := split_map_kv(inner)
				if k == '' || v == '' { return none }
				return prefix, k, v
			}
			return prefix, '', inner.trim_space()
		}
	}
	return none
}

// split_map_kv splits an inner map-type payload `K, V` into its key
// and value components. Bracket-balanced so nested types (`string,
// arr[u32]`) split correctly on the depth-0 comma.
fn split_map_kv(s string) (string, string) {
	mut depth := 0
	for i, b in s {
		if b == `[` { depth++; continue }
		if b == `]` { depth--; continue }
		if b == `,` && depth == 0 {
			return s[..i].trim_space(), s[i + 1..].trim_space()
		}
	}
	return '', ''
}

fn is_container_collection_kind(k string) bool {
	return k == 'arr' || k == 'seq' || k == 'map'
}

// attr_rule_from_element parses an attr declaration of
// the shape `[attr name::T [clause …] …]`.  Fragment-alias references
// (`[attr name *frag [clause …]]`) are preserved via ar.alias_target.
// The legacy `[attr name :T :flag …]` shape was removed in Drop 3.
fn attr_rule_from_element(e Element) AttrRule {
	return attr_rule_from_element_v0_8(e)
}

// elem_rule_from_element parses an elem declaration of
// the shape `[elem name [card "M..N"] …]` (or `[elem name::T …]` for a
// named-type / composite element ascription).  The legacy
// `[elem name :flag]` shape was removed in Drop 3.
fn elem_rule_from_element(e Element) ElemRule {
	return elem_rule_from_element_v0_8(e)
}

fn decl_name_from_element(e Element) string {
	return decl_name_from_element_v0_8(e)
}

// ── 6.f — schema vocabulary (constraint clauses) ────────────────────
//
// The current schema shape drops the legacy `:flag`
// trailing-sigil convention in favour of explicit `[clause …]` child
// elements and a `name::T` glued type ascription:
//
//   [user
//     [attr id::string   [req] [min-length 3] [max-length 20]]
//     [attr name::string [default "anon"]]
//     [attr role::string [req] [enum admin user guest]]
//     [elem address [card "1..1"]]]
//
// The CX parser already returns the natural shape for these — `name::T` /
// `name::[composite T]` lands as a single TextNode in the element's body,
// and each `[clause …]` lands as a child Element.  The §6.f extractors
// below fold both into the AttrRule / ElemRule / BodyRule shapes.

// body_rule_from_element_v0_8 parses the §6.f `[body kind [clause …] …]`
// shape.  The element's first body TextNode carries the kind (bareword
// or container literal `arr[T]` / `seq[T]` / `map[K, V]`); each child
// Element is a constraint clause.
fn body_rule_from_element_v0_8(e Element) BodyRule {
	mut br := BodyRule{ declared: true }
	// First text token is the kind (bareword or container literal).
	for n in e.items {
		if n is TextNode {
			toks := split_ws_quote_bracket(n.value.trim_space())
			if toks.len == 0 { continue }
			first := toks[0]
			if k, kk, ik := parse_container_kind(first) {
				br.kind = k
				br.key_kind = kk
				br.item_kind = ik
			} else {
				br.kind = first
			}
			break
		}
	}
	if is_scalar_kind(br.kind) || is_container_collection_kind(br.kind) {
		br.required = true
	}
	for n in e.items {
		if n is Element {
			apply_v0_8_clause_to_body(n, mut br)
		}
	}
	return br
}

// is_v0_8_clause_name returns true when a child Element's name matches
// the constraint-clause vocabulary specified.
fn is_v0_8_clause_name(name string) bool {
	return name in [
		'req', 'opt', 'default', 'min', 'max',
		'min-length', 'max-length', 'pattern', 'enum',
		'card', 'ref', 'len', 'range', 'open', 'closed',
	]
}

// decl_name_from_element_v0_8 extracts the declaration name from the
// first body text token, splitting on the `::` ascription if present.
fn decl_name_from_element_v0_8(e Element) string {
	name, _ := split_v0_8_name_type(e)
	return name
}

// split_v0_8_name_type returns (name, type_str).  The type_str is the
// raw post-`::` ascription text — a bareword like 'string' or a balanced
// `[list T]` / `[enum a b c]` / `[record …]` expression.  An untyped
// decl returns (name, '').
fn split_v0_8_name_type(e Element) (string, string) {
	for n in e.items {
		if n is TextNode {
			t := n.value.trim_space()
			if t == '' { continue }
			toks := split_ws_quote_bracket(t)
			if toks.len == 0 { continue }
			first := toks[0]
			// Split on `::` only when not at offset 0 (`::T` alone is
			// not a valid ascription form here — the leading `:` would
			// have been a parse error in the data parser, so we never
			// see that shape on the schema side).
			if idx := first.index('::') {
				if idx > 0 {
					name := first[..idx]
					typ := first[idx + 2..]
					return name, typ
				}
			}
			return first, ''
		}
	}
	return '', ''
}

// attr_rule_from_element_v0_8 parses the §6.f attr-decl form.  The
// element's first body TextNode carries `name` or `name::T`; each
// child Element is a constraint clause.  Composite type ascriptions
// (`[list T]`, `[enum …]`, `[ref Name]`, …) embed in the type_str.
// A `*frag` token in the body text is preserved as the alias_target
// for resolve_aliases (CX merge-sigil form, reused for fragment
// inlining — schema vocab doesn't redefine it).
fn attr_rule_from_element_v0_8(e Element) AttrRule {
	mut ar := AttrRule{ required: true }  // default
	_, type_str := split_v0_8_name_type(e)
	apply_v0_8_type_str_to_attr(type_str, mut ar)
	// Scan first TextNode for a `*frag` alias token after the name.
	for n in e.items {
		if n is TextNode {
			toks := split_ws_quote_bracket(n.value.trim_space())
			for i, t in toks {
				if i == 0 { continue }  // skip the name / name::T token
				if t.starts_with('*') && t.len > 1 && ar.alias_target == '' {
					ar.alias_target = t[1..]
					break
				}
			}
			break
		}
	}
	for n in e.items {
		if n is Element {
			apply_v0_8_clause_to_attr(n, mut ar)
		}
	}
	return ar
}

// apply_v0_8_type_str_to_attr resolves the post-`::` ascription text
// into the AttrRule slots.  Composite types (enum/list/map/ref) flow
// into the matching constraint slots in addition to (or instead of)
// type_name.
fn apply_v0_8_type_str_to_attr(typ string, mut ar AttrRule) {
	t := typ.trim_space()
	if t == '' { return }
	if t.starts_with('[') && t.ends_with(']') && t.len >= 2 {
		inner := t[1..t.len - 1].trim_space()
		toks := split_ws_quote_bracket(inner)
		if toks.len == 0 { return }
		head := toks[0]
		match head {
			'enum' {
				mut vals := []string{}
				for v in toks[1..] {
					vv := strip_quotes(v.trim_space())
					if vv != '' { vals << vv }
				}
				ar.enum_vals = vals
				ar.type_name = 'string'  // enum members are string atoms
			}
			'list', 'seq' {
				ar.type_name = 'arr'
				if toks.len > 1 { ar.item_kind = toks[1..].join(' ') }
			}
			'map' {
				ar.type_name = 'map'
				if toks.len > 1 { ar.key_kind = toks[1] }
				if toks.len > 2 { ar.item_kind = toks[2..].join(' ') }
			}
			'or' {
				// We keep the union shape opaque; the validator
				// will skip type-mismatch checking on union-typed attrs.
				ar.type_name = ''
			}
			'ref' {
				// `[ref Name]` — reference to a named type / id.  Stored
				// in alias_target so resolve_aliases / S023 paths can see
				// it; type_name stays empty so S005 doesn't fire.
				if toks.len > 1 { ar.alias_target = toks[1] }
			}
			'record', 'tuple' {
				// Composite shapes — kept opaque (full shape
				// validation is future work).  Mark type_name so the
				// schema-load default-coercion check skips.
				ar.type_name = ''
			}
			else {
				// Unknown bracket-head — leave type opaque.
				ar.type_name = ''
			}
		}
		return
	}
	// Bareword type ascription — atomic scalar (or a named type alias).
	ar.type_name = t
}

// apply_v0_8_clause_to_attr folds one constraint-clause child Element
// into the AttrRule.  Unknown clauses are silently ignored (forward-
// compatibility — future clauses won't break older validators).
fn apply_v0_8_clause_to_attr(n Element, mut ar AttrRule) {
	match n.name {
		'req' { ar.required = true }
		'opt' { ar.required = false }
		'default' {
			ar.has_def = true
			ar.def_value = clause_payload_text(n)
			ar.required = false  // [default V] implies optional (§5)
		}
		'min' { ar.range_min = clause_payload_text(n) }
		'max' { ar.range_max = clause_payload_text(n) }
		'range' {
			mn, mx := clause_payload_pair(n)
			ar.range_min = mn
			ar.range_max = mx
		}
		'min-length' { ar.len_min = clause_payload_text(n) }
		'max-length' { ar.len_max = clause_payload_text(n) }
		'len' {
			mn, mx := clause_payload_pair(n)
			ar.len_min = mn
			ar.len_max = mx
		}
		'pattern' { ar.pat = clause_payload_text(n) }
		'enum' { ar.enum_vals = clause_payload_list(n) }
		'ref' {
			tgt := clause_payload_text(n)
			if tgt != '' { ar.alias_target = tgt }
		}
		else {}
	}
}

// elem_rule_from_element_v0_8 parses the 6.f elem-decl form.
fn elem_rule_from_element_v0_8(e Element) ElemRule {
	mut er := ElemRule{ min: 1, max: 1 }
	name, type_str := split_v0_8_name_type(e)
	if type_str != '' {
		// Composite ascriptions on elem decls are typically `::TypeName`
		// (named-type reference) or `::[list T]`.  For named-type the
		// type_name is the bareword; for [list T] the type_name is the
		// inner T (the elem is one item; cardinality is on the parent).
		t := type_str.trim_space()
		if t.starts_with('[') && t.ends_with(']') && t.len >= 2 {
			inner := t[1..t.len - 1].trim_space()
			toks := split_ws_quote_bracket(inner)
			if toks.len >= 2 && (toks[0] == 'list' || toks[0] == 'seq') {
				er.type_name = toks[1]
			} else {
				er.type_name = name
			}
		} else {
			er.type_name = t
		}
	} else {
		er.type_name = name
	}
	for n in e.items {
		if n is Element {
			match n.name {
				'req' { er.min = 1; er.max = 1; er.max_unbounded = false }
				'opt' { er.min = 0; er.max = 1; er.max_unbounded = false }
				'card' {
					raw := clause_payload_text(n)
					mn, mx, unb := parse_card_range(raw)
					er.min = mn
					er.max = mx
					er.max_unbounded = unb
				}
				else {}
			}
		}
	}
	return er
}

// clause_payload_text returns the single scalar / text payload of a
// constraint clause Element (e.g. `[min 3]` → '3', `[pattern '^x$']`
// → '^x$', `[default "anon"]` → 'anon').  Returns '' on an empty
// clause body.
fn clause_payload_text(e Element) string {
	for n in e.items {
		if n is ScalarNode {
			return scalar_value_str(n.value)
		}
		if n is TextNode {
			t := n.value.trim_space()
			if t != '' { return strip_quotes(t) }
		}
	}
	return ''
}

// clause_payload_pair returns the first two whitespace-separated tokens
// from a clause body — used by `[range M N]` / `[len M N]`.  Also
// accepts a single `'M..N'` text token for back-compat with quoted ranges.
fn clause_payload_pair(e Element) (string, string) {
	mut tokens := []string{}
	for n in e.items {
		if n is ScalarNode {
			tokens << scalar_value_str(n.value)
		} else if n is TextNode {
			t := n.value.trim_space()
			if t == '' { continue }
			parts := split_ws_quote_bracket(t)
			for p in parts {
				tokens << strip_quotes(p)
			}
		}
	}
	if tokens.len == 1 && tokens[0].contains('..') {
		return split_range(tokens[0])
	}
	if tokens.len >= 2 {
		return tokens[0], tokens[1]
	}
	if tokens.len == 1 {
		return tokens[0], ''
	}
	return '', ''
}

// clause_payload_list returns the whitespace-separated tokens from an
// enum clause body — `[enum admin user guest]` → ['admin', 'user',
// 'guest'].  Quoted values survive intact (`[enum "a b" c]`).
fn clause_payload_list(e Element) []string {
	mut out := []string{}
	for n in e.items {
		if n is ScalarNode {
			out << scalar_value_str(n.value)
		} else if n is TextNode {
			t := n.value.trim_space()
			if t == '' { continue }
			for p in split_ws_quote_bracket(t) {
				pt := p.trim_space()
				if pt == '' { continue }
				// Quoted members survive verbatim; unquoted atom members
				// (`:NAME`) are stored canonically without the `:` sigil so
				// they compare equal to atom-typed attribute / body values
				// (which the data parser stores as the bare atom name). See
				// spec/schema.md §3 `[enum :ok :err]`.
				quoted := pt.starts_with("'") || pt.starts_with('"')
				mut v := strip_quotes(pt)
				if !quoted && v.len > 1 && v[0] == `:` {
					v = v[1..]
				}
				if v != '' { out << v }
			}
		}
	}
	return out
}

// parse_card_range parses an `'M..N'` cardinality string. Both ends
// can be `*` for unbounded. Returns (min, max, max_unbounded).
fn parse_card_range(s string) (int, int, bool) {
	mut t := s.trim_space()
	if t.starts_with('\'') && t.ends_with('\'') && t.len >= 2 { t = t[1..t.len-1] }
	if t.starts_with('"') && t.ends_with('"') && t.len >= 2 { t = t[1..t.len-1] }
	parts := t.split('..')
	if parts.len != 2 { return 1, 1, false }
	min_s := parts[0].trim_space()
	max_s := parts[1].trim_space()
	min_v := if min_s == '*' { 0 } else { min_s.int() }
	if max_s == '*' { return min_v, 0, true }
	return min_v, max_s.int(), false
}

// split_range parses an `M..N` range string (also used for length).
fn split_range(s string) (string, string) {
	parts := s.split('..')
	if parts.len != 2 { return '', '' }
	return parts[0].trim_space(), parts[1].trim_space()
}

fn strip_quotes(s string) string {
	mut t := s.trim_space()
	if t.len >= 2 && ((t.starts_with('\'') && t.ends_with('\''))
		|| (t.starts_with('"') && t.ends_with('"'))) {
		t = t[1..t.len-1]
	}
	return t
}

fn is_container_kind(dt string) bool {
	return dt == 'elem' || dt == 'mixed' || dt == 'table' || dt == 'frag'
}


// ── Schema content-hash ────────────────────────────────────────

// schema_content_hash returns the 32-byte SHA-256 of the schema's
// CXCol strict-canonical encoding. This is the same primitive
// `cx_hash` applies to data documents: parse → emit_data_bin → hash.
// Comments and whitespace in the schema source are stripped by the
// parse → emit_data_bin pipeline, so reformatted-but-semantically-
// equivalent schemas hash identically (sd-006).
pub fn schema_content_hash(schema_text string) ![]u8 {
	doc := parse(schema_text)!
	bytes := emit_data_bin(doc)
	// Strip the 4-byte framing prefix; the hash is over the CXCol
	// payload (header + values), not the framing wrapper.
	if bytes.len < 4 {
		return error('schema content-hash: short emit')
	}
	digest := sha256.sum256(bytes[4..])
	mut out := []u8{cap: 32}
	for b in digest { out << b }
	return out
}

// ── Schema-driven encoder (§3.13) ────────────────────────────────────────────

pub enum SchemaRefForm {
	hash_only       // 0x10
	inline_schema   // 0x11
	hash_with_name  // 0x12
}

@[params]
pub struct SchemaDrivenEmitOptions {
pub:
	schema_text string
	ref_form    SchemaRefForm = .hash_only
	name_hint   string  // used when ref_form == .hash_with_name
}

// emit_data_bin_schema_driven encodes a Document with header flag
// bit 1 set, a schema reference of the requested form, and per-field
// tag-omission against the schema. Output is framed as
// `[u32 LE size][payload]` matching emit_data_bin.
pub fn emit_data_bin_schema_driven(doc Document, opts SchemaDrivenEmitOptions) ![]u8 {
	if opts.schema_text == '' {
		return error('schema-driven: schema_text is required')
	}
	sm := parse_schema(opts.schema_text)!
	mut payload := []u8{cap: 256}
	encode_header_schema_driven(mut payload)
	encode_schema_reference(opts, sm, mut payload)!
	encode_root_with_schema(doc, sm, mut payload)!
	return frame_payload(payload)
}

fn encode_header_schema_driven(mut buf []u8) {
	buf << cxcol_magic
	buf << cxcol_version
	buf << (cxcol_flags_le | cxcol_flags_schema_driven)
	encode_u32_le(mut buf, cxcol_default_depth)
	buf << u8(0)  // reserved (1 byte — magic grew from 4→5)
}

fn encode_schema_reference(opts SchemaDrivenEmitOptions, _sm SchemaModel, mut buf []u8) ! {
	match opts.ref_form {
		.hash_only {
			h := schema_content_hash(opts.schema_text)!
			buf << tag_schema_ref_hash
			buf << h
		}
		.inline_schema {
			schema_doc := parse(opts.schema_text)!
			schema_bytes := emit_data_bin(schema_doc)
			payload := schema_bytes[4..]  // strip framing prefix
			buf << tag_schema_ref_inline
			encode_uvarint(mut buf, u64(payload.len))
			buf << payload
		}
		.hash_with_name {
			h := schema_content_hash(opts.schema_text)!
			buf << tag_schema_ref_hash_name
			buf << h
			name := opts.name_hint
			encode_uvarint(mut buf, u64(name.len))
			buf << name.bytes()
		}
	}
}

// encode_root_with_schema picks the encoding strategy based on the
// document's root shape and the schema's root type.
fn encode_root_with_schema(doc Document, sm SchemaModel, mut buf []u8) ! {
	roots := doc.elements.filter(it is Element)
	if roots.len == 0 {
		buf << tag_null
		return
	}
	if roots.len == 1 {
		e := roots[0] as Element
		if sm.root == '' || e.name == sm.root {
			st := sm.types[sm.root] or { SchemaType{} }
			encode_element_with_schema(e, st, sm, mut buf)!
			return
		}
	}
	// Fallback: emit as the standard wrapped keyed-collection map.
	// Schema-driven applies only to recognized declared roots.
	encode_keyed_collection(roots, mut buf)
}

// encode_element_with_schema emits one Element under the guidance of
// `st` (the SchemaType matching this element's name). Logic:
//   - If the element has attrs, emit a map and tag-omit declared
//     attr values per st.attrs.
//   - If the element has a scalar body declared in st.body_type,
//     emit the typed payload only (no tag).
//   - If the element has child elements declared in st.elems, recurse
//     into each child with the matching nested SchemaType.
//   - Anything not covered falls back to a self-describing emit by
//     projecting through element_to_dataval + encode_dataval.
fn encode_element_with_schema(e Element, st SchemaType, sm SchemaModel, mut buf []u8) ! {
	// Closed mode rejects undeclared attrs at emit time.
	if sm.mode == .closed {
		for a in e.attrs {
			if a.name !in st.attrs {
				return error('S012: unknown attribute \'${a.name}\' (schema-mode=closed; declared attrs: ${declared_attr_list(st)})')
			}
		}
	}
	body_decl := if !is_container_kind(st.body.kind) && st.body.kind != ''
		&& st.body.kind != 'none' && st.body.kind != 'any' { st.body.kind } else { '' }
	// Pure-attr element with no children → encode as map of attrs only.
	if e.attrs.len > 0 && content_is_empty(e) {
		encode_attr_map_with_schema(e.attrs, st, mut buf)!
		return
	}
	// Scalar body with declared type → tag-omitted payload.
	if body_decl != '' && e.attrs.len == 0 {
		if scalar := single_scalar_value(e) {
			encode_typed_payload(scalar, body_decl, mut buf)!
			return
		}
	}
	// Element-bodied (children) with attrs and declared :elem body.
	if (st.body.kind == 'elem' || st.body.kind == '') && e.attrs.len > 0 {
		encode_attr_map_with_schema(e.attrs, st, mut buf)!
		return
	}
	// Fallback: self-describing.
	dv := element_to_dataval(e)
	encode_dataval(dv, mut buf)
}

fn encode_attr_map_with_schema(attrs []Attribute, st SchemaType, mut buf []u8) ! {
	if attrs.len == 0 {
		buf << tag_map_empty
		return
	}
	buf << tag_map
	encode_uvarint(mut buf, u64(attrs.len))
	for a in attrs {
		encode_string_value(a.name, mut buf)
		if ar := st.attrs[a.name] {
			encode_typed_payload(a.value, ar.type_name, mut buf)!
		} else {
			// Undeclared attr → self-describing fallback.
			dv := scalar_value_to_dataval(a.value)
			encode_dataval(dv, mut buf)
		}
	}
}

// encode_typed_payload writes a ScalarValue using the type-tag-
// omitted form for the declared type. The output bytes match
// what a self-describing emit would produce *minus* the leading
// 1-byte type tag. Bool is a special case: its self-describing
// encoding is the tag itself (`0x02` true / `0x03` false), so the
// tag-omitted form for bool is unchanged from self-describing.
fn encode_typed_payload(v ScalarValue, declared_type string, mut buf []u8) ! {
	match declared_type {
		'string', 's' {
			s := scalar_to_string_for_typed(v)
			encode_uvarint(mut buf, u64(s.len))
			buf << s.bytes()
		}
		'bool' {
			// Bool's self-describing tag IS the value (sentinel scalars
			// per §3.3); schema-driven encoding leaves these unchanged.
			b := scalar_to_bool(v)
			buf << if b { tag_true } else { tag_false }
		}
		'i8' {
			n := scalar_to_i64(v)
			buf << u8(n)
		}
		'i16', 'u16' {
			n := scalar_to_i64(v)
			x := u16(u32(n))
			buf << u8(x & 0xFF)
			buf << u8((x >> 8) & 0xFF)
		}
		'i32', 'u32' {
			n := scalar_to_i64(v)
			encode_u32_le(mut buf, u32(n))
		}
		'i64', 'u64', 'int' {
			n := scalar_to_i64(v)
			encode_u64_le(mut buf, u64(n))
		}
		'f64', 'float' {
			f := scalar_to_f64(v)
			encode_u64_le(mut buf, math_f64_bits(f))
		}
		'date', 'd' {
			d := scalar_to_date(v)
			yu := u16(u32(d.year))
			buf << u8(yu & 0xFF)
			buf << u8((yu >> 8) & 0xFF)
			buf << d.month
			buf << d.day
		}
		'bytes' {
			b := scalar_to_bytes(v)
			encode_uvarint(mut buf, u64(b.len))
			buf << b
		}
		else {
			// Unknown declared type → emit self-describing as a safety net.
			dv := scalar_value_to_dataval(v)
			encode_dataval(dv, mut buf)
		}
	}
}

fn scalar_to_string_for_typed(v ScalarValue) string {
	return match v {
		string  { v }
		i64     { v.str() }
		f64     { v.str() }
		bool    { if v { 'true' } else { 'false' } }
		NullValue { '' }
	}
}

fn scalar_to_bool(v ScalarValue) bool {
	return match v {
		bool { v }
		i64  { v != 0 }
		string { v == 'true' || v == '1' }
		else { false }
	}
}

fn declared_attr_list(st SchemaType) string {
	mut names := []string{}
	for k, _ in st.attrs { names << k }
	return names.join(', ')
}

fn content_is_empty(e Element) bool {
	if e.items.len == 0 { return true }
	for n in e.items {
		if n is CommentNode || n is PINode || n is XMLDeclNode || n is CXDirectiveNode {
			continue
		}
		return false
	}
	return true
}

fn single_scalar_value(e Element) ?ScalarValue {
	mut found_value := ScalarValue('')
	mut found_count := 0
	for n in e.items {
		if n is CommentNode || n is PINode || n is XMLDeclNode || n is CXDirectiveNode {
			continue
		}
		if n is ScalarNode {
			found_count++
			if found_count > 1 { return none }
			found_value = n.value
			continue
		}
		return none
	}
	if found_count == 1 { return found_value }
	return none
}

// ── Schema-driven decoder ────────────────────────────────────────────────────

// parse_data_bin_schema_driven decodes a framed CXCol blob whose
// header flag bit 1 is set. `schema_hint` carries the schema source
// the consumer expects; the decoder verifies the embedded reference
// against the hint's content-hash (D002 on mismatch) and uses the
// hint to recover omitted type tags.
pub fn parse_data_bin_schema_driven(input []u8, schema_hint string) !Document {
	if input.len < 4 {
		return error('cxcol: input too short for size header')
	}
	payload_size := u32(input[0]) | (u32(input[1]) << 8)
		| (u32(input[2]) << 16) | (u32(input[3]) << 24)
	if 4 + int(payload_size) > input.len {
		return error('cxcol: declared payload (${payload_size}) exceeds remaining input')
	}
	mut r := BinReader{
		buf:       unsafe { input[4 .. 4 + int(payload_size)] }
		pos:       0
		depth:     0
		max_depth: int(cxcol_default_depth)
	}
	schema_driven := r.read_header_for_schema_driven()!
	if !schema_driven {
		return error('D004: header flag bit 1 (schema-driven) not set on schema-driven decode call')
	}
	sm := r.read_schema_reference(schema_hint)!
	root_type := sm.types[sm.root] or { SchemaType{} }
	root_val := r.read_dataval_with_schema(root_type, sm)!
	if r.pos != r.buf.len {
		return error('cxcol: trailing bytes after root value (${r.buf.len - r.pos} bytes)')
	}
	return root_val_to_document(sm.root, root_val)
}

fn (mut r BinReader) read_header_for_schema_driven() !bool {
	if r.buf.len < 12 {
		return error('cxcol: payload too short for 12-byte header')
	}
	magic := r.take(cxcol_magic_len)!
	if magic[0] != cxcol_magic[0] || magic[1] != cxcol_magic[1]
		|| magic[2] != cxcol_magic[2] || magic[3] != cxcol_magic[3]
		|| magic[4] != cxcol_magic[4] {
		return error('cxcol: bad magic')
	}
	version := r.take_u8()!
	if version != cxcol_version {
		return error('cxcol: unsupported version ${version}')
	}
	flags := r.take_u8()!
	if flags & 0xFC != 0 {
		return error('cxcol: reserved flag bits set in header')
	}
	if flags & 0x01 == 0 {
		return error('cxcol: only little-endian payloads supported in v1')
	}
	hdr_max_depth := r.read_u32_le()!
	r.max_depth = int(hdr_max_depth)
	rsv1 := r.take_u8()!
	if rsv1 != 0 {
		return error('cxcol: reserved header byte must be zero')
	}
	return (flags & cxcol_flags_schema_driven) != 0
}

fn (mut r BinReader) read_schema_reference(schema_hint string) !SchemaModel {
	tag := r.take_u8()!
	match tag {
		tag_schema_ref_hash {
			embedded := r.take(32)!
			if schema_hint == '' {
				return error('D001: schema hash referenced but no schema hint provided')
			}
			actual := schema_content_hash(schema_hint)!
			if !bytes_equal(embedded, actual) {
				return error('D002: schema content-hash mismatch')
			}
			return parse_schema(schema_hint)!
		}
		tag_schema_ref_inline {
			n := r.read_uvarint()!
			if n > u64(r.buf.len - r.pos) {
				return error('cxcol: inline schema length ${n} exceeds remaining input')
			}
			_ := r.take(int(n))!
			// We re-parse from the hint when present (richer source for
			// reconstruction). The inline blob is normative but losing
			// comments / source text limits round-trip fidelity. v0
			// requires a hint alongside inline schemas.
			if schema_hint == '' {
				return error('D001: inline schema decode without source hint not yet supported in v0')
			}
			return parse_schema(schema_hint)!
		}
		tag_schema_ref_hash_name {
			embedded := r.take(32)!
			n := r.read_uvarint()!
			if n > u64(r.buf.len - r.pos) {
				return error('cxcol: name-hint length ${n} exceeds remaining input')
			}
			_ := r.take(int(n))!  // name hint (informational; ignored at v0)
			if schema_hint == '' {
				return error('D001: schema hash+name referenced but no schema hint provided')
			}
			actual := schema_content_hash(schema_hint)!
			if !bytes_equal(embedded, actual) {
				return error('D002: schema content-hash mismatch')
			}
			return parse_schema(schema_hint)!
		}
		else {
			return error('D003: expected schema-ref tag (0x10/0x11/0x12) at offset ${r.pos - 1}, got 0x${tag:02x}')
		}
	}
}

fn (mut r BinReader) read_dataval_with_schema(st SchemaType, sm SchemaModel) !DataVal {
	r.depth++
	if r.depth > r.max_depth {
		return error('cxcol: recursion depth exceeds limit (${r.max_depth})')
	}
	defer { r.depth-- }
	body_decl := if !is_container_kind(st.body.kind) && st.body.kind != ''
		&& st.body.kind != 'none' && st.body.kind != 'any' { st.body.kind } else { '' }
	// If the schema root declares a scalar body and no attrs, the
	// payload is a typed-value-only encoding.
	if body_decl != '' && st.attrs.len == 0 {
		v := r.read_typed_payload(body_decl)!
		return v
	}
	// Otherwise expect a map: 0x50 count <(key, val)*>.
	tag := r.take_u8()!
	if tag == tag_map_empty {
		return DataVal(DataPairs{ keys: []string{}, vals: []DataVal{} })
	}
	if tag != tag_map {
		// Schema disagreement — try self-describing fallback by
		// rewinding and reading a regular dataval.
		r.pos--
		return r.read_dataval()!
	}
	count := r.read_uvarint()!
	mut keys := []string{cap: int(count)}
	mut vals := []DataVal{cap: int(count)}
	for _ in 0 .. int(count) {
		key_tag := r.take_u8()!
		if key_tag != tag_string {
			return error('cxcol: map key must be string (tag 0x30); got 0x${key_tag:02x}')
		}
		k := r.read_string_payload()!
		mut v := DataVal(DataNull{})
		if ar := st.attrs[k] {
			v = r.read_typed_payload(ar.type_name)!
		} else if er := st.elems[k] {
			child_st := sm.types[er.type_name] or { SchemaType{} }
			v = r.read_dataval_with_schema(child_st, sm)!
		} else {
			if sm.mode == .closed {
				return error('D003: unknown key \'${k}\' (schema-mode=closed)')
			}
			v = r.read_dataval()!
		}
		keys << k
		vals << v
	}
	return DataVal(DataPairs{ keys: keys, vals: vals })
}

fn (mut r BinReader) read_typed_payload(declared_type string) !DataVal {
	return match declared_type {
		'string', 's' {
			n := r.read_uvarint()!
			if n > u64(r.buf.len - r.pos) {
				return error('cxcol: string length ${n} exceeds remaining input')
			}
			bs := r.take(int(n))!
			DataVal(bs.bytestr())
		}
		'bool' {
			b := r.take_u8()!
			match b {
				tag_true  { DataVal(true) }
				tag_false { DataVal(false) }
				else      { return error('D003: bool sentinel expected, got 0x${b:02x}') }
			}
		}
		'i8' { DataVal(i64(i8(r.take_u8()!))) }
		'i16', 'u16' { DataVal(i64(r.read_i16_le()!)) }
		'i32', 'u32' { DataVal(i64(r.read_i32_le()!)) }
		'i64', 'u64', 'int' { DataVal(r.read_i64_le()!) }
		'f64', 'float' { DataVal(r.read_f64()!) }
		'date', 'd' {
			d := r.read_date_payload()!
			DataVal(d)
		}
		'bytes' {
			b := r.read_bytes_payload()!
			DataVal(DataBytes{ value: b })
		}
		else {
			// Unknown declared type — fall back to self-describing read.
			r.read_dataval()!
		}
	}
}

fn root_val_to_document(root_name string, v DataVal) Document {
	if root_name == '' {
		// No schema-of declared; treat root_val as anonymous.
		return Document{ elements: [Node(dataval_to_element('_', v))] }
	}
	return Document{ elements: [Node(dataval_to_element(root_name, v))] }
}

fn bytes_equal(a []u8, b []u8) bool {
	if a.len != b.len { return false }
	for i in 0 .. a.len {
		if a[i] != b[i] { return false }
	}
	return true
}
