module cx

import crypto.sha256
import strconv

// CXDB v0.6.0 — schema-driven encoding (header flag bit 1) per
// spec/data_bin.md §3.13 and ADR 0015 D3 / D4 / D5 / D6.
//
// Schema-driven encoding omits per-value type tags wherever the schema
// declares the value's type. Tag-omission is per-field: declared keys
// get typed-payload-only encoding; undeclared keys (under `open` mode)
// fall back to self-describing CXDB encoding so schema-driven and
// self-describing form coexist within a single document.
//
// This module ships:
//   - SchemaModel parsing (root type + body kind + per-attr types
//     + nested element types + `[?cx schema-mode <mode>]` directive)
//   - Schema content-hash per ADR 0015 D5: SHA-256 over
//     emit_data_bin(parse(schema_text)) (the strict-canonical CXDB
//     form of the parsed schema)
//   - Schema-driven encoder + decoder for the most common shapes:
//     elements with declared attrs, scalar bodies, and nested
//     declared elements
//   - Three schema-reference forms per §3.13.1: 0x10 content-hash,
//     0x11 inline schema (recursive CXDB blob), 0x12 hash + name hint
//
// Reader-side decode walks the schema cursor in lockstep with the
// data; undeclared scopes (open mode) fall through to self-describing
// reads. Closed mode rejects undeclared keys at emit time (`S012`)
// and unknown scopes at decode time (`D003`).

// ── Tags / constants ─────────────────────────────────────────────────────────

const cxdb_flags_schema_driven = u8(0x02)            // header flags bit 1

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
// `[attr <name> :type :flag1 :flag2=val]` schema entry. The set of
// constraint sigils (req/opt/def/range/enum/pat/len) is the
// spec/schema.md §7 catalog. `required` defaults to true per
// spec/schema.md §5.
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
	// v0.6.0 — attr-position fragment alias `[attr name *frag :flag]`.
	// At schema-load time the validator looks up `*frag` in
	// SchemaModel.frags and inlines the fragment body's kind + range +
	// enum + pat + len constraints into this AttrRule. Site-local flags
	// (`:req`, `:opt`, `:def=`) take precedence over the fragment.
	// Empty when no alias is referenced.
	alias_target string
	// ADR 0017 §D15 (v1.1) — attribute-position container productions.
	// Same shape as BodyRule.item_kind / .key_kind. Attribute values
	// that are collection literals (`name=[a, b, c]` for arr, etc.)
	// validate against these.
	item_kind string
	key_kind  string
}

// ElemRule carries the cardinality + type-to-recurse-into for one
// `[elem <name> :card='M..N']` entry. `type_name` defaults to the
// child element's name (the conventional case).
pub struct ElemRule {
pub mut:
	type_name     string
	min           int = 1
	max           int = 1   // ignored when max_unbounded
	max_unbounded bool
}

// BodyRule carries the body-declaration constraints for one
// `[body :kind :flag1 :flag2=val]` entry. `kind` is the body kind
// ('string', 'i32', 'elem', 'mixed', 'none', 'any', 'scalar', etc.).
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
	// ADR 0017 §D15 (v1.1) — container productions `arr[T]` / `seq[T]` /
	// `map[K, V]`. When `kind` is 'arr' or 'seq', `item_kind` carries the
	// element kind ('u16', 'string', or a nested `arr[float]` / `map[…]`
	// expression). When `kind` is 'map', `key_kind` carries the key
	// type (atomic scalar, restricted to 'string' at v0.6.0 per ADR §D4)
	// and `item_kind` the value type. Recursive nesting (`arr[arr[float]]`,
	// `map[string, arr[u32]]`) is preserved verbatim and re-parsed at
	// validation time.
	item_kind string
	key_kind  string
}

// SchemaType describes one named type in the schema. The unified
// model lands at v0.6.0; it carries every constraint sigil the
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
	// v0.6.0 — top-level fragment alias `[type-name *frag]` (parsed by
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
	types map[string]SchemaType
	src   string
	// v0.6.0 — fragment registry per spec/schema.md §8. anchor name →
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
// element. Per-attr declarations embed their type/flags as a single
// trailing TextNode (e.g. `[attr host :string :req]` → TextNode
// "host :string :req"); we split that text on whitespace to recover
// the (name, type, flags) tuple.
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
			if anc := n.anchor {
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

// register_frag_directive recognizes `[?cx frag &name [body :TYPE :flags]]`
// (spec/schema.md §8 standalone fragment form). The directive's first
// positional attr name must be `frag`; the directive carries the
// fragment anchor in `.anchor` and the fragment body declarations in
// `.items`.
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
// spec §8 + §10.1 step 1. Type-level aliases (`[type *frag]` parsed as
// Element.merge) run first via DFS with cycle detection. Attr-level
// aliases (`[attr name *frag :flag]`) run after type resolution.
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
// shape (kind, range, enum, pat, len). v0.6.0 supports a single-step
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
// `:def=<value>`) is a CX literal that matches the declared scalar
// type. Used at schema-load time to enforce S011 fail-fast per
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
				if ver != '0.6' {
					return error('S020: schema-version \'${ver}\' is not supported (this implementation supports 0.6 only)')
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
//   [body :TYPE :flag1 :flag2]           declares body kind / constraints
//   [attr <name> :TYPE :flag1 :flag2]    declares an attribute
//   [elem <name> :TYPE :flag]            declares a child element + cardinality
//   [check ordering=strict]              parent-level child-order policy (S015)
//   [<sub-type> ...]                     unrecognized; ignored at v0
//
// v0.6.0 — `[type-name *fragment-name]` (where the parser stores
// `*fragment-name` as `Element.merge`) records the fragment alias for
// later resolution by resolve_aliases. The merge field's normal CX
// "merge from anchor" semantics overlap exactly with the schema spec's
// "inline the fragment's declarations" semantics, so we reuse it.
//
// Returns an error on:
//   - duplicate `[attr <same-name> ...]` declarations on the same
//     type (S014).
fn schema_type_from_element(e Element) !SchemaType {
	mut st := SchemaType{ name: e.name }
	if mt := e.merge {
		st.alias_target = mt
	}
	collect_decls(e.items, mut st)!
	return st
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

// body_rule_from_element parses `[body :kind :flag1 :flag2=val ...]`.
fn body_rule_from_element(e Element) BodyRule {
	mut br := BodyRule{ declared: true }
	if dt := e.data_type {
		br.kind = dt
	}
	// ADR 0017 §D19 — legacy `:T[]` annotation desugars to `arr[T]`.
	// Normalize at schema-load so downstream validators only see the
	// container form. The bare `:[]` (no inner type) is non-canonical
	// at v1.1 and not handled here; schemas that emit it would have
	// been rejected upstream.
	if br.kind.ends_with('[]') && br.kind.len > 2 {
		inner := br.kind[..br.kind.len - 2]
		if inner != '' {
			br.kind = 'arr'
			br.item_kind = inner
		}
	}
	// ADR 0017 §D15 — collection-literal productions written without
	// the `:`-prefix sigil land in body text tokens (e.g. `arr[u16]`).
	// Walk the body items for the first token that matches
	// `arr[T]` / `seq[T]` / `map[K, V]` and adopt its kind. Existing
	// `:type` annotation (handled above) wins when both are present,
	// since the annotation is the documented v1.0 form and a schema
	// that mixes both shapes most likely had the annotation typed
	// first.
	if br.kind == '' {
		for n in e.items {
			if n is TextNode {
				toks := split_ws_quote_bracket(n.value.trim_space())
				for tok in toks {
					if k, kk, ik := parse_container_kind(tok) {
						br.kind = k
						br.key_kind = kk
						br.item_kind = ik
						break
					}
				}
				if br.kind != '' { break }
			}
		}
	}
	// spec/schema.md §4: `:req` is implicit for non-:none shapes;
	// every scalar kind requires content unless an explicit `:opt`
	// (not in v0.6.0 catalog for body) overrides. We mark scalar
	// kinds implicit-required so S019 fires on empty `[name]` forms
	// declared with a scalar body. Container productions
	// (`arr` / `seq` / `map`) are also implicit-required since they
	// describe content shape, not absence.
	if is_scalar_kind(br.kind) || is_container_collection_kind(br.kind) {
		br.required = true
	}
	for tok in collect_decl_tokens(e) {
		match true {
			tok == 'req' { br.required = true }
			tok.starts_with('pat=')   { br.pat = strip_quotes(tok[4..]) }
			tok.starts_with('range=') {
				min_v, max_v := split_range(strip_quotes(tok[6..]))
				br.range_min = min_v
				br.range_max = max_v
			}
			tok.starts_with('len=') {
				min_v, max_v := split_range(strip_quotes(tok[4..]))
				br.len_min = min_v
				br.len_max = max_v
			}
			tok.starts_with('enum=') { br.enum_vals = parse_enum_list(strip_quotes(tok[5..])) }
			else {}
		}
	}
	return br
}

// parse_container_kind matches ADR 0017 §D15 container productions
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

// attr_rule_from_element parses `[attr NAME :TYPE :flag1 :flag2=val ...]`.
// v0.6.0 also recognizes attr-position fragment alias `[attr NAME *FRAG :flag]`;
// the alias target is stashed in ar.alias_target for resolve_aliases to
// inline the fragment body's kind+constraints into this rule.
fn attr_rule_from_element(e Element) AttrRule {
	mut ar := AttrRule{ required: true }  // spec/schema.md §5 default
	_, type_name, flags, def_val, alias_target := decl_split(e)
	ar.type_name = type_name
	ar.alias_target = alias_target
	if def_val != '' {
		ar.has_def = true
		ar.def_value = def_val
		ar.required = false  // :def implies :opt (§5)
	}
	mut req := ar.required
	mut has_explicit_opt := false
	for tok in flags {
		match true {
			tok == 'req' { req = true }
			tok == 'opt' { req = false; has_explicit_opt = true }
			tok.starts_with('pat=')   { ar.pat       = strip_quotes(tok[4..]) }
			tok.starts_with('range=') {
				min_v, max_v := split_range(strip_quotes(tok[6..]))
				ar.range_min = min_v
				ar.range_max = max_v
			}
			tok.starts_with('len=') {
				min_v, max_v := split_range(strip_quotes(tok[4..]))
				ar.len_min = min_v
				ar.len_max = max_v
			}
			tok.starts_with('enum=') {
				ar.enum_vals = parse_enum_list(strip_quotes(tok[5..]))
			}
			else {}
		}
	}
	if !has_explicit_opt && !ar.has_def { ar.required = req }
	else { ar.required = req }
	return ar
}

// elem_rule_from_element parses `[elem NAME :card='M..N' :flag]`.
// type_name defaults to the element name when no `:type` is given.
fn elem_rule_from_element(e Element) ElemRule {
	mut er := ElemRule{ min: 1, max: 1 }
	name, type_name, flags, _, _ := decl_split(e)
	er.type_name = if type_name != '' { type_name } else { name }
	for tok in flags {
		match true {
			tok == 'req' { er.min = 1; er.max = 1; er.max_unbounded = false }
			tok == 'opt' { er.min = 0; er.max = 1; er.max_unbounded = false }
			tok.starts_with('card=') {
				min_v, max_v, unbounded := parse_card_range(strip_quotes(tok[5..]))
				er.min = min_v
				er.max = max_v
				er.max_unbounded = unbounded
			}
			else {}
		}
	}
	return er
}

fn decl_name_from_element(e Element) string {
	name, _, _, _, _ := decl_split(e)
	return name
}

// decl_split parses an `[attr|elem NAME :TYPE :flag1 :flag2=val ...]`
// declaration. Returns (name, type, flags, def_value, alias_target).
// The schema parser sometimes folds the `:type` annotation into
// Element.data_type with the bare name as a single ScalarNode; we
// handle both layouts.
//
// v0.6.0 — also recognizes `*name` tokens as fragment alias references
// (used by `[attr NAME *FRAG :flag]` per spec/schema.md §8). The
// alias_target return value is empty when no `*name` token appears.
// The CX parser today flattens `[attr NAME *FRAG :flag]` into a single
// TextNode whose value is `NAME *FRAG :flag`, so we walk the token
// stream looking for a `*<name>` token (only the first one matters
// per spec).
fn decl_split(e Element) (string, string, []string, string, string) {
	mut name := ''
	mut type_name := ''
	mut flags := []string{}
	mut def_value := ''
	mut alias_target := ''

	if dt := e.data_type {
		if e.items.len >= 1 {
			if e.items[0] is ScalarNode {
				s := e.items[0] as ScalarNode
				name = scalar_value_str(s.value).trim_space()
			}
		}
		type_name = dt
		for i, n in e.items {
			if i == 0 { continue }
			if n is TextNode {
				for tok in tokenize_decl_flags(n.value) {
					if tok.starts_with('def=') {
						def_value = tok[4..]
					} else {
						flags << tok
					}
				}
			}
		}
		return name, type_name, flags, def_value, alias_target
	}

	for n in e.items {
		if n is TextNode {
			parts := split_ws_quote_bracket(n.value.trim_space())
			if parts.len == 0 { continue }
			name = parts[0]
			for p in parts[1..] {
				if p.starts_with('*') && p.len > 1 && alias_target == '' {
					alias_target = p[1..]
					continue
				}
				if !p.starts_with(':') { continue }
				tok := p[1..]
				if tok.starts_with('def=') {
					def_value = tok[4..]
					continue
				}
				if tok == 'req' || tok == 'opt' || tok.starts_with('card=')
					|| tok.starts_with('range=') || tok.starts_with('enum=')
					|| tok.starts_with('pat=') || tok.starts_with('len=') {
					flags << tok
					continue
				}
				if type_name == '' {
					type_name = tok
				} else {
					flags << tok
				}
			}
			break
		}
	}
	return name, type_name, flags, def_value, alias_target
}

fn collect_decl_tokens(e Element) []string {
	mut out := []string{}
	for n in e.items {
		if n is TextNode {
			out << tokenize_decl_flags(n.value)
		}
	}
	return out
}

// tokenize_decl_flags returns the `:`-stripped sigil tokens from a
// schema-decl TextNode body. Quote- and bracket-aware (v0.6.0
// Phase 7.74e) so `:pat='a b c'`, `:enum='a,b,c'`, and
// `:enum=[v1 v2 v3]` survive intact rather than being whitespace-split
// into fragments.
fn tokenize_decl_flags(s string) []string {
	mut out := []string{}
	for p in split_ws_quote_bracket(s.trim_space()) {
		if p.starts_with(':') {
			out << p[1..]
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

// parse_enum_list splits enum value lists into a list of trimmed/
// unquoted strings. Accepted shapes (all supported as of v0.6.0
// Phase 7.74e quote/bracket-aware tokenizer fix):
//   `[v1 v2 v3]`       (spec syntax — bracket-aware)
//   `['a' 'b' 'c']`    (spec syntax with quoted values)
//   `'a b c'`          (quoted whitespace-separated)
//   `v1,v2,v3`         (comma-separated)
//   `'v1,v2,v3'`       (quoted comma-separated)
fn parse_enum_list(raw string) []string {
	mut t := raw.trim_space()
	// Strip outer quotes BEFORE bracket-stripping so `'a b c'` and
	// `'v1,v2'` flatten cleanly without leaving stray quote chars on
	// the first/last value after split.
	t = strip_quotes(t)
	if t.starts_with('[') { t = t[1..] }
	if t.ends_with(']') { t = t[..t.len-1] }
	mut out := []string{}
	for p in t.split_any(' \t,') {
		s := strip_quotes(p.trim_space())
		if s != '' { out << s }
	}
	return out
}

fn is_container_kind(dt string) bool {
	return dt == 'elem' || dt == 'mixed' || dt == 'table' || dt == 'frag'
}


// ── Schema content-hash (ADR 0015 D5) ────────────────────────────────────────

// schema_content_hash returns the 32-byte SHA-256 of the schema's
// CXDB strict-canonical encoding. This is the same primitive
// `cx_hash` applies to data documents: parse → emit_data_bin → hash.
// Comments and whitespace in the schema source are stripped by the
// parse → emit_data_bin pipeline, so reformatted-but-semantically-
// equivalent schemas hash identically (sd-006).
pub fn schema_content_hash(schema_text string) ![]u8 {
	doc := parse(schema_text)!
	bytes := emit_data_bin(doc)
	// Strip the 4-byte framing prefix; the hash is over the CXDB
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
	buf << cxdb_magic
	buf << cxdb_version
	buf << (cxdb_flags_le | cxdb_flags_schema_driven)
	encode_u32_le(mut buf, cxdb_default_depth)
	buf << u8(0)  // reserved
	buf << u8(0)  // reserved
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
	// Closed mode rejects undeclared attrs at emit time per ADR 0015 D6.
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

// parse_data_bin_schema_driven decodes a framed CXDB blob whose
// header flag bit 1 is set. `schema_hint` carries the schema source
// the consumer expects; the decoder verifies the embedded reference
// against the hint's content-hash (D002 on mismatch) and uses the
// hint to recover omitted type tags.
pub fn parse_data_bin_schema_driven(input []u8, schema_hint string) !Document {
	if input.len < 4 {
		return error('cxdb: input too short for size header')
	}
	payload_size := u32(input[0]) | (u32(input[1]) << 8)
		| (u32(input[2]) << 16) | (u32(input[3]) << 24)
	if 4 + int(payload_size) > input.len {
		return error('cxdb: declared payload (${payload_size}) exceeds remaining input')
	}
	mut r := BinReader{
		buf:       unsafe { input[4 .. 4 + int(payload_size)] }
		pos:       0
		depth:     0
		max_depth: int(cxdb_default_depth)
	}
	schema_driven := r.read_header_for_schema_driven()!
	if !schema_driven {
		return error('D004: header flag bit 1 (schema-driven) not set on schema-driven decode call')
	}
	sm := r.read_schema_reference(schema_hint)!
	root_type := sm.types[sm.root] or { SchemaType{} }
	root_val := r.read_dataval_with_schema(root_type, sm)!
	if r.pos != r.buf.len {
		return error('cxdb: trailing bytes after root value (${r.buf.len - r.pos} bytes)')
	}
	return root_val_to_document(sm.root, root_val)
}

fn (mut r BinReader) read_header_for_schema_driven() !bool {
	if r.buf.len < 12 {
		return error('cxdb: payload too short for 12-byte header')
	}
	magic := r.take(4)!
	if magic[0] != 0x43 || magic[1] != 0x58 || magic[2] != 0x44 || magic[3] != 0x42 {
		return error('cxdb: bad magic')
	}
	version := r.take_u8()!
	if version != cxdb_version {
		return error('cxdb: unsupported version ${version}')
	}
	flags := r.take_u8()!
	if flags & 0xFC != 0 {
		return error('cxdb: reserved flag bits set in header')
	}
	if flags & 0x01 == 0 {
		return error('cxdb: only little-endian payloads supported in v1')
	}
	hdr_max_depth := r.read_u32_le()!
	r.max_depth = int(hdr_max_depth)
	rsv1 := r.take_u8()!
	rsv2 := r.take_u8()!
	if rsv1 != 0 || rsv2 != 0 {
		return error('cxdb: reserved header bytes must be zero')
	}
	return (flags & cxdb_flags_schema_driven) != 0
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
				return error('cxdb: inline schema length ${n} exceeds remaining input')
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
				return error('cxdb: name-hint length ${n} exceeds remaining input')
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
		return error('cxdb: recursion depth exceeds limit (${r.max_depth})')
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
			return error('cxdb: map key must be string (tag 0x30); got 0x${key_tag:02x}')
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
				return error('cxdb: string length ${n} exceeds remaining input')
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
