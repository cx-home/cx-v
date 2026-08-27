module code

import cx

// stdlib_cx.v — the `cx:` self-host module surface (spec/modules/cx.md §2.1).
//
// #437: nine of the ten "Core (always available)" functions had engine
// machinery but no module dispatch. This file wires the real functions:
//
//   cx:serialize    value → concrete-syntax text (grammar.ebnf bytes)
//   cx:canonical    value → strict canonical text (canonical.md §1.2)
//   cx:hash         value → SHA-256 hex of the strict canonical bytes
//   cx:diff         (a, b) → diff value (a [diff [change …]…] tree)
//   cx:patch        (value, diff) → patched value (apply is diff's inverse)
//   cx:to-format    (value, fmt) → text in the registry format
//   cx:from-format  (text, fmt) → parsed value
//   cx:equal        (a, b) → bool (canonical-aware, anchor/ID-resolving)
//   cx:select       (value, path) → sequence (runtime CXPath string)
//
// `cx:parse` (the tenth) lives in the codec registry dispatch
// (stdlib_codec.v → vcx/cx/codec.v codec_parse_node).
//
// Activation is "Always — no [?lib] required" (modules/cx.md §1): the
// dispatch hook accepts BOTH the namespaced `cx:<fn>` form and the flat
// `cx-<fn>` alias (mirroring `[$cx:parse]` / `[$cx-parse]`, §4), and is
// chained into the env-aware call fallback so it works with or without
// `[?lib 'cx-stdlib/cx']` (whose [?def] bodies forward to the flat names).
//
// String-as-source pivot: `cx:canonical` / `cx:hash` / `cx:equal` /
// `cx:diff` / `cx:patch` / `cx:to-format` / `cx:select` accept EITHER a
// CXDM value or a string of CX source text — a string argument reads as
// source (the CLI verbs `cx canonical` / `cx hash` / `cx eq` / `cx diff`
// operate on source text; this keeps the module functions verb-agreeing
// and makes the §4 identity `cx:serialize(cx:parse($t)) ≡ cx:canonical($t)`
// well-typed for a string $t). `cx:serialize` / `cx:from-format` keep
// pure value/text semantics (a string VALUE serializes as a quoted
// scalar; from-format's TEXT is always source).
//
// Error codes (modules/cx.md §6): CXER4100 malformed CX source, CXER4101
// non-serializable value, CXER4102 diff cannot apply, CXER4103 unknown
// format, CXER4104 not representable, CXER4105 source-format parse
// failure, CXER4106 malformed CXPath.

// ── dispatch ──────────────────────────────────────────────────────────────────

// cx_module_stdlib_builtin_env dispatches the §2.1 function surface.
// Env-aware because cx:select evaluates its runtime CXPath through the
// SAME inline binding-path engine (walk_binding_path_seq) the language
// uses for `$v//x` — so `[$cx:select $v "//x"]` ≡ `$v//x` by construction.
fn cx_module_stdlib_builtin_env(name string, args []cx.Node, mut env MatchEnv) ?cx.Node {
	if !name.starts_with('cx:') && !name.starts_with('cx-') {
		return none
	}
	local := name[3..]
	match local {
		'serialize' { return cx_mod_serialize(args) }
		'canonical' { return cx_mod_canonical(args) }
		'ast' { return cx_mod_ast(args) }
		'schema-of' { return cx_mod_schema_of(args) }
		'hash' { return cx_mod_hash(args) }
		'version' { return cx_mod_version(args) }
		'env' { return cx_mod_env(args) }
		'builtins' { return cx_mod_builtins(args) }
		'computation-id' { return cx_mod_computation_id(args) }
		'plan-address' { return cx_mod_plan_address(args) }
		'equal' { return cx_mod_equal(args) }
		'type-binding' { return cx_mod_type_binding(args) }
		'type-binding-verify' { return cx_mod_type_binding_verify(args) }
		'diff' { return cx_mod_diff(args) }
		'patch' { return cx_mod_patch(args) }
		'merge' { return cx_mod_merge(args) }
		'to-format' { return cx_mod_to_format(args) }
		'from-format' { return cx_mod_from_format(args) }
		'select' { return cx_mod_select(args, mut env) }
		'propose' { return cx_mod_propose(args, mut env) }
		// §2.2 eval + analysis / §2.3 transform (#940, VC-6). The two
		// string-eval arms are env-aware; their wrappers convert a raise from
		// inside the sandbox into an err VALUE, because a `!` propagated out
		// of THIS function becomes `none` and the chain then reports
		// `no callable "cx:eval"` — see cx_mod_eval in dynamic_construction.v.
		'eval' { return cx_mod_eval(args, mut env) }
		'render' { return cx_mod_render(args, mut env) }
		'validate' { return cx_mod_validate(args) }
		'anchors' { return cx_mod_anchors(args) }
		'ids' { return cx_mod_ids(args) }
		'references' { return cx_mod_references(args) }
		'resolve-includes' { return cx_mod_resolve_includes(args) }
		'strip-comments' { return cx_mod_strip_comments(args) }
		'strip-attrs' { return cx_mod_strip_attrs(args) }
		'pretty-print' { return cx_mod_pretty_print(args) }
		else { return none }
	}
}

// ── cx:propose — the proposal-value constructor (stream 6 W6, L113) ─────────
//
// `[$cx:propose <command-fn> <args-map> <opts-map>?]` constructs the
// PROPOSAL VALUE for a command call WITHOUT executing it: the engine
// half of propose mode (the boundary decides the mode; approval +
// commit are cx-stdlib/authz's, §3.9 there). The value carries:
//   [command tier1=… code=…]   — Tier-1 of the def TEXT is the TRUST
//                                 key (L139); Tier-2 rides for
//                                 cache/equivalence only.
//   [args {…}]                  — the param-name → value record AFTER
//                                 defaulting (one key basis with the
//                                 idempotency machinery).
//   [effects …]                 — the resolved effect set (v1:
//                                 resolved == declared, scopes as
//                                 declared — the honest note).
//   [preconditions [ok …]…]     — each predicate EVALUATED at propose;
//                                 a FALSE one refuses the proposal
//                                 (CXER4112 — nothing coherent to
//                                 approve); commit re-evaluates and
//                                 divergence refuses there.
//   [via …]                     — the authority basis, opts-supplied.
//   [idempotency-key …]         — explicit (opts) or derived; present
//                                 only for [idempotent] commands or an
//                                 explicit key.
//   [tenant …]                  — opts-supplied ('' default).
// The proposal is an ORDINARY CX value: its Tier-1 address (cx:hash)
// is what an approval binds — a re-lowering with different args is a
// DIFFERENT proposal (tamper = address movement).
fn cx_mod_propose(args []cx.Node, mut env MatchEnv) cx.Node {
	if args.len < 2 || args.len > 3 {
		return mk_err('cx-err:CXER4111', 'E_CX_PROPOSAL_INVALID: cx:propose requires (command-fn, args-map, opts-map?) (cx-err:CXER4111)')
	}
	fnv := args[0]
	if !is_fn_value(fnv) {
		return mk_err('cx-err:CXER4111', 'E_CX_PROPOSAL_INVALID: cx:propose argument 1 must be a command function value (cx-err:CXER4111)')
	}
	id := closure_id_of(fnv) or {
		return mk_err('cx-err:CXER4111', 'E_CX_PROPOSAL_INVALID: cx:propose could not resolve the function value (cx-err:CXER4111)')
	}
	cl := lookup_closure(id, env) or {
		return mk_err('cx-err:CXER4111', 'E_CX_PROPOSAL_INVALID: cx:propose could not resolve `${id}` to a definition (cx-err:CXER4111)')
	}
	if cl.cmd_meta == unsafe { nil } || !cl.has_effects {
		return mk_err('cx-err:CXER4111', 'E_CX_PROPOSAL_INVALID: `${id}` is not a command — a command def carries an [effects …] clause (code.md §12.2.7) (cx-err:CXER4111)')
	}
	meta := cl.cmd_meta
	// args-map → the §5 NAME-KEYED record: each key binds its param by NAME
	// (positional or named alike — the record is name-keyed over the whole
	// parameter list; defaults fill; unknown keys refuse loud). Stream 18 W2:
	// the general call surface binds positionals by position only, so the
	// propose/commit seam gets its own record builder.
	mut record := map[string]cx.Node{}
	if args[1] is cx.Element && (args[1] as cx.Element).name == '__cx_map__' {
		for e in (args[1] as cx.Element).items {
			if e is cx.Element && e.items.len > 0 {
				record[e.name] = e.items[0]
			}
		}
	} else {
		return mk_err('cx-err:CXER4111', 'E_CX_PROPOSAL_INVALID: cx:propose argument 2 must be an args MAP (param-name → value) (cx-err:CXER4111)')
	}
	mut call_env := build_param_call_env_record(cl, record, mut env) or {
		return mk_err('cx-err:CXER4111', 'E_CX_PROPOSAL_INVALID: args do not bind `${id}`: ${err.msg()} (cx-err:CXER4111)')
	}
	// opts
	mut explicit_key := ''
	mut tenant := ''
	mut via := ?cx.Node(none)
	if args.len > 2 && args[2] is cx.Element && (args[2] as cx.Element).name == '__cx_map__' {
		for e in (args[2] as cx.Element).items {
			if e is cx.Element && e.items.len > 0 {
				match e.name {
					'idempotency-key' {
						v := e.items[0]
						if v is cx.ScalarNode {
							explicit_key = cx.scalar_value_str_public(v.value)
						}
					}
					'tenant' {
						v := e.items[0]
						if v is cx.ScalarNode {
							tenant = cx.scalar_value_str_public(v.value)
						}
					}
					'via' {
						via = e.items[0]
					}
					else {}
				}
			}
		}
	}
	// preconditions — evaluated at propose over the bound frame; FALSE
	// refuses (R16: nothing coherent to approve). Recorded verbatim.
	mut pre_items := []cx.Node{}
	for src in meta.preconditions {
		prog := cx.parse_program(src) or {
			return mk_err('cx-err:CXER4111', 'E_CX_PROPOSAL_INVALID: precondition `${src}` does not parse: ${err.msg()} (cx-err:CXER4111)')
		}
		r := eval_node(prog.body, mut call_env) or {
			return mk_err('cx-err:CXER4112', 'E_CX_PRECONDITION_FAILED: precondition `${src}` faulted at propose: ${err.msg()} (cx-err:CXER4112)')
		}
		ok := node_ebv(r) or { false }
		if !ok {
			return mk_err('cx-err:CXER4112', 'E_CX_PRECONDITION_FAILED: precondition `${src}` is false at propose — the proposal is refused (cx-err:CXER4112)')
		}
		pre_items << cx.Node(cx.Element{
			name:  'ok'
			items: [cx.Node(codec_str_node(src))]
		})
	}
	// normalized args record — param order (the def's own, deterministic).
	mut arg_entries := []cx.Node{}
	for spec in cl.param_specs {
		if v := call_env.bindings[spec.name] {
			arg_entries << cx.Node(cx.Element{
				name:  spec.name
				items: [v]
			})
		}
	}
	args_map := cx.Node(cx.Element{
		name:  '__cx_map__'
		items: arg_entries
	})
	// resolved effect set (v1: resolved == declared, scopes as declared).
	mut eff_items := []cx.Node{}
	for item in meta.effects_items {
		mut sc := []cx.Node{}
		for sscope in item.scopes {
			sc << cx.Node(codec_str_node(sscope))
		}
		eff_items << cx.Node(cx.Element{
			name:  item.cap
			items: sc
		})
	}
	// idempotency key: explicit wins; derived only for [idempotent].
	mut key := ''
	if explicit_key != '' {
		key = 'x:' + explicit_key
	} else if cl.is_idempotent {
		key = idem_derive_key(cl, call_env)
	}
	mut items := [
		cx.Node(cx.Element{
			name:  'command'
			attrs: [
				cx.Attribute{
					name:  'tier1'
					value: cx.ScalarValue(meta.src_addr)
				},
				cx.Attribute{
					name:  'code'
					value: cx.ScalarValue(meta.code_addr)
				},
			]
		}),
		cx.Node(cx.Element{
			name:  'args'
			items: [args_map]
		}),
		cx.Node(cx.Element{
			name:  'effects'
			items: eff_items
		}),
		cx.Node(cx.Element{
			name:  'preconditions'
			items: pre_items
		}),
	]
	if v := via {
		items << cx.Node(cx.Element{
			name:  'via'
			items: [v]
		})
	}
	if key != '' {
		items << cx.Node(cx.Element{
			name:  'idempotency-key'
			items: [cx.Node(codec_str_node(key))]
		})
	}
	items << cx.Node(cx.Element{
		name:  'tenant'
		items: [cx.Node(codec_str_node(tenant))]
	})
	return cx.Element{
		name:  'proposal'
		items: items
	}
}

// cx_mod_computation_id returns the COMPUTATION IDENTITY of a `[?def …]`
// source — "same function?" — as the distinct claim element
// `[computation-id sha2-256:<hex>]`. F1/A1 (2026-08-08): computation identity
// is a derived equivalence relation (alpha/name/comment/format-invariant),
// used only as an index or a recompute-and-refuse verification claim — NEVER
// an object address. The claim rides as this distinct element so it can never
// be mistaken for, or parsed as, a document address (the confusability that
// let the pre-F1 `code:`-address wart form). Pure: the hash is a function of
// the normalized program text alone (code-identity.md §2), no store, no
// effects.
fn cx_mod_computation_id(args []cx.Node) cx.Node {
	if args.len != 1 {
		return mk_err('cx-err:CXER0100', 'cx:computation-id requires exactly one [?def …] source argument')
	}
	src := cx_mod_value_source(args[0]) or {
		return mk_err('cx-err:CXER4101', 'cx:computation-id: ${err.msg()}')
	}
	hash := cx_code_tier2_hash(src) or {
		return mk_err('cx-err:CXER0100', 'cx:computation-id: ${err.msg()}')
	}
	// A1 (2026-08-08): the claim is a DISTINCT scalar token, spelled
	// `computes-as:<algo>:<hex>` — never the bare `<algo>:<hex>` document-address
	// form (indistinguishable at a glance) and never the retired `code:` address.
	// A string scalar so value-equality ($eq / $cx:equal) compares the claim by
	// content, exactly as the pre-F1 bare-hash string did. `hash` already carries
	// the `<algo>:<hex>` tag from cx_code_tier2_hash.
	return cx.ScalarNode{
		value:     cx.ScalarValue('computes-as:${hash}')
		data_type: cx.ScalarType.string_type
	}
}

// cx_mod_plan_address returns the PLAN ADDRESS of a planar comprehension —
// the caching-identity tier ABOVE E1 text identity (code.md §7.9, stream-2
// ruling L93) — as the distinct token `plan:<algo>:<hex>` (never a document
// address: the tagged-address reader refuses `plan` as an algorithm; never
// a `computes-as:` claim). This function is the §7.8 membership test's
// canonical runtime consumer: a non-member returns the typed
// cx-err:CXER0120 E_NOT_PLANAR whose message names the violated point —
// never a silent fallback. Pure: the address is a function of the source
// text alone (parse → membership → canonical plan encoding → hash), no
// store, no effects.
fn cx_mod_plan_address(args []cx.Node) cx.Node {
	if args.len != 1 {
		return mk_err('cx-err:CXER0100', 'cx:plan-address requires exactly one comprehension source argument')
	}
	src := cx_mod_value_source(args[0]) or {
		return mk_err('cx-err:CXER4101', 'cx:plan-address: ${err.msg()}')
	}
	prog := cx.parse_program(src) or {
		return mk_err('cx-err:CXER4100', 'cx:plan-address: malformed CX source: ${err.msg()}')
	}
	if r := planar_membership(prog) {
		return planar_refusal_err(r)
	}
	addr := plan_address_of_node(prog) or {
		// unreachable after the membership gate above; loud if it ever is.
		return mk_err(planar_err_code, 'cx:plan-address: ${err.msg()}')
	}
	return cx.ScalarNode{
		value:     cx.ScalarValue(addr)
		data_type: cx.ScalarType.string_type
	}
}

// ── argument helpers ──────────────────────────────────────────────────────────

// cx_mod_source_text returns the text of a string-typed value (a string
// scalar or a text node) — the shapes the string-as-source pivot reads
// as CX source. Atoms and every other kind return none.
fn cx_mod_source_text(n cx.Node) ?string {
	if n is cx.TextNode {
		return n.value
	}
	if n is cx.ScalarNode {
		if n.data_type == cx.ScalarType.string_type {
			v := n.value
			if v is string {
				return v
			}
		}
	}
	return none
}

// cx_mod_value_source projects an argument to CX source text: a string
// value IS the source; any other value serializes through the cx codec.
fn cx_mod_value_source(n cx.Node) !string {
	if s := cx_mod_source_text(n) {
		return s
	}
	if cx_mod_contains_closure(n) {
		return error('a function value is not serialisable')
	}
	return cx.codec_emit_node('cx', cx_mod_lower_value(n), false)!
}

// cx_mod_lower_value rewrites evaluator-internal collection envelopes
// (`__cx_seq__` / `__cx_arr__` / `__cx_map__` marker elements, and lazy
// iterators) into the plain CXDM collection nodes before a value crosses
// into the data-codec layer (#564): the cx module has no knowledge of the
// evaluator's marker spellings, so an unlowered envelope emits as a
// literal `[__cx_seq__ …]` element — leaking an internal name into the
// serialized surface and breaking `serialize ∘ parse` identity for any
// value built from a sequence of elements (e.g. a `[?for]` body handed to
// `[?element]`). The renderer (render_element_to) unwraps the same
// markers for display; this is the codec-lane twin of that rule.
fn cx_mod_lower_value(n cx.Node) cx.Node {
	match n {
		cx.Element {
			// #566: the ANONYMOUS wrapper (name == '', the multi-value shape a
			// [?for] comprehension yields) is a sequence in body position —
			// program-conc-018 pins the paren form, render_body_item_to emits
			// it as `(…)`, and walk_binding_path_seq expands it as a node-set.
			// Unlowered, the codec emitted it as a NAMELESS element `[ … ]`,
			// so put-doc (render lane) and cx:serialize (codec lane) disagreed
			// on the text form and the collection kind flipped through the
			// store. Attr-less only: a named-but-empty spelling never carries
			// attrs when it is the evaluator's wrapper.
			if n.name == '' && n.attrs.len == 0 {
				return cx.Node(cx.SequenceNode{ items: n.items.map(cx_mod_lower_value(it)) })
			}
			// I1 row 7 (#708, L85): Lane 1 is an INERT side-band EXCLUDED
			// from identity — the `[?meta]` wrapper must never reach the
			// codec surface. Unlowered it emitted as a literal
			// `[__cx_meta__ …]` element, so cx:hash / cx:equal /
			// cx:serialize of a meta-annotated value diverged from the
			// bare value — on the exact bytes that feed address-bound
			// approvals. The display renderer (render_element_to) already
			// unwraps; this is the codec-lane twin, at the ONE lowering
			// chokepoint (code.md §4.2).
			if n.name == meta_marker_name {
				if n.items.len >= 1 {
					return cx_mod_lower_value(n.items[0])
				}
				return cx.Node(cx.TextNode{})
			}
			if n.name == seq_marker_name {
				return cx.Node(cx.SequenceNode{ items: n.items.map(cx_mod_lower_value(it)) })
			}
			if n.name == arr_marker_name {
				return cx.Node(cx.ArrayNode{ items: n.items.map(cx_mod_lower_value(it)) })
			}
			if n.name == map_marker_name {
				// entry elements carry name=key-image, items=[value], and the
				// key's CXDM kind on meta (see render_element_to's
				// `__cx_map__` lane and eval_map's stamping). #927: the kind
				// must survive this funnel — key identity is (kind, image)
				// (cxdm §2.6/§5.1), and every cx: consumer (serialize,
				// canonical, hash, equal, diff, patch, to-format) inherits
				// what is lowered here. Hard-coding .string_type folded
				// {1: 'x'} and {'1': 'x'} to one identity and made
				// cx:canonical emit text it then refuses as a duplicate key.
				mut entries := []cx.MapEntry{cap: n.items.len}
				for it in n.items {
					if it is cx.Element {
						value := if it.items.len > 0 {
							cx_mod_lower_value(it.items[0])
						} else {
							cx.Node(cx.ScalarNode{ value: cx.ScalarValue(cx.NullValue{}), data_type: .null_type })
						}
						kind := map_entry_effective_key_kind(it)
						mut kt := cx.ScalarType.string_type
						mut kv := cx.ScalarValue(it.name)
						if kind != 'string' {
							sn := cx.coerce_scalar_strict(kind, it.name) or {
								cx.ScalarNode{ data_type: .string_type, value: cx.ScalarValue(it.name) }
							}
							kt = sn.data_type
							kv = sn.value
						}
						// The declaration kind (MSS-4) rides the same entry
						// meta; carry it so a declared entry stays declared
						// through the codec lane.
						entries << cx.MapEntry{
							key_type:  kt
							key_value: kv
							value:     value
							decl_kind: map_entry_decl_kind(it) or { '' }
						}
					}
				}
				return cx.Node(cx.MapNode{ entries: entries })
			}
			mut e := n
			e.items = n.items.map(cx_mod_lower_value(it))
			return cx.Node(e)
		}
		cx.SequenceNode {
			return cx.Node(cx.SequenceNode{ items: n.items.map(cx_mod_lower_value(it)) })
		}
		cx.ArrayNode {
			return cx.Node(cx.ArrayNode{ items: n.items.map(cx_mod_lower_value(it)) })
		}
		cx.MapNode {
			mut entries := []cx.MapEntry{cap: n.entries.len}
			for en in n.entries {
				entries << cx.MapEntry{ key_type: en.key_type, key_value: en.key_value, value: cx_mod_lower_value(en.value), decl_kind: en.decl_kind }
			}
			return cx.Node(cx.MapNode{ entries: entries })
		}
		cx.IteratorNode {
			// materialize at the codec boundary — the memo is force-pulled
			// so the emitted sequence is the iterator's full item list.
			return cx.Node(cx.SequenceNode{ items: iterate(n).map(cx_mod_lower_value(it)) })
		}
		else {
			return n
		}
	}
}

// cx_mod_contains_closure deep-checks for a function value (closure
// sentinel) — no faithful data round-trip exists for it (CXER4101).
fn cx_mod_contains_closure(n cx.Node) bool {
	if n is cx.Element {
		if n.name == closure_sentinel_name {
			return true
		}
		for it in n.items {
			if cx_mod_contains_closure(it) {
				return true
			}
		}
	}
	return false
}

// cx_mod_contains_iterator / cx_mod_contains_secret — the other two E1
// totality classes (I1 row 14, semantic_value_model §2, audit C4):
// identity acquisition REFUSES, never falls back. An iterator's identity
// would depend on consumption state (and an infinite source would hang
// the hash path); a secret-bearing value has NO Tier-1 address — hashing
// the plaintext would make every address a secret-confirmation oracle,
// hashing the redacted form would give two different secrets one address.
fn cx_mod_contains_iterator(n cx.Node) bool {
	if n is cx.IteratorNode {
		return true
	}
	if n is cx.Element {
		for it in n.items {
			if cx_mod_contains_iterator(it) {
				return true
			}
		}
	}
	if n is cx.SequenceNode {
		for it in n.items {
			if cx_mod_contains_iterator(it) {
				return true
			}
		}
	}
	return false
}

fn cx_mod_contains_secret(n cx.Node) bool {
	if n is cx.Element {
		if n.name == secret_marker_name {
			return true
		}
		for it in n.items {
			if cx_mod_contains_secret(it) {
				return true
			}
		}
	}
	if n is cx.SequenceNode {
		for it in n.items {
			if cx_mod_contains_secret(it) {
				return true
			}
		}
	}
	return false
}

fn cx_mod_bool_node(b bool) cx.Node {
	return cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue(b)
		data_type: cx.ScalarType.bool_type
	})
}

// ── serialize / canonical / hash / equal ──────────────────────────────────────

fn cx_mod_serialize(args []cx.Node) cx.Node {
	if args.len != 1 {
		return mk_err('cx-err:CXER0100', 'cx:serialize requires exactly one VALUE argument')
	}
	if cx_mod_contains_closure(args[0]) {
		return mk_err('cx-err:CXER4101', 'cx:serialize: a function value is not serialisable')
	}
	out := cx.codec_emit_node('cx', cx_mod_lower_value(args[0]), false) or {
		return mk_err('cx-err:CXER4101', 'cx:serialize: ${err.msg()}')
	}
	// #807(f): the §4 normative identity serialize∘parse ≡ canonical
	// holds at the BYTE level — canonical text carries the trailing LF
	// (the stream-12 ruling), so serialize emits it too.
	if !out.ends_with('\n') {
		return codec_str_node(out + '\n')
	}
	return codec_str_node(out)
}

// ── cx:ast — the declaration-AST projection (stream 18, L146) ────────────────
//
// `[$cx:ast SOURCE]` parses SOURCE's module-declaration header — the
// same `[?lib]` / `[?def]` / `[?const]` scan the module loader runs at
// Pass 1 — and returns the ast.md program-AST JSON projection:
//
//   {"type":"Program","libs":[LibNode…],"consts":[ConstNode…],"defs":[DefNode…]}
//
// Arrays are omitted when empty (the ast.md omit-when-absent
// convention); a source with no declarations projects as
// {"type":"Program"}. Each DefNode carries the full [152] surface
// including the [152d–h] command clauses (effects / requires /
// preconditions / idempotent / compensates / requires-at) — the
// structured view the agent-tool projection (x/tools.cx) consumes;
// the CX-callable twin of what the loader / identity / LSP lanes
// read via cx.parse_def. Module BODY expressions are not part of
// this projection — the contract is the declaration header, exactly
// the set the module system itself extracts.
//
// Argument: a SOURCE STRING only (`[$cx:ast [$io:read-file "mod.cx"]]`).
// A directive-as-data value (a `//effects/..`-recovered def focus) is
// NOT accepted: its canonical serialization quotes the def-head text
// run, which is not program-parseable — the module-source lane is the
// projection lane; the data lane pairs by def name.
fn cx_mod_ast(args []cx.Node) cx.Node {
	if args.len != 1 {
		return mk_err('cx-err:CXER0100', 'cx:ast requires exactly one SOURCE argument')
	}
	src := cx_mod_source_text(args[0]) or {
		return mk_err('cx-err:CXER0100', 'cx:ast: SOURCE must be a string of CX source text (a value focus does not carry program-parseable def source — project from the module source)')
	}
	spans := module_loader_scan_spans(src) or {
		return mk_err('cx-err:CXER4100', 'cx:ast: malformed CX source: ${err.msg()}')
	}
	mut libs := []string{}
	mut consts := []string{}
	mut defs := []string{}
	mut docs := []string{}
	for sp in spans {
		match sp.kind {
			.lib {
				n := cx.parse_lib(sp.text) or {
					return mk_err('cx-err:CXER4100', 'cx:ast: [?lib] parse failed: ${err.msg()}')
				}
				libs << cx.lib_node_to_json(n)
			}
			.def {
				n := cx.parse_def(sp.text) or {
					return mk_err('cx-err:CXER4100', 'cx:ast: [?def] parse failed: ${err.msg()}')
				}
				defs << cx.def_node_to_json(n)
			}
			.const_ {
				n := cx.parse_const(sp.text) or {
					return mk_err('cx-err:CXER4100', 'cx:ast: [?const] parse failed: ${err.msg()}')
				}
				consts << cx.const_node_to_json(n)
			}
			.plain {
				// The module's top-level plain elements (co-located doc
				// blocks among them), as VERBATIM SOURCE SPANS — each span
				// parses cleanly as DATA on its own, where a whole-module
				// data parse chokes on program-bearing def bodies (the
				// stream-18 W5 finding). Consumers ([$cx:parse] per span)
				// pair fn-docs by name.
				docs << cx.json_str_public(sp.text)
			}
			.other_directive {}
		}
	}
	mut pairs := []string{}
	pairs << '"type":"Program"'
	if libs.len > 0 {
		pairs << '"libs":[${libs.join(',')}]'
	}
	if consts.len > 0 {
		pairs << '"consts":[${consts.join(',')}]'
	}
	if defs.len > 0 {
		pairs << '"defs":[${defs.join(',')}]'
	}
	if docs.len > 0 {
		pairs << '"docs":[${docs.join(',')}]'
	}
	return codec_str_node('{${pairs.join(',')}}')
}

// ── cx:schema-of — corpus shape inference as a pure function ────────────────
//
// The modules/cx.md §2.2 row (spec'd since the table's authoring; wired at
// stream 14 with the §11 infer→validate corpus family as its live
// consumer): `[$cx:schema-of $value]` synthesizes the deterministic
// open-mode .cxs (shape_inference.md §8 — the SAME engine as `cx schema
// infer`) and returns its TEXT (the schema's identity form).
// A SEQUENCE argument reads as a corpus (one inference over all items —
// the join lattice engages); any other value infers over itself alone.
// Element-rooted items only (inference synthesizes element schemas).
fn cx_mod_schema_of(args []cx.Node) cx.Node {
	if args.len != 1 {
		return mk_err('cx-err:CXER0100', 'cx:schema-of requires exactly one VALUE argument')
	}
	mut items := []cx.Node{}
	arg := args[0]
	if arg is cx.Element && arg.name == seq_marker_name {
		items = arg.items.clone()
	} else if arg is cx.SequenceNode {
		items = arg.items.clone()
	} else {
		items << arg
	}
	mut docs := []cx.Document{}
	for it in items {
		lowered := cx_mod_lower_value(it)
		if lowered is cx.Element {
			docs << cx.Document{
				elements: [cx.Node(lowered)]
			}
		} else {
			return mk_err('cx-err:CXER4101', 'cx:schema-of: every corpus item must be element-rooted (inference synthesizes element schemas)')
		}
	}
	text := cx.schema_infer(docs, cx.SchemaInferOpts{}) or {
		return mk_err('cx-err:CXER4101', 'cx:schema-of: ${err.msg()}')
	}
	// Return the synthesized .cxs TEXT (a string): byte-exact (determinism
	// is string equality), engine-faithful (schema_infer emits text), and
	// it composes directly with register-schema / validate-against's .cxs
	// lane. (Returning a PARSED carrier was tried and refused: canonical
	// re-serialization quotes the .cxs barewords with their trailing
	// spaces — 'email ' — which the validator then cannot match; the text
	// is the schema's identity form.) Navigate via [$cx:parse] when needed.
	return codec_str_node(text)
}

fn cx_mod_canonical(args []cx.Node) cx.Node {
	if args.len != 1 {
		return mk_err('cx-err:CXER0100', 'cx:canonical requires exactly one VALUE argument')
	}
	src := cx_mod_value_source(args[0]) or {
		return mk_err('cx-err:CXER4101', 'cx:canonical: ${err.msg()}')
	}
	out := cx.cx_text_canonical(src) or {
		return mk_err('cx-err:CXER4100', 'cx:canonical: malformed CX source: ${err.msg()}')
	}
	return codec_str_node(out)
}

fn cx_mod_hash(args []cx.Node) cx.Node {
	if args.len != 1 {
		return mk_err('cx-err:CXER0100', 'cx:hash requires exactly one VALUE argument')
	}
	// I1 row 14 (E1 totality, audit C4): identity acquisition refuses the
	// three value classes with typed errors — closures (CXER4101, below
	// via value_source), iterators (CXER4117 — identity would depend on
	// consumption state), and secret-bearing values (CXER4118 — no Tier-1
	// address, by construction: neither plaintext-oracle nor
	// redacted-collision addresses exist).
	if cx_mod_contains_iterator(args[0]) {
		return mk_err('cx-err:CXER4117', 'cx:hash: an iterator has no Tier-1 address — its identity would depend on consumption state; materialize deliberately ([?to-sequence]) and hash the value (cx-err:CXER4117)')
	}
	if cx_mod_contains_secret(args[0]) {
		return mk_err('cx-err:CXER4118', 'cx:hash: a secret-bearing value has no Tier-1 address (plaintext would be a confirmation oracle; the redacted form would alias distinct secrets) (cx-err:CXER4118)')
	}
	src := cx_mod_value_source(args[0]) or {
		return mk_err('cx-err:CXER4101', 'cx:hash: ${err.msg()}')
	}
	out := cx.cx_text_hash(src) or {
		return mk_err('cx-err:CXER4100', 'cx:hash: malformed CX source: ${err.msg()}')
	}
	return codec_str_node(out)
}

// ── type identity (E2/L82–L83, semantic_value_model §3, I5 stream 1) ─────────

// cx_mod_type_anchor_check enforces the L83 anchoring preconditions
// (fail-closed, the #702 posture): the schema loads clean, declares
// EXACTLY ONE type, and both that type and the header's `of` root name
// the subject's root element. One-type-per-schema-document is
// NORMATIVE for identity-anchoring schemas — multi-type documents stay
// legal for validation but CANNOT anchor (editing one type's schema
// must never move another type's identity).
fn cx_mod_type_anchor_check(subject_root string, schema_text string) ! {
	sm := cx.parse_schema(schema_text) or {
		return error('the schema fails to load: ${err.msg()}')
	}
	if sm.types.len != 1 {
		return error('the schema declares ${sm.types.len} types — an identity-anchoring schema document MUST declare exactly one (L83; multi-type schemas validate, they cannot anchor)')
	}
	mut only := ''
	for k, _ in sm.types {
		only = k
	}
	if only != subject_root {
		return error('the schema\'s one declared type is \'${only}\' but the subject\'s root element is \'${subject_root}\'')
	}
	if sm.root != '' && sm.root != subject_root {
		return error('the schema header\'s of=\'${sm.root}\' does not name the subject\'s root element \'${subject_root}\'')
	}
}

// cx_mod_elem_body_text reads an element's body as text (bareword or
// quoted scalar) — claim children like `[name order]` / `[schema
// 'sha2-256:…']` carry their payload this way.
fn cx_mod_elem_body_text(e cx.Element) ?string {
	for it in e.items {
		if s := cx_mod_source_text(it) {
			return s
		}
	}
	return none
}

struct TypeBindingFields {
	subject string // Tier-1 address of the subject value
	tname   string // the element/type name (the pair's name half)
	saddr   string // Tier-1 address of the schema document
}

// cx_mod_type_binding_fields extracts the three fields of a
// `[type-binding [subject hash=…] [name …] [schema …]]` claim.
fn cx_mod_type_binding_fields(n cx.Node) !TypeBindingFields {
	v := cx_mod_lower_value(n)
	if v is cx.Element {
		if v.name != 'type-binding' {
			return error('claim root must be [type-binding], got [${v.name}]')
		}
		mut subject := ''
		mut tname := ''
		mut saddr := ''
		for it in v.items {
			if it is cx.Element {
				match it.name {
					'subject' {
						for a in it.attrs {
							if a.name == 'hash' {
								subject = cx.scalar_value_str_public(a.value)
							}
						}
					}
					'name' {
						tname = cx_mod_elem_body_text(it) or { '' }
					}
					'schema' {
						saddr = cx_mod_elem_body_text(it) or { '' }
					}
					else {}
				}
			}
		}
		if subject == '' || tname == '' || saddr == '' {
			return error('claim must carry [subject hash=…], [name …], and [schema …]')
		}
		return TypeBindingFields{ subject: subject, tname: tname, saddr: saddr }
	}
	return error('claim must be a [type-binding] element')
}

// cx:type-binding(value, schema-text) — constructs the Lane-2 type
// identity claim `[type-binding [subject hash=…] [name …] [schema …]]`
// (semantic_value_model §3). The pair is recoverable-by-computation:
// the NAME comes from the subject's root element, the schema address
// from the schema text in force. Anchoring preconditions are enforced
// fail-closed (CXER4116); the E1 totality refusals propagate through
// the cx:hash acquisition path — a value with no Tier-1 address cannot
// anchor a type identity.
fn cx_mod_type_binding(args []cx.Node) cx.Node {
	if args.len != 2 {
		return mk_err('cx-err:CXER0100', 'cx:type-binding requires VALUE and SCHEMA-TEXT arguments')
	}
	schema_text := cx_mod_source_text(args[1]) or {
		return mk_err('cx-err:CXER0100', 'cx:type-binding: SCHEMA-TEXT must be a string')
	}
	// Tier-1 subject address — the SAME acquisition path as cx:hash, so
	// closure/iterator/secret refusals (CXER4101/4117/4118) propagate.
	hashed := cx_mod_hash([args[0]])
	if is_err_value(hashed) {
		return hashed
	}
	subject_hash := cx_mod_source_text(hashed) or {
		return mk_err('cx-err:CXER4116', 'cx:type-binding: subject address unreadable (internal)')
	}
	// The pair's NAME half: the subject's root element name.
	src := cx_mod_value_source(args[0]) or {
		return mk_err('cx-err:CXER4101', 'cx:type-binding: ${err.msg()}')
	}
	parsed := cx.codec_parse_node('cx', src) or {
		return mk_err('cx-err:CXER4100', 'cx:type-binding: malformed CX source: ${err.msg()}')
	}
	if parsed !is cx.Element {
		return mk_err('cx-err:CXER4116', 'cx:type-binding: only an element value can anchor a type identity (the pair\'s name half is the root element name)')
	}
	root_name := (parsed as cx.Element).name
	cx_mod_type_anchor_check(root_name, schema_text) or {
		return mk_err('cx-err:CXER4116', 'cx:type-binding: schema cannot anchor: ${err.msg()}')
	}
	sh := cx.schema_content_hash(schema_text) or {
		return mk_err('cx-err:CXER4116', 'cx:type-binding: schema cannot anchor: ${err.msg()}')
	}
	schema_addr := 'sha2-256:' + sh.hex()
	subj := cx.Node(cx.Element{
		name:  'subject'
		attrs: [cx.Attribute{ name: 'hash', value: cx.ScalarValue(subject_hash) }]
	})
	nm := cx.Node(cx.Element{ name: 'name', items: [cx.Node(cx.TextNode{ value: root_name })] })
	sc := cx.Node(cx.Element{ name: 'schema', items: [cx.Node(cx.TextNode{ value: schema_addr })] })
	return cx.Node(cx.Element{ name: 'type-binding', items: [subj, nm, sc] })
}

// cx:type-binding-verify(claim, value, schema-text) — fail-closed
// verification of a presented claim at a trust boundary: the claim is
// recomputed from the value + schema in force and compared field by
// field. Any malformation or mismatch is CXER4119; anchoring-precondition
// failures surface as the CXER4116 they are.
fn cx_mod_type_binding_verify(args []cx.Node) cx.Node {
	if args.len != 3 {
		return mk_err('cx-err:CXER0100', 'cx:type-binding-verify requires CLAIM, VALUE, and SCHEMA-TEXT arguments')
	}
	got := cx_mod_type_binding_fields(args[0]) or {
		return mk_err('cx-err:CXER4119', 'cx:type-binding-verify: malformed claim: ${err.msg()}')
	}
	expected_node := cx_mod_type_binding([args[1], args[2]])
	if is_err_value(expected_node) {
		return expected_node
	}
	want := cx_mod_type_binding_fields(expected_node) or {
		return mk_err('cx-err:CXER4119', 'cx:type-binding-verify: internal recomputation malformed: ${err.msg()}')
	}
	if got.subject != want.subject {
		return mk_err('cx-err:CXER4119', 'cx:type-binding-verify: subject address mismatch — claim ${got.subject}, value ${want.subject}')
	}
	if got.tname != want.tname {
		return mk_err('cx-err:CXER4119', 'cx:type-binding-verify: type name mismatch — claim \'${got.tname}\', value root \'${want.tname}\'')
	}
	if got.saddr != want.saddr {
		return mk_err('cx-err:CXER4119', 'cx:type-binding-verify: schema address mismatch — claim ${got.saddr}, schema in force ${want.saddr}')
	}
	return cx_mod_bool_node(true)
}

fn cx_mod_equal(args []cx.Node) cx.Node {
	if args.len != 2 {
		return mk_err('cx-err:CXER0100', 'cx:equal requires exactly two arguments')
	}
	sa := cx_mod_value_source(args[0]) or {
		return mk_err('cx-err:CXER4101', 'cx:equal: ${err.msg()}')
	}
	sb := cx_mod_value_source(args[1]) or {
		return mk_err('cx-err:CXER4101', 'cx:equal: ${err.msg()}')
	}
	eq := cx.cx_text_eq(sa, sb) or {
		return mk_err('cx-err:CXER4100', 'cx:equal: malformed CX source: ${err.msg()}')
	}
	return cx_mod_bool_node(eq)
}

// ── to-format / from-format (conversions.md registry) ────────────────────────

fn cx_mod_to_format(args []cx.Node) cx.Node {
	if args.len != 2 {
		return mk_err('cx-err:CXER0100', 'cx:to-format requires VALUE and FORMAT arguments')
	}
	fmt := codec_name_of(args[1]) or {
		return mk_err('cx-err:CXER4103', 'cx:to-format: FORMAT must be a string or atom')
	}
	if _ := cx.codec_lookup(fmt) {
	} else {
		return mk_err('cx-err:CXER4103', 'cx:to-format: unknown format "${fmt}" (registry: ${cx.codec_names().join(', ')})')
	}
	mut value := args[0]
	if s := cx_mod_source_text(args[0]) {
		value = cx.codec_parse_node('cx', s) or {
			return mk_err('cx-err:CXER4100', 'cx:to-format: malformed CX source: ${err.msg()}')
		}
	}
	out := cx.codec_emit_node(fmt, value, false) or {
		return mk_err('cx-err:CXER4104', 'cx:to-format: value not representable in "${fmt}": ${err.msg()}')
	}
	return codec_str_node(out)
}

fn cx_mod_from_format(args []cx.Node) cx.Node {
	if args.len != 2 {
		return mk_err('cx-err:CXER0100', 'cx:from-format requires TEXT and FORMAT arguments')
	}
	fmt := codec_name_of(args[1]) or {
		return mk_err('cx-err:CXER4103', 'cx:from-format: FORMAT must be a string or atom')
	}
	if _ := cx.codec_lookup(fmt) {
	} else {
		return mk_err('cx-err:CXER4103', 'cx:from-format: unknown format "${fmt}" (registry: ${cx.codec_names().join(', ')})')
	}
	text := cx_mod_source_text(args[0]) or {
		return mk_err('cx-err:CXER0100', 'cx:from-format: TEXT must be a string')
	}
	return cx.codec_parse_node(fmt, text) or {
		return mk_err('cx-err:CXER4105', 'cx:from-format: ${fmt} parse failure: ${err.msg()}')
	}
}

// ── select — runtime CXPath (code.md §5.5) ────────────────────────────────────

// cx_mod_select evaluates a runtime CXPath string against a value by
// splicing the path onto a fresh binding and running the INLINE
// binding-path engine — so a select result is identical to the
// equivalent compile-time `$v//x` path by construction (predicates,
// attribute axes, descendant semantics included). The result is always
// a sequence per the §2.1 signature `[sequence any]`.
pub fn cx_mod_select(args []cx.Node, mut env MatchEnv) cx.Node {
	if args.len != 2 {
		return mk_err('cx-err:CXER0100', 'cx:select requires VALUE and PATH arguments')
	}
	path_s := cx_mod_source_text(args[1]) or {
		return mk_err('cx-err:CXER4106', 'cx:select: PATH must be a string')
	}
	mut value := args[0]
	if s := cx_mod_source_text(args[0]) {
		value = cx.codec_parse_node('cx', s) or {
			return mk_err('cx-err:CXER4100', 'cx:select: malformed CX source: ${err.msg()}')
		}
	}
	p := path_s.trim_space()
	if p == '' {
		return mk_err('cx-err:CXER4106', 'cx:select: empty CXPath expression')
	}
	joiner := if p.starts_with('/') || p.starts_with('@') || p.starts_with('.') { '' } else { '/' }
	src := '\$__cxsel__${joiner}${p}'
	prog := cx.parse_program(src) or {
		return mk_err('cx-err:CXER4106', 'cx:select: malformed CXPath "${path_s}": ${err.msg()}')
	}
	body := prog.body
	if body !is cx.ProgramBinding {
		return mk_err('cx-err:CXER4106', 'cx:select: "${path_s}" is not a CXPath expression')
	}
	b := body as cx.ProgramBinding
	if b.name != '__cxsel__' || b.path.len == 0 {
		return mk_err('cx-err:CXER4106', 'cx:select: "${path_s}" is not a CXPath expression')
	}
	res := walk_binding_path_seq(value, b.path, mut env, false) or {
		return mk_err('cx-err:CXER4106', 'cx:select: ${err.msg()}')
	}
	if is_err_value(res) {
		return res
	}
	// Normalize to a sequence: node-set wrappers re-tag as a sequence;
	// a single node wraps as a one-item sequence; absence is empty.
	if res is cx.Element {
		e := res as cx.Element
		if e.name == '' || e.name == seq_marker_name {
			return cx.Node(cx.Element{ name: seq_marker_name, items: e.items })
		}
	}
	mut items := []cx.Node{}
	items << res
	return cx.Node(cx.Element{ name: seq_marker_name, items: items })
}

// ── diff — structural diff as a navigable CX value ────────────────────────────

// cx_mod_diff computes the strict-canonical structural diff (vcx/cx/diff.v,
// the same engine as `cx diff`) and lifts the change records into a
// navigable CX value:
//
//   [diff
//     [change kind='attribute-changed' path='/a/@x' before='1' after='2'
//       payload='attr' [before [v x=1]] [after [v x=2]]]
//     …]
//
// `kind`/`path`/`before`/`after` mirror the CLI JSON record shape;
// the `before`/`after` CHILDREN carry the apply-grade payloads (parsed,
// navigable) when the record has them. An empty diff is `[diff]`.
pub fn cx_mod_diff(args []cx.Node) cx.Node {
	if args.len != 2 {
		return mk_err('cx-err:CXER0100', 'cx:diff requires exactly two arguments')
	}
	sa := cx_mod_value_source(args[0]) or {
		return mk_err('cx-err:CXER4101', 'cx:diff: ${err.msg()}')
	}
	sb := cx_mod_value_source(args[1]) or {
		return mk_err('cx-err:CXER4101', 'cx:diff: ${err.msg()}')
	}
	changes := cx.cx_text_diff(sa, sb) or {
		return mk_err('cx-err:CXER4100', 'cx:diff: malformed CX source: ${err.msg()}')
	}
	mut items := []cx.Node{}
	for ch in changes {
		mut attrs := []cx.Attribute{}
		attrs << cx.Attribute{ name: 'kind', value: cx.ScalarValue(cx.change_kind_str(ch.kind)) }
		attrs << cx.Attribute{ name: 'path', value: cx.ScalarValue(ch.path) }
		if ch.before != '' {
			attrs << cx.Attribute{ name: 'before', value: cx.ScalarValue(ch.before) }
		}
		if ch.after != '' {
			attrs << cx.Attribute{ name: 'after', value: cx.ScalarValue(ch.after) }
		}
		mut kids := []cx.Node{}
		if ch.payload_kind != '' {
			attrs << cx.Attribute{ name: 'payload', value: cx.ScalarValue(ch.payload_kind) }
			if ch.before_payload != '' {
				if n := cx_mod_parse_single(ch.before_payload) {
					kids << wrap_cx('before', n)
				}
			}
			if ch.after_payload != '' {
				if n := cx_mod_parse_single(ch.after_payload) {
					kids << wrap_cx('after', n)
				}
			}
		}
		items << cx.Node(cx.Element{ name: 'change', attrs: attrs, items: kids })
	}
	return cx.Node(cx.Element{ name: 'diff', items: items })
}

// cx_mod_parse_single parses a compact canonical payload back to its
// single element (payloads are the diff engine's own emission — a parse
// failure here is structurally unreachable for engine-built diffs).
fn cx_mod_parse_single(src string) ?cx.Node {
	doc := cx.parse(src) or { return none }
	for el in doc.elements {
		if el is cx.Element {
			return cx.Node(el)
		}
	}
	return none
}

// ── patch — apply a diff value (the inverse of cx:diff) ──────────────────────

// CxPatchChange is one lowered change record from a diff value.
struct CxPatchChange {
	kind        string
	path        string
	payload     string
	before_node ?cx.Node
	after_node  ?cx.Node
}

// cx_mod_patch applies a cx:diff value to a value. The target is reduced
// to strict canonical first (diff paths are canonical positions), each
// record is verified against the current state and applied — a record
// whose target already carries the AFTER state is skipped as
// already-applied (idempotent re-patch); a record that matches neither
// side raises CXER4102 naming the path. The §5 identity is
// `cx:equal(cx:patch($a [$cx:diff $a $b]) $b)` for canonical inputs.
fn cx_mod_patch(args []cx.Node) cx.Node {
	if args.len != 2 {
		return mk_err('cx-err:CXER0100', 'cx:patch requires VALUE and DIFF arguments')
	}
	src := cx_mod_value_source(args[0]) or {
		return mk_err('cx-err:CXER4101', 'cx:patch: ${err.msg()}')
	}
	can := cx.cx_text_canonical(src) or {
		return mk_err('cx-err:CXER4100', 'cx:patch: malformed CX source: ${err.msg()}')
	}
	doc := cx.parse(can) or {
		return mk_err('cx-err:CXER4100', 'cx:patch: malformed CX source: ${err.msg()}')
	}
	changes := cx_mod_diff_value_changes(args[1]) or {
		return mk_err('cx-err:CXER4102', 'cx:patch: DIFF is not a cx:diff value (expected [diff [change …]…])')
	}
	// Virtual root: apply against a wrapper so document-level paths
	// (`/name`) resolve like any other parent.
	mut vroot := cx.Element{ name: '__cx_patch_root__', items: doc.elements }
	// Same-parent removals are emitted in ascending tail order; apply
	// each consecutive removal run in REVERSE so earlier removals don't
	// shift the later records' 1-based positions.
	ordered := cx_mod_patch_order(changes)
	mut done_table_paths := map[string]bool{}
	for ch in ordered {
		if ch.payload == 'table' && done_table_paths[ch.path] {
			// Whole-element replacement already applied for this path —
			// the remaining per-row records are satisfied by it.
			continue
		}
		vroot = cx_mod_apply_change(vroot, ch) or {
			return mk_err('cx-err:CXER4102', 'cx:patch: ${err.msg()}')
		}
		if ch.payload == 'table' {
			done_table_paths[ch.path] = true
		}
	}
	if vroot.items.len == 1 {
		return vroot.items[0]
	}
	return cx.doc_to_node(cx.Document{ elements: vroot.items })
}

// ── cx:merge — the value-level deep merge, conflicts as VALUES ──────────────
//
// (Stream 9, #719 item 3 — the ruled edit map: cx:merge's conflict posture
// ALIGNED to conflicts-as-values.) Policies per modules/cx.md §2.3:
// 'last-wins' (b shadows a — the default), 'first-wins' (a shadows b), and
// 'error-on-conflict' — which raises CXER4110 CARRYING every collision as a
// typed [conflict subject=<path> kind=:merge-value [ours <a-side>] [theirs
// <b-side>]] child (ours = $a's value, theirs = $b's; base absent — a
// two-input merge has no recorded ancestor), never a bare message.
// Semantics: elements of the SAME name merge — attrs union (a value
// collision is one policy point at `<path>/@name`), element children pair
// BY NAME (first unpaired match) and merge recursively, unpaired children
// keep source order (a's, then b's), and differing non-element bodies are
// ONE policy point at the element's path; elements of different names,
// differing scalars, arrays, and mixed kinds are one policy point each;
// maps union per-key, colliding keys recurse.

struct CxMergeCtx {
	policy string
mut:
	conflicts []cx.Node
}

fn cx_merge_conflict(mut ctx CxMergeCtx, path string, ours cx.Node, theirs cx.Node) {
	ctx.conflicts << cx.Node(cx.Element{
		name:  'conflict'
		attrs: [
			cx.Attribute{
				name:  'subject'
				value: cx.ScalarValue(path)
			},
			cx.new_attribute('kind', cx.ScalarValue('merge-value'), cx.AttributeMeta{
				data_type: 'atom'
			}),
		]
		items: [
			cx.Node(cx.Element{
				name:  'ours'
				items: [ours]
			}),
			cx.Node(cx.Element{
				name:  'theirs'
				items: [theirs]
			}),
		]
	})
}

fn cx_merge_pick(mut ctx CxMergeCtx, path string, a cx.Node, b cx.Node) cx.Node {
	if ctx.policy == 'error-on-conflict' {
		cx_merge_conflict(mut ctx, path, a, b)
	}
	if ctx.policy == 'first-wins' {
		return a
	}
	return b
}

fn cx_merge_eq(a cx.Node, b cx.Node) bool {
	return render_canonical(a) == render_canonical(b)
}

fn cx_merge_values(mut ctx CxMergeCtx, path string, a cx.Node, b cx.Node) cx.Node {
	if cx_merge_eq(a, b) {
		return a
	}
	if a is cx.Element && b is cx.Element {
		if a.name != b.name {
			return cx_merge_pick(mut ctx, path, cx.Node(a), cx.Node(b))
		}
		p := path + '/' + a.name
		// attrs: a's order, b's values per policy on collision, b's new
		// attrs appended in b's order.
		mut attrs := []cx.Attribute{}
		for aa in a.attrs {
			mut out := aa
			for ba in b.attrs {
				if ba.name == aa.name {
					if cx.scalar_value_str_public(ba.value) != cx.scalar_value_str_public(aa.value) {
						picked := cx_merge_pick(mut ctx, '${p}/@${aa.name}', cx.Node(cx.ScalarNode{
							value: aa.value
						}), cx.Node(cx.ScalarNode{
							value: ba.value
						}))
						if picked is cx.ScalarNode {
							out = cx.Attribute{
								...aa
								value: picked.value
							}
						}
					}
					break
				}
			}
			attrs << out
		}
		for ba in b.attrs {
			mut seen := false
			for aa in a.attrs {
				if aa.name == ba.name {
					seen = true
					break
				}
			}
			if !seen {
				attrs << ba
			}
		}
		// children: element children pair by name; non-element bodies are
		// one policy point when both sides carry one and they differ.
		mut a_elems := []cx.Element{}
		mut a_others := []cx.Node{}
		for it in a.items {
			if it is cx.Element {
				a_elems << it
			} else {
				a_others << it
			}
		}
		mut b_elems := []cx.Element{}
		mut b_others := []cx.Node{}
		for it in b.items {
			if it is cx.Element {
				b_elems << it
			} else {
				b_others << it
			}
		}
		mut paired := []int{len: b_elems.len, init: -1}
		mut used := []bool{len: a_elems.len}
		for bi, be in b_elems {
			for ai, ae in a_elems {
				if !used[ai] && ae.name == be.name {
					paired[bi] = ai
					used[ai] = true
					break
				}
			}
		}
		mut items := []cx.Node{}
		// body scalars/text first (positional content leads).
		if a_others.len > 0 && b_others.len > 0 {
			mut same := a_others.len == b_others.len
			if same {
				for i in 0 .. a_others.len {
					if !cx_merge_eq(a_others[i], b_others[i]) {
						same = false
						break
					}
				}
			}
			if same {
				items << a_others
			} else {
				oursb := if a_others.len == 1 { a_others[0] } else { cx.Node(cx.Element{
						name:  'body'
						items: a_others
					}) }
				theirsb := if b_others.len == 1 { b_others[0] } else { cx.Node(cx.Element{
						name:  'body'
						items: b_others
					}) }
				picked := cx_merge_pick(mut ctx, p, oursb, theirsb)
				if picked is cx.Element && picked.name == 'body' {
					items << picked.items
				} else {
					items << picked
				}
			}
		} else {
			items << a_others
			items << b_others
		}
		for ai, ae in a_elems {
			mut merged := cx.Node(ae)
			for bi, be in b_elems {
				if paired[bi] == ai {
					merged = cx_merge_values(mut ctx, p, cx.Node(ae), cx.Node(be))
					break
				}
			}
			items << merged
		}
		for bi, be in b_elems {
			if paired[bi] == -1 {
				items << cx.Node(be)
			}
		}
		return cx.Node(cx.Element{
			...a
			attrs: attrs
			items: items
		})
	}
	if a is cx.MapNode && b is cx.MapNode {
		mut entries := a.entries.clone()
		for be in b.entries {
			bkey := cx.scalar_value_str_public(be.key_value)
			mut found := false
			for i, ae in entries {
				if ae.key_type == be.key_type
					&& cx.scalar_value_str_public(ae.key_value) == bkey {
					entries[i] = cx.MapEntry{
						...ae
						value: cx_merge_values(mut ctx, '${path}/${bkey}', ae.value,
							be.value)
					}
					found = true
					break
				}
			}
			if !found {
				entries << be
			}
		}
		return cx.Node(cx.MapNode{
			...a
			entries: entries
		})
	}
	return cx_merge_pick(mut ctx, path, a, b)
}

fn cx_mod_merge(args []cx.Node) cx.Node {
	if args.len < 2 || args.len > 3 {
		return mk_err('cx-err:CXER0100', 'cx:merge requires A and B arguments (policy optional)')
	}
	mut policy := 'last-wins'
	if args.len == 3 {
		if args[2] is cx.ScalarNode {
			policy = cx.scalar_value_str_public((args[2] as cx.ScalarNode).value)
		} else {
			return mk_err('cx-err:CXER0100', 'cx:merge: POLICY must be a string')
		}
	}
	if policy !in ['last-wins', 'first-wins', 'error-on-conflict'] {
		return mk_err('cx-err:CXER0100', 'cx:merge: unknown policy `${policy}` (last-wins | first-wins | error-on-conflict)')
	}
	mut ctx := CxMergeCtx{
		policy: policy
	}
	merged := cx_merge_values(mut ctx, '', args[0], args[1])
	if policy == 'error-on-conflict' && ctx.conflicts.len > 0 {
		first := if ctx.conflicts[0] is cx.Element {
			(ctx.conflicts[0] as cx.Element).attr('subject')
		} else {
			''
		}
		return cx.Node(cx.Element{
			name:  'err'
			attrs: [
				cx.Attribute{
					name:  'code'
					value: cx.ScalarValue('cx-err:CXER4110')
				},
				cx.Attribute{
					name:  'message'
					value: cx.ScalarValue('E_CX_MERGE_CONFLICT: ${ctx.conflicts.len} collision(s) under error-on-conflict (first at `${first}`) — each [conflict] child carries ours/theirs as values (modules/cx.md §2.3; conflicts-as-values, stream 9)')
				},
			]
			items: ctx.conflicts
		})
	}
	return merged
}

// cx_mod_diff_value_changes lowers a diff VALUE back to change records.
fn cx_mod_diff_value_changes(v cx.Node) ?[]CxPatchChange {
	if v !is cx.Element {
		return none
	}
	root := v as cx.Element
	if root.name != 'diff' {
		return none
	}
	mut out := []CxPatchChange{}
	for it in root.items {
		if it !is cx.Element {
			continue
		}
		el := it as cx.Element
		if el.name != 'change' {
			return none
		}
		mut kind := ''
		mut path := ''
		mut payload := ''
		for a in el.attrs {
			av := cx.scalar_value_str_public(a.value)
			match a.name {
				'kind' { kind = av }
				'path' { path = av }
				'payload' { payload = av }
				else {}
			}
		}
		if kind == '' || path == '' {
			return none
		}
		mut before_node := ?cx.Node(none)
		mut after_node := ?cx.Node(none)
		for ch in el.items {
			if ch is cx.Element {
				if ch.name == 'before' && ch.items.len > 0 {
					before_node = ch.items[0]
				}
				if ch.name == 'after' && ch.items.len > 0 {
					after_node = ch.items[0]
				}
			}
		}
		out << CxPatchChange{
			kind:        kind
			path:        path
			payload:     payload
			before_node: before_node
			after_node:  after_node
		}
	}
	return out
}

// cx_mod_patch_order reverses each consecutive run of element-removed
// records (tail removals are emitted in ascending position; applying in
// reverse keeps the remaining records' positions stable). Reversing a
// mixed-parent run reverses each parent's subsequence — parents are
// independent, so the cross-parent order is irrelevant.
fn cx_mod_patch_order(changes []CxPatchChange) []CxPatchChange {
	mut out := []CxPatchChange{cap: changes.len}
	mut i := 0
	for i < changes.len {
		if changes[i].kind == 'element-removed' {
			mut j := i
			for j < changes.len && changes[j].kind == 'element-removed' {
				j++
			}
			for k := j - 1; k >= i; k-- {
				out << changes[k]
			}
			i = j
		} else {
			out << changes[i]
			i++
		}
	}
	return out
}

// ── patch path resolution + application ───────────────────────────────────────

struct CxPatchSeg {
	name string
	idx  int // 1-based among same-name element siblings; -1 = first/only
}

// cx_mod_split_path parses a diff record path (`/users/user[2]/name`,
// attribute tail `/@x` already stripped by the caller) into segments.
fn cx_mod_split_path(path string) ?[]CxPatchSeg {
	p := path.trim_string_left('/')
	if p == '' {
		return none
	}
	mut segs := []CxPatchSeg{}
	for raw in p.split('/') {
		if raw == '' {
			return none
		}
		mut name := raw
		mut idx := -1
		if raw.ends_with(']') {
			open := raw.index('[') or { return none }
			name = raw[..open]
			idx_s := raw[open + 1..raw.len - 1]
			idx = idx_s.int()
			if idx <= 0 {
				return none
			}
		}
		segs << CxPatchSeg{ name: name, idx: idx }
	}
	return segs
}

// cx_mod_child_pos returns the position in `items` of the seg-addressed
// element child (idx-th same-name element, 1-based; -1 = first).
fn cx_mod_child_pos(items []cx.Node, seg CxPatchSeg) ?int {
	mut nth := 0
	for i, it in items {
		if it is cx.Element {
			if (it as cx.Element).name == seg.name {
				nth++
				if seg.idx == -1 || nth == seg.idx {
					return i
				}
			}
		}
	}
	return none
}

// cx_mod_emit_compact renders a node in the compact canonical form used
// for state-vs-payload verification (both sides are canonical, so byte
// comparison is exact).
fn cx_mod_emit_compact(n cx.Node) string {
	return cx.cx_emit_node_str(n, true)
}

// cx_mod_apply_change routes one change record into the tree under the
// virtual root, returning the rebuilt root. Every failure is an error
// naming the record — patch is fail-loud (CXER4102 at the caller).
fn cx_mod_apply_change(root cx.Element, ch CxPatchChange) !cx.Element {
	// Attribute records address `parent-path/@name`.
	if ch.kind.starts_with('attribute-') {
		at := ch.path.last_index('/@') or {
			return error('${ch.kind} at "${ch.path}": missing /@ attribute tail')
		}
		attr_name := ch.path[at + 2..]
		parent_path := ch.path[..at]
		mut segs := []CxPatchSeg{}
		if parent_path != '' && parent_path != '/' {
			segs = cx_mod_split_path(parent_path) or {
				return error('${ch.kind} at "${ch.path}": unresolvable path')
			}
		}
		return cx_mod_rebuild(root, segs, ch, attr_name)
	}
	segs := cx_mod_split_path(ch.path) or {
		return error('${ch.kind} at "${ch.path}": unresolvable path')
	}
	return cx_mod_rebuild(root, segs, ch, '')
}

// cx_mod_rebuild walks `segs` down from `el`, applies the record at the
// terminal position, and rebuilds the spine immutably.
fn cx_mod_rebuild(el cx.Element, segs []CxPatchSeg, ch CxPatchChange, attr_name string) !cx.Element {
	if segs.len == 0 {
		// Terminal parent reached: body / attribute records apply to
		// THIS element.
		return cx_mod_apply_here(el, ch, attr_name)
	}
	seg := segs[0]
	if segs.len == 1 {
		match ch.kind {
			'element-added' {
				// The added element does not exist yet — verify nothing,
				// append the payload subtree to THIS parent (positional
				// diff adds are tail appends).
				an := ch.after_node or {
					return error('element-added at "${ch.path}": record carries no [after] payload')
				}
				if an !is cx.Element {
					return error('element-added at "${ch.path}": payload is not an element')
				}
				if (an as cx.Element).name != seg.name {
					return error('element-added at "${ch.path}": payload element is [${(an as cx.Element).name}]')
				}
				mut new_items := el.items.clone()
				new_items << an
				return cx_mod_with_items(el, new_items)
			}
			'element-removed' {
				pos := cx_mod_child_pos(el.items, seg) or {
					return error('element-removed at "${ch.path}": no such element')
				}
				mut new_items := []cx.Node{cap: el.items.len - 1}
				for i, it in el.items {
					if i != pos {
						new_items << it
					}
				}
				return cx_mod_with_items(el, new_items)
			}
			'element-renamed', 'type-changed', 'body-changed' {
				if ch.kind == 'body-changed' && ch.payload != 'table' {
					// Leaf-body change applies INTO the child.
					pos := cx_mod_child_pos(el.items, seg) or {
						return error('${ch.kind} at "${ch.path}": no such element')
					}
					child := el.items[pos] as cx.Element
					new_child := cx_mod_apply_here(child, ch, '')!
					mut new_items := el.items.clone()
					new_items[pos] = cx.Node(new_child)
					return cx_mod_with_items(el, new_items)
				}
				// Whole-subtree replacement (rename / type-change /
				// table): verify current equals BEFORE (apply) or AFTER
				// (already applied → skip).
				pos := cx_mod_child_pos_any(el.items, seg, ch) or {
					return error('${ch.kind} at "${ch.path}": no such element')
				}
				cur := cx_mod_emit_compact(el.items[pos])
				an := ch.after_node or {
					return error('${ch.kind} at "${ch.path}": record carries no [after] payload')
				}
				if cur == cx_mod_emit_compact(an) {
					return el // already applied
				}
				bn := ch.before_node or {
					return error('${ch.kind} at "${ch.path}": record carries no [before] payload')
				}
				if cur != cx_mod_emit_compact(bn) {
					return error('${ch.kind} at "${ch.path}": target does not match the diff BEFORE state')
				}
				mut new_items := el.items.clone()
				new_items[pos] = an
				return cx_mod_with_items(el, new_items)
			}
			else {
				// Attribute records route here with segs consumed down to
				// the OWNING element.
				pos := cx_mod_child_pos(el.items, seg) or {
					return error('${ch.kind} at "${ch.path}": no such element')
				}
				child := el.items[pos] as cx.Element
				new_child := cx_mod_apply_here(child, ch, attr_name)!
				mut new_items := el.items.clone()
				new_items[pos] = cx.Node(new_child)
				return cx_mod_with_items(el, new_items)
			}
		}
	}
	pos := cx_mod_child_pos(el.items, segs[0]) or {
		return error('${ch.kind} at "${ch.path}": unresolvable path (no [${segs[0].name}])')
	}
	child := el.items[pos] as cx.Element
	new_child := cx_mod_rebuild(child, segs[1..], ch, attr_name)!
	mut new_items := el.items.clone()
	new_items[pos] = cx.Node(new_child)
	return cx_mod_with_items(el, new_items)
}

// cx_mod_child_pos_any resolves a rename-record position: the child may
// carry the BEFORE name (not yet applied) or the AFTER name (already
// applied) — element-renamed paths address the BEFORE name.
fn cx_mod_child_pos_any(items []cx.Node, seg CxPatchSeg, ch CxPatchChange) ?int {
	if pos := cx_mod_child_pos(items, seg) {
		return pos
	}
	if ch.kind == 'element-renamed' {
		if an := ch.after_node {
			if an is cx.Element {
				return cx_mod_child_pos(items, CxPatchSeg{ name: (an as cx.Element).name, idx: seg.idx })
			}
		}
	}
	return none
}

fn cx_mod_with_items(el cx.Element, items []cx.Node) cx.Element {
	return cx.Element{
		name:  el.name
		attrs: el.attrs
		items: items
		meta:  el.meta
		table: el.table
	}
}

// cx_mod_apply_here applies a body/attribute record to the element it
// addresses (attribute records carry `attr_name`; body-changed carries
// the leaves payloads).
fn cx_mod_apply_here(el cx.Element, ch CxPatchChange, attr_name string) !cx.Element {
	match ch.kind {
		'attribute-added', 'attribute-changed', 'attribute-removed' {
			return cx_mod_apply_attr(el, ch, attr_name)
		}
		'body-changed' {
			return cx_mod_apply_leaves(el, ch)
		}
		else {
			return error('${ch.kind} at "${ch.path}": record kind not applicable here')
		}
	}
}

// cx_mod_payload_attr extracts the typed attribute from a `[v name=value]`
// payload carrier.
fn cx_mod_payload_attr(n ?cx.Node, attr_name string) ?cx.Attribute {
	pn := n or { return none }
	if pn is cx.Element {
		for a in (pn as cx.Element).attrs {
			if a.name == attr_name {
				return a
			}
		}
	}
	return none
}

fn cx_mod_attr_eq(a cx.Attribute, b cx.Attribute) bool {
	return cx_mod_emit_compact(cx.Node(cx.Element{ name: 'v', attrs: [a] })) == cx_mod_emit_compact(cx.Node(cx.Element{
		name:  'v'
		attrs: [b]
	}))
}

fn cx_mod_apply_attr(el cx.Element, ch CxPatchChange, attr_name string) !cx.Element {
	mut cur_pos := -1
	for i, a in el.attrs {
		if a.name == attr_name {
			cur_pos = i
			break
		}
	}
	match ch.kind {
		'attribute-added' {
			na := cx_mod_payload_attr(ch.after_node, attr_name) or {
				return error('attribute-added at "${ch.path}": record carries no [after] payload')
			}
			if cur_pos >= 0 {
				if cx_mod_attr_eq(el.attrs[cur_pos], na) {
					return el // already applied
				}
				return error('attribute-added at "${ch.path}": attribute already present with a different value')
			}
			mut new_attrs := el.attrs.clone()
			new_attrs << na
			return cx_mod_with_attrs(el, new_attrs)
		}
		'attribute-changed' {
			na := cx_mod_payload_attr(ch.after_node, attr_name) or {
				return error('attribute-changed at "${ch.path}": record carries no [after] payload')
			}
			ba := cx_mod_payload_attr(ch.before_node, attr_name) or {
				return error('attribute-changed at "${ch.path}": record carries no [before] payload')
			}
			if cur_pos < 0 {
				return error('attribute-changed at "${ch.path}": no such attribute')
			}
			if cx_mod_attr_eq(el.attrs[cur_pos], na) {
				return el // already applied
			}
			if !cx_mod_attr_eq(el.attrs[cur_pos], ba) {
				return error('attribute-changed at "${ch.path}": target does not match the diff BEFORE state')
			}
			mut new_attrs := el.attrs.clone()
			new_attrs[cur_pos] = na
			return cx_mod_with_attrs(el, new_attrs)
		}
		'attribute-removed' {
			if cur_pos < 0 {
				return el // already applied
			}
			ba := cx_mod_payload_attr(ch.before_node, attr_name) or {
				return error('attribute-removed at "${ch.path}": record carries no [before] payload')
			}
			if !cx_mod_attr_eq(el.attrs[cur_pos], ba) {
				return error('attribute-removed at "${ch.path}": target does not match the diff BEFORE state')
			}
			mut new_attrs := []cx.Attribute{cap: el.attrs.len - 1}
			for i, a in el.attrs {
				if i != cur_pos {
					new_attrs << a
				}
			}
			return cx_mod_with_attrs(el, new_attrs)
		}
		else {
			return error('${ch.kind} at "${ch.path}": not an attribute record')
		}
	}
}

fn cx_mod_with_attrs(el cx.Element, attrs []cx.Attribute) cx.Element {
	return cx.Element{
		name:  el.name
		attrs: attrs
		items: el.items
		meta:  el.meta
		table: el.table
	}
}

// cx_mod_apply_leaves replaces the element's non-element body items with
// the AFTER payload's items (a `[v <leaf …>]` carrier), verifying the
// current leaves against BEFORE first. The new leaves land at the first
// old leaf position (or lead the body when there were none) — leaf
// interleaving finer than that is beneath the diff engine's own
// resolution (bodies compare by concatenated leaf text).
fn cx_mod_apply_leaves(el cx.Element, ch CxPatchChange) !cx.Element {
	an := ch.after_node or {
		return error('body-changed at "${ch.path}": record carries no [after] payload')
	}
	bn := ch.before_node or {
		return error('body-changed at "${ch.path}": record carries no [before] payload')
	}
	mut cur_leaves := []cx.Node{}
	mut first_leaf_pos := -1
	for i, it in el.items {
		if it !is cx.Element {
			if first_leaf_pos < 0 {
				first_leaf_pos = i
			}
			cur_leaves << it
		}
	}
	cur_carrier := cx_mod_emit_compact(cx.Node(cx.Element{ name: 'v', items: cur_leaves }))
	if cur_carrier == cx_mod_emit_compact(an) {
		return el // already applied
	}
	if cur_carrier != cx_mod_emit_compact(bn) {
		return error('body-changed at "${ch.path}": target does not match the diff BEFORE state')
	}
	new_leaves := if an is cx.Element { (an as cx.Element).items } else { []cx.Node{} }
	insert_at := if first_leaf_pos < 0 { 0 } else { first_leaf_pos }
	mut new_items := []cx.Node{cap: el.items.len}
	mut inserted := false
	for i, it in el.items {
		if i == insert_at && !inserted {
			for nl in new_leaves {
				new_items << nl
			}
			inserted = true
		}
		if it !is cx.Element {
			continue
		}
		new_items << it
	}
	if !inserted {
		for nl in new_leaves {
			new_items << nl
		}
	}
	return cx_mod_with_items(el, new_items)
}

// ── the environment quadrant (L103, stream 5 — computation_identity.md §3) ───
//
// Three PURE builtins (constants of the runtime build — same value on every
// run, on every host, for a given build; a colon-qualified module call is
// purity-unconstrained by the checker, and these honor that by construction):
//
//   [$cx:version]  — the FULL runtime semver (cx_version build define; the
//                    repo-root VERSION file is the single source; unreleased
//                    dev/test builds default '0.0.0-dev'). A patch can fix a
//                    determinism bug, so a patch MUST invalidate computation
//                    addresses — correct-by-construction beats hit rate.
//   [$cx:builtins] — the canonical CX value listing the two closed,
//                    governance-amended spec tables: the §4.1 program-
//                    directive registry (cx.directive_names — gate-3-bound
//                    to grammar.ebnf [127e] and code.md) and the §6.5.x
//                    purity classification (builtin_purity_table — the
//                    effect-alignment gate's drift-canaried source, bare
//                    names + module prims). Host-independent by
//                    construction — NEVER cx_features or a binary hash.
//   [$cx:env]      — the canonical environment record of the stream-5
//                    [computation] identity: {builtins: <Tier-1 of
//                    [$cx:builtins]>, runtime: [$cx:version],
//                    schema-dialect: cx.schema_dialect_version (the S020
//                    single source)}. Map-shaped = self-canonicalizing.
//
// The additivity contract (L103): a new env field APPENDS — every
// computation address changes exactly once, the old cache is cold, never
// wrong, no negotiation.

// code_runtime_version is the module-code mirror of the cx_version build
// define (cmd/main.v, cx/cabi.v read the same define — one source, three
// readers, zero copies).
const code_runtime_version = $d('cx_version', '0.0.0-dev')

fn cx_mod_version(args []cx.Node) cx.Node {
	if args.len != 0 {
		return mk_err('cx-err:CXER0100', 'cx:version takes no arguments')
	}
	return cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue(code_runtime_version)
		data_type: cx.ScalarType.string_type
	})
}

// cx_mod_builtins_value constructs the two-tables value (shared by
// [$cx:builtins] and the env record's builtins-id derivation).
fn cx_mod_builtins_value() cx.Node {
	mut dirs := cx.directive_names.clone()
	dirs.sort()
	mut dir_items := []cx.Node{cap: dirs.len}
	for d in dirs {
		dir_items << cx.Node(cx.ScalarNode{ value: cx.ScalarValue(d), data_type: .string_type })
	}
	pt := builtin_purity_table()
	mut names := pt.keys()
	names.sort()
	mut purity_entries := []cx.Node{cap: names.len}
	for n in names {
		p := if pt[n] == cx.Purity.pure_ { 'pure' } else { 'impure' }
		purity_entries << cx.Node(cx.Element{
			name:  n
			items: [cx.Node(cx.ScalarNode{ value: cx.ScalarValue(p), data_type: .string_type })]
		})
	}
	return cx.Node(cx.Element{
		name:  map_marker_name
		items: [
			cx.Node(cx.Element{
				name:  'directives'
				items: [cx.Node(cx.Element{ name: seq_marker_name, items: dir_items })]
			}),
			cx.Node(cx.Element{
				name:  'purity'
				items: [cx.Node(cx.Element{ name: map_marker_name, items: purity_entries })]
			}),
		]
	})
}

fn cx_mod_builtins(args []cx.Node) cx.Node {
	if args.len != 0 {
		return mk_err('cx-err:CXER0100', 'cx:builtins takes no arguments')
	}
	return cx_mod_builtins_value()
}

// cx_mod_builtins_id derives the builtin-set id: the plain Tier-1 address
// of the two-tables value (the same acquisition path as [$cx:hash], so the
// M5 re-hash-to-verify property holds by construction).
fn cx_mod_builtins_id() !string {
	src := cx_mod_value_source(cx_mod_builtins_value())!
	return cx.cx_text_hash(src)!
}

fn cx_mod_env(args []cx.Node) cx.Node {
	if args.len != 0 {
		return mk_err('cx-err:CXER0100', 'cx:env takes no arguments')
	}
	bid := cx_mod_builtins_id() or {
		return mk_err('cx-err:CXER4100', 'cx:env: builtin-set id derivation failed: ${err.msg()}')
	}
	// keys pre-sorted: builtins < runtime < schema-dialect.
	return cx.Node(cx.Element{
		name:  map_marker_name
		items: [
			cx.Node(cx.Element{
				name:  'builtins'
				items: [cx.Node(cx.ScalarNode{ value: cx.ScalarValue(bid), data_type: .string_type })]
			}),
			cx.Node(cx.Element{
				name:  'runtime'
				items: [cx.Node(cx.ScalarNode{ value: cx.ScalarValue(code_runtime_version), data_type: .string_type })]
			}),
			cx.Node(cx.Element{
				name:  'schema-dialect'
				items: [cx.Node(cx.ScalarNode{ value: cx.ScalarValue(cx.schema_dialect_version), data_type: .string_type })]
			}),
		]
	})
}

// ── stream 6 W6b: the engine half of COMMIT (consumed by authz §3.9) ────────

// value_tier1_address exposes the cx:hash acquisition path to the
// platform layer (authz approve/commit/resolve-cap bind and verify
// proposal + authority-artifact addresses). Returns the tagged address
// as a string node, or the E1-totality err VALUE.
pub fn value_tier1_address(n cx.Node) cx.Node {
	return cx_mod_hash([n])
}

// CommandCommitResult is command_commit_execute's verdict: `refusal`
// names the engine-side failure class ('' = executed), so the authz
// commit verb (the ONE surface that owns the typed commit codes) maps
// it without a second spelling of the checks.
pub struct CommandCommitResult {
pub:
	refusal  string // '' | 'not-command' | 'version-mismatch' | 'precondition-divergence: <src>' | 'args-invalid: <detail>'
	outcome  cx.Node
	idem_key string
}

// command_commit_execute runs the ENGINE half of a proposal commit
// (stream 6 W6b, R17 steps b/e/i): verifies the presented command fn's
// def-text Tier-1 address equals the proposal's trust key (commit runs
// the EXACT approved version — L139), re-evaluates the preconditions
// over the proposal's args (divergence = refusal; they were recorded
// TRUE at propose), then executes the body through the ordinary invoke
// path (effects narrowing + idempotent dedup included). The authority
// checks (approval binding, tier, propose-only, PEP, debit, journal)
// are the CALLER's — cx-stdlib/authz §3.9.
// The two-pass protocol (W7 — the M5 ordering rule "preconditions →
// debit → execute"): the VERIFY pass (run_preconditions=true,
// do_execute=false) checks version binding + re-evaluates preconditions
// exactly ONCE; the caller then debits under the commit lock; the
// EXECUTE pass (false, true) re-verifies the version and runs the body.
// A refused commit therefore exercises no authority (no debit, no
// body); a debited crash is correct — budgets meter authority
// EXERCISED, not net economic effect (L112).
pub fn command_commit_execute(fnv cx.Node, proposal cx.Element, run_preconditions bool, do_execute bool, mut env MatchEnv) CommandCommitResult {
	id := closure_id_of(fnv) or {
		return CommandCommitResult{
			refusal: 'not-command'
		}
	}
	cl := lookup_closure(id, env) or {
		return CommandCommitResult{
			refusal: 'not-command'
		}
	}
	if cl.cmd_meta == unsafe { nil } || !cl.has_effects {
		return CommandCommitResult{
			refusal: 'not-command'
		}
	}
	meta := cl.cmd_meta
	// (b) the trust key: proposal [command tier1=…] vs the presented def.
	mut prop_tier1 := ''
	mut args_map := cx.Node(cx.Element{})
	mut idem_key := ''
	for it in proposal.items {
		if it is cx.Element {
			match it.name {
				'command' {
					for a in it.attrs {
						if a.name == 'tier1' {
							prop_tier1 = cx.scalar_value_str_public(a.value)
						}
					}
				}
				'args' {
					if it.items.len == 1 {
						args_map = it.items[0]
					}
				}
				'idempotency-key' {
					if it.items.len == 1 {
						v := it.items[0]
						if v is cx.ScalarNode {
							idem_key = cx.scalar_value_str_public(v.value)
						}
					}
				}
				else {}
			}
		}
	}
	if prop_tier1 == '' || prop_tier1 != meta.src_addr {
		return CommandCommitResult{
			refusal: 'version-mismatch'
		}
	}
	// args → the §5 NAME-KEYED record (same builder as propose — the two
	// binding passes MUST agree or propose-predicts-commit breaks).
	mut record := map[string]cx.Node{}
	if args_map is cx.Element && (args_map as cx.Element).name == '__cx_map__' {
		for e in (args_map as cx.Element).items {
			if e is cx.Element && e.items.len > 0 {
				record[e.name] = e.items[0]
			}
		}
	}
	mut call_env := build_param_call_env_record(cl, record, mut env) or {
		return CommandCommitResult{
			refusal: 'args-invalid: ${err.msg()}'
		}
	}
	// (e) re-evaluate preconditions — recorded TRUE at propose; any
	// now-false/faulting one is the divergence refusal (the two-times
	// enforcement table: live facts re-check at commit). Verify pass
	// only — evaluated exactly once per commit.
	pre_list := if run_preconditions { meta.preconditions } else { []string{} }
	for src in pre_list {
		prog := cx.parse_program(src) or {
			return CommandCommitResult{
				refusal: 'precondition-divergence: ${src}'
			}
		}
		r := eval_node(prog.body, mut call_env) or {
			return CommandCommitResult{
				refusal: 'precondition-divergence: ${src}'
			}
		}
		ok := node_ebv(r) or { false }
		if !ok {
			return CommandCommitResult{
				refusal: 'precondition-divergence: ${src}'
			}
		}
	}
	if !do_execute {
		return CommandCommitResult{
			idem_key: idem_key
		}
	}
	// (i) execute through the ordinary invoke path (effects narrowing +
	// the in-process idempotent dedup ride along). The record-resolved
	// values (defaults already evaluated ONCE by the record builder) are
	// laid out in spec order — positionals by position, named by label —
	// so the invoke binds value-identically to the verify pass.
	mut call_vals := []cx.Node{}
	mut call_labels := []string{}
	for spec in cl.param_specs {
		if spec.is_rest {
			continue
		}
		bound := call_env.bindings[spec.name] or { continue }
		call_labels << if spec.is_named { spec.name } else { '' }
		call_vals << bound
	}
	outcome := invoke_closure_l(cl, call_vals, call_labels, mut env) or {
		return CommandCommitResult{
			outcome: mk_err('cx-err:CXER0001', err.msg())
		}
	}
	return CommandCommitResult{
		outcome:  outcome
		idem_key: idem_key
	}
}
