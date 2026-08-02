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
		'hash' { return cx_mod_hash(args) }
		'equal' { return cx_mod_equal(args) }
		'diff' { return cx_mod_diff(args) }
		'patch' { return cx_mod_patch(args) }
		'to-format' { return cx_mod_to_format(args) }
		'from-format' { return cx_mod_from_format(args) }
		'select' { return cx_mod_select(args, mut env) }
		else { return none }
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
			if n.name == seq_marker_name {
				return cx.Node(cx.SequenceNode{ items: n.items.map(cx_mod_lower_value(it)) })
			}
			if n.name == arr_marker_name {
				return cx.Node(cx.ArrayNode{ items: n.items.map(cx_mod_lower_value(it)) })
			}
			if n.name == map_marker_name {
				// entry elements carry name=key, items=[value] (see
				// render_element_to's `__cx_map__` lane).
				mut entries := []cx.MapEntry{cap: n.items.len}
				for it in n.items {
					if it is cx.Element {
						value := if it.items.len > 0 {
							cx_mod_lower_value(it.items[0])
						} else {
							cx.Node(cx.ScalarNode{ value: cx.ScalarValue(cx.NullValue{}), data_type: .null_type })
						}
						entries << cx.MapEntry{
							key_type:  .string_type
							key_value: cx.ScalarValue(it.name)
							value:     value
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
				entries << cx.MapEntry{ key_type: en.key_type, key_value: en.key_value, value: cx_mod_lower_value(en.value) }
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
	return codec_str_node(out)
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
	src := cx_mod_value_source(args[0]) or {
		return mk_err('cx-err:CXER4101', 'cx:hash: ${err.msg()}')
	}
	out := cx.cx_text_hash(src) or {
		return mk_err('cx-err:CXER4100', 'cx:hash: malformed CX source: ${err.msg()}')
	}
	return codec_str_node(out)
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
fn cx_mod_select(args []cx.Node, mut env MatchEnv) cx.Node {
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
fn cx_mod_diff(args []cx.Node) cx.Node {
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
