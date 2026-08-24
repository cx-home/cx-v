module code

// ── cx-stdlib/map natives (#925, RULED: PYE-1) ────────────────────────────
//
// The `map-` primitives stdlib/map.cx bottoms out in (the strings.cx
// pattern: thin CX wrappers over natives, prefixed so they never clash
// with a language-core builtin). They implement
// spec/03-approved/std-lib/map.md over BOTH runtime map representations:
// the eval lane's `__cx_map__` envelope (entry Elements carrying the key
// image in `name` and the kind on meta, eval_map's stamping) and the data
// lane's materialized `cx.MapNode` (cx:parse results, [?to-map] rows).
//
// Key identity everywhere is the (kind, image) pair (cxdm §2.6/§5.1,
// RULED: 777-1a; string images NFC), through ONE normalization
// (map_native_key_id) so `get`/`contains`/`remove`/`put` and the literal
// reader can never disagree.

import cx

// map_native_entry is the normalized view of one map entry, whichever
// representation it came from.
struct MapNativeEntry {
	kind  string // CXDM kind name ('int', 'string', …)
	image string // canonical value image (NFC for strings)
	decl  string // MSS-4 declaration kind ('' for a valued entry)
	value cx.Node
}

// map_native_entries normalizes a map argument. none = not a map.
fn map_native_entries(n cx.Node) ?[]MapNativeEntry {
	if n is cx.Element {
		if n.name == map_marker_name {
			mut out := []MapNativeEntry{cap: n.items.len}
			for it in n.items {
				if it is cx.Element {
					kind := map_entry_effective_key_kind(it)
					image := map_native_norm_image(kind, it.name)
					decl := map_entry_decl_kind(it) or { '' }
					value := if it.items.len > 0 {
						it.items[0]
					} else {
						cx.Node(cx.ScalarNode{ data_type: .null_type, value: cx.ScalarValue(cx.NullValue{}) })
					}
					out << MapNativeEntry{ kind: kind, image: image, decl: decl, value: value }
				}
			}
			return out
		}
		return none
	}
	if n is cx.MapNode {
		mut out := []MapNativeEntry{cap: n.entries.len}
		for e in n.entries {
			kind := cx.scalar_type_name_public(e.key_type)
			image := map_native_norm_image(kind, cx.scalar_value_str_public(e.key_value))
			out << MapNativeEntry{ kind: kind, image: image, decl: e.decl_kind, value: e.value }
		}
		return out
	}
	return none
}

// map_native_norm_image canonicalizes a key image within its kind so two
// spellings of one value share one identity (hex ints, decimal scale,
// NFC strings) — the same normalization read_map_key applies at parse.
fn map_native_norm_image(kind string, image string) string {
	if kind == 'string' {
		return cx.cx_nfc_name(image)
	}
	sn := cx.coerce_scalar_strict(kind, image) or { return image }
	return cx.scalar_value_str_public(sn.value)
}

// map_native_key_of reads the lookup ARGUMENT's (kind, image) pair.
// none = not an admissible key scalar.
fn map_native_key_of(n cx.Node) ?(string, string) {
	k := meta_unwrap(n)
	if k is cx.ScalarNode {
		kind := cx.scalar_type_name_public(k.data_type)
		if kind in ['atom', 'null', 'duration', 'period'] {
			return none
		}
		return kind, map_native_norm_image(kind, cx.scalar_value_str_public(k.value))
	}
	if k is cx.TextNode {
		return 'string', cx.cx_nfc_name(k.value)
	}
	return none
}

// map_native_rebuild builds the eval-lane envelope back from normalized
// entries, stamping every key's kind explicitly (the renderer and the
// codec funnel both honor the stamp — 777-1a / #927).
fn map_native_rebuild(entries []MapNativeEntry) cx.Node {
	mut items := []cx.Node{cap: entries.len}
	for e in entries {
		mut meta := &cx.ElementMeta{
			key_kind: ?string(e.kind)
		}
		if e.decl != '' {
			meta.decl_kind = ?string(e.decl)
	}
		items << cx.Node(cx.Element{
			name:  e.image
			meta:  meta
			items: [e.value]
		})
	}
	return cx.Node(cx.Element{ name: map_marker_name, items: items })
}

// map_native_key_scalar materializes an entry's key as a typed scalar
// (the map:keys / for-each item shape).
fn map_native_key_scalar(e MapNativeEntry) cx.Node {
	if e.kind == 'string' {
		return cx.Node(cx.ScalarNode{ data_type: .string_type, value: cx.ScalarValue(e.image) })
	}
	sn := cx.coerce_scalar_strict(e.kind, e.image) or {
		return cx.Node(cx.ScalarNode{ data_type: .string_type, value: cx.ScalarValue(e.image) })
	}
	return cx.Node(sn)
}

fn map_native_err(msg string) cx.Node {
	return mk_err('cx-err:CXER0100', msg)
}

// eval_map_builtin dispatches the map- native primitives. Reached from the
// higher-order built-in path (mut env for for-each's callable). Returns
// none for a non-map- name.
fn eval_map_builtin(name string, args []cx.Node, mut env MatchEnv) ?cx.Node {
	match name {
		'map-get' { return map_native_get(args) }
		'map-put' { return map_native_put(args) }
		'map-keys' { return map_native_keys(args) }
		'map-size' { return map_native_size(args) }
		'map-contains' { return map_native_contains(args) }
		'map-entry' { return map_native_entry_fn(args) }
		'map-merge' { return map_native_merge(args) }
		'map-remove' { return map_native_remove(args) }
		'map-for-each' { return map_native_for_each(args, mut env) }
		else { return none }
	}
}

// map_native_operand validates arity + the map operand; the error VALUE
// (errors-are-values) rides the V error channel's message as a marker the
// callers convert back via map_native_err.
fn map_native_operand(args []cx.Node, fname string, want_args int) ![]MapNativeEntry {
	if args.len != want_args {
		return error('[\$map:${fname}] wrong arity — expected ${want_args} argument(s), got ${args.len}')
	}
	entries := map_native_entries(args[0]) or {
		return error('[\$map:${fname}] first argument must be a map (cxdm §2.6)')
	}
	return entries
}

fn map_native_get(args []cx.Node) cx.Node {
	entries := map_native_operand(args, 'get', 2) or { return map_native_err(err.msg()) }
	kind, image := map_native_key_of(args[1]) or {
		return map_native_err('[$map:get] KEY must be an admissible key scalar (cxdm §2.6)')
	}
	for e in entries {
		if e.kind == kind && e.image == image {
			if e.decl != '' {
				return fp_mk_seq([]) // declared entry: value reads are ABSENT (MSS-4)
			}
			return e.value
		}
	}
	return fp_mk_seq([]) // absence, never an invented null (#584)
}

fn map_native_put(args []cx.Node) cx.Node {
	mut entries := map_native_operand(args, 'put', 3) or { return map_native_err(err.msg()) }
	kind, image := map_native_key_of(args[1]) or {
		return map_native_err('[$map:put] KEY must be an admissible key scalar (cxdm §2.6)')
	}
	new_e := MapNativeEntry{ kind: kind, image: image, decl: '', value: args[2] }
	mut replaced := false
	for i, e in entries {
		if e.kind == kind && e.image == image {
			entries[i] = new_e
			replaced = true
			break
		}
	}
	if !replaced {
		entries << new_e
	}
	return map_native_rebuild(entries)
}

fn map_native_keys(args []cx.Node) cx.Node {
	entries := map_native_operand(args, 'keys', 1) or { return map_native_err(err.msg()) }
	mut out := []cx.Node{cap: entries.len}
	for e in entries {
		out << map_native_key_scalar(e)
	}
	return fp_mk_seq(out)
}

fn map_native_size(args []cx.Node) cx.Node {
	entries := map_native_operand(args, 'size', 1) or { return map_native_err(err.msg()) }
	return cx.Node(cx.ScalarNode{ data_type: .int_type, value: cx.ScalarValue(i64(entries.len)) })
}

fn map_native_contains(args []cx.Node) cx.Node {
	entries := map_native_operand(args, 'contains', 2) or { return map_native_err(err.msg()) }
	kind, image := map_native_key_of(args[1]) or {
		return map_native_err('[$map:contains] KEY must be an admissible key scalar (cxdm §2.6)')
	}
	for e in entries {
		if e.kind == kind && e.image == image {
			return cx.Node(cx.ScalarNode{ data_type: .bool_type, value: cx.ScalarValue(true) })
		}
	}
	return cx.Node(cx.ScalarNode{ data_type: .bool_type, value: cx.ScalarValue(false) })
}

fn map_native_entry_fn(args []cx.Node) cx.Node {
	if args.len != 2 {
		return map_native_err('[$map:entry] wrong arity — expected KEY and VALUE, got ${args.len}')
	}
	kind, image := map_native_key_of(args[0]) or {
		return map_native_err('[$map:entry] KEY must be an admissible key scalar (cxdm §2.6, never atom/null)')
	}
	return map_native_rebuild([
		MapNativeEntry{ kind: kind, image: image, decl: '', value: args[1] },
	])
}

fn map_native_merge(args []cx.Node) cx.Node {
	if args.len != 1 {
		return map_native_err('[$map:merge] wrong arity — expected one sequence/array of maps, got ${args.len} argument(s)')
	}
	mut acc := []MapNativeEntry{}
	operand := meta_unwrap(args[0])
	mut maps := []cx.Node{}
	if es := map_native_entries(operand) {
		// a single bare map merges to itself
		_ = es
		maps << operand
	} else {
		maps = iterate(operand)
	}
	for m in maps {
		entries := map_native_entries(m) or {
			return map_native_err('[$map:merge] every item must be a map (cxdm §2.6)')
		}
		for e in entries {
			mut replaced := false
			for i, a in acc {
				if a.kind == e.kind && a.image == e.image {
					acc[i] = MapNativeEntry{ kind: a.kind, image: a.image, decl: e.decl, value: e.value }
					replaced = true
					break
				}
			}
			if !replaced {
				acc << e
			}
		}
	}
	return map_native_rebuild(acc)
}

fn map_native_remove(args []cx.Node) cx.Node {
	entries := map_native_operand(args, 'remove', 2) or { return map_native_err(err.msg()) }
	kind, image := map_native_key_of(args[1]) or {
		return map_native_err('[$map:remove] KEY must be an admissible key scalar (cxdm §2.6)')
	}
	mut out := []MapNativeEntry{cap: entries.len}
	for e in entries {
		if !(e.kind == kind && e.image == image) {
			out << e
		}
	}
	return map_native_rebuild(out)
}

fn map_native_for_each(args []cx.Node, mut env MatchEnv) cx.Node {
	entries := map_native_operand(args, 'for-each', 2) or { return map_native_err(err.msg()) }
	fn_val := args[1]
	mut out := []cx.Node{cap: entries.len}
	for e in entries {
		r := apply_fn_value(fn_val, [map_native_key_scalar(e), e.value], mut env) or {
			return err_to_node(err)
		}
		if is_err_node(r) {
			return r
		}
		out << r
	}
	return fp_mk_seq(out)
}
