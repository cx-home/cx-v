module code

// ── cx-stdlib/array natives (#925, RULED: PYE-1) ──────────────────────────
//
// The `arr-` primitives stdlib/array.cx bottoms out in. They implement
// spec/03-approved/std-lib/array.md over BOTH runtime array
// representations: the eval lane's `__cx_arr__` envelope and the data
// lane's materialized `cx.ArrayNode`. Natives operate on the item list
// DIRECTLY (never decompose through sequence flattening — a boxed-
// sequence item `[(1, 2), 3]` must survive every constructor intact).
//
// Positions are 1-based (spec §2); out-of-range REFUSES loudly, never a
// silent no-op or an invented value.

import cx

// arr_native_items normalizes an array argument. none = not an array.
fn arr_native_items(n cx.Node) ?[]cx.Node {
	u := meta_unwrap(n)
	if u is cx.Element {
		if u.name == arr_marker_name {
			return u.items
		}
		return none
	}
	if u is cx.ArrayNode {
		return u.items
	}
	return none
}

fn arr_native_rebuild(items []cx.Node) cx.Node {
	return cx.Node(cx.Element{ name: arr_marker_name, items: items })
}

fn arr_native_err(msg string) cx.Node {
	return mk_err('cx-err:CXER0100', msg)
}

fn arr_native_int_arg(n cx.Node) ?i64 {
	u := meta_unwrap(n)
	if u is cx.ScalarNode {
		if u.data_type == .int_type {
			if u.value is i64 {
				return u.value as i64
			}
		}
	}
	return none
}

fn arr_native_oob(fname string, i i64, size int) cx.Node {
	return arr_native_err('[$array:${fname}] position ${i} is out of range for an array of ${size} item(s) — positions are 1-based (E_ARRAY_INDEX_OUT_OF_RANGE)')
}

// eval_arr_builtin dispatches the arr- native primitives.
fn eval_arr_builtin(name string, args []cx.Node, mut env MatchEnv) ?cx.Node {
	match name {
		'arr-size' { return arr_native_size(args) }
		'arr-get' { return arr_native_get(args) }
		'arr-append' { return arr_native_append(args) }
		'arr-head' { return arr_native_head(args) }
		'arr-tail' { return arr_native_tail(args) }
		'arr-reverse' { return arr_native_reverse(args) }
		'arr-subarray' { return arr_native_subarray(args) }
		'arr-put' { return arr_native_put(args) }
		'arr-remove' { return arr_native_remove(args) }
		'arr-insert-before' { return arr_native_insert_before(args) }
		'arr-flatten' { return arr_native_flatten(args) }
		'arr-join' { return arr_native_join(args) }
		'arr-filter' { return arr_native_filter(args, mut env) }
		'arr-for-each' { return arr_native_for_each(args, mut env) }
		'arr-fold-left' { return arr_native_fold_left(args, mut env) }
		'arr-fold-right' { return arr_native_fold_right(args, mut env) }
		'arr-sort' { return arr_native_sort(args) }
		else { return none }
	}
}

fn arr_native_size(args []cx.Node) cx.Node {
	if args.len != 1 {
		return arr_native_err('[$array:size] wrong arity — expected 1 argument, got ${args.len}')
	}
	items := arr_native_items(args[0]) or {
		return arr_native_err('[$array:size] the argument must be an array (cxdm §2.5)')
	}
	return cx.Node(cx.ScalarNode{ data_type: .int_type, value: cx.ScalarValue(i64(items.len)) })
}

fn arr_native_get(args []cx.Node) cx.Node {
	if args.len != 2 {
		return arr_native_err('[$array:get] wrong arity — expected ARRAY and POSITION, got ${args.len}')
	}
	items := arr_native_items(args[0]) or {
		return arr_native_err('[$array:get] the first argument must be an array (cxdm §2.5)')
	}
	i := arr_native_int_arg(args[1]) or {
		return arr_native_err('[$array:get] POSITION must be an int')
	}
	if i < 1 || i > items.len {
		return arr_native_oob('get', i, items.len)
	}
	return items[i - 1]
}

fn arr_native_append(args []cx.Node) cx.Node {
	if args.len != 2 {
		return arr_native_err('[$array:append] wrong arity — expected ARRAY and VALUE, got ${args.len}')
	}
	items := arr_native_items(args[0]) or {
		return arr_native_err('[$array:append] the first argument must be an array (cxdm §2.5)')
	}
	mut out := items.clone()
	out << args[1]
	return arr_native_rebuild(out)
}

fn arr_native_head(args []cx.Node) cx.Node {
	if args.len != 1 {
		return arr_native_err('[$array:head] wrong arity — expected 1 argument, got ${args.len}')
	}
	items := arr_native_items(args[0]) or {
		return arr_native_err('[$array:head] the argument must be an array (cxdm §2.5)')
	}
	if items.len == 0 {
		return fp_mk_seq([]) // absence (#584), matching the language reader
	}
	return items[0]
}

fn arr_native_tail(args []cx.Node) cx.Node {
	if args.len != 1 {
		return arr_native_err('[$array:tail] wrong arity — expected 1 argument, got ${args.len}')
	}
	items := arr_native_items(args[0]) or {
		return arr_native_err('[$array:tail] the argument must be an array (cxdm §2.5)')
	}
	if items.len == 0 {
		return arr_native_rebuild([])
	}
	return arr_native_rebuild(items[1..])
}

fn arr_native_reverse(args []cx.Node) cx.Node {
	if args.len != 1 {
		return arr_native_err('[$array:reverse] wrong arity — expected 1 argument, got ${args.len}')
	}
	items := arr_native_items(args[0]) or {
		return arr_native_err('[$array:reverse] the argument must be an array (cxdm §2.5)')
	}
	mut out := []cx.Node{cap: items.len}
	for i := items.len - 1; i >= 0; i-- {
		out << items[i]
	}
	return arr_native_rebuild(out)
}

fn arr_native_subarray(args []cx.Node) cx.Node {
	if args.len != 3 {
		return arr_native_err('[$array:subarray] wrong arity — expected ARRAY, START, LENGTH, got ${args.len}')
	}
	items := arr_native_items(args[0]) or {
		return arr_native_err('[$array:subarray] the first argument must be an array (cxdm §2.5)')
	}
	start := arr_native_int_arg(args[1]) or {
		return arr_native_err('[$array:subarray] START must be an int')
	}
	length := arr_native_int_arg(args[2]) or {
		return arr_native_err('[$array:subarray] LENGTH must be an int')
	}
	if start < 1 || start > items.len + 1 {
		return arr_native_oob('subarray', start, items.len)
	}
	if length < 0 {
		return arr_native_err('[$array:subarray] LENGTH must be non-negative, got ${length}')
	}
	mut endpos := int(start - 1 + length)
	if endpos > items.len {
		endpos = items.len // clamp to the array's end (spec §3)
	}
	return arr_native_rebuild(items[int(start - 1)..endpos])
}

fn arr_native_put(args []cx.Node) cx.Node {
	if args.len != 3 {
		return arr_native_err('[$array:put] wrong arity — expected ARRAY, POSITION, VALUE, got ${args.len}')
	}
	items := arr_native_items(args[0]) or {
		return arr_native_err('[$array:put] the first argument must be an array (cxdm §2.5)')
	}
	i := arr_native_int_arg(args[1]) or {
		return arr_native_err('[$array:put] POSITION must be an int')
	}
	if i < 1 || i > items.len {
		return arr_native_oob('put', i, items.len)
	}
	mut out := items.clone()
	out[i - 1] = args[2]
	return arr_native_rebuild(out)
}

fn arr_native_remove(args []cx.Node) cx.Node {
	if args.len != 2 {
		return arr_native_err('[$array:remove] wrong arity — expected ARRAY and POSITION, got ${args.len}')
	}
	items := arr_native_items(args[0]) or {
		return arr_native_err('[$array:remove] the first argument must be an array (cxdm §2.5)')
	}
	i := arr_native_int_arg(args[1]) or {
		return arr_native_err('[$array:remove] POSITION must be an int')
	}
	if i < 1 || i > items.len {
		return arr_native_oob('remove', i, items.len)
	}
	mut out := []cx.Node{cap: items.len - 1}
	for j, it in items {
		if j != int(i - 1) {
			out << it
		}
	}
	return arr_native_rebuild(out)
}

fn arr_native_insert_before(args []cx.Node) cx.Node {
	if args.len != 3 {
		return arr_native_err('[$array:insert-before] wrong arity — expected ARRAY, POSITION, VALUE, got ${args.len}')
	}
	items := arr_native_items(args[0]) or {
		return arr_native_err('[$array:insert-before] the first argument must be an array (cxdm §2.5)')
	}
	i := arr_native_int_arg(args[1]) or {
		return arr_native_err('[$array:insert-before] POSITION must be an int')
	}
	if i < 1 || i > items.len + 1 {
		return arr_native_oob('insert-before', i, items.len)
	}
	mut out := []cx.Node{cap: items.len + 1}
	for j, it in items {
		if j == int(i - 1) {
			out << args[2]
		}
		out << it
	}
	if int(i) == items.len + 1 {
		out << args[2]
	}
	return arr_native_rebuild(out)
}

// arr_native_flatten_into expands nested arrays AND boxed sequences,
// depth-first, per XPath array:flatten (whose result is a SEQUENCE).
fn arr_native_flatten_into(n cx.Node, mut out []cx.Node) {
	if items := arr_native_items(n) {
		for it in items {
			arr_native_flatten_into(it, mut out)
		}
		return
	}
	u := meta_unwrap(n)
	if u is cx.Element {
		if u.name == seq_marker_name {
			for it in u.items {
				arr_native_flatten_into(it, mut out)
			}
			return
		}
	}
	if u is cx.SequenceNode {
		for it in u.items {
			arr_native_flatten_into(it, mut out)
		}
		return
	}
	out << n
}

fn arr_native_flatten(args []cx.Node) cx.Node {
	if args.len != 1 {
		return arr_native_err('[$array:flatten] wrong arity — expected 1 argument, got ${args.len}')
	}
	mut out := []cx.Node{}
	arr_native_flatten_into(args[0], mut out)
	return fp_mk_seq(out)
}

fn arr_native_join(args []cx.Node) cx.Node {
	if args.len != 1 {
		return arr_native_err('[$array:join] wrong arity — expected one sequence/array of arrays, got ${args.len}')
	}
	operand := meta_unwrap(args[0])
	mut arrays := []cx.Node{}
	if _ := arr_native_items(operand) {
		arrays << operand // a single bare array joins to itself
	} else {
		arrays = iterate(operand)
	}
	mut out := []cx.Node{}
	for a in arrays {
		items := arr_native_items(a) or {
			return arr_native_err('[$array:join] every item must be an array (cxdm §2.5)')
		}
		for it in items {
			out << it
		}
	}
	return arr_native_rebuild(out)
}

fn arr_native_filter(args []cx.Node, mut env MatchEnv) cx.Node {
	if args.len != 2 {
		return arr_native_err('[$array:filter] wrong arity — expected ARRAY and FN, got ${args.len}')
	}
	items := arr_native_items(args[0]) or {
		return arr_native_err('[$array:filter] the first argument must be an array (cxdm §2.5)')
	}
	fn_val := args[1]
	mut out := []cx.Node{}
	for it in items {
		r := apply_fn_value(fn_val, [it], mut env) or { return err_to_node(err) }
		if is_err_node(r) {
			return r
		}
		ru := meta_unwrap(r)
		if ru is cx.ScalarNode {
			if ru.data_type == .bool_type {
				if ru.value is bool {
					if ru.value as bool {
						out << it
					}
					continue
				}
			}
		}
		return mk_err('cx-err:CXER0290', '[$array:filter] the predicate must answer a bool (cx-err:CXER0290)')
	}
	return arr_native_rebuild(out)
}

fn arr_native_for_each(args []cx.Node, mut env MatchEnv) cx.Node {
	if args.len != 2 {
		return arr_native_err('[$array:for-each] wrong arity — expected ARRAY and FN, got ${args.len}')
	}
	items := arr_native_items(args[0]) or {
		return arr_native_err('[$array:for-each] the first argument must be an array (cxdm §2.5)')
	}
	fn_val := args[1]
	mut out := []cx.Node{cap: items.len}
	for it in items {
		r := apply_fn_value(fn_val, [it], mut env) or { return err_to_node(err) }
		if is_err_node(r) {
			return r
		}
		out << r
	}
	return arr_native_rebuild(out)
}

fn arr_native_fold_left(args []cx.Node, mut env MatchEnv) cx.Node {
	if args.len != 3 {
		return arr_native_err('[$array:fold-left] wrong arity — expected ARRAY, INIT, FN, got ${args.len}')
	}
	items := arr_native_items(args[0]) or {
		return arr_native_err('[$array:fold-left] the first argument must be an array (cxdm §2.5)')
	}
	fn_val := args[2]
	mut acc := args[1]
	for it in items {
		acc = apply_fn_value(fn_val, [acc, it], mut env) or { return err_to_node(err) }
		if is_err_node(acc) {
			return acc
		}
	}
	return acc
}

fn arr_native_fold_right(args []cx.Node, mut env MatchEnv) cx.Node {
	if args.len != 3 {
		return arr_native_err('[$array:fold-right] wrong arity — expected ARRAY, INIT, FN, got ${args.len}')
	}
	items := arr_native_items(args[0]) or {
		return arr_native_err('[$array:fold-right] the first argument must be an array (cxdm §2.5)')
	}
	fn_val := args[2]
	mut acc := args[1]
	for i := items.len - 1; i >= 0; i-- {
		acc = apply_fn_value(fn_val, [items[i], acc], mut env) or { return err_to_node(err) }
		if is_err_node(acc) {
			return acc
		}
	}
	return acc
}

fn arr_native_sort(args []cx.Node) cx.Node {
	if args.len != 1 {
		return arr_native_err('[$array:sort] wrong arity — expected 1 argument, got ${args.len}')
	}
	items := arr_native_items(args[0]) or {
		return arr_native_err('[$array:sort] the argument must be an array (cxdm §2.5)')
	}
	// The ordering delegates to the SAME comparator the [$sort] builtin
	// uses (similar_sort_key_of / similar_sort_keys), boxed back into an
	// array — one ordering authority for both surfaces.
	mut keys := []SimilarSortKey{cap: items.len}
	for i, it in items {
		keys << similar_sort_key_of(it, i)
	}
	order := similar_sort_keys(keys, false)
	return arr_native_rebuild(order.map(items[it]))
}
