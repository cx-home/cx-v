@[has_globals]
// The R-A8 operand-kind fault slot below is a thread-local global (the
// module already carries globals for the error hooks / effects trace).
module code

import cx

// stdlib_operand_fault.v — R-A8 (#955): an operand-KIND fault raised by a
// cx-stdlib native primitive answers a uniform `cx-err:CXER0100` err naming
//   (a) the argument position,
//   (b) the expected kind, and
//   (c) the function name AS WRITTEN.
// The internal `str-`/`math-`/… primitive spelling never appears in a
// message, and `none` out of a module dispatcher means ONLY "this
// dispatcher does not own this name" — a genuine name miss keeps the
// `user-undefined` / `no callable "…"` lane exactly as it was.
//
// WHY HERE, NOT AT THE 888 ARM SITES. Every stdlib arm is written
//
//     'str-split' {
//         s   := s_arg_str(args[0]) or { return none }
//         sep := s_arg_str(args[1]) or { return none }
//         return s_seq_str(str_split(s, sep))
//     }
//
// so the arm itself cannot tell "wrong kind" from "not my name": both are
// `none`. There are ~888 such `or { return none }` sites across the
// `vcx/code/stdlib_*.v` files, so the distinction is carried by the SHARED
// ARGUMENT READERS instead — each module's `*_arg_*` reader calls
// `note_operand_fault` on its reject path before returning none, recording
// the module, its primitive prefix, the expected kind and the offending
// node. `stdlib_builtin` clears that slot at the head of the dispatch chain
// and, when the WHOLE chain misses the name while a fault stands, converts
// the fault into the CXER0100 err (`operand_fault_err`).
//
// The conversion is self-limiting by construction: an arm that merely
// PROBES a reader and recovers (`… or { default }`) still returns a value,
// the chain hands that value back, and the recorded fault is discarded
// unread at the next dispatch. Only an arm that owned the name and then
// bailed reaches the terminal.
//
// A name that is ALSO a §6.5 core builtin (`contains`, `distinct`, …) is
// left to `builtin_args_diagnostic` in eval.v — that #536 lane already
// answers CXER0100 under the bare name the caller wrote, which is the more
// faithful "as written" rendering for those.
//
// THREAD NOTE: the slot is `@[thread_local]`, so a concurrent evaluator
// thread can never observe another thread's half-written fault; the slot is
// written and read inside one dispatch on one thread.

@[thread_local]
__global (
	cx_operand_fault_live     bool
	cx_operand_fault_module   string
	cx_operand_fault_prefix   string
	cx_operand_fault_expected string
	// 0 or 1 items — the offending argument node. Held as a slice because a
	// bare `cx.Node` global has no meaningful zero value.
	cx_operand_fault_node []cx.Node
)

// note_operand_fault records the operand-kind fault a stdlib argument
// reader just rejected. `mod` is the PUBLIC module name (`strings`),
// `prefix` the internal primitive prefix that must be stripped from the
// primitive name to recover the public function name (`str-`), `expected`
// the kind the slot requires (`string`, `int`, …), `n` the offending node.
fn note_operand_fault(mod string, prefix string, expected string, n cx.Node) {
	cx_operand_fault_live = true
	cx_operand_fault_module = mod
	cx_operand_fault_prefix = prefix
	cx_operand_fault_expected = expected
	cx_operand_fault_node = [n]
}

// clear_operand_fault drops any standing fault. Called at the head of the
// stdlib dispatch chain so a fault can only ever describe the call being
// dispatched right now.
fn clear_operand_fault() {
	if cx_operand_fault_live {
		cx_operand_fault_live = false
		cx_operand_fault_module = ''
		cx_operand_fault_prefix = ''
		cx_operand_fault_expected = ''
		cx_operand_fault_node = []cx.Node{}
	}
}

// operand_fault_written_name renders the function name AS WRITTEN from the
// internal primitive name: `str-split` under module `strings` / prefix
// `str-` is `strings:split`. A primitive whose name does NOT carry the
// module prefix is already spelled the way the caller wrote it (the
// `similar` module claims bare `distinct`/`contains`), so it is returned
// verbatim rather than being decorated with a qualifier the source never
// had.
fn operand_fault_written_name(name string, mod string, prefix string) string {
	if prefix != '' && name.starts_with(prefix) && name.len > prefix.len {
		return '${mod}:${name[prefix.len..]}'
	}
	// The reader did not know which module owns this primitive (the `bytes`
	// readers are shared with `diagram`; the codec surface dispatches one
	// name per registered format). Recover the module from the primitive's
	// own leading segment.
	dash := name.index('-') or { return name }
	if dash == 0 || dash == name.len - 1 {
		return name
	}
	head := name[..dash]
	owner := stdlib_prim_prefix_owners[head] or { return name }
	return '${owner}:${name[dash + 1..]}'
}

// stdlib_prim_prefix_owners maps a native primitive's leading segment to
// the PUBLIC cx-stdlib module that owns it. Only the three abbreviated
// spellings differ from the segment itself; the rest are listed so an
// unknown segment (a bare core-builtin name, a Ring-2 registry name) is
// left alone rather than being decorated with a module it does not have.
const stdlib_prim_prefix_owners = {
	'str':        'strings'
	'arr':        'array'
	'proc':       'process'
	'array':      'array'
	'bytes':      'bytes'
	'codec':      'codec'
	'crypto':     'crypto'
	'csv':        'csv'
	'diagram':    'diagram'
	'env':        'env'
	'format':     'format'
	'ft':         'ft'
	'geo':        'geo'
	'hash':       'hash'
	'html':       'html'
	'http':       'http'
	'i18n':       'i18n'
	'io':         'io'
	'json':       'json'
	'jsonschema': 'jsonschema'
	'locale':     'locale'
	'log':        'log'
	'map':        'map'
	'math':       'math'
	'mime':       'mime'
	'path':       'path'
	'prof':       'prof'
	'process':    'process'
	'random':     'random'
	're':         're'
	'sched':      'sched'
	'similar':    'similar'
	'strings':    'strings'
	'term':       'term'
	'test':       'test'
	'time':       'time'
	'url':        'url'
	'uuid':       'uuid'
	'validate':   'validate'
}

// operand_kind_label names the kind of the node that was rejected, for the
// "got …" half of the diagnostic.
fn operand_kind_label(n cx.Node) string {
	match n {
		cx.ScalarNode {
			return match n.data_type {
				.int_type { 'int' }
				.float_type { 'float' }
				.bool_type { 'bool' }
				.null_type { 'null' }
				.string_type { 'string' }
				.date_type { 'date' }
				.datetime_type { 'datetime' }
				.bytes_type { 'bytes' }
				.decimal_type { 'decimal' }
				.bigint_type { 'bigint' }
				.duration_type { 'duration' }
				.period_type { 'period' }
				.atom_type { 'atom' }
			}
		}
		cx.TextNode {
			return 'text'
		}
		cx.Element {
			if n.name == seq_marker_name || n.name == '' {
				if n.items.len == 0 {
					return 'absence (the empty sequence)'
				}
				return 'a ${n.items.len}-item sequence'
			}
			if n.name == arr_marker_name {
				return 'an array of ${n.items.len} item(s)'
			}
			if n.name == map_marker_name {
				return 'a map'
			}
			return 'an element [${n.name}]'
		}
		else {
			return 'a non-scalar node'
		}
	}
}

// operand_fault_position locates the offending node among the call's
// arguments (1-based). The stdlib arms read their arguments in order and
// bail at the FIRST rejected slot, so the recorded node is one of `args`
// and structural identity finds it. If it is not among them — a reader
// applied to a nested item rather than to an argument — the position falls
// back to the first argument that is not itself the expected kind, and
// finally to 1, so the diagnostic always names a slot.
fn operand_fault_position(args []cx.Node) int {
	if cx_operand_fault_node.len == 1 {
		bad := cx_operand_fault_node[0]
		for i, a in args {
			if a == bad {
				return i + 1
			}
		}
	}
	for i, a in args {
		if operand_kind_label(a) != cx_operand_fault_expected {
			return i + 1
		}
	}
	return 1
}

// operand_fault_err converts a standing operand-kind fault into the R-A8
// CXER0100 err VALUE (error-as-value model — it propagates as the call
// result per code.md §9.2). Returns none when no fault stands, or when the
// name is a §6.5 core builtin whose own #536 diagnostic is the better
// "as written" rendering.
fn operand_fault_err(name string, args []cx.Node) ?cx.Node {
	if !cx_operand_fault_live {
		return none
	}
	if builtin_dispatchable(name) {
		return none
	}
	written := operand_fault_written_name(name, cx_operand_fault_module, cx_operand_fault_prefix)
	pos := operand_fault_position(args)
	expected := cx_operand_fault_expected
	got := if cx_operand_fault_node.len == 1 {
		operand_kind_label(cx_operand_fault_node[0])
	} else {
		'an unusable operand'
	}
	clear_operand_fault()
	return mk_err('cx-err:CXER0100',
		'${written}: argument ${pos} expects ${expected}, got ${got} — operand-kind fault (E_ARG)')
}
