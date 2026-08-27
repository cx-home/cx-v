module code

import cx
import os
import runtime

// C.abort — immediate termination without flushing (spec §3.5 `abort`).
fn C.abort()

// stdlib_env.v — native primitives backing the `cx-stdlib/env` module
// (spec/stdlib_env.md). Environment is process-global + read-only from
// CX (no setters — see spec §2); argv is parsed once against a
// declarative argspec; process metadata + std-stream handles + exit /
// abort round out the surface.
//
// Per-module ownership: this whole module's implementation (the [?def]
// source bodies in `stdlib_src_env` AND the native primitives backing
// them) lives in this one file. Registered via bundled_stdlib_source /
// bundled_stdlib_names (stdlib_bundle.v) and the stdlib_builtin chain
// (stdlib_dispatch.v).
//
// Error values are returned as `[err :code cx-err:CXERxxxx :message …]`
// element nodes built via `mk_err` (eval.v); the renderer surfaces the
// code string, which the conformance harness matches against
// `--- out_err`.
//
// NOTE on `parse-args`: the public `parse-args(spec)` parses the PROGRAM
// argv (#926, RULED: PYE-2 — code.program_argv(), the launcher-installed
// [resource, ...program-args] vector). To keep the parser deterministically
// testable, the backing primitive `env-parse-args` accepts an OPTIONAL
// second argument — an explicit argv sequence. With one arg it reads
// the program argv; with two it parses the supplied sequence. The pure
// accessors (`flag` / `positional` / `remaining` / `usage`) operate on
// the parsed-args / spec element shapes and are fully deterministic.

// stdlib_src_env lives in stdlib_bundle.v (I4: the module-loader source
// embed is DATA, profile-invariant — a pack-less artifact still serves the
// CX wrapper source; its underlying builtins refuse as undefined callables,
// the same not-in-subset class as Ring-2 names without the platform module).

// ── error codes (spec §5) ────────────────────────────────────────────

const env_err_required_missing = 'cx-err:CXER2500' // E_ENV_REQUIRED_MISSING
const env_err_unknown_flag      = 'cx-err:CXER2501' // E_ENV_UNKNOWN_FLAG
const env_err_flag_type         = 'cx-err:CXER2502' // E_ENV_FLAG_TYPE_MISMATCH
const env_err_positional_missing = 'cx-err:CXER2503' // E_ENV_POSITIONAL_MISSING
const env_err_parse_failed      = 'cx-err:CXER2504' // E_ENV_PARSE_FAILED

// ── scalar / sequence / map / error builders ─────────────────────────

fn env_str(s string) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(s), data_type: cx.ScalarType.string_type }
}

fn env_int(n i64) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(n), data_type: cx.ScalarType.int_type }
}

fn env_float(f f64) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(f), data_type: cx.ScalarType.float_type }
}

fn env_bool(b bool) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(b), data_type: cx.ScalarType.bool_type }
}

fn env_null() cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(cx.NullValue{}), data_type: cx.ScalarType.null_type }
}

// env_empty is the absence channel: the empty node-set / empty sequence
// (`code.md` §9.1.2). An unset optional env var is "nothing here" — a pure,
// in-memory, optional read found nothing — NOT a `null` value (the §9.1.2.1
// no-conflation guard: no builtin returns `null` to mean "absent"). SAP C1.
fn env_empty() cx.Node {
	return cx.Element{ name: '__cx_seq__', items: [] }
}

fn env_seq(parts []string) cx.Node {
	mut items := []cx.Node{cap: parts.len}
	for p in parts {
		items << env_str(p)
	}
	return cx.Element{ name: '__cx_seq__', items: items }
}

fn env_seq_nodes(items []cx.Node) cx.Node {
	return cx.Element{ name: '__cx_seq__', items: items }
}

// env_map builds a `__cx_map__` envelope from key→value string pairs
// in sorted-key order (deterministic rendering).
fn env_map(m map[string]string) cx.Node {
	mut keys := m.keys()
	keys.sort()
	mut items := []cx.Node{cap: keys.len}
	for k in keys {
		items << cx.Element{ name: k, items: [env_str(m[k])] }
	}
	return cx.Element{ name: '__cx_map__', items: items }
}

fn env_err(err_code string, msg string) cx.Node {
	return mk_err(err_code, msg)
}

// ── argument extraction ──────────────────────────────────────────────

fn env_arg_str(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	note_operand_fault('env', 'env-', 'string', n)
	return none
}

fn env_arg_int(n cx.Node) ?i64 {
	if n is cx.ScalarNode {
		v := n.value
		if v is i64 {
			return v
		}
	}
	note_operand_fault('env', 'env-', 'int', n)
	return none
}

fn env_arg_float(n cx.Node) ?f64 {
	if n is cx.ScalarNode {
		v := n.value
		if v is f64 {
			return v
		}
		if v is i64 {
			return f64(v)
		}
	}
	note_operand_fault('env', 'env-', 'float', n)
	return none
}

fn env_arg_bool(n cx.Node) ?bool {
	if n is cx.ScalarNode {
		v := n.value
		if v is bool {
			return v
		}
	}
	note_operand_fault('env', 'env-', 'bool', n)
	return none
}

// ── value parsing (typed defaults, §3.1.1) ───────────────────────────

// env_parse_bool parses the pinned accepted set (case-insensitive):
//   true / false / 1 / 0 / yes / no / on / off
// Returns none for anything else (incl. empty string).
fn env_parse_bool(s string) ?bool {
	match s.to_lower() {
		'true', '1', 'yes', 'on' { return true }
		'false', '0', 'no', 'off' { return false }
		else { return none }
	}
}

// ── §3.1 environment variables ───────────────────────────────────────

fn env_var(name string) cx.Node {
	// §9.1.2: an unset variable is absence (empty sequence), not `null`. The
	// caller extracts with `[?else]` (getOrElse) or `var-required` for a fault.
	v := os.getenv_opt(name) or { return env_empty() }
	return env_str(v)
}

fn env_has_var(name string) cx.Node {
	if _ := os.getenv_opt(name) {
		return env_bool(true)
	}
	return env_bool(false)
}

fn env_vars() cx.Node {
	return env_map(os.environ())
}

fn env_var_or_default(name string, def string) cx.Node {
	v := os.getenv_opt(name) or { return env_str(def) }
	return env_str(v)
}

fn env_var_int(name string, def i64) cx.Node {
	v := os.getenv_opt(name) or { return env_int(def) }
	parsed := v.i64()
	// V's i64() returns 0 on un-parseable input, so re-validate the
	// round-trip: a set-but-unparseable value is an error (§3.1.1), not
	// a silent fall-back to the default.
	if parsed.str() != v.trim_space() {
		return env_err(env_err_parse_failed,
			'E_ENV_PARSE_FAILED: env var ${name}=${v} is not a valid int')
	}
	return env_int(parsed)
}

fn env_var_float(name string, def f64) cx.Node {
	v := os.getenv_opt(name) or { return env_float(def) }
	t := v.trim_space()
	if !env_float_parseable(t) {
		return env_err(env_err_parse_failed,
			'E_ENV_PARSE_FAILED: env var ${name}=${v} is not a valid float')
	}
	return env_float(t.f64())
}

// env_float_parseable validates that a string is a well-formed decimal
// float (optionally signed, with optional fraction / exponent). V's
// `.f64()` silently yields 0 on garbage, so we gate it explicitly.
fn env_float_parseable(s string) bool {
	if s == '' {
		return false
	}
	mut i := 0
	mut seen_digit := false
	mut seen_dot := false
	mut seen_exp := false
	if s[i] == `+` || s[i] == `-` {
		i++
	}
	for i < s.len {
		c := s[i]
		if c >= `0` && c <= `9` {
			seen_digit = true
			i++
		} else if c == `.` && !seen_dot && !seen_exp {
			seen_dot = true
			i++
		} else if (c == `e` || c == `E`) && !seen_exp && seen_digit {
			seen_exp = true
			i++
			if i < s.len && (s[i] == `+` || s[i] == `-`) {
				i++
			}
			// require at least one digit in the exponent
			if i >= s.len || !(s[i] >= `0` && s[i] <= `9`) {
				return false
			}
		} else {
			return false
		}
	}
	return seen_digit
}

fn env_var_bool(name string, def bool) cx.Node {
	v := os.getenv_opt(name) or { return env_bool(def) }
	b := env_parse_bool(v) or {
		return env_err(env_err_parse_failed,
			'E_ENV_PARSE_FAILED: env var ${name}=${v} is not a valid bool')
	}
	return env_bool(b)
}

fn env_var_required(name string) cx.Node {
	v := os.getenv_opt(name) or {
		return env_err(env_err_required_missing,
			'E_ENV_REQUIRED_MISSING: required env var ${name} is not set')
	}
	return env_str(v)
}

// ── §3.3 process metadata ────────────────────────────────────────────

fn env_pid() cx.Node {
	return env_int(i64(os.getpid()))
}

fn env_ppid() cx.Node {
	return env_int(i64(os.getppid()))
}

fn env_executable_path() cx.Node {
	return env_str(os.executable())
}

fn env_cwd() cx.Node {
	return env_str(os.getwd())
}

fn env_hostname() cx.Node {
	h := os.hostname() or { return env_str('') }
	return env_str(h)
}

fn env_username() cx.Node {
	u := os.loginname() or { return env_str('') }
	return env_str(u)
}

fn env_os_name() cx.Node {
	return env_str(os.user_os())
}

fn env_os_arch() cx.Node {
	mut a := 'unknown'
	$if amd64 {
		a = 'amd64'
	}
	$if arm64 {
		a = 'arm64'
	}
	$if i386 {
		a = 'x86'
	}
	$if arm32 {
		a = 'arm'
	}
	return env_str(a)
}

fn env_cpu_count() cx.Node {
	return env_int(i64(runtime.nr_cpus()))
}

// ── §3.4 standard streams ────────────────────────────────────────────
//
// Handle elements carry `fd` + `name` as ATTRIBUTES (data has
// no slots; scalar fields are attributes) so cx-stdlib/io can dispatch on
// them. The handle shape is `[std-stream name=<n> fd=<n>]`; actual
// reading/writing lives in cx-stdlib/io. Reads use `@name` / `@fd`.

fn env_std_handle(name string, fd i64) cx.Node {
	return cx.Element{
		name:  'std-stream'
		attrs: [
			cx.new_attribute('name', cx.ScalarValue(name), cx.AttributeMeta{}),
			cx.new_attribute('fd', cx.ScalarValue(fd), cx.AttributeMeta{
				data_type: ?string('int')
			}),
		]
	}
}

// ── §3.5 process termination ─────────────────────────────────────────
//
// `exit` / `abort` terminate the host process. Inside the conformance
// harness this would tear down the test runner, so the conformance
// fixtures intentionally do NOT exercise the terminating path; the
// surface is present and dispatches to the real syscalls in production.

fn env_exit(exit_code i64) cx.Node {
	// Flush pending I/O before terminating (env.md §3.5): C.exit flushes
	// stdout, but stderr is flushed explicitly here so a "print report,
	// then exit N" CLI never loses buffered output on either stream.
	os.flush()
	os.stderr().flush()
	exit(int(exit_code))
	return env_null()
}

fn env_abort() cx.Node {
	os.flush()
	C.abort()
	return env_null()
}

// ── §3.2 argv + argspec parsing ──────────────────────────────────────

// FlagSpec / PositionalSpec mirror the declarative argspec element
// (§2): [argspec [flag :name … :short … :type … :default … :required …]
//                [positional :name … :type … :required …]].
struct FlagSpec {
	name     string
	short    string
	typ      string // bool / int / float / string
	default  cx.Node // optional declared default (env_null when absent)
	has_def  bool
	required bool
}

struct PositionalSpec {
	name     string
	typ      string
	required bool
}

struct ArgSpec {
mut:
	flags         []FlagSpec
	positionals   []PositionalSpec
	allow_unknown bool
}

// env_slot_node returns the value node of an argspec field. 
// scalar fields are ATTRIBUTES (`[flag name='x' short='v' type='bool']`),
// so the attribute is read first; a legacy `:label` slot child is the
// transitional fallback until all argspec fixtures migrate to attribute
// form. (Despite the name, this reads an attribute when present.)
fn env_slot_node(el cx.Element, label string) ?cx.Node {
	if sv := el.attr_val(label) {
		return cx.Node(cx.ScalarNode{ value: sv })
	}
	target := '${slot_child_prefix}${label}'
	for it in el.items {
		if it is cx.Element {
			if it.name == target {
				if it.items.len > 0 {
					return it.items[0]
				}
				return none
			}
		}
	}
	return none
}

// env_node_word extracts a bareword from a node: a string scalar, an
// atom scalar (`:NAME`), or a bare identifier (AliasNode). Argspec
// modifiers like `:type int` / `:type bool` arrive as bare identifiers,
// while `:name "verbose"` arrives as a quoted string — both must read
// as their textual form.
fn env_node_word(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	if n is cx.AliasNode {
		return n.name
	}
	if n is cx.TextNode {
		return n.value
	}
	return none
}

// env_slot_str reads a textual `:label` slot (string / atom / bareword).
fn env_slot_str(el cx.Element, label string) ?string {
	n := env_slot_node(el, label) or { return none }
	return env_node_word(n)
}

// env_slot_bool reads a bool-valued `:label` slot (defaults to `false`
// when absent or non-bool).
fn env_slot_bool(el cx.Element, label string) bool {
	n := env_slot_node(el, label) or { return false }
	return env_arg_bool(n) or { false }
}

// env_build_spec parses the argspec element into an ArgSpec.
fn env_build_spec(spec cx.Node) ?ArgSpec {
	if spec !is cx.Element {
		return none
	}
	el := spec as cx.Element
	mut out := ArgSpec{
		allow_unknown: env_slot_bool(el, 'allow-unknown')
	}
	for it in el.items {
		if it !is cx.Element {
			continue
		}
		child := it as cx.Element
		// skip slot children (e.g. :allow-unknown) on the argspec head
		if child.name.starts_with(slot_child_prefix) {
			continue
		}
		match child.name {
			'flag' {
				nm := env_slot_str(child, 'name') or { continue }
				short := env_slot_str(child, 'short') or { '' }
				typ := env_slot_str(child, 'type') or { 'string' }
				mut has_def := false
				mut def := env_null()
				if dn := env_slot_node(child, 'default') {
					has_def = true
					def = dn
				}
				out.flags << FlagSpec{
					name:     nm
					short:    short
					typ:      typ
					default:  def
					has_def:  has_def
					required: env_slot_bool(child, 'required')
				}
			}
			'positional' {
				nm := env_slot_str(child, 'name') or { continue }
				typ := env_slot_str(child, 'type') or { 'string' }
				out.positionals << PositionalSpec{
					name:     nm
					typ:      typ
					required: env_slot_bool(child, 'required')
				}
			}
			else {}
		}
	}
	return out
}

// env_find_flag locates a flag spec by long name.
fn env_find_flag_by_name(spec ArgSpec, name string) ?FlagSpec {
	for f in spec.flags {
		if f.name == name {
			return f
		}
	}
	return none
}

// env_find_flag_by_short locates a flag spec by short name.
fn env_find_flag_by_short(spec ArgSpec, short string) ?FlagSpec {
	if short == '' {
		return none
	}
	for f in spec.flags {
		if f.short == short {
			return f
		}
	}
	return none
}

// env_coerce coerces a raw string flag/positional value to the declared
// type. Returns an err-value (CXER2502) on a mismatch.
fn env_coerce(typ string, raw string) cx.Node {
	match typ {
		'int' {
			t := raw.trim_space()
			parsed := t.i64()
			if parsed.str() != t {
				return env_err(env_err_flag_type,
					'E_ENV_FLAG_TYPE_MISMATCH: ${raw} is not a valid int')
			}
			return env_int(parsed)
		}
		'float' {
			t := raw.trim_space()
			if !env_float_parseable(t) {
				return env_err(env_err_flag_type,
					'E_ENV_FLAG_TYPE_MISMATCH: ${raw} is not a valid float')
			}
			return env_float(t.f64())
		}
		'bool' {
			b := env_parse_bool(raw) or {
				return env_err(env_err_flag_type,
					'E_ENV_FLAG_TYPE_MISMATCH: ${raw} is not a valid bool')
			}
			return env_bool(b)
		}
		else {
			// string (and any unknown declared type → string passthrough)
			return env_str(raw)
		}
	}
}

// env_parse_argv runs the argument parser over `argv` (argv[0] is the
// program name / executable path and is NOT consumed as a flag or
// positional). Returns the parsed-args element
//   [args [flags …] [positional [sequence …]] [unparsed [sequence …]]]
// or an err-value on the first parse error.
fn env_parse_argv(spec ArgSpec, argv []string) cx.Node {
	mut flag_vals := map[string]cx.Node{}
	mut positionals := []string{}
	mut i := 1 // skip argv[0]
	mut flags_done := false
	for i < argv.len {
		tok := argv[i]
		if flags_done {
			positionals << tok
			i++
			continue
		}
		if tok == '--' {
			flags_done = true
			i++
			continue
		}
		if tok.starts_with('--') {
			// long flag: --name or --name=value
			body := tok[2..]
			mut name := body
			mut inline_val := ''
			mut has_inline := false
			if eq := body.index('=') {
				name = body[..eq]
				inline_val = body[eq + 1..]
				has_inline = true
			}
			fspec := env_find_flag_by_name(spec, name) or {
				if spec.allow_unknown {
					i++
					continue
				}
				return env_err(env_err_unknown_flag,
					'E_ENV_UNKNOWN_FLAG: --${name}')
			}
			if fspec.typ == 'bool' && !has_inline {
				flag_vals[fspec.name] = env_bool(true)
				i++
				continue
			}
			mut raw := ''
			if has_inline {
				raw = inline_val
			} else {
				if i + 1 >= argv.len {
					return env_err(env_err_flag_type,
						'E_ENV_FLAG_TYPE_MISMATCH: --${name} requires a value')
				}
				raw = argv[i + 1]
				i++
			}
			coerced := env_coerce(fspec.typ, raw)
			if is_err_value(coerced) {
				return coerced
			}
			flag_vals[fspec.name] = coerced
			i++
			continue
		}
		if tok.starts_with('-') && tok.len > 1 {
			// short flag(s): clustering (-vn 10 == -v -n 10). The last
			// flag in a cluster may take the following arg as its value.
			cluster := tok[1..]
			mut ci := 0
			mut consumed_next := false
			for ci < cluster.len {
				short := cluster[ci..ci + 1]
				fspec := env_find_flag_by_short(spec, short) or {
					if spec.allow_unknown {
						ci++
						continue
					}
					return env_err(env_err_unknown_flag,
						'E_ENV_UNKNOWN_FLAG: -${short}')
				}
				if fspec.typ == 'bool' {
					flag_vals[fspec.name] = env_bool(true)
					ci++
					continue
				}
				// value-taking short flag: rest of the cluster (if any) is
				// the inline value, else the next argv token.
				mut raw := ''
				if ci + 1 < cluster.len {
					raw = cluster[ci + 1..]
					ci = cluster.len
				} else {
					if i + 1 >= argv.len {
						return env_err(env_err_flag_type,
							'E_ENV_FLAG_TYPE_MISMATCH: -${short} requires a value')
					}
					raw = argv[i + 1]
					consumed_next = true
					ci = cluster.len
				}
				coerced := env_coerce(fspec.typ, raw)
				if is_err_value(coerced) {
					return coerced
				}
				flag_vals[fspec.name] = coerced
			}
			if consumed_next {
				i++
			}
			i++
			continue
		}
		// bare positional
		positionals << tok
		i++
	}

	// Apply declared flag defaults for flags not supplied.
	for f in spec.flags {
		if f.name in flag_vals {
			continue
		}
		if f.required {
			return env_err(env_err_required_missing,
				'E_ENV_REQUIRED_MISSING: required flag --${f.name} not supplied')
		}
		if f.has_def {
			flag_vals[f.name] = f.default
		} else if f.typ == 'bool' {
			// bool flags default to false when unspecified
			flag_vals[f.name] = env_bool(false)
		}
	}

	// Bind declared positionals in order; surplus go to `remaining`.
	mut pos_named := map[string]cx.Node{}
	mut remaining := []string{}
	for idx, pspec in spec.positionals {
		if idx < positionals.len {
			coerced := env_coerce(pspec.typ, positionals[idx])
			if is_err_value(coerced) {
				return coerced
			}
			pos_named[pspec.name] = coerced
		} else if pspec.required {
			return env_err(env_err_positional_missing,
				'E_ENV_POSITIONAL_MISSING: required positional ${pspec.name} not supplied')
		}
	}
	if positionals.len > spec.positionals.len {
		for k in spec.positionals.len .. positionals.len {
			remaining << positionals[k]
		}
	}

	// Assemble the parsed-args element.
	mut flags_items := []cx.Node{}
	mut fkeys := flag_vals.keys()
	fkeys.sort()
	for k in fkeys {
		fv := flag_vals[k] or { env_null() }
		flags_items << cx.Element{ name: k, items: [fv] }
	}
	mut pos_items := []cx.Node{}
	mut pkeys := pos_named.keys()
	pkeys.sort()
	for k in pkeys {
		pv := pos_named[k] or { env_null() }
		pos_items << cx.Element{ name: k, items: [pv] }
	}
	return cx.Element{
		name:  'args'
		items: [
			cx.Node(cx.Element{ name: 'flags', items: flags_items }),
			cx.Node(cx.Element{ name: 'positional', items: pos_items }),
			cx.Node(cx.Element{ name: 'remaining', items: [env_seq(remaining)] }),
		]
	}
}

// env_parse_args is the primitive behind `parse-args`. With one arg
// (the spec) it parses the PROGRAM argv (#926, RULED: PYE-2 — the
// launcher-installed [resource, ...program-args] vector, never cx's own
// flags); with a second arg (an explicit argv sequence) it parses that —
// used by the deterministic conformance fixtures.
fn env_parse_args(args []cx.Node) ?cx.Node {
	if args.len == 0 {
		return none
	}
	spec := env_build_spec(args[0]) or { return none }
	mut argv := []string{}
	if args.len >= 2 {
		if args[1] is cx.Element {
			seq := args[1] as cx.Element
			if seq.name == '__cx_seq__' || seq.name == '__cx_arr__' {
				for it in seq.items {
					argv << env_arg_str(it) or { return none }
				}
			}
		}
	} else {
		argv = program_argv()
	}
	return env_parse_argv(spec, argv)
}

// env_child_named returns the body node of the first child element named
// `name` of `el`, or none.
fn env_child_named(el cx.Element, name string) ?cx.Element {
	for it in el.items {
		if it is cx.Element {
			if it.name == name {
				return it
			}
		}
	}
	return none
}

// env_flag reads a parsed flag value by name from a parsed-args element.
fn env_flag(parsed cx.Node, name string) cx.Node {
	if parsed !is cx.Element {
		return env_null()
	}
	el := parsed as cx.Element
	flags := env_child_named(el, 'flags') or { return env_null() }
	entry := env_child_named(flags, name) or { return env_null() }
	if entry.items.len > 0 {
		return entry.items[0]
	}
	return env_null()
}

// env_positional reads a parsed positional value by spec name.
fn env_positional(parsed cx.Node, name string) cx.Node {
	if parsed !is cx.Element {
		return env_null()
	}
	el := parsed as cx.Element
	pos := env_child_named(el, 'positional') or { return env_null() }
	entry := env_child_named(pos, name) or { return env_null() }
	if entry.items.len > 0 {
		return entry.items[0]
	}
	return env_null()
}

// env_remaining returns the `remaining` sequence of a parsed-args
// element.
fn env_remaining(parsed cx.Node) cx.Node {
	if parsed !is cx.Element {
		return env_seq([])
	}
	el := parsed as cx.Element
	rem := env_child_named(el, 'remaining') or { return env_seq([]) }
	if rem.items.len > 0 {
		inner := rem.items[0]
		if inner is cx.Element {
			return env_seq_nodes(inner.items.clone())
		}
	}
	return env_seq([])
}

// env_usage renders a human-readable usage string from the argspec.
fn env_usage(spec cx.Node) cx.Node {
	parsed := env_build_spec(spec) or {
		return env_str('usage: <program>')
	}
	mut sb := []string{}
	sb << 'usage: <program>'
	for f in parsed.flags {
		mut tok := '--${f.name}'
		if f.short != '' {
			tok = '-${f.short}/${tok}'
		}
		if f.typ != 'bool' {
			tok += ' <${f.typ}>'
		}
		if f.required {
			sb << tok
		} else {
			sb << '[${tok}]'
		}
	}
	for p in parsed.positionals {
		if p.required {
			sb << '<${p.name}>'
		} else {
			sb << '[${p.name}]'
		}
	}
	return env_str(sb.join(' '))
}

// ── dispatch table ───────────────────────────────────────────────────

// env_uncapped_prims are the capability-free env primitives (spec/std-lib/env.md
// §7 + security.md §2). Two groups, neither gated:
//   • pure transforms — OS identity + accessors over already-parsed args;
//   • ambient process basics — standard streams, process identity, argv,
//     CPU count, and process exit/abort. Per env.md §7 these are "intrinsic
//     to the running process and are never gated" (the §7 table's `(none)`
//     row). They are effectful but require no capability.
// Everything else env handles (var reads, hostname/username, cwd/exec-path)
// is gated — `env` or `read` — and raises CXER0271 when the grant is absent.
// `parse-args` reads the process argument vector (os.args) and then parses
// purely; argv itself is in the §7 `(none)` row, so parse-args is uncapped
// too (gating it behind `env` would deny a CLI parsing its own argv).
// env_uncapped_prims lives in effect_alignment.v — I4: profile-invariant
// purity data, outside this `-d cx_no_pack_env`-gated file.

// env_read_prims are the env names gated under `read` rather than `env`:
// cwd / executable-path disclose filesystem layout (env.md §7 `read` row),
// not environment/identity, so they charge the filesystem-read capability.
const env_read_prims = ['env-cwd', 'env-executable-path']

fn env_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	// Capability gate (security.md §4): fail-closed BEFORE any arg/type
	// handling, but only for names this module actually owns (an unknown
	// name must fall through to the next module, not deny). Per env.md §7
	// the charged capability is `read` for filesystem-layout disclosure
	// (cwd / executable-path) and `env` for everything else gated.
	if name.starts_with('env-') && name !in env_uncapped_prims {
		cap := if name in env_read_prims { 'read' } else { 'env' }
		if d := cap_guard(cap, name) {
			return d
		}
	}
	match name {
		// §3.1 environment variables
		'env-var' {
			nm := env_arg_str(args[0]) or { return none }
			return env_var(nm)
		}
		'env-has-var' {
			nm := env_arg_str(args[0]) or { return none }
			return env_has_var(nm)
		}
		'env-vars' {
			return env_vars()
		}
		'env-var-or-default' {
			nm := env_arg_str(args[0]) or { return none }
			def := env_arg_str(args[1]) or { return none }
			return env_var_or_default(nm, def)
		}
		'env-var-int' {
			nm := env_arg_str(args[0]) or { return none }
			def := env_arg_int(args[1]) or { return none }
			return env_var_int(nm, def)
		}
		'env-var-float' {
			nm := env_arg_str(args[0]) or { return none }
			def := env_arg_float(args[1]) or { return none }
			return env_var_float(nm, def)
		}
		'env-var-bool' {
			nm := env_arg_str(args[0]) or { return none }
			def := env_arg_bool(args[1]) or { return none }
			return env_var_bool(nm, def)
		}
		'env-var-required' {
			nm := env_arg_str(args[0]) or { return none }
			return env_var_required(nm)
		}
		// §3.2 command-line arguments (#926, RULED: PYE-2/PYE-3): the
		// PROGRAM argv installed by the launcher ([resource,
		// ...program-args] — sys.argv shape), never cx's own flags.
		// Ungated (PYE-3) — see program_argv.v.
		'env-argv' {
			return env_seq(program_argv())
		}
		'env-parse-args' {
			return env_parse_args(args)
		}
		'env-flag' {
			nm := env_arg_str(args[1]) or { return none }
			return env_flag(args[0], nm)
		}
		'env-positional' {
			nm := env_arg_str(args[1]) or { return none }
			return env_positional(args[0], nm)
		}
		'env-remaining' {
			return env_remaining(args[0])
		}
		'env-usage' {
			return env_usage(args[0])
		}
		// §3.3 process metadata
		'env-pid' {
			return env_pid()
		}
		'env-ppid' {
			return env_ppid()
		}
		'env-executable-path' {
			return env_executable_path()
		}
		'env-cwd' {
			return env_cwd()
		}
		'env-hostname' {
			return env_hostname()
		}
		'env-username' {
			return env_username()
		}
		'env-os-name' {
			return env_os_name()
		}
		'env-os-arch' {
			return env_os_arch()
		}
		'env-cpu-count' {
			return env_cpu_count()
		}
		// §3.4 standard streams
		'env-stdin' {
			return env_std_handle('stdin', 0)
		}
		'env-stdout' {
			return env_std_handle('stdout', 1)
		}
		'env-stderr' {
			return env_std_handle('stderr', 2)
		}
		// §3.5 process termination
		'env-exit' {
			exit_code := env_arg_int(args[0]) or { return none }
			return env_exit(exit_code)
		}
		'env-abort' {
			return env_abort()
		}
		else {
			return none
		}
	}
}
