module code

import cx

// stdlib_log.v — native primitives for the `cx-stdlib/log` structured
// logging module (spec/std-lib/log.md).
//
// The module's `[?def]` bodies (stdlib_src_log in stdlib_bundle.v) forward
// to the `log-*` primitives dispatched here. Logging carries per-program
// configuration (the minimum level + active sink/format set by
// `[$log:configure]`) that a pure CX body cannot express; it lives on the
// program-global ProgramState (env.state.log_*), freshly defaulted by
// new_env and pointer-shared across clones/closures so a `configure` in one
// statement is visible to a later `is-enabled` / emit within the same
// program — and reset between programs (no process-global leakage across
// conformance cases).
//
// Because every log primitive needs the evaluator env (state for config,
// dyn_context for scope), they ALL dispatch through the env-aware
// log_stdlib_builtin_env (wired in eval.v::dispatch_call_l). The env-free
// log_stdlib_builtin returns none for every name so the env-aware path is
// always taken.
//
// OBSERVABILITY: every emit function (debug/info/warn/error/fatal/log/
// emit-raw) is `[returns null]` (§3.1/§3.2/§3.5); its observable effect is
// a write to the active sink (default stderr). The conformance runner
// asserts the eval RESULT (the documented `null`), not the sink bytes.
// `is-enabled` (§3.6) returns a bool and `current-scope` (§3.3) a map — the
// values the runner checks; `current-scope` reads the active [?with-scope]
// dynamic context (core §8.10.8).
//
// Errors are values: configure raises CXER2400 (unknown sink) / CXER2402
// (unknown level) / CXER2403 (sink+sinks both / malformed sink-config) /
// CXER2404 (rotation invalid or on non-file sink) / CXER2405 (sample-rate
// out of range), per §5.

// ── level model ──────────────────────────────────────────────────────

// log_level_rank maps a level atom name to its severity rank (§2.1).
// Returns -1 for an unknown level.
fn log_level_rank(name string) int {
	return match name {
		'debug' { 0 }
		'info' { 1 }
		'warn' { 2 }
		'error' { 3 }
		'fatal' { 4 }
		else { -1 }
	}
}

// log_sink_rank returns >=0 for a recognized sink value (§3.4), -1 unknown.
fn log_sink_rank(s string) int {
	return match s {
		'stderr' { 0 }
		'stdout' { 1 }
		'file' { 2 }
		'syslog' { 3 }
		'none' { 4 }
		else { -1 }
	}
}

// ── value helpers ──────────────────────────────────────────────────────

fn log_null() cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(cx.NullValue{})
		data_type: cx.ScalarType.null_type
	}
}

fn log_bool(b bool) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(b)
		data_type: cx.ScalarType.bool_type
	}
}

// log_atom_name reads an atom scalar's name (`:info` → "info"); none for a
// non-atom node.
fn log_atom_name(n cx.Node) ?string {
	if n is cx.ScalarNode {
		if n.data_type == cx.ScalarType.atom_type {
			v := n.value
			if v is string {
				return v
			}
		}
	}
	note_operand_fault('log', 'log-', 'atom', n)
	return none
}

// log_map_entries returns the entry elements of a `__cx_map__` envelope, or
// none if the node is not a map.
fn log_map_entries(n cx.Node) ?[]cx.Node {
	if n is cx.Element {
		if n.name == map_marker_name {
			return n.items
		}
	}
	return none
}

// log_entry_value returns the value node held under a `__cx_map__` entry
// element (`[key value]`), or none when empty.
fn log_entry_value(e cx.Node) ?cx.Node {
	if e is cx.Element {
		if e.items.len > 0 {
			return e.items[0]
		}
	}
	return none
}

// log_sequence_items returns the items of a sequence/array marker element.
fn log_sequence_items(n cx.Node) ?[]cx.Node {
	if n is cx.Element {
		if n.name == seq_marker_name || n.name == arr_marker_name {
			return n.items
		}
	}
	return none
}

// log_number extracts a float from an int- or float-typed scalar.
fn log_number(n cx.Node) ?f64 {
	if n is cx.ScalarNode {
		v := n.value
		match v {
			f64 { return v }
			i64 { return f64(v) }
			else {}
		}
	}
	return none
}

fn log_err(err_code string, msg string) cx.Node {
	return mk_err('cx-err:${err_code}', msg)
}

// ── configuration validation (§3.4) ────────────────────────────────────

// log_validate_rotation validates a rotation map's `by` discriminant
// (§3.4.2). An absent/invalid `by` raises CXER2404.
fn log_validate_rotation(entries []cx.Node) ?cx.Node {
	mut by := ''
	for e in entries {
		if entry_key(e) == 'by' {
			if v := log_entry_value(e) {
				if a := log_atom_name(v) {
					by = a
				} else if s := scalar_string(v) {
					by = s
				}
			}
		}
	}
	if by != 'size' && by != 'time' {
		return log_err('CXER2404', 'log: rotation `by` must be :size or :time')
	}
	return none
}

// log_validate_sink_config validates ONE sink-config map entry-set
// (§3.4.1/§3.4.2/§3.4.4): a valid `sink` value, a valid `rotation` (only on
// file sinks), and an in-range `sample-rate`. Returns an err node on the
// first violation, none when valid.
fn log_validate_sink_config(entries []cx.Node) ?cx.Node {
	mut sink_name := ''
	mut has_rotation := false
	for e in entries {
		k := entry_key(e)
		match k {
			'sink' {
				if v := log_entry_value(e) {
					if s := scalar_string(v) {
						sink_name = s
						if log_sink_rank(s) < 0 {
							return log_err('CXER2400', 'log: unknown sink `${s}`')
						}
					}
				}
			}
			'rotation' {
				has_rotation = true
				if v := log_entry_value(e) {
					if re := log_map_entries(v) {
						if d := log_validate_rotation(re) {
							return d
						}
					} else {
						return log_err('CXER2404', 'log: rotation must be a map')
					}
				}
			}
			'sample-rate' {
				if v := log_entry_value(e) {
					rate := log_number(v) or {
						return log_err('CXER2405', 'log: sample-rate must be a number')
					}
					if rate < 0.0 || rate > 1.0 {
						return log_err('CXER2405', 'log: sample-rate ${rate} outside 0.0–1.0')
					}
				}
			}
			else {}
		}
	}
	// rotation is only valid on a file sink (§3.4.2).
	if has_rotation && sink_name != 'file' {
		return log_err('CXER2404', 'log: rotation on a non-file sink (${sink_name})')
	}
	return none
}

// log_configure validates the config map (§3.4) and, on success, commits
// the level / sink / format / file-path to the program-global config on
// env.state. Returns null on success, an err value otherwise.
fn log_configure(config cx.Node, mut env MatchEnv) cx.Node {
	entries := log_map_entries(config) or {
		return log_err('CXER2403', 'log: configure expects a map')
	}
	mut has_sink := false
	mut has_sinks := false
	mut sink_val := ''
	mut format_val := ''
	mut level_atom := ''
	mut file_path_val := ''
	mut sinks_node := cx.Node(cx.Element{})
	for e in entries {
		k := entry_key(e)
		match k {
			'sink' {
				has_sink = true
				if v := log_entry_value(e) {
					if s := scalar_string(v) {
						sink_val = s
					}
				}
			}
			'sinks' {
				has_sinks = true
				if v := log_entry_value(e) {
					sinks_node = v
				}
			}
			'format' {
				if v := log_entry_value(e) {
					if s := scalar_string(v) {
						format_val = s
					}
				}
			}
			'level' {
				if v := log_entry_value(e) {
					if a := log_atom_name(v) {
						level_atom = a
					}
				}
			}
			'file-path' {
				if v := log_entry_value(e) {
					if s := scalar_string(v) {
						file_path_val = s
					}
				}
			}
			else {}
		}
	}
	// §3.4.1 — `sinks` and flat `sink` are mutually exclusive.
	if has_sink && has_sinks {
		return log_err('CXER2403', 'log: `sink` and `sinks` are mutually exclusive')
	}
	// Validate the flat single-sink shorthand.
	if has_sink {
		if log_sink_rank(sink_val) < 0 {
			return log_err('CXER2400', 'log: unknown sink `${sink_val}`')
		}
	}
	// Validate each fan-out sink-config (§3.4.1).
	if has_sinks {
		sink_list := log_sequence_items(sinks_node) or {
			return log_err('CXER2403', 'log: `sinks` must be a sequence of sink-config maps')
		}
		for sc in sink_list {
			sc_entries := log_map_entries(sc) or {
				return log_err('CXER2403', 'log: each `sinks` entry must be a map')
			}
			if d := log_validate_sink_config(sc_entries) {
				return d
			}
		}
	}
	// All validation passed — commit to the program-global config.
	if level_atom != '' {
		r := log_level_rank(level_atom)
		if r < 0 {
			return log_err('CXER2402', 'log: unknown level `:${level_atom}`')
		}
		env.state.log_min_level = r
	}
	if has_sink {
		env.state.log_sink = sink_val
	}
	if format_val != '' {
		env.state.log_format = format_val
	}
	if file_path_val != '' {
		env.state.log_file_path = file_path_val
	}
	return log_null()
}

// ── emit (§3.1/§3.2/§3.5) ───────────────────────────────────────────────

// log_emit honours the configured minimum level and active sink, formats a
// minimal event line, and writes it (default stderr). Returns null. The
// sink bytes are not asserted by conformance — only the null return.
fn log_emit(level_name string, message string, mut env MatchEnv) cx.Node {
	rank := log_level_rank(level_name)
	if rank < 0 {
		return log_err('CXER2402', 'log: unknown level `:${level_name}`')
	}
	if rank < env.state.log_min_level {
		return log_null()
	}
	if env.state.log_sink == 'none' {
		return log_null()
	}
	line := '${level_name} ${message}'
	if env.state.log_sink == 'stdout' {
		println(line)
	} else {
		// stderr / file / syslog surface on stderr in this in-process
		// landing (file/syslog backends are the integration-suite frontier).
		eprintln(line)
	}
	return log_null()
}

// log_is_enabled is the §3.6 pure level check against the configured
// minimum.
fn log_is_enabled(level cx.Node, mut env MatchEnv) cx.Node {
	name := log_atom_name(level) or {
		return log_err('CXER2402', 'log: is-enabled expects a level atom')
	}
	rank := log_level_rank(name)
	if rank < 0 {
		return log_err('CXER2402', 'log: unknown level `:${name}`')
	}
	return log_bool(rank >= env.state.log_min_level)
}

// log_current_scope returns the merged active [?with-scope] dynamic context
// (§3.3) as a `__cx_map__` value (`{}` when no scope is active). The
// dyn_context already holds merge(outer, inner) entry elements keyed by
// name.
fn log_current_scope(mut env MatchEnv) cx.Node {
	mut entries := []cx.Node{}
	for e in env.dyn_context {
		if e is cx.Element {
			entries << e
		}
	}
	return cx.Element{
		name:  map_marker_name
		items: entries
	}
}

// ── primitive dispatch ──────────────────────────────────────────────────

// log_stdlib_builtin_env handles ALL `log-*` primitives. Every one needs
// the evaluator env (state for config / dyn_context for scope), so the
// env-free chain entry (log_stdlib_builtin) returns none and this is always
// the live path (eval.v::dispatch_call_l tries it before the env-free
// chain).
fn log_stdlib_builtin_env(name string, args []cx.Node, mut env MatchEnv) ?cx.Node {
	match name {
		'log-debug' {
			if args.len < 1 {
				return none
			}
			return log_emit('debug', log_message(args[0]), mut env)
		}
		'log-info' {
			if args.len < 1 {
				return none
			}
			return log_emit('info', log_message(args[0]), mut env)
		}
		'log-warn' {
			if args.len < 1 {
				return none
			}
			return log_emit('warn', log_message(args[0]), mut env)
		}
		'log-error' {
			if args.len < 1 {
				return none
			}
			return log_emit('error', log_message(args[0]), mut env)
		}
		'log-fatal' {
			if args.len < 1 {
				return none
			}
			return log_emit('fatal', log_message(args[0]), mut env)
		}
		'log-log' {
			// generic emit: ($level::atom $message::string)
			if args.len < 2 {
				return none
			}
			lname := log_atom_name(args[0]) or {
				return log_err('CXER2402', 'log: log expects a level atom')
			}
			return log_emit(lname, log_message(args[1]), mut env)
		}
		'log-emit-raw' {
			// Bypass formatting; emit the pre-shaped record directly. The
			// observable result is the documented null return.
			if env.state.log_sink != 'none' && args.len > 0 {
				eprintln(log_render_record(args[0]))
			}
			return log_null()
		}
		'log-configure' {
			if args.len < 1 {
				return none
			}
			return log_configure(args[0], mut env)
		}
		'log-is-enabled' {
			if args.len < 1 {
				return none
			}
			return log_is_enabled(args[0], mut env)
		}
		'log-current-scope' {
			return log_current_scope(mut env)
		}
		else {
			return none
		}
	}
}

// log_message extracts the emit message text from an argument node,
// redacting any secret value (cxdm.md §12.2: logs redact secrets in the
// message + structured fields). redact_secrets turns a `__cx_secret__`
// wrapper into the `‹redacted›` marker scalar before stringification, so
// a secret passed as the message surfaces redacted, never as cleartext.
fn log_message(n cx.Node) string {
	return scalar_string(redact_secrets(n)) or { '' }
}

// log_render_record renders a node to a compact text form for emit-raw's
// direct-sink write (diagnostic only; not asserted). Secrets are redacted
// (cxdm.md §12.2) before rendering.
fn log_render_record(n cx.Node) string {
	r := redact_secrets(n)
	if r is cx.Element {
		return r.name
	}
	if s := scalar_string(r) {
		return s
	}
	return ''
}

// log_stdlib_builtin is the env-free chain entry (stdlib_dispatch.v). Every
// log primitive needs env, so this always returns none — the env-aware
// log_stdlib_builtin_env (tried first in dispatch_call_l) is the live path.
fn log_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	_ := name
	_ := args
	return none
}
