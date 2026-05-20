module cx

import os
import strings
import time

// ── log: structured-logging module ────────────────────────────────────────────
//
// Per ADR 0023 §D10 and spec/modules/log.md. Seven functions plus
// three FF8 directives. Pulled forward from v0.8.0 Tier B so v0.8.0
// BaseX modules slot in around a settled logging surface.
//
// Emitter pipeline:
//   1. log:NAME(msg, fields?) — filter functions in this file
//   2. log_emit() — level filter, record build, format dispatch, sink write
//   3. log_format_logfmt() / log_format_json() — record → bytes
//   4. log_write_sink() — bytes → stderr / stdout / file:<path>
//
// Determinism: under [?cx test-mode=true] the timestamp is stubbed
// to '1970-01-01T00:00:00Z' so conformance fixtures (FF10) are
// byte-identical across runs and bindings. Production code leaves
// test_mode at its default false; timestamps are wall-clock UTC
// at second precision per spec/modules/log.md §4.
//
// Field ordering: ts / level / msg fixed at the head of each record
// (in that order); remaining fields sorted alphabetically by key.
// This makes byte-identity stable across hash-map iteration order.

// ── Level priority table ──────────────────────────────────────────────────────

const log_level_priority_table = {
	'trace': 0
	'debug': 1
	'info':  2
	'warn':  3
	'error': 4
	'off':   5
}

fn log_level_priority(level string) int {
	return log_level_priority_table[level.to_lower()] or { 2 }  // unknown → info
}

// log_should_emit reports whether a record at `level` passes the
// current minimum-level filter set by [?cx log-level=...].
fn log_should_emit(env &CXLEnv, level string) bool {
	min := log_level_priority(env.log_level)
	rec := log_level_priority(level)
	return rec >= min && rec < log_level_priority_table['off']
}

// ── Timestamp ────────────────────────────────────────────────────────────────

const log_test_timestamp = '1970-01-01T00:00:00Z'

fn log_timestamp(env &CXLEnv) string {
	if env.test_mode {
		return log_test_timestamp
	}
	now := time.utc()
	return '${now.year:04d}-${now.month:02d}-${now.day:02d}T${now.hour:02d}:${now.minute:02d}:${now.second:02d}Z'
}

// ── Field extraction ─────────────────────────────────────────────────────────

// extract_fields_map converts a CXLValue (typically a MapNode passed
// as the optional second arg to log:trace / debug / info / warn /
// error) into a flat map[string]string. Non-map values are ignored
// (return empty map); MapNode entries with string-or-scalar values
// are stringified via scalar_value_str / item_to_text.
fn extract_fields_map(v CXLValue) map[string]string {
	mut out := map[string]string{}
	if v.len == 0 { return out }
	it := v[0]
	if it is MapNode {
		for entry in it.entries {
			key := scalar_value_str(entry.key_value)
			val := node_to_field_string(entry.value)
			out[key] = val
		}
	}
	return out
}

// node_to_field_string renders a MapEntry value as a flat string for
// logfmt output. Scalar nodes produce their lexical form; nested
// elements/arrays produce their sentinel form so the line stays
// single-line (multi-line content would break logfmt's per-line
// record contract).
fn node_to_field_string(n Node) string {
	return match n {
		TextNode    { n.value }
		ScalarNode  { scalar_value_str(n.value) }
		Element     { '[${n.name} …]' }
		ArrayNode   { '[array size=${n.items.len}]' }
		MapNode     { '[map entries=${n.entries.len}]' }
		else        { '' }
	}
}

// ── Context-stack merge ──────────────────────────────────────────────────────

// merge_context_into walks env.log_context_stack from outermost to
// innermost, merging each frame's keys into `out`. Inner frames
// shadow outer per the contract in spec/modules/log.md §2.4.
fn merge_context_into(env &CXLEnv, mut out map[string]string) {
	for frame in env.log_context_stack {
		for k, v in frame {
			out[k] = v
		}
	}
}

// ── Record build + format ────────────────────────────────────────────────────

// log_format_logfmt renders a record as a single-line logfmt string
// ending in '\n'. Field order: ts, level, msg, then remaining fields
// sorted alphabetically by key. Values containing whitespace, `=`,
// or `"` are double-quoted with internal quotes escaped.
fn log_format_logfmt(ts string, level string, msg string, fields map[string]string) string {
	mut b := strings.new_builder(64 + msg.len)
	b.write_string('ts=')
	b.write_string(logfmt_quote(ts))
	b.write_string(' level=')
	b.write_string(logfmt_quote(level))
	b.write_string(' msg=')
	b.write_string(logfmt_quote(msg))
	mut keys := []string{cap: fields.len}
	for k, _ in fields { keys << k }
	keys.sort()
	for k in keys {
		b.write_string(' ')
		b.write_string(k)
		b.write_string('=')
		b.write_string(logfmt_quote(fields[k]))
	}
	b.write_string('\n')
	return b.str()
}

// logfmt_quote returns s as-is when it contains no whitespace, `=`,
// or `"`; otherwise wraps s in double quotes with internal `"` and
// `\` escaped. Matches the rules in spec/eval.md logfmt rules.
fn logfmt_quote(s string) string {
	mut needs_quote := false
	mut has_escape := false
	for c in s {
		if c == ` ` || c == `\t` || c == `=` || c == `"` || c == `\n` {
			needs_quote = true
		}
		if c == `"` || c == `\\` {
			has_escape = true
		}
	}
	if !needs_quote { return s }
	if !has_escape { return '"${s}"' }
	mut b := strings.new_builder(s.len + 4)
	b.write_string('"')
	for c in s {
		if c == `"` || c == `\\` { b.write_string('\\') }
		b.write_u8(c)
	}
	b.write_string('"')
	return b.str()
}

// log_format_json renders a record as a single-line NDJSON object
// ending in '\n'. Same field-ordering rule as logfmt (ts/level/msg
// fixed, remaining sorted). All values stringified at v0.7.0 — full
// structural typing (numbers as numbers, nested objects) is filed
// as a v0.7.x enhancement.
fn log_format_json(ts string, level string, msg string, fields map[string]string) string {
	mut b := strings.new_builder(64 + msg.len)
	b.write_string('{"ts":')
	b.write_string(log_json_quote(ts))
	b.write_string(',"level":')
	b.write_string(log_json_quote(level))
	b.write_string(',"msg":')
	b.write_string(log_json_quote(msg))
	mut keys := []string{cap: fields.len}
	for k, _ in fields { keys << k }
	keys.sort()
	for k in keys {
		b.write_string(',')
		b.write_string(log_json_quote(k))
		b.write_string(':')
		b.write_string(log_json_quote(fields[k]))
	}
	b.write_string('}\n')
	return b.str()
}

fn log_json_quote(s string) string {
	mut b := strings.new_builder(s.len + 4)
	b.write_string('"')
	for c in s {
		match c {
			`"`   { b.write_string('\\"') }
			`\\`  { b.write_string('\\\\') }
			`\n`  { b.write_string('\\n') }
			`\r`  { b.write_string('\\r') }
			`\t`  { b.write_string('\\t') }
			else  { b.write_u8(c) }
		}
	}
	b.write_string('"')
	return b.str()
}

// ── Sink dispatch ────────────────────────────────────────────────────────────

// log_write_sink emits the rendered record bytes to env.log_output.
// stderr (default) and stdout use V's eprint / print without
// auto-newline (the record already ends in '\n'). file:<path>
// appends to the path; failures fall through silently per
// spec/modules/log.md §7 (emission failures propagate as
// implementation errors, not cxl-level errors at v0.7.0).
fn log_write_sink(env &CXLEnv, bytes string) {
	target := env.log_output
	match target {
		'stderr' { eprint(bytes) }
		'stdout' { print(bytes) }
		else {
			if target.starts_with('file:') {
				path := target[5..]
				existing := os.read_file(path) or { '' }
				os.write_file(path, existing + bytes) or {}
			} else {
				// Unknown sink — fall back to stderr.
				eprint(bytes)
			}
		}
	}
}

// ── Emit pipeline ────────────────────────────────────────────────────────────

// log_emit dispatches a record through the level filter, format
// selector, and sink write. Returns the empty CXLValue (emitter
// functions are void per spec/modules/log.md §1).
fn log_emit(mut env CXLEnv, level string, msg string, raw_fields CXLValue) CXLValue {
	if !log_should_emit(env, level) {
		return CXLValue([]CXLItem{})
	}
	mut all_fields := map[string]string{}
	merge_context_into(env, mut all_fields)
	for k, v in extract_fields_map(raw_fields) {
		all_fields[k] = v
	}
	ts := log_timestamp(env)
	bytes := match env.log_format {
		'json' { log_format_json(ts, level, msg, all_fields) }
		else   { log_format_logfmt(ts, level, msg, all_fields) }
	}
	log_write_sink(env, bytes)
	return CXLValue([]CXLItem{})
}

// ── Filter functions ─────────────────────────────────────────────────────────

fn filter_log_trace(args []CXLValue, mut env CXLEnv) !CXLValue {
	if args.len < 1 { return error('cxl: log:trace expects a message argument') }
	msg := value_to_string(args[0])
	fields := if args.len >= 2 { args[1] } else { CXLValue([]CXLItem{}) }
	return log_emit(mut env, 'trace', msg, fields)
}

fn filter_log_debug(args []CXLValue, mut env CXLEnv) !CXLValue {
	if args.len < 1 { return error('cxl: log:debug expects a message argument') }
	msg := value_to_string(args[0])
	fields := if args.len >= 2 { args[1] } else { CXLValue([]CXLItem{}) }
	return log_emit(mut env, 'debug', msg, fields)
}

fn filter_log_info(args []CXLValue, mut env CXLEnv) !CXLValue {
	if args.len < 1 { return error('cxl: log:info expects a message argument') }
	msg := value_to_string(args[0])
	fields := if args.len >= 2 { args[1] } else { CXLValue([]CXLItem{}) }
	return log_emit(mut env, 'info', msg, fields)
}

fn filter_log_warn(args []CXLValue, mut env CXLEnv) !CXLValue {
	if args.len < 1 { return error('cxl: log:warn expects a message argument') }
	msg := value_to_string(args[0])
	fields := if args.len >= 2 { args[1] } else { CXLValue([]CXLItem{}) }
	return log_emit(mut env, 'warn', msg, fields)
}

fn filter_log_error(args []CXLValue, mut env CXLEnv) !CXLValue {
	if args.len < 1 { return error('cxl: log:error expects a message argument') }
	msg := value_to_string(args[0])
	fields := if args.len >= 2 { args[1] } else { CXLValue([]CXLItem{}) }
	return log_emit(mut env, 'error', msg, fields)
}

// filter_log_level returns the current minimum log level as a
// lowercase string scalar per spec/modules/log.md §1. ReadOnly per
// the EE1 catalog. Reflects the closest enclosing [?cx log-level=...]
// directive.
fn filter_log_level(args []CXLValue, env CXLEnv) !CXLValue {
	_ = args
	level := env.log_level.to_lower()
	return [CXLItem(CXLScalar{ data_type: .string_type, value: ScalarValue(level) })]
}

// filter_log_with_context pushes a context frame from the first
// slot's MapNode, evaluates the body slot (2nd slot), pops the frame
// on both success and error exit paths. Returns the body's evaluated
// value.
//
// Accepts the raw EvalDirectiveNode so it can extract the body
// slot uninterpreted — the body is most often a SequenceNode of
// statements, which the slot evaluator would otherwise atomize.
fn filter_log_with_context(n EvalDirectiveNode, mut env CXLEnv) !CXLValue {
	slots := arg_array_slots(n)!
	if slots.len < 2 {
		return error('cxl: log:with-context expects 2 arguments (fields, body)')
	}
	fields_val := eval_slot_to_value(slots[0], mut env)!
	frame := extract_fields_map(fields_val)
	env.log_context_stack << frame
	defer { env.log_context_stack.delete_last() }
	return eval_slot_to_value(slots[1], mut env)!
}
