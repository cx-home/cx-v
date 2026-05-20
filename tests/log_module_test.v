module main

import cx
import os

// ── log: module tests (FF1–FF7 + FF8 directives, ADR 0023 §D10) ──────────
//
// Output captured via [?cx log-output=file:<tmp>] sink. test-mode
// pins the timestamp to '1970-01-01T00:00:00Z' so byte-identity
// assertions are stable.

fn tmp_log_path(name string) string {
	return os.join_path(os.temp_dir(), 'cx_log_${name}_${os.getpid()}.log')
}

fn read_and_clean(path string) string {
	c := os.read_file(path) or { '' }
	os.rm(path) or {}
	return c
}

fn run_with_log(prog string, path string) {
	full := '[?cx log-output=file:${path}]\n[?cx test-mode=true]\n${prog}'
	cx.eval_cxl('[input]', full, '') or { panic('cxl: ${err}') }
}

// ── FF3 log:info — logfmt default ────────────────────────────────────────

fn test_log_info_logfmt_default_emits_record() {
	path := tmp_log_path('info_logfmt')
	defer { os.rm(path) or {} }
	run_with_log("[?log:info ['hello']]", path)
	out := read_and_clean(path)
	assert out.contains('level=info'), 'got: "${out}"'
	assert out.contains('msg=hello'), 'got: "${out}"'
	assert out.contains('ts=1970-01-01T00:00:00Z'), 'got: "${out}"'
}

// ── FF1 / FF2 / FF4 / FF5 ─────────────────────────────────────────────────

fn test_log_trace_below_default_filter_emits_nothing() {
	path := tmp_log_path('trace_filtered')
	defer { os.rm(path) or {} }
	// Default level is 'info'; trace records are filtered.
	run_with_log("[?log:trace ['suppressed']]", path)
	out := read_and_clean(path)
	assert out == '', 'expected empty (filtered) output, got: "${out}"'
}

fn test_log_trace_passes_when_min_level_is_trace() {
	path := tmp_log_path('trace_pass')
	defer { os.rm(path) or {} }
	prog := "[?cx log-level=trace]\n[?log:trace ['visible']]"
	full := '[?cx log-output=file:${path}]\n[?cx test-mode=true]\n${prog}'
	cx.eval_cxl('[input]', full, '') or { panic('cxl: ${err}') }
	out := read_and_clean(path)
	assert out.contains('level=trace'), 'got: "${out}"'
	assert out.contains('msg=visible'), 'got: "${out}"'
}

fn test_log_warn_passes_at_default_info() {
	path := tmp_log_path('warn_info')
	defer { os.rm(path) or {} }
	run_with_log("[?log:warn ['attention']]", path)
	out := read_and_clean(path)
	assert out.contains('level=warn'), 'got: "${out}"'
}

fn test_log_error_passes_at_default_info() {
	path := tmp_log_path('error_info')
	defer { os.rm(path) or {} }
	run_with_log("[?log:error ['boom']]", path)
	out := read_and_clean(path)
	assert out.contains('level=error'), 'got: "${out}"'
}

// ── FF8 — json format ────────────────────────────────────────────────────

fn test_log_json_format_emits_ndjson_object() {
	path := tmp_log_path('json')
	defer { os.rm(path) or {} }
	prog := "[?cx log-format=json]\n[?log:info ['hello']]"
	full := '[?cx log-output=file:${path}]\n[?cx test-mode=true]\n${prog}'
	cx.eval_cxl('[input]', full, '') or { panic('cxl: ${err}') }
	out := read_and_clean(path)
	assert out.starts_with('{'), 'expected JSON object start, got: "${out}"'
	assert out.contains('"level":"info"'), 'got: "${out}"'
	assert out.contains('"msg":"hello"'), 'got: "${out}"'
	assert out.contains('"ts":"1970-01-01T00:00:00Z"'), 'got: "${out}"'
}

// ── Field-byte-identity under test-mode ──────────────────────────────────

fn test_log_logfmt_byte_identity_with_test_mode() {
	path := tmp_log_path('byte_identity')
	defer { os.rm(path) or {} }
	run_with_log("[?log:info ['done']]", path)
	out := read_and_clean(path)
	expected := 'ts=1970-01-01T00:00:00Z level=info msg=done\n'
	assert out == expected, 'expected: "${expected}", got: "${out}"'
}

// ── FF8 — log-level=off filters everything ───────────────────────────────

fn test_log_level_off_suppresses_all_emission() {
	path := tmp_log_path('off')
	defer { os.rm(path) or {} }
	prog := "[?cx log-level=off]\n[?log:error ['silenced']]"
	full := '[?cx log-output=file:${path}]\n[?cx test-mode=true]\n${prog}'
	cx.eval_cxl('[input]', full, '') or { panic('cxl: ${err}') }
	out := read_and_clean(path)
	assert out == '', 'expected empty, got: "${out}"'
}

// ── FF6 log:level — reflects [?cx log-level=...] ─────────────────────────

fn test_log_level_returns_default_info() {
	out := cx.eval_cxl('[input]', '[?=[?log:level []]]', '') or {
		panic('cxl: ${err}')
	}
	assert out == 'info', 'got: "${out}"'
}

fn test_log_level_returns_configured_value() {
	out := cx.eval_cxl('[input]', "[?cx log-level=debug]\n[?=[?log:level []]]", '') or {
		panic('cxl: ${err}')
	}
	assert out == 'debug', 'got: "${out}"'
}

// ── FF7 log:with-context — frame push / pop / inheritance ────────────────

fn test_log_with_context_inherits_fields() {
	path := tmp_log_path('with_ctx')
	defer { os.rm(path) or {} }
	prog := "[?log:with-context [{request-id: r123}, [?log:info ['started']]]]"
	full := '[?cx log-output=file:${path}]\n[?cx test-mode=true]\n${prog}'
	cx.eval_cxl('[input]', full, '') or { panic('cxl: ${err}') }
	out := read_and_clean(path)
	assert out.contains('request-id=r123'), 'expected request-id field, got: "${out}"'
	assert out.contains('msg=started'), 'got: "${out}"'
}

fn test_log_with_context_restores_on_exit() {
	path := tmp_log_path('with_ctx_restore')
	defer { os.rm(path) or {} }
	prog := "[?log:with-context [{ctx-key: in-frame}, [?log:info ['inside']]]]\n[?log:info ['outside']]"
	full := '[?cx log-output=file:${path}]\n[?cx test-mode=true]\n${prog}'
	cx.eval_cxl('[input]', full, '') or { panic('cxl: ${err}') }
	out := read_and_clean(path)
	lines := out.split('\n').filter(it.len > 0)
	assert lines.len == 2, 'expected 2 lines, got ${lines.len}: "${out}"'
	assert lines[0].contains('ctx-key=in-frame'), 'first line missing context: "${lines[0]}"'
	assert !lines[1].contains('ctx-key='), 'second line should not carry context: "${lines[1]}"'
}
