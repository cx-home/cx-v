module main

import cx

// ── cx:eval gate enforcement tests (DD11 + EE5 M1/M2/M5) ─────────────────
//
// v0.7.0 lands the gates; the actual evaluator engine + M3 sandboxing
// + M4 module-widening check is filed for the EE5 engine row. These
// tests prove the gate boundary is correct: nothing slips past the
// security perimeter, even though the engine isn't there yet.

// M1 — off by default

fn test_cx_eval_off_by_default_raises_cxer0041() {
	doc := '[input]'
	prog := "[?cx:eval ['1+1', {}]]"
	res := cx.eval_cxl(doc, prog, '') or { err.msg() }
	assert res.contains('CXER0041'), 'expected CXER0041 in: "${res}"'
	assert res.contains('allow-eval=true'), 'expected directive name in message: "${res}"'
}

fn test_cx_render_off_by_default_raises_cxer0041() {
	doc := '[input]'
	prog := "[?cx:render ['hello', {}]]"
	res := cx.eval_cxl(doc, prog, '') or { err.msg() }
	assert res.contains('CXER0041'), 'expected CXER0041 in: "${res}"'
}

// M2 — incompatible with pure-only (CXER0042 fires before CXER0041)

fn test_cx_eval_under_pure_only_raises_cxer0042() {
	doc := '[input]'
	prog := "[?cx pure-only]\n[?cx allow-eval=true]\n[?cx:eval ['1+1', {}]]"
	res := cx.eval_cxl(doc, prog, '') or { err.msg() }
	assert res.contains('CXER0042'), 'expected CXER0042 in: "${res}"'
}

fn test_cx_render_under_pure_only_raises_cxer0042() {
	doc := '[input]'
	prog := "[?cx pure-only]\n[?cx allow-eval=true]\n[?cx:render ['x', {}]]"
	res := cx.eval_cxl(doc, prog, '') or { err.msg() }
	assert res.contains('CXER0042'), 'expected CXER0042 in: "${res}"'
}

// Gate-pass path — past M1/M2/M5, engine executes the fragment

fn test_cx_eval_past_gates_executes() {
	doc := '[input]'
	// Interpolation fragment — emits the literal "1".
	prog := "[?cx allow-eval=true]\n[?cx:eval ['[?=1]', {}]]"
	res := cx.eval_cxl(doc, prog, '') or { panic('eval failed: ${err.msg()}') }
	assert res.contains('1'), 'expected eval result "1" in: "${res}"'
}

fn test_cx_render_past_gates_returns_text() {
	doc := '[input]'
	prog := "[?cx allow-eval=true]\n[?cx:render ['[?=1]', {}]]"
	res := cx.eval_cxl(doc, prog, '') or { panic('render failed: ${err.msg()}') }
	assert res.contains('1'), 'expected render text "1" in: "${res}"'
}

// M5 — recursion-depth gate fires before engine when eval_depth >= max

fn test_cx_eval_max_depth_default_8() {
	// We can't actually nest cx:eval calls (the engine isn't there)
	// but we can confirm a high pre-set eval_depth would refuse —
	// indirect: set max-eval-depth=0 and watch the gate fire.
	doc := '[input]'
	prog := "[?cx allow-eval=true]\n[?cx max-eval-depth=0]\n[?cx:eval ['x', {}]]"
	res := cx.eval_cxl(doc, prog, '') or { err.msg() }
	assert res.contains('CXER0044'), 'expected CXER0044 (recursion-depth) in: "${res}"'
}

// Always-pass check — pure-only on, allow-eval not set: CXER0042
// because pure-only fires first (CXER0042 — eval-incompatible).
fn test_cx_eval_pure_only_without_allow_eval_still_cxer0042() {
	doc := '[input]'
	prog := "[?cx pure-only]\n[?cx:eval ['x', {}]]"
	res := cx.eval_cxl(doc, prog, '') or { err.msg() }
	// CXER0042 should fire (pure-only collision) regardless of
	// allow-eval state, per spec/modules/cx.md §2.2.
	assert res.contains('CXER0042'), 'expected CXER0042 in: "${res}"'
}

// ── EE5 engine tests (M3 sandbox, M4 widening, origin threading) ──────────

// M3 — context-map keys ARE visible as bare-identifier bindings inside
// the evaluated fragment (cxl reference syntax is `name`, not `\$name`).
fn test_cx_eval_m3_context_binds_visible() {
	doc := '[input]'
	prog := "[?cx allow-eval=true]\n[?cx:eval ['[?=name]', {name: 'Alice'}]]"
	res := cx.eval_cxl(doc, prog, '') or { panic('eval failed: ${err.msg()}') }
	assert res.contains('Alice'), 'expected context binding "Alice" in: "${res}"'
}

// M3 — caller's bindings (?let) are NOT visible inside the sandboxed
// eval scope when the context map doesn't pass them through.
fn test_cx_eval_m3_caller_bindings_sandboxed() {
	doc := '[input]'
	// Caller binds x via ?let. cx:eval fragment also references x but
	// the context map is empty — must NOT resolve to "leaked".
	prog := "[?cx allow-eval=true]\n[?let [x, 'leaked', [?cx:eval ['[?=x]', {}]]]]"
	res := cx.eval_cxl(doc, prog, '') or { err.msg() }
	// Result must NOT contain 'leaked' — fragment can't see caller's x.
	assert !res.contains('leaked'),
		'M3 leak: caller\'s "x" visible inside cx:eval sandbox: "${res}"'
}

// M3 — caller's ?def NOT visible. The fragment uses a named template
// the caller defined; M3 sandboxing means resolution fails.
fn test_cx_eval_m3_caller_defs_sandboxed() {
	doc := '[input]'
	prog := "[?cx allow-eval=true]\n[?def [helper, [hello]]]\n[?cx:eval ['[?use helper]', {}]]"
	res := cx.eval_cxl(doc, prog, '') or { err.msg() }
	// "hello" should NOT appear — fragment can't see caller's ?def 'helper'.
	assert !res.contains('hello'),
		'M3 leak: caller\'s ?def visible inside cx:eval sandbox: "${res}"'
}

// M4 — fragment that activates a module the caller didn't activate is
// refused with CXER0043.
fn test_cx_eval_m4_module_widening_refused() {
	doc := '[input]'
	// Caller activates no modules. Fragment prolog tries to activate hash.
	prog := "[?cx allow-eval=true]\n[?cx:eval ['[?cx use-module=hash][?=1]', {}]]"
	res := cx.eval_cxl(doc, prog, '') or { err.msg() }
	assert res.contains('CXER0043'),
		'expected CXER0043 (module widening) in: "${res}"'
}

// M4 — fragment that activates a module the caller DID activate is
// allowed through.
fn test_cx_eval_m4_module_passthrough_allowed() {
	doc := '[input]'
	// Caller activates 'http'. Fragment may re-declare 'http'.
	prog := "[?cx allow-eval=true]\n[?cx use-module=http]\n[?cx:eval ['[?cx use-module=http][?=1]', {}]]"
	res := cx.eval_cxl(doc, prog, '') or { panic('passthrough failed: ${err.msg()}') }
	assert res.contains('1'),
		'expected fragment output "1" in: "${res}"'
}

// M5 — options-map third arg can RAISE the per-call max-depth above
// the document-level cap.
fn test_cx_eval_m5_options_max_depth_override() {
	doc := '[input]'
	// Document max-eval-depth=0 would normally refuse; options-map
	// override sets max-depth=4 for this one call.
	prog := "[?cx allow-eval=true]\n[?cx max-eval-depth=0]\n[?cx:eval ['[?=1]', {}, {max-depth: 4}]]"
	res := cx.eval_cxl(doc, prog, '') or { panic('override failed: ${err.msg()}') }
	assert res.contains('1'),
		'expected override result "1" in: "${res}"'
}

// Origin — ?try inside caller binds err-eval-origin when an error
// thrown inside cx:eval carries the origin keys.
fn test_cx_eval_err_origin_threaded_through_try() {
	doc := '[input]'
	// Fragment raises via [?error]; options-map threads origin-uri/line/col.
	// ?try catches and emits err-eval-origin via bare-identifier reference.
	prog := "[?cx allow-eval=true]\n[?try [[?cx:eval ['[?error [FOAR0001, oops]]', {}, {origin-uri: 'frag.cx', origin-line: 42, origin-col: 5}]], [?=err-eval-origin]]]"
	res := cx.eval_cxl(doc, prog, '') or { panic('try failed: ${err.msg()}') }
	assert res.contains('frag.cx'),
		'expected origin-uri "frag.cx" in: "${res}"'
	assert res.contains('42'),
		'expected origin-line 42 in: "${res}"'
}

// Origin — when no origin keys threaded, err-eval-origin is the
// synthetic payload `{"synthetic":true}`.
fn test_cx_eval_err_origin_synthetic_when_unthreaded() {
	doc := '[input]'
	prog := "[?cx allow-eval=true]\n[?try [[?cx:eval ['[?error [FOAR0001, oops]]', {}]], [?=err-eval-origin]]]"
	res := cx.eval_cxl(doc, prog, '') or { panic('try failed: ${err.msg()}') }
	assert res.contains('synthetic'),
		'expected "synthetic" sentinel in: "${res}"'
}

// Parse-time M2 hoist — co-presence of [?cx pure-only] and
// [?cx allow-eval=true] in same document head refused BEFORE any
// evaluation begins.
fn test_cx_eval_m2_parse_time_hoist() {
	doc := '[input]'
	prog := "[?cx pure-only]\n[?cx allow-eval=true]\n[?=1]"
	res := cx.eval_cxl(doc, prog, '') or { err.msg() }
	assert res.contains('CXER0042'), 'expected parse-time CXER0042 in: "${res}"'
	assert res.contains('parse-time') || res.contains('parse time'),
		'expected "parse-time" marker in: "${res}"'
}
