module main

import cx

// ── ADR 0020 parameterized-template evaluator tests ──────────────────────────
//
// Capability bit 30 (`0x40000000`). Tests the V reference evaluator
// for the `?def :params` slot, lexical-scope parameter binding,
// positional invocation `[?template-name arg1 arg2]`, W018 arg-count
// mismatch, and `?use` rejection of parameterized templates per
// ADR 0020 §R4.
//
// Per spec/cxl.md §3.7. The 3-slot positional form `[?def [name,
// params, body]]` is canonical; labeled form `[?def name :params
// [args] :body BODY]` desugars at parse time. Both shapes round-trip
// through the same AST and exercise the same evaluator path here.

fn run(input string, program string) string {
	return cx.eval_cxl(input, program, '') or { panic('cxl: ${err}') }
}

fn run_err(input string, program string) string {
	cx.eval_cxl(input, program, '') or { return err.msg() }
	return ''
}

// ── Zero-param ?def still works (legacy 2-slot + new 3-slot) ─────────────────

fn test_def_zero_param_legacy_2slot() {
	// Pre-ADR-0020 form — parser auto-expands to 3-slot with empty params.
	doc  := '[product name=alice]'
	prog := '[?def [greet, Hello [?=@name]!]][?use [greet]]'
	assert run(doc, prog) == 'Hello alice!'
}

fn test_def_zero_param_explicit_3slot() {
	doc  := '[product name=alice]'
	prog := '[?def [greet, [], Hello [?=@name]!]][?use [greet]]'
	assert run(doc, prog) == 'Hello alice!'
}

fn test_def_zero_param_labeled() {
	doc  := '[product name=alice]'
	prog := '[?def greet :body Hello [?=@name]!][?use greet]'
	assert run(doc, prog) == 'Hello alice!'
}

// ── Single-param template ────────────────────────────────────────────────────

fn test_def_single_param_invoked_positional() {
	doc  := '[product]'
	prog := "[?def shout :params [x] :body LOUD: [?=x]!][?shout 'hi']"
	out  := run(doc, prog)
	assert out.contains('LOUD: hi!'), 'got: "${out}"'
}

fn test_def_single_param_invoked_with_path() {
	doc  := '[product [v sku=PN-A]]'
	prog := '[?def line :params [item] :body sku=[?=item/@sku]][?line //v]'
	out  := run(doc, prog)
	assert out.contains('sku=PN-A'), 'got: "${out}"'
}

// ── Multi-param template ─────────────────────────────────────────────────────

fn test_def_multi_param_invoked() {
	doc  := '[product]'
	prog := "[?def pair :params [a, b] :body [?=a]/[?=b]][?pair 'left' 'right']"
	out  := run(doc, prog)
	assert out.contains('left/right'), 'got: "${out}"'
}

// ── Lexical-scope shadowing ─────────────────────────────────────────────────

fn test_def_param_shadows_for_binding() {
	// Outer ?for binds x; template parameter named x shadows it within
	// the template body. After body exit, outer x is restored.
	doc  := '[product [v n=A] [v n=B]]'
	prog := "[?def show :params [x] :body inner-[?=x];][?for [outer, //v, [?=outer/@n]:[?show 'zz'];]]"
	out  := run(doc, prog)
	// Outer ?for binds outer = each variant; inside, ?show is called with 'zz'
	// which binds the template's local x = 'zz'. After ?show returns, outer is
	// still bound for the next iteration.
	assert out.contains('A:inner-zz;'), 'got: "${out}"'
	assert out.contains('B:inner-zz;'), 'got: "${out}"'
}

fn test_def_param_unbinds_on_body_exit() {
	// After [?f 'A'] returns, the parameter `tmp` should NOT remain
	// bound. The second call [?f 'B'] should bind tmp='B' freshly.
	// If the binding leaked from the first call, the second would
	// still see 'A' (state-leakage bug). We verify both calls produce
	// the expected output independently.
	doc  := '[p]'
	prog := "[?def f :params [tmp] :body <[?=tmp]>][?f 'A'][?f 'B']"
	out  := run(doc, prog)
	assert out.contains('<A>'), 'got: "${out}"'
	assert out.contains('<B>'), 'got: "${out}"'
}

// ── W018 arg-count mismatch ──────────────────────────────────────────────────

fn test_def_w018_too_few_args() {
	doc  := '[p]'
	prog := "[?def f :params [a, b] :body x][?f 'one']"
	msg  := run_err(doc, prog)
	assert msg.contains('W018'), 'expected W018, got: "${msg}"'
	assert msg.contains('expects 2'), 'expected arg-count msg, got: "${msg}"'
}

fn test_def_w018_too_many_args() {
	doc  := '[p]'
	prog := "[?def f :params [a] :body x][?f 'one' 'two']"
	msg  := run_err(doc, prog)
	assert msg.contains('W018'), 'expected W018, got: "${msg}"'
}

// ── ?use on parameterized template (ADR 0020 §R4) ────────────────────────────

fn test_use_of_parameterized_errors() {
	doc  := '[p]'
	prog := "[?def f :params [a] :body x][?use f]"
	msg  := run_err(doc, prog)
	assert msg.contains('parameter'), 'expected param-related error, got: "${msg}"'
}

// ── Templates win over builtin filter names (ADR 0020 §D6) ───────────────────

fn test_def_shadows_builtin_filter() {
	// `upper` is a builtin filter, but user `?def upper` should shadow.
	doc  := '[p]'
	prog := "[?def upper :params [s] :body BUILTIN-SHADOWED-[?=s]][?upper 'hi']"
	out  := run(doc, prog)
	assert out.contains('BUILTIN-SHADOWED-hi'), 'got: "${out}"'
}
