module main

import cx

// ── [?cx use-module=...] activation tests (EE2, ADR 0023 §D3) ────────────
//
// At v0.7.0 every registered module's activation is .always so the
// directive is a no-op in practice; framework lands for v0.8.0
// BaseX modules. These tests confirm:
//   1. The directive is absorbed (not emitted as text in output)
//   2. Always-on modules work without declaration
//   3. The activation gate doesn't break unknown filters (passes
//      through to downstream "filter not in CXL set" error)

fn test_use_module_directive_absorbed_not_emitted() {
	// The directive parses + absorbs cleanly; no text output.
	out := cx.eval_cxl('[input]', '[?cx use-module=cx,log]\n', '') or {
		panic('cxl: ${err}')
	}
	assert !out.contains('[?cx use-module'), 'directive leaked into output: "${out}"'
	assert !out.contains('use-module'), 'directive attr leaked: "${out}"'
}

fn test_always_on_modules_work_without_declaration() {
	// cx:hash is in the .always module. No [?cx use-module=cx] needed.
	out := cx.eval_cxl('[input]', "[?=[?cx:hash [[?cx:parse ['[a]']]]]]", '') or {
		panic('cxl: ${err}')
	}
	assert out.len == 64, 'expected hash, got: "${out}"'
}

fn test_log_module_works_without_declaration() {
	// log: is also .always.
	out := cx.eval_cxl('[input]', "[?cx test-mode=true][?cx log-output=stdout][?log:info ['hi']]", '') or {
		panic('cxl: ${err}')
	}
	// Returns the captured eval output (stdout sink wrote outside V's
	// out buffer); main thing is no error and no directive leakage.
	assert !out.contains('use-module'), 'leaked: "${out}"'
}

fn test_unknown_filter_does_not_trigger_activation_gate() {
	// 'bogus-thing' has no module entry; activation gate must pass
	// through to the downstream filter dispatch (which raises
	// "not in CXL set"). CXER0032 must NOT appear.
	res := cx.eval_cxl('[input]', '[?bogus-thing []]', '') or { err.msg() }
	assert !res.contains('CXER0032'), 'activation gate spuriously rejected unknown: "${res}"'
}

fn test_use_module_directive_can_list_multiple_namespaces() {
	// Comma-separated form. Should parse without error even though
	// none of the listed modules need declaration.
	_ := cx.eval_cxl('[input]', "[?cx use-module=cx,log,inspect]\n[?=[?cx:hash [[?cx:parse ['[a]']]]]]", '') or {
		panic('cxl: ${err}')
	}
}
