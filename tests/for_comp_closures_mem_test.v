module main

import code
import cx
import runtime

// for_comp_closures_mem_test.v — BEHAVIORAL guard for cx-private #62 (NON-HTTP).
//
// The `[?for]` comprehension walker built each per-generator-item frame with
// `MatchEnv.clone()`, which DEEP-COPIES the whole `closures` table. So a
// comprehension's transient memory scaled with (items × closures-in-scope): an
// N-item `[?for]` evaluated with a large closures table (e.g. after `[?lib]`)
// copied that table N times. This is a general evaluator bug — it has nothing to
// do with HTTP; it was merely amplified in the reactor path (#57). The fix
// (`matcher.v::clone_frame_sharing_closures`) aliases the closures table, so a
// comprehension's footprint is independent of how many closures are in scope.
//
// This test compares the heap footprint of the SAME large comprehension with a
// big closures table vs a tiny one. Pre-fix the ratio was ~(closure-count)×;
// after, it is flat. It runs in-process via the public eval path (no socket), so
// it isolates the eval bug from the reactor.

fn used() u64 {
	return runtime.used_memory() or { 0 }
}

// prog builds an `items`-long `[?for]` comprehension over a range, optionally
// preceded by a `[?lib]` import. A lib import is the real #62 trigger: it
// populates the program-global closures table with the imported module's
// functions, which the comprehension walker copied per generator item.
fn prog(with_lib bool, items int) string {
	head := if with_lib { "[?lib 'cx-stdlib/http' :as http]\n" } else { '' }
	return head + '[?for [in \$i [\$range 1 ${items}]] [yield [\$text \$i]]]'
}

fn run_prog(src string) {
	mut env := code.new_env()
	p := cx.parse_program(src) or { panic('parse failed: ${err}') }
	code.eval(p.body, mut env) or { panic('eval failed: ${err}') }
}

// The comprehension's memory footprint must not scale with the size of the
// program-global closures table (#62). The same loop with a `[?lib]`-loaded
// closures table must cost about the same as without it.
fn test_for_comp_memory_independent_of_loaded_closures() {
	// Warm up the allocator / global state (incl. the embedded stdlib bundle) so
	// the baselines reflect steady state, not first-load.
	run_prog(prog(true, 200))
	gc_collect()

	base0 := used()
	run_prog(prog(false, 4000)) // same loop, no lib loaded
	small := i64(used()) - i64(base0)

	gc_collect()
	base1 := used()
	run_prog(prog(true, 4000)) // same loop, http lib loaded (large closures table)
	big := i64(used()) - i64(base1)

	if base0 == 0 || small <= 0 {
		eprintln('NOTE: used_memory() unmeasurable / noisy on this platform; skipping ratio assert')
		return
	}
	ratio := f64(big) / f64(small)
	// Pre-fix each of the 4000 generator items copied the whole stdlib closures
	// table, so the lib-loaded run cost ~8× the bare loop (measured 580 MB vs
	// 71 MB). With the alias fix the comprehension footprint is independent of
	// the closures table, so the ratio is ~1. 3× is a generous ceiling that
	// still cleanly separates fixed from regressed.
	assert ratio < 3.0, 'for-comp memory scaled with the loaded closures table (#62 regressed): big=${big} small=${small} ratio=${ratio:.1f} (want < 3.0; pre-fix ~8×)'
}

// Same contract for `[?let]` frames (#272): a let frame only writes bindings,
// so it must alias the closures table, not deep-copy it. Pre-fix EVERY let in
// EVERY closure call cloned the whole program closure table — on a served
// [$xap:host] render path (nested-let readout bodies × 540+ closures in scope)
// that allocated tens of MB per HTTP request and drove the vgc collect storm
// that wedged the xap-marine helm (multi-second HTTP freezes → keepalive
// kill-loops). The let-chain's footprint must be independent of how many
// closures are loaded.
fn test_let_chain_memory_independent_of_loaded_closures() {
	lets := '[?def deep (\$x) [?let [= \$a [\$concat \$x "-a"]] [= \$b [\$concat \$a "-b"]] [= \$c [\$concat \$b "-c"]] \$c]]\n'
	loop := '[?for [in \$i [\$range 1 3000]] [yield [deep [\$text \$i]]]]'
	run_prog(lets + loop) // warm-up
	gc_collect()

	base0 := used()
	run_prog(lets + loop) // no lib: small closures table
	small := i64(used()) - i64(base0)

	gc_collect()
	base1 := used()
	run_prog("[?lib 'cx-stdlib/http' :as http]\n" + lets + loop) // large closures table
	big := i64(used()) - i64(base1)

	if base0 == 0 || small <= 0 {
		eprintln('NOTE: used_memory() unmeasurable / noisy on this platform; skipping ratio assert')
		return
	}
	ratio := f64(big) / f64(small)
	assert ratio < 3.0, 'let-frame memory scaled with the loaded closures table (#272 regressed): big=${big} small=${small} ratio=${ratio:.1f} (want < 3.0)'
}

// Correctness: closures must still resolve THROUGH the aliased table inside a
// comprehension (the alias is read-only; this guards that aliasing did not break
// closure scoping in `[?for]` bodies).
fn test_for_comp_resolves_closures_through_alias() {
	src := "[?def sq (\$x) [* \$x \$x]]\n" +
		'[?for [in \$i [\$range 1 4]] [yield [sq \$i]]]'
	mut env := code.new_env()
	p := cx.parse_program(src) or { panic('parse failed: ${err}') }
	r := code.eval(p.body, mut env) or { panic('eval failed: ${err}') }
	// expect the sequence 1, 4, 9, 16
	if r is cx.Element {
		mut got := []i64{}
		for it in r.items {
			if it is cx.ScalarNode {
				v := it.value
				if v is i64 {
					got << v
				}
			}
		}
		assert got == [i64(1), 4, 9, 16], 'comprehension over closure gave ${got}, want [1, 4, 9, 16]'
		return
	}
	assert false, 'expected a sequence Element, got ${r.type_name()}'
}
