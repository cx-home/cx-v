module main

import code
import strings

// lazy_record_differential_test — the safety instrument for #804 leg 2's
// lazy record (`vcx/cx/lazy_record.v`), and the thing ruling 1a traded for.
//
// THE SITUATION THIS EXISTS FOR. `cx.Node` gained a 28th variant, and the
// audit measured that the compiler will not police it: 1,323 of the tree's
// 1,341 non-test `is Element` sites are `if`-form tag tests that silently
// take the else branch. An unforced lazy record reaching one of them does
// not crash — it reads as *not an element*, a plausible wrong answer on the
// most identity-sensitive code in the system. Only ~18 sites sit in
// exhaustive `match` position; adding the variant produced exactly three
// compile errors, which is the measurement confirming itself.
//
// So leg 2's forcing discipline cannot be sound BY CONSTRUCTION, and ruling
// 1a did not pretend otherwise. It is sound by DIFFERENTIAL:
//
//     for every program and input, the bytes rendered with lazy records
//     enabled == the bytes rendered with them disabled
//
// With the mechanism off, the streamed walk materialises every child at
// creation and no LazyRecord is ever built — that arm is the engine as it
// was before leg 2. So any difference between the two arms is a forcing bug
// and nothing else: a site that observed a lazy record without forcing it.
//
// It runs IN-PROCESS, both arms in one binary, on every suite run. A
// differential that only fires when someone remembers to build twice is
// most of the way back to no differential at all.
//
// WHAT TO DO IF THIS GOES RED. Do not add a case-specific force to make it
// pass. The red means some site read a lazy record's structure without
// forcing; find that site. The failing program tells you which shape
// reached it.

// DrSink accumulates the streamed chunks.
//
// It is a HEAP struct captured by pointer, and that detail is load-bearing:
// capturing a `strings.Builder` by value in the sink closure silently drops
// every chunk, so `dr_eval` returns "" for everything and the whole file
// compares "" against "" and passes. That is exactly what the first version
// of this test did, and the only reason it was caught is the break-test
// below — deleting a real forcing site and confirming this goes RED. Do that
// again after any change to how the bytes are captured.
@[heap]
struct DrSink {
mut:
	chunks []string
}

// dr_eval renders one program over one input through the streaming API,
// returning the exact bytes a caller would receive.
fn dr_eval(input string, program string) !string {
	sk := &DrSink{}
	sink := fn [sk] (chunk string) ! {
		unsafe {
			sk.chunks << chunk
		}
	}
	code.eval_code_streaming(input, program, 'text', sink)!
	return sk.chunks.join('')
}

// dr_both evaluates the same work with lazy records on and off, and returns
// the two byte strings. The switch is restored either way.
fn dr_both(input string, program string) (string, string) {
	code.set_lazy_records_off(false)
	lazy := dr_eval(input, program) or { 'ERR: ${err.msg()}' }
	code.set_lazy_records_off(true)
	strict := dr_eval(input, program) or { 'ERR: ${err.msg()}' }
	code.set_lazy_records_off(false)
	return lazy, strict
}

fn dr_assert_agree(input string, program string, origin string) {
	lazy, strict := dr_both(input, program)
	assert lazy == strict, 'LAZY/STRICT DIVERGENCE — a site read a lazy record without forcing it\n' +
		'  origin  : ${origin}\n  program : ${program}\n' +
		'  lazy    : ${lazy}\n  strict  : ${strict}'
}

// dr_assert_live refuses a program that FAILS on both arms.
//
// Two arms that both error agree perfectly and test nothing. This file has
// been bitten by exactly that twice — first by a sink that dropped every
// chunk (both arms ""), then by three programs written with `:take` / `:drop`
// / `:where` slot spellings that the for-comprehension parser rejects, so
// both arms returned the same parse error and passed. A mis-spelled program
// in a differential is indistinguishable from a passing one unless something
// checks, so this checks.
//
// It is deliberately about the BASELINE corpus only: the refusal-parity test
// below feeds inputs that are SUPPOSED to error, and asserting liveness there
// would be wrong.
fn dr_assert_live(input string, program string) {
	lazy, _ := dr_both(input, program)
	assert !lazy.starts_with('ERR:'),
		'DEAD PROGRAM — it fails on both arms, so it agrees vacuously and tests nothing:\n' +
		'  program : ${program}\n  error   : ${lazy}'
	assert lazy.len > 0,
		'DEAD PROGRAM — it produces no bytes on either arm:\n  program : ${program}'
}

// ── the corpus ────────────────────────────────────────────────────────

// dr_records builds a JSON-shape input of `n` records — the §11.4.4 shape,
// the one the fast path is for.
//
// Each record carries a NESTED CHILD ELEMENT as well as its slots, and that
// is not decoration. Slots (`:name "a"`) are not children, so `$u/name`
// selects nothing — slots are NOT path-readable at all (`$u/name` and
// `$u@name` both yield `()`; only real attributes answer `/@k`) — and a
// program written that way yields empty on BOTH arms —
// it agrees vacuously and exercises no forcing at all. The first version of
// this corpus was slots-only, which is why removing a real forcing site left
// it green. `[tag …]` gives the path programs something to actually reach.
fn dr_records(n int) string {
	mut b := strings.new_builder(256)
	b.write_string('[users\n')
	for i in 0 .. n {
		active := if (i & 1) == 0 { 'true' } else { 'false' }
		b.write_string('  [user :id ${i} :name "n-${i}" :active ${active} :ratio 0.${i} [tag :k ${i} :label "t-${i}"]]\n')
	}
	b.write_string(']\n')
	return b.str()
}

// The programs. Each one is here because it reaches the bound value a
// DIFFERENT way — the point is coverage of how a record can be observed,
// not of how many records there are.
const dr_programs = [
	// pure pass-through: the record is never inspected at all. This is the
	// shape the whole architecture exists for, and the one where a forcing
	// bug would be invisible to a test that only checked "does it run".
	'[?for [in \$u \$doc/user] [yield \$u]]',
	// navigation forces: a path step is a structural read. These reach the
	// NESTED CHILD, not the slots — a slot step selects nothing and would
	// agree vacuously (see dr_records).
	'[?for [in \$u \$doc/user] [yield \$u/tag]]',
	'[?for [in \$u \$doc/user] [yield [\$count \$u/tag]]]',
	'[?for [in \$u \$doc/user] [yield [wrap \$u/tag]]]',
	// the value flows into a builtin as a whole — the escape route the
	// audit identified, where a path-less read hands the record to
	// arbitrary code.
	'[?for [in \$u \$doc/user] [yield [\$count \$u]]]',
	// ...and into a comparison, and a guard.
	'[?for [in \$u \$doc/user] [where [\$exists \$u/tag]] [yield \$u]]',
	'[?for [in \$u \$doc/user] [where [\$exists \$u/tag]] [yield \$u/tag]]',
	// bound to another name first, then navigated — aliasing, which is
	// how a "does this program touch $u" analysis would have been fooled.
	'[?for [in \$u \$doc/user] [= \$v \$u] [yield \$v/tag]]',
	'[?for [in \$u \$doc/user] [= \$v \$u] [yield \$v]]',
	// the record inside a constructed element — carried, not inspected.
	'[?for [in \$u \$doc/user] [yield [wrapped \$u]]]',
	// limits and skips, which change WHICH records are forced.
	'[?for [in \$u \$doc/user] [take 3] [yield \$u]]',
	'[?for [in \$u \$doc/user] [drop 2] [yield \$u]]',
	'[?for [in \$u \$doc/user] [take 2] [yield \$u/tag]]',
	// two-step plan: steps INTO the record, so it forces and must also
	// pay the resolve it skipped.
	'[?for [in \$n \$doc/user/tag] [yield \$n]]',
	// reserved position binding alongside a lazy value.
	'[?for [in \$u \$doc/user] [yield [p \$_position]]]',
	// ── #845: the [?map] lane, which hands a lazy record to a CLOSURE ──
	// A new escape route, and the reason these are here rather than assumed
	// covered: the [?for] programs above reach the record through clause
	// machinery this project controls, while `:using` hands it to an
	// arbitrary user closure. Every observation route is re-run through that
	// boundary. At corpus sizes 1 and 2 these also exercise the DECLINING
	// side of the deferred commit (a 1-match walk never commits), so both
	// halves of the refusal-parity discipline are differentiated.
	//
	// pure pass-through THROUGH a closure — never inspected.
	'[?map \$doc/user [using [?fn (\$u) \$u]]]',
	// navigation inside the closure body forces.
	'[?map \$doc/user [using [?fn (\$u) \$u/tag]]]',
	// the whole record into a builtin, from inside the closure.
	'[?map \$doc/user [using [?fn (\$u) [\$count \$u]]]]',
	// carried into a construction rather than inspected.
	'[?map \$doc/user [using [?fn (\$u) [wrapped \$u]]]]',
	// two-step plan on the map lane: steps INTO the record, so it forces and
	// must also pay the resolve the one-step form skips.
	'[?map \$doc/user/tag [using [?fn (\$n) \$n]]]',
]

fn test_lazy_and_strict_agree_over_the_record_shape() {
	// The instrument must be exercising the lazy arm. Without this the whole
	// file could pass by comparing the strict path against itself — the
	// vacuous-green shape this project keeps meeting.
	code.set_lazy_records_off(false)
	assert code.lazy_records_active(), 'the lazy arm is disabled — this differential would be vacuous'

	// The bytes must actually exist. A sink that silently drops its chunks
	// makes every comparison "" == "" and the file passes green over
	// nothing — which is what the first version of this test did.
	probe := dr_eval(dr_records(40), '[?for [in \$u \$doc/user] [yield \$u]]') or {
		assert false, 'baseline eval failed: ${err.msg()}'
		return
	}
	assert probe.len > 100, 'the harness captured ${probe.len} bytes — the sink is dropping chunks and this differential is vacuous'
	assert probe.contains('[user'), 'the harness captured bytes that are not the records: ${probe#[..80]}'

	// Every program must actually RUN before its agreement means anything.
	live_input := dr_records(40)
	for p in dr_programs {
		dr_assert_live(live_input, p)
	}

	for n in [1, 2, 3, 5, 40] {
		input := dr_records(n)
		for p in dr_programs {
			dr_assert_agree(input, p, '${n} records')
		}
	}
	println('[lazy-diff] ${dr_programs.len} programs x 5 corpus sizes, lazy == strict')
}

// Inputs that DECLINE the certified subset, so the walk mixes lazy and
// materialised children in one pass. A record that forces beside one that
// does not is where an ordering or aliasing bug would show up, and it is not
// reachable from the uniform corpus above.
const dr_mixed_inputs = [
	// a QName child declines (namespaces leave the subset), its neighbours
	// certify.
	'[users [user :id 1 :name "a"] [ns:user :id 2 :name "b"] [user :id 3 :name "c"]]',
	// an escape-bearing string declines.
	'[users [user :id 1 :name "a"] [user :id 2 :name "b\\tc"] [user :id 3 :name "d"]]',
	// bare body text declines.
	'[users [user :id 1 :name "a"] [user hello] [user :id 3 :name "c"]]',
	// a nested child element inside one record.
	'[users [user :id 1 :name "a"] [user :id 2 [inner :k 1]] [user :id 3 :name "c"]]',
	// attributes are certified but never canonical (the renderer emits
	// values bare when safe), so these force at render.
	'[users [user id=1 name="a"] [user id=2 name="b"] [user id=3 name="c"]]',
	// canonical single-quoted source — already its own image, no rewrite.
	"[users [user :id 1 :name 'a'] [user :id 2 :name 'b'] [user :id 3 :name 'c']]",
	// content containing a quote, so `\"…\"` IS the canonical form.
	'[users [user :id 1 :name "o\'hara"] [user :id 2 :name "b"] [user :id 3 :name "c"]]',
	// negative zero and leading zeros: well-formed, NOT canonical.
	'[users [user :id -0 :name "a"] [user :id 2 :name "b"] [user :id 3 :name "c"]]',
	// decimals carried verbatim, trailing zeros included.
	'[users [user :id 1 :ratio 10.50] [user :id 2 :ratio 0.10] [user :id 3 :ratio 1.0]]',
]

fn test_lazy_and_strict_agree_when_the_walk_is_mixed() {
	code.set_lazy_records_off(false)
	for input in dr_mixed_inputs {
		for p in dr_programs {
			dr_assert_agree(input, p, 'mixed: ${input#[..40]}')
		}
	}
	println('[lazy-diff] ${dr_mixed_inputs.len} mixed inputs x ${dr_programs.len} programs, lazy == strict')
}

// A record forced TWICE must parse once and answer identically both times.
// Without the shared memo cell this is a silent throughput regression
// against the materialising path rather than an improvement — two reads of
// one record would parse it twice.
fn test_repeated_reads_agree() {
	code.set_lazy_records_off(false)
	input := dr_records(6)
	for p in [
		'[?for [in \$u \$doc/user] [yield [pair \$u/tag \$u/tag]]]',
		'[?for [in \$u \$doc/user] [yield [triple \$u/tag \$u/tag \$u/tag]]]',
		'[?for [in \$u \$doc/user] [where [\$exists \$u/tag]] [yield [pair \$u/tag \$u/tag]]]',
	] {
		dr_assert_agree(input, p, 'repeated reads')
	}
}

// Inputs the fast path REFUSES must refuse identically on both arms —
// success/refusal parity is the property PASS 1 exists for, and a lazy
// record must not change which inputs are accepted.
fn test_refusals_agree() {
	code.set_lazy_records_off(false)
	for input in [
		'[users [user :id 1 :name "a"] [user :id 2 :name "b"',   // unterminated
		'[users [user :id 1 :name "a"] [cx:reserved x=1]]',      // reserved ns
		'[users [user :id 1] [user :id 2]] [extra]',             // trailing content
		'[users [user :id 1 :name "a"] &anchor [user :id 2]]',   // anchors decline
	] {
		for p in dr_programs {
			dr_assert_agree(input, p, 'refusal: ${input#[..30]}')
		}
	}
	println('[lazy-diff] refusal parity holds on both arms')
}
