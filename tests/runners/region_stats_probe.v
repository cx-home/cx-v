// region_stats_probe.v — how much of a [?worker] body's allocation actually
// lands in the region? Runs one eval and prints (region hits, GC fallbacks).
// Build with -d cx_regions or the stats are always 0.
module main

import code



const program = r"[?let [= $w [?worker name='w' [$sum [$map [$range 1 40000] [?fn ($x) [* $x 2]]]]]] [?wait-for [worker $w]]]"

fn main() {
	h0, o0 := cx_region_stats()
	r := code.eval_code('', program, 'text') or { panic('eval failed: ${err}') }
	h1, o1 := cx_region_stats()
	println('result=${r}')
	println('region_hits=${h1 - h0} gc_fallbacks=${o1 - o0}')
}
