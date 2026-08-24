// #804 leg 9 — WHERE THE GARBAGE COMES FROM.
//
// Leg 8 falsified the assumption this probe exists to replace. Removing a
// per-record heap allocation (`rewrites []int`) bought +7.1% — the
// allocation's own cost and nothing more — while GC still stood at ~22% of
// samples. So the collector is being fed by something else, and the next
// optimisation must not be chosen by intuition again.
//
// WHAT THIS MEASURES, and why sampling could not. `sample` attributes CPU;
// it cannot attribute BYTES. Collection work is triggered by allocation
// VOLUME but is paid at whatever safepoint the mutator next reaches, so a
// call tree charges collection to whoever happened to poll, not to whoever
// produced the garbage. `gc_total_allocated()` is monotone bytes-since-start
// (one atomic load), so a baseline-and-subtract around one trial meters the
// allocation that trial actually caused — the quantity that drives the
// collector — with no attribution ambiguity at all.
//
// HOW IT ATTRIBUTES. One corpus, and a ladder of rungs that each stop one
// stage earlier than the next, so consecutive differences are one stage's
// allocation and its throughput cost. The lower rungs are driven in native V
// so the ladder can see BELOW what any CX program can express; the upper ones
// are real programs through the real engine, and the two meet: `scan+write`
// and `yield-u` agree to within 2 bytes/record, which is the measurement that
// says the evaluator is no longer allocating anything.
//
//   box-*        ATTRIBUTION rungs: construct the structs the walk builds,
//                with no scan and no stream anywhere near them.
//   setup-only   open the stream and read nothing — `new_parser` does
//                `src.bytes()`, a COPY of the whole corpus, before the first
//                record is read. Metered separately by every rung, because a
//                one-time O(input) cost divided by record count is a fiction
//                that grows with corpus size and reads as garbage that is not
//                there.
//   fn-*         the scan functions alone, over the raw buffer.
//   scan+lazy    `next_lazy` — the above + build the cx.LazyRecord and box it
//                into a cx.Node.
//   scan+write   + the canonical writer + StreamCtx-shaped chunked flush.
//   walk         `[where false]` — the evaluator: per-item frame, bind,
//                clause. Nothing yielded.
//   yield-const  `[yield 1]` — + yield eval + emit + flush, with the OUTPUT
//                reduced to ~2 bytes/record.
//   yield-u      `[yield $u]` — the gate-15 shape.
//
// `[where false]` does NOT push the walk off the fast path: commit is decided
// by the SECOND MATCH, which is computed before any clause runs, so the
// filtered walk commits and streams exactly like the others (it simply emits
// nothing). Verified by the committed-count line this probe prints — a run
// that fell back to the materializing path would report zero commits, and
// then its numbers would be about a different code path entirely.
//
// TWO WAYS TO MISREAD THIS PROBE, both hit while building it:
//
//   1. RUN ONE RUNG PER PROCESS (`LEG9_SHAPES=<name>`). Three rungs in one
//      process pollute each other's heap state; the jitter read 45-70% of
//      mean instead of ~90%, and the allocation figures stayed sound while
//      the throughput figures did not.
//   2. DO NOT SHRINK THE CORPUS. vgc accumulates allocation in a per-thread
//      delta and folds it into the global counter only every 1 MiB, so a
//      reading carries up to 1 MiB of lag — negligible at 64 MiB, ±25% at
//      2 MiB. The same rung read 191.8 then 143.8 bytes/record across two
//      2 MiB runs. The probe prints a warning below 16 MiB of allocation
//      rather than trusting the operator to remember.
//
// WHAT IT SAID AT LEG 9 (64 MiB, -prod, 5 trials + 2 warmup, ONE RUNG PER
// PROCESS, 688,424 records). Per-record figures EXCLUDE the one-time 64 MiB
// buffer copy, which every rung pays:
//
//                        MB/s     bytes/record     ns/record
//   fn-canonical        461.7          8.8            201
//   scan+lazy           262.6        150.2            354   (+153)
//   scan+write          217.5        436.1
//   walk                165.0        177.0
//   yield-u (GATE)      164.0        438.3
//
// The gate shape's 438 bytes/record decomposed as: the scan 9, the lazy
// record's box and name string ~141, the output path ~286, and the evaluator
// about TWO. The output path's 286 closed exactly — 2004 flushes x (65,536
// for a fresh builder + 32,800 for the chunk memdup) / 688,424 records =
// 190.6 + 95.4, against 285.9 measured. The 190.6 was pure waste and leg 9
// removed it (see StreamCtx.flush), giving:
//
//                        MB/s     bytes/record     ns/record
//   scan+write (post)   238.0        245.1            391   (+37)
//   yield-u    (post)   172.6        247.7            539   (+148)
//
// LEG 10 then took the ns column seriously and left the bytes column alone,
// which is the whole point of reading them separately:
//
//                        MB/s     bytes/record     ns/record
//   scan+lazy           321.0        150.2 (same)     266
//   yield-u  (GATE)     194.9        247.7 (same)     477
//
// LEG 11 dropped the per-record name STRING for the name's offsets (its only
// reader is the walk's name compare, which is now a byte compare against the
// buffer the record already holds; sizeof(LazyRecord) 136 -> 128):
//
//                        MB/s     bytes/record
//   scan+lazy           348.7        137.1
//   yield-u  (GATE)   ~202.5        234.5
//
// AND THAT CROSSES THE §11.4.4 FLOOR FOR THIS SHAPE — but read the trial count
// before quoting it. At the GATE'S configuration (5 trials, 2 warmup) four
// consecutive runs gave 202.2 / 202.9 / 203.6 / 201.6, jitter 88-90%. At TEN
// trials the same build gives 192.6-199.7 with jitter 81.8-84.1%, because heap
// pressure accumulates across trials in one process and the probe does not
// reset between them. That is a property of this harness, not of the engine —
// but it means the margin is thin, and a 5-trial pass is not evidence of a
// 10-trial one. Quote the configuration with the number.
//
// `Parser.skip_span_to` re-walked every byte of a certified span purely to keep
// line/col accurate for a later error message — a SECOND full pass over bytes
// the scan had just read. The scan now tallies newlines inside the whitespace
// walk it already performs and the position update is arithmetic. Allocation
// did not move by a single byte; throughput moved 12.9%. An allocation census
// could never have found this, which is why the ns column is in the table.
//
// READ THE TWO COLUMNS SEPARATELY — THEY DO NOT RANK THE SAME, and treating
// them as one is the leg-8 mistake in a new costume. By ALLOCATION the
// evaluator is finished: it adds ~2 bytes/record, so leg 7's frame pool
// closed that account. By TIME it is one of the two largest costs left, at
// +148 ns/record. An allocation census cannot rank the work; it can only say
// which work feeds the collector.
//
// So the remaining budget, in ns/record, is:
//
//   201  the scan itself                     (the floor of this architecture)
//  +153  the stream wrapper + LazyRecord box
//   +37  render + flush
//  +148  the evaluator
//  ----
//   539  now.   200 MB/s is 465.  SO THE GAP IS 74 ns/record, 13.6%.
//
// That is a better statement of what is left than leg 8's "roughly half of
// all non-scan cost", and the two candidates it names are the 153 and the
// 148, not the 37 this leg just fixed.
//
// WHAT `bench-lazy-ceiling` MEASURES IS NOT REACHABLE, and this probe is how
// that became visible. At 64 MiB it reports scan+write at 333.2 MB/s (and
// recognition alone at 524.6) — HIGHER than its 16 MiB figures, so the
// worry that the published ceiling was a small-corpus artifact is refuted.
// But its writer builds no node and calls `go_back_to(0)` instead of `str()`,
// so it pays neither the LazyRecord the engine must construct nor the chunk
// STRING the CXStreamSink contract requires (~95 bytes/record, measured
// here). It also still writes in RUNS, which leg 5 replaced in the engine
// with one memmove per record. The engine-reachable ceiling for this
// architecture is this probe's `scan+write` rung — 238.0 MB/s — and the
// engine is at 172.6, which is 73% of it rather than 52% of 333.
//
// WHAT IS LEFT ON THE ALLOCATION SIDE, in size order, all measured:
//   ~141 B/record  the cx.LazyRecord box. sizeof is 136, not the 96 leg 8
//                  assumed, and 72 of those bytes are RewriteSet's inline
//                  [8]int + spill header for a record that uses two slots.
//    ~95 B/record  the chunk memdup — required while the sink takes a string.
//   64 MiB/eval    `new_parser`'s `src.bytes()`. One copy of the whole input
//                  per evaluation, 28% of all remaining allocation. Removing
//                  it means a non-owning byte view, and LazyRecord holds
//                  `src []u8` — so that is a lifetime question, not a tweak.
//
// Not a gate. A decision instrument, like `bench-lazy-ceiling`.
//
// Env overrides:
//   LEG9_INPUT_MB — corpus size in MiB (default 64; the size #804's
//                   published figures are quoted at)
//   LEG9_TRIALS   — measured trials (default 5)
//   LEG9_WARMUP   — warmup trials (default 2, matching gate 15)
//   LEG9_SHAPES   — comma-separated subset of the rung names

module main

import code
import cx
import platform as _
import time
import os
import strings

const default_input_mb = 64
const default_trials = 5
const default_warmup = 2

@[heap]
struct ByteSink {
mut:
	total  i64
	chunks int
}

struct Rung {
	name string
	prog string // a CX program, or '' for a raw (native) rung
	mode int    // raw rungs only: 0 = scan, 1 = scan+lazy, 2 = scan+write
	note string
}

// The ladder, cheapest first. Consecutive differences are one stage's cost.
const rungs = [
	Rung{'box-childvalidation', '', 6, 'ATTRIBUTION: construct ChildValidation{} only — no scan, no stream'},
	Rung{'box-lazyrecord', '', 7, 'ATTRIBUTION: + the cx.LazyRecord box in its node field'},
	Rung{'setup-only', '', 5, 'open the stream and read nothing (new_parser copies the whole buffer)'},
	Rung{'fn-certified', '', 3, 'scan_child_certified alone, no Parser, no stream'},
	Rung{'fn-canonical', '', 4, 'scan_child_canonical alone (+ canonicality + rewrite offsets)'},
	Rung{'scan+lazy', '', 1, '+ build cx.LazyRecord and box it into a cx.Node'},
	Rung{'scan+write', '', 2, '+ the canonical writer + StreamCtx-shaped chunked flush'},
	Rung{'walk', '[?for [in \$u \$doc/user] [where false] [yield \$u]]', -1, '+ the evaluator: per-item frame, bind, clause; nothing emitted'},
	Rung{'yield-const', '[?for [in \$u \$doc/user] [yield 1]]', -1, '+ yield eval + emit + flush, ~2 output bytes/record'},
	Rung{'yield-u', '[?for [in \$u \$doc/user] [yield \$u]]', -1, '+ the record image (THE GATE-15 SHAPE)'},
]

// build_input reproduces the §11.6 gate-15 corpus byte for byte. Any
// divergence here makes every number in this probe about a different
// workload than the one the threshold is quoted against.
fn build_input(target_bytes int) (string, int) {
	mut b := strings.new_builder(target_bytes + 4096)
	b.write_string('[users\n')
	mut i := 0
	for b.len < target_bytes {
		name_n := 1000 + (i * 7919) % 9000
		host_a := (i * 31) % 256
		host_b := (i * 131) % 256
		port := 1024 + (i * 17) % 64000
		active := if (i & 1) == 0 { 'true' } else { 'false' }
		ratio_n := (i * 53) % 1000
		b.write_string('  [user :id ${i} :name "alice-${name_n}" :host "10.0.${host_a}.${host_b}"')
		b.write_string(' :port ${port} :active ${active} :ratio 0.${ratio_n}]\n')
		i++
	}
	b.write_string(']\n')
	return b.str(), i
}

struct Trial {
	ms        i64
	out_bytes i64
	chunks    int
	records   int
	// alloc is every byte the trial allocated; setup is the part of it spent
	// before the first record is read (the parser's whole-buffer copy). The
	// per-record figure this probe reports is (alloc - setup) / records —
	// a one-time O(input) cost divided by record count is a fiction that
	// scales with corpus size and looks like garbage that is not there.
	alloc     u64
	setup     u64
	gc_cycles u64
}

fn run_trial(input string, program string) Trial {
	sk := &ByteSink{}
	sink := fn [sk] (chunk string) ! {
		unsafe {
			sk.total += chunk.len
			sk.chunks++
		}
	}
	// Baseline taken as late as possible and read as early as possible, so
	// the meter spans the evaluation and as little else as it can.
	cyc0 := gc_heap_usage().bytes_since_gc
	a0 := gc_total_allocated()
	t0 := time.now()
	code.eval_code_streaming(input, program, 'text', sink) or { panic('${err}') }
	elapsed := time.since(t0).milliseconds()
	a1 := gc_total_allocated()
	cyc1 := gc_heap_usage().bytes_since_gc
	return Trial{
		ms:        elapsed
		out_bytes: sk.total
		chunks:    sk.chunks
		// The CX rungs cannot split their own setup from the inside; the
		// engine's one whole-buffer copy is charged from the outside, which
		// the `setup-only` raw rung measures directly.
		setup:     u64(input.len)
		alloc:     a1 - a0
		gc_cycles: u64(cyc1) - u64(cyc0)
	}
}


// ── RAW RUNGS ────────────────────────────────────────────────────────────
//
// The CX-program rungs above cannot see below `[where false]` — everything
// from the byte scan up to and including the per-item frame is one opaque
// block there. These three drive the same corpus through the same stream in
// native V, each stopping one stage earlier, so the walk's own allocation
// decomposes the same way the yield path did.
//
//   fn-*       the scan functions alone, over the raw buffer.
//   scan+lazy  `next_lazy` — the above + build the cx.LazyRecord and box it
//                            into a cx.Node. Leg 8 named this as an
//                            unmeasured candidate and put it at 96 B; it is
//                            136 B of struct plus the name string, and the
//                            ladder charges it ~141 B/record.
//   scan+write `next_lazy` + the canonical writer into a chunked builder
//                            that flushes exactly as StreamCtx does.
//
// These are the ceiling probe's rungs with an allocation meter attached; the
// throughput figures should agree with `make bench-lazy-ceiling` and the
// bytes figures are what that probe could not report.
fn raw_trial(input string, mode int, threshold int, records_hint int) Trial {
	mut sk := &ByteSink{}
	a0 := gc_total_allocated()
	t0 := time.now()
	// SETUP is metered separately. `new_parser` does `src.bytes()` — a full
	// COPY of the input buffer — so every rung pays one allocation the size
	// of the corpus before it reads a single record. Folding that into the
	// per-record figure is how a one-time O(input) cost gets misread as
	// per-record garbage, which is exactly the mistake this probe exists to
	// stop making.
	// Modes 3/4 drive the scan functions directly and so open no stream; they
	// take the same one whole-buffer copy `new_parser` would, inside the same
	// metered setup window, so every rung's setup line means the same thing.
	mut raw_src := []u8{}
	mut stream := cx.CXChildStream{}
	if mode == 3 || mode == 4 {
		raw_src = input.bytes()
	} else {
		stream = cx.open_top_level_children(input) or { panic('${err}') }
	}
	mut b := strings.new_builder(threshold * 2)
	setup := gc_total_allocated() - a0
	mut n := 0
	if mode == 5 {
		// setup only — the stream is opened and nothing is read.
	} else if mode == 6 || mode == 7 {
		// ATTRIBUTION CHECK for the two boxes the ladder charges per record.
		// `ChildValidation` carries a `node Node` field, and `Node`'s first
		// variant is `Element` — so every construction that leaves `node`
		// unset still materialises a zero Element, and V boxes sumtype
		// payloads on the heap. Rung 6 constructs nothing else; whatever it
		// reports is that field's cost with no scan, no stream and no record
		// anywhere near it. Rung 7 adds the lazy record's own box.
		src := input.bytes()
		mut at := 1
		for at < src.len && src[at] != `[` {
			at++
		}
		sc := cx.scan_child_canonical(src, at) or { panic('probe corpus: child scan declined') }
		mut sum := 0
		for _ in 0 .. records_hint {
			if mode == 6 {
				cv := cx.ChildValidation{
					has: true
				}
				sum += int(cv.has)
			} else {
				cv := cx.ChildValidation{
					has:  true
					node: cx.new_lazy_record(src, at, sc)
				}
				sum += int(cv.has)
			}
		}
		n = if sum > 0 { records_hint } else { records_hint }
	} else if mode == 3 || mode == 4 {
		// The scan functions alone, walked over the stream's OWN buffer with
		// no Parser between them and the bytes. Isolates the recognizer's own
		// allocation from everything the stream wraps it in. Starts past the
		// root's `[` so the walk sees the CHILDREN, not one whole-document
		// element (which would scan once and report a per-record cost that
		// was never paid per record).
		src := raw_src
		mut i := 1
		for i < src.len {
			if src[i] != `[` {
				i++
				continue
			}
			if mode == 3 {
				e := cx.scan_child_certified(src, i) or {
					i++
					continue
				}
				i = e
			} else {
				sc := cx.scan_child_canonical(src, i) or {
					i++
					continue
				}
				i = sc.end
			}
			n++
		}
	} else {
		for {
			v := stream.next_lazy(true) or { panic('${err}') }
			if !v.has {
				break
			}
			if mode == 2 {
				if n > 0 {
					b.write_string('\n')
				}
				// The emit path's own renderer, entered exactly as
				// StreamCtx.emit_node enters it — a canonical lazy record
				// takes the writer arm, anything else renders normally.
				code.render_node_to(mut b, v.node)
				if b.len >= threshold {
					// Mirrors StreamCtx.flush AFTER leg 9: `str()` memdups and
					// clears, so the builder is reused rather than replaced. If
					// the engine ever goes back to a fresh buffer this rung has
					// to follow, or it stops modelling the path it names.
					chunk := b.str()
					sk.total += chunk.len
					sk.chunks++
				}
			}
			n++
		}
	}
	if b.len > 0 {
		chunk := b.str()
		sk.total += chunk.len
		sk.chunks++
	}
	elapsed := time.since(t0).milliseconds()
	a1 := gc_total_allocated()
	return Trial{
		ms:        elapsed
		out_bytes: sk.total
		chunks:    sk.chunks
		records:   n
		alloc:     a1 - a0
		setup:     setup
		gc_cycles: 0
	}
}

fn env_int(name string, dflt int) int {
	v := os.getenv(name)
	if v == '' {
		return dflt
	}
	return v.int()
}

fn main() {
	input_mb := env_int('LEG9_INPUT_MB', default_input_mb)
	trials := env_int('LEG9_TRIALS', default_trials)
	warmup := env_int('LEG9_WARMUP', default_warmup)
	only := os.getenv('LEG9_SHAPES').split(',').filter(it != '')

	input, records := build_input(input_mb * 1024 * 1024)
	println('#804 leg 9 — streamed [?for] allocation census')
	println('  corpus   : ${input_mb} MiB (${input.len} bytes, ${records} records)')
	println('  trials   : ${trials} measured, ${warmup} warmup')
	mut lazy := 'ON'
	$if cx_no_lazy_record ? {
		lazy = 'OFF (-d cx_no_lazy_record)'
	}
	println('  lazy rec : ${lazy}')
	println('  sizeof         : cx.Node ${sizeof(cx.Node)}  cx.LazyRecord ${sizeof(cx.LazyRecord)}  cx.Element ${sizeof(cx.Element)}  cx.RewriteSet ${sizeof(cx.RewriteSet)}')
	println('')

	for r in rungs {
		if only.len > 0 && r.name !in only {
			continue
		}
		raw := r.prog == ''
		for _ in 0 .. warmup {
			if raw {
				raw_trial(input, r.mode, code.stream_chunk_threshold, records)
			} else {
				run_trial(input, r.prog)
			}
		}
		commits0 := code.streamed_input_commits()
		mut ts := []Trial{}
		for _ in 0 .. trials {
			ts << if raw {
				raw_trial(input, r.mode, code.stream_chunk_threshold, records)
			} else {
				run_trial(input, r.prog)
			}
		}
		commits := code.streamed_input_commits() - commits0
		mut sum := 0.0
		mut min := 1.0e30
		mut alloc_sum := u64(0)
		mut setup_sum := u64(0)
		for t in ts {
			setup_sum += t.setup
			m := if t.ms <= 0 { 0.0 } else { f64(input.len) * 1000.0 / f64(t.ms) / (1024.0 * 1024.0) }
			sum += m
			if m < min {
				min = m
			}
			alloc_sum += t.alloc
		}
		mean := sum / f64(ts.len)
		alloc := alloc_sum / u64(ts.len)
		setup := setup_sum / u64(ts.len)
		per_rec := if alloc > setup { f64(alloc - setup) / f64(records) } else { 0.0 }
		println('${r.name} — ${r.note}')
		if raw {
			println('  driver         : native (raw rung ${r.mode})')
		} else {
			println('  program        : ${r.prog}')
		}
		println('  throughput     : ${mean:7.1f} MB/s mean   ${min:7.1f} min (${min / mean * 100.0:5.1f}% of mean)')
		println('  output         : ${ts[0].out_bytes} bytes in ${ts[0].chunks} chunks')
		println('  ALLOCATED      : ${f64(alloc) / (1024.0 * 1024.0):9.1f} MiB / trial   (${f64(alloc) / f64(input.len):5.2f}x input)')
		println('    one-time     : ${f64(setup) / (1024.0 * 1024.0):9.1f} MiB   (the parser\'s whole-buffer copy)')
		println('    PER RECORD   : ${per_rec:9.1f} bytes/record   (${f64(alloc - setup) / (1024.0 * 1024.0):.1f} MiB over ${records} records)')
		// INSTRUMENT LIMIT, and it is not a rounding remark. vgc accumulates
		// allocation in a PER-THREAD delta and folds it into the global
		// counter only every `vgc_acct_flush` (1 MiB), so a reading carries up
		// to 1 MiB of lag. Over a 64 MiB corpus (180-350 MiB allocated) that is
		// under 0.6%; over a 2 MiB corpus it is ±25%, which is enough to move a
		// per-record figure by a whole allocation. Measured: the same rung read
		// 191.8 and then 143.8 bytes/record across two 2 MiB runs. Any rung
		// whose total sits near the flush granularity says so rather than
		// publishing a number it cannot support.
		if alloc < 16 * 1024 * 1024 {
			println('    *** ${f64(alloc) / (1024.0 * 1024.0):.1f} MiB is within ~16x of vgc\'s 1 MiB accounting flush — run a LARGER corpus before quoting this ***')
		}
		if !raw {
			println('  commits (fast) : ${commits} over ${trials} trials  ${if commits == u64(trials) { '(every trial took the streamed-input path)' } else { '*** NOT the streamed-input path — numbers are about a different walk ***' }}')
		}
		println('')
	}
}
