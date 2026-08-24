// #804 leg 2 — the LAZY-RECORD CEILING PROBE.
//
// Leg 2 defers a record's materialisation until something reads its
// structure. Before choosing a forcing discipline (the design question
// the blast-radius measurement opened), one number decides whether the
// discipline is worth its cost at all: what does the streamed-input walk
// measure when NOTHING ever forces?
//
// That is the ceiling. This probe walks the gate-15 corpus doing exactly
// what a never-forced lazy record would do and no more:
//
//   scan the child's bytes (cx.scan_child_canonical, leg 1 + 804-1d)
//   → emit its canonical image (cx.apply_rewrites) into a flushing sink
//
// No parse, no AST, no resolve, no binding, no eval. Every one of those
// is work a real leg 2 still pays on some record, so the real number
// lands BELOW this. If the ceiling is under the §11.4.4 floor, no
// forcing discipline can reach the threshold and leg 2's architecture is
// answering the wrong question — which is exactly what a ceiling probe
// exists to find out before the code gets written, not after.
//
// Three legs are timed so the ceiling decomposes:
//   scan      — recognition alone (the floor of any lazy design)
//   scan+emit — recognition plus the canonical-image write (the real
//               ceiling: a pass-through record's whole cost)
//   parse     — today's PASS-2 cost on the same bytes, for scale
//
// Env: LAZY_PROBE_MB (default 16), LAZY_PROBE_TRIALS (default 3),
//      LAZY_PROBE_WARMUP (default 1).
//
// Run -prod or it reads ~5x slow (the gate-15 measurement repair).

module main

import cx
import time
import os
import strings

const default_mb = 16
const default_trials = 3
const default_warmup = 1

// flush_threshold mirrors StreamCtx's default so the emit leg pays the
// same buffering cadence the real streamed path pays.
const flush_threshold = 64 * 1024

fn env_int(name string, dflt int) int {
	v := os.getenv(name)
	if v == '' {
		return dflt
	}
	return v.int()
}

// build_input reproduces the gate-15 corpus verbatim (§11.4.4 JSON-shape
// workload) — same generator as code_streaming_throughput_bench.v, so
// the numbers are comparable to the gate's.
fn build_input(target_bytes int) string {
	mut b := strings.new_builder(target_bytes + 4096)
	b.write_string('[users\n')
	mut i := 0
	for b.len < target_bytes {
		id := i
		name_n := 1000 + (i * 7919) % 9000
		host_a := (i * 31) % 256
		host_b := (i * 131) % 256
		port := 1024 + (i * 17) % 64000
		active := if (i & 1) == 0 { 'true' } else { 'false' }
		ratio_n := (i * 53) % 1000
		b.write_string('  [user :id ${id} :name "alice-${name_n}" :host "10.0.${host_a}.${host_b}"')
		b.write_string(' :port ${port} :active ${active} :ratio 0.${ratio_n}]\n')
		i++
	}
	b.write_string(']\n')
	return b.str()
}

// body_start locates the first byte after the root element's head. The
// corpus root is `[users\n`, so this is a probe-local shortcut, not a
// parser: the probe measures the per-child walk, and the head is one
// record's worth of bytes out of ~170 000.
fn body_start(src []u8) int {
	mut i := 0
	for i < src.len && src[i] != `\n` {
		i++
	}
	return i + 1
}

@[inline]
fn skip_ws(src []u8, at int) int {
	mut i := at
	for i < src.len {
		c := src[i]
		if c == ` ` || c == `\t` || c == `\r` || c == `\n` {
			i++
		} else {
			break
		}
	}
	return i
}

struct Legs {
mut:
	children  int
	canonical int
	declined  int
	out_bytes int
	ms        i64
}

// leg_scan — recognition alone. What a lazy record costs when the walk
// never even asks for its bytes.
fn leg_scan(src []u8) Legs {
	t0 := time.now()
	mut i := body_start(src)
	mut children := 0
	mut canonical := 0
	mut declined := 0
	for {
		i = skip_ws(src, i)
		if i >= src.len || src[i] == `]` {
			break
		}
		sc := cx.scan_child_canonical(src, i) or {
			declined++
			break
		}
		children++
		if sc.canonical {
			canonical++
		}
		i = sc.end
	}
	return Legs{
		children:  children
		canonical: canonical
		declined:  declined
		ms:        time.since(t0).milliseconds()
	}
}

// leg_scan_emit — the real ceiling: recognition plus writing the
// canonical image through a flushing sink, which is the entire cost of a
// record that is emitted and never forced.
fn leg_scan_emit(src []u8) Legs {
	mut sunk := 0
	t0 := time.now()
	mut buf := strings.new_builder(flush_threshold * 2)
	mut i := body_start(src)
	mut children := 0
	mut canonical := 0
	mut declined := 0
	for {
		i = skip_ws(src, i)
		if i >= src.len || src[i] == `]` {
			break
		}
		sc := cx.scan_child_canonical(src, i) or {
			declined++
			break
		}
		children++
		if sc.canonical {
			canonical++
			if children > 1 {
				buf.write_string('\n')
			}
			buf.write_string(cx.apply_rewrites(src[i..sc.end], i, sc.rewrites))
		}
		i = sc.end
		if buf.len >= flush_threshold {
			sunk += buf.len
			buf.go_back_to(0)
		}
	}
	sunk += buf.len
	return Legs{
		children:  children
		canonical: canonical
		declined:  declined
		out_bytes: sunk
		ms:        time.since(t0).milliseconds()
	}
}

// leg_scan_write — the same ceiling with the intermediate string
// removed. `cx.apply_rewrites` returns a String, so it CLONES the span
// once per rewritten record; on this workload every record is rewritten,
// so that is one heap allocation per record sitting directly in the hot
// path. Writing the span through the rewrite offsets straight into the
// output builder pays none of it. The gap between this leg and
// scan+emit is what the emit seam's SHAPE is worth, and it is the reason
// leg 2's renderer arm should be a writer, not a string function.
fn leg_scan_write(src []u8) Legs {
	mut sunk := 0
	t0 := time.now()
	mut buf := strings.new_builder(flush_threshold * 2)
	mut i := body_start(src)
	mut children := 0
	mut canonical := 0
	mut declined := 0
	for {
		i = skip_ws(src, i)
		if i >= src.len || src[i] == `]` {
			break
		}
		sc := cx.scan_child_canonical(src, i) or {
			declined++
			break
		}
		children++
		if sc.canonical {
			canonical++
			if children > 1 {
				buf.write_string('\n')
			}
			// Write the span in runs, substituting `'` at each recorded
			// delimiter offset. No copy of the span is ever made.
			mut at := i
			for ri in 0 .. sc.rewrites.len {
				r := sc.rewrites.get(ri)
				if r > at {
					buf.write(src[at..r]) or {}
				}
				buf.write_u8(`'`)
				at = r + 1
			}
			if sc.end > at {
				buf.write(src[at..sc.end]) or {}
			}
		}
		i = sc.end
		if buf.len >= flush_threshold {
			sunk += buf.len
			buf.go_back_to(0)
		}
	}
	sunk += buf.len
	return Legs{
		children:  children
		canonical: canonical
		declined:  declined
		out_bytes: sunk
		ms:        time.since(t0).milliseconds()
	}
}

// leg_two_pass — the ceiling WITH PASS 1 retained (#804 leg 3).
//
// The streamed-input fast path runs two walks, and leg 2 did not change
// that: PASS 1 validates every child pre-emission so an input the
// materialising path would refuse declines BEFORE any output exists, and
// PASS 2 evaluates. After leg 2 both walks scan, so the input is now
// traversed twice by the scan rather than once by the scan and once by the
// parser.
//
// Two sequential walks compose as 1/(1/a + 1/b), which is the whole reason
// to measure this separately: each walk on its own clears the §11.4.4 floor
// comfortably, and the pair may not. If this leg lands under 200 MB/s then
// no amount of per-item tuning inside PASS 2 can reach the floor, and the
// thing in the way is the two-pass STRUCTURE rather than any cost inside it.
fn leg_two_pass(src []u8) Legs {
	mut sunk := 0
	t0 := time.now()
	// PASS 1 — validation only, retaining nothing (what the engine does).
	mut i := body_start(src)
	mut declined := 0
	for {
		i = skip_ws(src, i)
		if i >= src.len || src[i] == `]` {
			break
		}
		end := cx.scan_child_certified(src, i) or {
			declined++
			break
		}
		i = end
	}
	// PASS 2 — the evaluation walk, emitting canonical images.
	mut buf := strings.new_builder(flush_threshold * 2)
	mut j := body_start(src)
	mut children := 0
	mut canonical := 0
	for {
		j = skip_ws(src, j)
		if j >= src.len || src[j] == `]` {
			break
		}
		sc := cx.scan_child_canonical(src, j) or {
			declined++
			break
		}
		children++
		if sc.canonical {
			canonical++
			if children > 1 {
				buf.write_string('\n')
			}
			mut at := j
			for ri in 0 .. sc.rewrites.len {
				r := sc.rewrites.get(ri)
				if r > at {
					buf.write(src[at..r]) or {}
				}
				buf.write_u8(`'`)
				at = r + 1
			}
			if sc.end > at {
				buf.write(src[at..sc.end]) or {}
			}
		}
		j = sc.end
		if buf.len >= flush_threshold {
			sunk += buf.len
			buf.go_back_to(0)
		}
	}
	sunk += buf.len
	return Legs{
		children:  children
		canonical: canonical
		declined:  declined
		out_bytes: sunk
		ms:        time.since(t0).milliseconds()
	}
}

// leg_parse — today's cost on the same bytes: the real parser over every
// child, which is what PASS 2 pays per record now.
fn leg_parse(src []u8) Legs {
	t0 := time.now()
	mut i := body_start(src)
	mut children := 0
	mut declined := 0
	for {
		i = skip_ws(src, i)
		if i >= src.len || src[i] == `]` {
			break
		}
		end := cx.scan_child_certified(src, i) or {
			declined++
			break
		}
		span := src[i..end].bytestr()
		cx.parse(span) or {
			declined++
			cx.Document{}
		}
		children++
		i = end
	}
	return Legs{
		children: children
		declined: declined
		ms:       time.since(t0).milliseconds()
	}
}

fn mbps(bytes int, ms i64) f64 {
	if ms <= 0 {
		return 0.0
	}
	return f64(bytes) * 1000.0 / f64(ms) / (1024.0 * 1024.0)
}

fn report(name string, src []u8, trials int, warmup int, f fn ([]u8) Legs) f64 {
	for _ in 0 .. warmup {
		f(src)
	}
	mut sum := 0.0
	mut last := Legs{}
	for _ in 0 .. trials {
		l := f(src)
		sum += mbps(src.len, l.ms)
		last = l
	}
	mean := sum / f64(trials)
	extra := if last.out_bytes > 0 { ', out ${last.out_bytes} bytes' } else { '' }
	println('  ${name:-12} : ${mean:8.1f} MB/s   (${last.children} children, ${last.canonical} canonical, ${last.declined} declined${extra})')
	return mean
}

fn main() {
	input_mb := env_int('LAZY_PROBE_MB', default_mb)
	trials := env_int('LAZY_PROBE_TRIALS', default_trials)
	warmup := env_int('LAZY_PROBE_WARMUP', default_warmup)

	println('#804 leg-2 lazy-record CEILING probe')
	println('  corpus : gate-15 JSON-shape, ${input_mb} MiB')
	println('  trials : ${trials} (warmup ${warmup})')
	println('')

	input := build_input(input_mb * 1024 * 1024)
	src := input.bytes()

	scan_mbps := report('scan', src, trials, warmup, leg_scan)
	emit_mbps := report('scan+emit', src, trials, warmup, leg_scan_emit)
	write_mbps := report('scan+write', src, trials, warmup, leg_scan_write)
	two_mbps := report('two-pass', src, trials, warmup, leg_two_pass)
	parse_mbps := report('parse', src, trials, warmup, leg_parse)

	println('')
	println('  CEILING with PASS 1 : ${two_mbps:.1f} MB/s  <- what the ENGINE can reach')
	if two_mbps < 200.0 {
		println('    ** BELOW the 200 MB/s floor. The two-pass STRUCTURE is the')
		println('       binding constraint — no per-item tuning inside PASS 2')
		println('       can reach the floor while PASS 1 is a separate walk. **')
	}
	println('  CEILING (scan+write): ${write_mbps:.1f} MB/s vs the §11.4.4 floor of 200 MB/s')
	println('  via apply_rewrites  : ${emit_mbps:.1f} MB/s (one span copy per record)')
	println('  recognition alone   : ${scan_mbps:.1f} MB/s')
	if parse_mbps > 0 {
		println('  speedup over parse  : ${write_mbps / parse_mbps:.1f}x')
	}
	verdict := if write_mbps >= 200.0 {
		'ceiling CLEARS the floor — a forcing discipline can reach it'
	} else {
		'ceiling is BELOW the floor — no forcing discipline reaches 200 MB/s on this architecture'
	}
	println('  verdict : ${verdict}')
}
