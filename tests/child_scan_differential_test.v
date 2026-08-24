module main

import cx
import code
import fixtures
import os

// child_scan_differential_test — the safety instrument for the #804
// leg-1 validating span scan (`vcx/cx/child_scan.v`).
//
// The scan is a SOUND RECOGNIZER FOR A SUBSET, not a second parser, and
// the whole design rests on ONE property:
//
//     scan certifies span  ⇒  cx.parse(span) succeeds
//
// If that ever fails, the streamed-input fast path would accept an input
// the materializing path refuses — precisely the
// partial-output-then-error divergence PASS 1 exists to prevent. This
// gate hunts for a counter-example three ways:
//
//   1. every conformance in-cx input (the real corpus),
//   2. the gate-15 synthetic record corpus (the hot workload),
//   3. a MUTATION corpus — single-byte edits of well-formed records,
//      which is where a hand-written recognizer actually breaks: it is
//      easy to accept `[k 1]` correctly and also accept `[k 1.]`.
//
// The converse is deliberately NOT asserted. A parseable child the scan
// declines is merely slower, and declining is the conservative answer
// everywhere in this design.

fn conformance_dir() string {
	return os.real_path(os.join_path(os.dir(@FILE), '..', '..', 'conformance'))
}

// certified_span runs the scan over `src` and returns the certified end
// offset, or none.
fn certified_span(src string) ?int {
	return cx.scan_child_certified(src.bytes(), 0)
}

// assert_sound checks the one-directional obligation for `src`.
fn assert_sound(src string, origin string) {
	end := certified_span(src) or { return } // declined — always safe
	span := src[..end]
	cx.parse(span) or {
		assert false, 'UNSOUND: scan certified a span the parser REJECTS\n' +
			'  origin: ${origin}\n  span  : ${span}\n  error : ${err.msg()}'
		return
	}
}

fn test_conformance_corpus_soundness() {
	files := os.ls(conformance_dir()) or {
		assert false, 'cannot list conformance dir'
		return
	}
	mut checked := 0
	mut certified := 0
	for f in files {
		if !f.ends_with('.cxd') {
			continue
		}
		path := os.join_path(conformance_dir(), f)
		for c in fixtures.load_fixtures(path) {
			src := c.sections['in_cx'].trim_space()
			if src == '' || src == '[ignored]' || src == '[empty]' {
				continue
			}
			checked++
			if _ := certified_span(src) {
				certified++
			}
			assert_sound(src, '${f}/${c.name}')
		}
	}
	assert checked > 500, 'corpus shrank unexpectedly: only ${checked} inputs'
	println('[child-scan] conformance: ${checked} inputs, ${certified} certified, 0 unsound')
}

fn gate_record(i int) string {
	name_n := 1000 + (i * 7919) % 9000
	host_a := (i * 31) % 256
	host_b := (i * 131) % 256
	port := 1024 + (i * 17) % 64000
	active := if (i & 1) == 0 { 'true' } else { 'false' }
	ratio_n := (i * 53) % 1000
	return '[user :id ${i} :name "alice-${name_n}" :host "10.0.${host_a}.${host_b}" :port ${port} :active ${active} :ratio 0.${ratio_n}]'
}

fn test_gate_corpus_certified_and_sound() {
	mut certified := 0
	n := 3000
	for i in 0 .. n {
		r := gate_record(i)
		assert_sound(r, 'gate-15 record ${i}')
		if end := certified_span(r) {
			assert end == r.len, 'gate record ${i}: scan stopped at ${end}, expected ${r.len}'
			certified++
		}
	}
	// The gate-15 record shape is the reason the subset exists. If this
	// ever drops, the scan has stopped covering its own workload.
	assert certified == n, 'gate-15 corpus: only ${certified}/${n} records certified'
	println('[child-scan] gate-15: ${certified}/${n} records certified, 0 unsound')
}

// ── mutation corpus ───────────────────────────────────────────────────

const mutation_seeds = [
	'[user :id 1 :name "alice" :active true :ratio 0.5]',
	'[k]',
	'[k a=1 b=2]',
	'[k [n 1] [m 2]]',
	'[k :s 1 :t "x"]',
	'[outer [inner :v -12.75 :flag false :nil null]]',
	'[k a="x" :s \'y\']',
]

const mutation_bytes = [u8(`[`), `]`, `:`, `=`, `"`, `'`, ` `, `\t`, `\n`, `\\`, `#`, `&`,
	`*`, `$`, `@`, `,`, `(`, `)`, `{`, `}`, `.`, `-`, `+`, `0`, `9`, `e`, `x`, `_`, `!`,
	`?`, `<`, `;`, `/`]

fn test_mutation_corpus_soundness() {
	mut cases := 0
	mut certified := 0
	for seed in mutation_seeds {
		// substitutions
		for i in 0 .. seed.len {
			for mb in mutation_bytes {
				mutant := seed[..i] + mb.ascii_str() + seed[i + 1..]
				cases++
				if _ := certified_span(mutant) {
					certified++
				}
				assert_sound(mutant, 'substitute @${i} in ${seed}')
			}
		}
		// deletions
		for i in 0 .. seed.len {
			mutant := seed[..i] + seed[i + 1..]
			cases++
			if _ := certified_span(mutant) {
				certified++
			}
			assert_sound(mutant, 'delete @${i} in ${seed}')
		}
		// insertions
		for i in 0 .. seed.len + 1 {
			for mb in mutation_bytes {
				mutant := seed[..i] + mb.ascii_str() + seed[i..]
				cases++
				if _ := certified_span(mutant) {
					certified++
				}
				assert_sound(mutant, 'insert @${i} in ${seed}')
			}
		}
	}
	assert cases > 10000, 'mutation corpus too small: ${cases}'
	println('[child-scan] mutation: ${cases} mutants, ${certified} certified, 0 unsound')
}

// ── the specific shapes the subset must REFUSE ────────────────────────
//
// These are not soundness failures if admitted (the parser accepts them
// too) — they are the conservative exclusions the subset documents, and
// pinning them keeps a later widening deliberate rather than accidental.

const must_decline = [
	'[ns:name 1]', // QName — namespace resolution is not a no-op
	'[k::int 1]', // type tag
	'[k xmlns="http://x"]', // reserved namespace binding
	'[k a.b=1]', // dotted name
	'[k "has\\nescape"]', // escape decoding
	'[k bare text]', // bare body text folding
	'[k &anchor]', // anchor
	'[k #id]', // id declaration
	'[k *merge]', // merge
	'[k \$hole]', // hole
	'[k a, b]', // sequence literal
	'[k (1, 2)]', // paren sequence
	'[k {a: 1}]', // map literal
	'[k # comment\n]', // line comment
	'[k 007]', // non-canonical integer
	'[k 1e3]', // exponent
	'[k 5.]', // trailing dot
	'[k .5]', // leading dot
	'[k :atom]', // atom vs slot ambiguity
	'[k 2024-01-15]', // date
	'[k 1h30m]', // duration
	'[!DOCTYPE x]', // declaration
	'[?for 1]', // directive
	'[#raw#]', // raw text
]

fn test_documented_exclusions_decline() {
	for src in must_decline {
		if end := certified_span(src) {
			assert false, 'subset widened WITHOUT a decision: ${src} certified through ${end}'
		}
	}
	println('[child-scan] ${must_decline.len} documented exclusions all decline')
}

// ── the CANONICALITY obligation (804-1d, ruled 1a) ────────────────────
//
// The scan may declare a span canonical only when emitting that span —
// with its recorded delimiter rewrites applied — is byte-for-byte what
// the canonical renderer would produce:
//
//     canonical(span) ⇒ apply_rewrites(span) == render_canonical(parse(span))
//
// A false negative costs throughput. A false positive corrupts canonical
// output and every Tier-1 address derived from it, which is why the
// ruling made the predicate conservative and why this check is total
// rather than sampled. It runs over the same three corpora as soundness.

// canon_verdict returns (declared_canonical, matches_renderer).
fn canon_verdict(src string) (bool, bool) {
	bytes := src.bytes()
	sc := cx.scan_child_canonical(bytes, 0) or { return false, true }
	if !sc.canonical {
		return false, true
	}
	span := bytes[..sc.end]
	emitted := cx.apply_rewrites(span, 0, sc.rewrites)
	doc := cx.parse(src[..sc.end]) or { return true, false }
	if doc.elements.len != 1 {
		return true, false
	}
	return true, emitted == code.render_canonical(doc.elements[0])
}

fn assert_canonical_sound(src string, origin string) {
	declared, matches := canon_verdict(src)
	if declared && !matches {
		bytes := src.bytes()
		sc := cx.scan_child_canonical(bytes, 0) or { return }
		emitted := cx.apply_rewrites(bytes[..sc.end], 0, sc.rewrites)
		doc := cx.parse(src[..sc.end]) or { return }
		assert false, 'CANONICALITY FALSE POSITIVE — the span is NOT the canonical image\n' +
			'  origin  : ${origin}\n  span    : ${src[..sc.end]}\n' +
			'  emitted : ${emitted}\n  renderer: ${code.render_canonical(doc.elements[0])}'
	}
}

fn test_canonicality_never_false_positive() {
	mut declared := 0
	mut checked := 0
	files := os.ls(conformance_dir()) or {
		assert false, 'cannot list conformance dir'
		return
	}
	for f in files {
		if !f.ends_with('.cxd') {
			continue
		}
		path := os.join_path(conformance_dir(), f)
		for c in fixtures.load_fixtures(path) {
			src := c.sections['in_cx'].trim_space()
			if src == '' || src == '[ignored]' || src == '[empty]' {
				continue
			}
			checked++
			d, _ := canon_verdict(src)
			if d {
				declared++
			}
			assert_canonical_sound(src, '${f}/${c.name}')
		}
	}
	println('[child-scan] canonicality/conformance: ${checked} inputs, ${declared} declared canonical, 0 false positives')
}

fn test_canonicality_over_gate_corpus() {
	n := 3000
	mut declared := 0
	mut rewritten := 0
	for i in 0 .. n {
		r := gate_record(i)
		assert_canonical_sound(r, 'gate-15 record ${i}')
		bytes := r.bytes()
		sc := cx.scan_child_canonical(bytes, 0) or { continue }
		if sc.canonical {
			declared++
			if sc.rewrites.len > 0 {
				rewritten++
			}
		}
	}
	// This is the whole point of ruling 1a: the gate workload is
	// double-quoted, so a strict-identity predicate would score ZERO
	// here. If this regresses to 0 the delimiter rewrite has been lost
	// and the architecture's win with it.
	assert declared == n, 'gate-15: only ${declared}/${n} records declared canonical'
	assert rewritten == n, 'gate-15: only ${rewritten}/${n} records needed the delimiter rewrite — the corpus or the rule moved'
	println('[child-scan] canonicality/gate-15: ${declared}/${n} canonical, ${rewritten} via delimiter rewrite, 0 false positives')
}

fn test_canonicality_over_mutation_corpus() {
	mut cases := 0
	mut declared := 0
	for seed in mutation_seeds {
		for i in 0 .. seed.len {
			for mb in mutation_bytes {
				mutant := seed[..i] + mb.ascii_str() + seed[i + 1..]
				cases++
				d, _ := canon_verdict(mutant)
				if d {
					declared++
				}
				assert_canonical_sound(mutant, 'substitute @${i} in ${seed}')
			}
			del := seed[..i] + seed[i + 1..]
			cases++
			assert_canonical_sound(del, 'delete @${i} in ${seed}')
		}
	}
	assert cases > 5000, 'mutation corpus too small: ${cases}'
	println('[child-scan] canonicality/mutation: ${cases} mutants, ${declared} declared canonical, 0 false positives')
}

// The specific spellings the predicate must call NON-canonical. Each is
// well-formed (so the scan certifies it) but the renderer moves it, and
// each was measured against the renderer rather than assumed.
const must_not_be_canonical = [
	'[k ]', // trailing space before `]`
	'[k  1]', // double space between items
	'[k :s  1]', // double space inside a slot
	'[k\n 1]', // newline separator
	'[k -0]', // negative zero renders `0`
	'[k -0.0]', // negative zero decimal renders `0.0`
	'[k ""]', // empty string renders as nothing
	"[k '']", // ditto
	'[k a=1]', // attribute values render bare when safe
	'[k a="x"]', // ditto
	'[k "a\tb"]', // raw TAB is escaped `\t` in canonical text
	'[k "a\x01b"]', // other C0 controls become `\u00xx`
	'[k "a\x7fb"]', // DEL likewise
]

fn test_documented_non_canonical_spellings() {
	for src in must_not_be_canonical {
		bytes := src.bytes()
		sc := cx.scan_child_canonical(bytes, 0) or { continue }
		assert !sc.canonical, 'predicate widened WITHOUT a decision: ${src} declared canonical'
	}
	println('[child-scan] ${must_not_be_canonical.len} documented non-canonical spellings all declined')
}

// And the shapes it MUST call canonical — the regression guard on the
// other side, so a conservative drift cannot silently forfeit the win.
const must_be_canonical = [
	'[k]',
	'[k 1]',
	'[k -1]',
	'[k 0.53]',
	'[k 10.50]',
	'[k true]',
	'[k false]',
	'[k null]',
	"[k 'abc']",
	'[k "abc"]', // via the delimiter rewrite
	'[k "it\'s"]', // content has a `\'`, so `"…"` IS canonical
	'[k :s 1]',
	'[k :s 1 :t "x"]',
	'[k [n 1] [m 2]]',
	'[user :id 0 :name "alice" :active true :ratio 0.5]',
]

fn test_documented_canonical_shapes() {
	for src in must_be_canonical {
		bytes := src.bytes()
		sc := cx.scan_child_canonical(bytes, 0) or {
			assert false, 'expected canonical, but the scan DECLINED: ${src}'
			continue
		}
		assert sc.canonical, 'expected canonical, got not-canonical: ${src}'
		emitted := cx.apply_rewrites(bytes[..sc.end], 0, sc.rewrites)
		doc := cx.parse(src) or {
			assert false, 'unparseable: ${src}'
			continue
		}
		want := code.render_canonical(doc.elements[0])
		assert emitted == want, 'emit mismatch for ${src}: got ${emitted}, renderer says ${want}'
	}
	println('[child-scan] ${must_be_canonical.len} documented canonical shapes all emit the renderer\'s bytes')
}

// ── the resolve-is-a-no-op obligation ─────────────────────────────────
//
// Soundness (above) proves a certified span PARSES. That is only half of
// what PASS 1 did: it also ran `resolve_namespaces` +
// `validate_reserved_ns_bindings` per child, and either of those can
// REFUSE. A certified child skips them, so the subset's exclusions have
// to make that skip lossless — every certified child must resolve
// without error AND without its image moving.
//
// This is the half that would fail silently. An unsound parse shows up
// as a crash somewhere; a lost refusal shows up as an input the
// streaming path accepts and the materializing path rejects, which is
// the exact divergence PASS 1 exists to prevent.

// resolve_is_noop mirrors code/streamed_input.v's streamed_input_resolve:
// wrap the child under a synthetic namespace-free root, resolve, unwrap.
// Returns false if it errors or if the child's image moved.
fn resolve_is_noop(span string) bool {
	doc := cx.parse(span) or { return false }
	if doc.elements.len != 1 {
		return false
	}
	child := doc.elements[0]
	before := code.render_canonical(child)
	mut sdoc := cx.Document{
		elements: [
			cx.Node(cx.Element{
				name:  'root'
				items: [child]
			}),
		]
	}
	cx.resolve_namespaces(mut sdoc)
	cx.validate_reserved_ns_bindings(sdoc) or { return false }
	wrapped := sdoc.elements[0]
	if wrapped !is cx.Element {
		return false
	}
	el := wrapped as cx.Element
	if el.items.len != 1 {
		return false
	}
	return code.render_canonical(el.items[0]) == before
}

fn test_certified_children_resolve_to_a_noop() {
	mut checked := 0
	files := os.ls(conformance_dir()) or {
		assert false, 'cannot list conformance dir'
		return
	}
	for f in files {
		if !f.ends_with('.cxd') {
			continue
		}
		path := os.join_path(conformance_dir(), f)
		for c in fixtures.load_fixtures(path) {
			src := c.sections['in_cx'].trim_space()
			if src == '' || src == '[ignored]' || src == '[empty]' {
				continue
			}
			end := certified_span(src) or { continue }
			checked++
			assert resolve_is_noop(src[..end]), 'certified child does NOT resolve to a no-op — ' +
				'PASS 1 would lose a refusal or a rewrite\n  ${f}/${c.name}\n  span: ${src[..end]}'
		}
	}
	for seed in mutation_seeds {
		end := certified_span(seed) or { continue }
		checked++
		assert resolve_is_noop(seed[..end]), 'certified seed does not resolve to a no-op: ${seed}'
	}
	for i in 0 .. 500 {
		r := gate_record(i)
		end := certified_span(r) or { continue }
		checked++
		assert resolve_is_noop(r[..end]), 'certified gate record does not resolve to a no-op: ${r}'
	}
	assert checked > 300, 'only ${checked} certified spans checked — corpus coverage collapsed'
	println('[child-scan] resolve no-op: ${checked} certified spans, 0 movements')
}

// ── the root-namespace precondition ───────────────────────────────────

fn test_top_namespace_free_gate() {
	free := cx.open_top_level_children('[users [user :id 1]]') or {
		assert false, 'open failed: ${err.msg()}'
		return
	}
	assert free.top.top_is_namespace_free()

	bound := cx.open_top_level_children('[users xmlns="http://x" [user :id 1]]') or {
		assert false, 'open failed: ${err.msg()}'
		return
	}
	assert !bound.top.top_is_namespace_free(), 'a default-namespace root must block certification'

	lang := cx.open_top_level_children('[users cx:lang="en" [user :id 1]]') or {
		assert false, 'open failed: ${err.msg()}'
		return
	}
	assert !lang.top.top_is_namespace_free(), 'a cx:lang root must block certification'
}

// ── #804 leg 8: the RewriteSet SPILL path ─────────────────────────────────
//
// Leg 8 moved a record's rewrite offsets from a heap `[]int` into an inline
// `[8]int` with a heap spill past that. The inline half is covered by every
// other case in this file, because the §11.4.4 gate record carries two
// strings = four offsets and never comes close to the boundary.
//
// THAT IS EXACTLY THE PROBLEM. The spill branch is unreachable from the
// corpus that motivated the change, so it could be wrong in every build and
// nothing here would notice — the shape this issue has already been bitten by
// three times (#851). These cases exist to reach it deliberately: at the
// boundary, one past it, and far past it, with the offsets checked in ORDER
// (a spill that appends correctly but reads back out of order still corrupts
// the emitted image, and `apply_rewrites` would happily produce plausible
// wrong bytes).
fn test_rewrite_set_spill_boundary() {
	// n quoted strings => 2n rewrite offsets. cap is 8, so n=4 exactly fills
	// the inline buffer, n=5 spills by two, n=12 spills heavily.
	for n in [1, 3, 4, 5, 6, 12] {
		mut src := '[rec'
		for i in 0 .. n {
			src += ' :k${i} "v${i}"'
		}
		src += ']'
		bytes := src.bytes()
		sc := cx.scan_child_canonical(bytes, 0) or {
			assert false, 'leg 8 spill: scan declined a plain quoted-string record (n=${n}): ${src}'
			continue
		}
		assert sc.canonical, 'leg 8 spill: n=${n} should certify canonical: ${src}'
		assert sc.rewrites.len == 2 * n,
			'leg 8 spill: n=${n} must record ${2 * n} offsets, got ${sc.rewrites.len}'

		// Offsets must come back STRICTLY INCREASING — scan order. An
		// inline/spill read that returns them out of order still renders
		// well-formed output, just wrong output.
		for i in 1 .. sc.rewrites.len {
			assert sc.rewrites.get(i) > sc.rewrites.get(i - 1),
				'leg 8 spill: offsets out of order at i=${i} (n=${n}): ' +
				'${sc.rewrites.get(i - 1)} then ${sc.rewrites.get(i)}'
		}
		// Every recorded offset must actually point at a `"` in the source.
		for i in 0 .. sc.rewrites.len {
			off := sc.rewrites.get(i)
			assert off >= 0 && off < bytes.len,
				'leg 8 spill: offset ${off} out of range (n=${n})'
			assert bytes[off] == `"`,
				'leg 8 spill: offset ${off} points at `${bytes[off].ascii_str()}`, not a quote (n=${n})'
		}
		// And the end-to-end obligation this all exists for: the emitted
		// image must equal what the real renderer produces.
		emitted := cx.apply_rewrites(bytes[..sc.end], 0, sc.rewrites)
		doc := cx.parse(src) or {
			assert false, 'leg 8 spill: n=${n} did not parse: ${src}'
			continue
		}
		want := code.render_canonical(doc.elements[0])
		assert emitted == want,
			'leg 8 spill: emitted image diverges from the renderer at n=${n}\n' +
			'  src     : ${src}\n  emitted : ${emitted}\n  renderer: ${want}'
	}
}
