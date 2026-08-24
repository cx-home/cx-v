module cx

// ── The lazy record node (#804 leg 2, architecture 804-1c, ruled 1a) ──
//
// A `LazyRecord` is one top-level child of a streamed input that has been
// CERTIFIED by the span scan (`child_scan.v`) but not materialised. It
// carries the bytes, the scan's canonicality verdict, and the element
// NAME — which the scan already walked past, so it costs nothing — and
// it builds its typed AST only when something reads its structure.
//
// WHY THIS EXISTS. `code/streamed_input.v` PASS 2 parses every child in
// order to evaluate the comprehension over it. On the workload §11.4.4
// measures, most of those children are yielded unchanged: nothing ever
// asks what is inside them. Parse is ~81% of samples, so materialising
// a record no one inspects is very nearly the entire cost of the gate.
//
// THE CEILING, measured before this was built (`make bench-lazy-ceiling`,
// -prod, 16 MiB): scan 349.1 MB/s, scan+write 315.8 MB/s, parse 30.7
// MB/s. So a record that is never forced costs about a tenth of one that
// is, and the architecture clears the §11.4.4 floor with headroom. The
// real number must sit under 315.8; the gap is this discipline's cost.
//
// ── THE FORCING DISCIPLINE, AND ITS HONEST STATUS ────────────────────
//
// This is the part to read before touching anything here.
//
// `cx.Node` has 27 other variants and **1,341 non-test `is Element`
// sites, of which 1,323 are `if`-form tag tests** that silently take the
// else branch. Only ~18 sit in exhaustive `match` position where the
// compiler would object. So an unforced LazyRecord reaching general code
// does not crash — it reads as *not an element*, which is a plausible
// wrong answer on the most identity-sensitive code in the system.
//
// The reachable set was measured rather than assumed. Inside the
// streamed walk, a record's structure is touched at exactly four places
// (the name compare, the per-child resolve, `apply_binding_step` for
// two-step plans, and `match_pattern`), and every read of the bound
// variable funnels through `eval_binding_opt`. But a PATH-LESS read
// returns the value unchanged into arbitrary expression context, and
// from there it can reach the whole evaluator.
//
// **So this cannot be made sound by construction under the current
// representation, and it is not claimed to be.** Forcing on every read
// would be sound and would win nothing (on the gate workload every child
// matches, so every child is read). Forcing only on structural access
// wins, and lets the value escape.
//
// Ruled 1a: take the variant, and carry soundness with a DUAL-BUILD
// DIFFERENTIAL instead of an audit. Under `-d cx_no_lazy_record` the
// streamed walk forces at creation and this variant never exists; the
// entire corpus — conformance, gates, fixtures — must produce
// byte-identical output in both builds. Any of those 1,323 sites that
// mis-observes a lazy record diverges, and the corpus says so. That is
// the same instrument that caught the raw-TAB false positive in 804-1d,
// which reading the escaper's source did not.
//
// If you add a way for a LazyRecord to reach new code, the differential
// is what has to still pass — not a re-reading of this comment.
//
// ── WHAT FORCES ───────────────────────────────────────────────────────
//
//   * `eval_binding_opt`  — any path-bearing read (`$u/x`, `$u@a`).
//   * `match_pattern`     — a pattern destructures structure by nature.
//   * `apply_binding_step`— the two-step plan's second step.
//   * every renderer arm  — EXCEPT a canonical span, which writes its
//                           bytes through the recorded rewrite offsets.
//
// That last exemption is the win, and it is not a special case for the
// pass-through shape: the renderer arm fires on the record's own
// PROVENANCE (these bytes are already the canonical image), never on the
// program's shape. `[yield $u]` is fast because it demands no structure,
// not because anything recognises it.

// LazyRecord is a certified, unmaterialised top-level child.
//
// MEMOISATION LIVES IN THE BINDING, NOT IN THE RECORD (#804 leg 4).
//
// This carried a shared heap `LazyCell` so a record read twice (`$u/a` then
// `$u/b`) would parse once. Profiling the gate workload showed what that
// cost: allocation is ~50% of samples on this path, and the cell was one
// heap object PER RECORD for a memo that, on a pass-through workload, is
// never read at all — nothing forces, so nothing consults it.
//
// The memo moved to where it is free. When `eval_binding_opt` forces a
// record it writes the materialised Element back over the binding, so the
// next read of `$u` finds an ordinary Element and the parse happens once
// per binding without any per-record allocation. The binding table already
// exists; the cell was a second one built to hold the same fact.
pub struct LazyRecord {
pub:
	// src is the whole input buffer; the record is `src[start..end]`.
	// Held by reference, not copied — the streamed walk owns the input
	// for the duration of the comprehension.
	src   []u8
	start int
	end   int
	// name_start / name_end delimit the element's NAME inside `src`.
	//
	// #804 leg 11 — this used to be a `name string`, built by
	// `CanonicalScan.name_str` at construction: one heap string per record for
	// a name that has exactly ONE reader, the streamed walk's
	// `child_name != step1.name` compare. Offsets make that compare a byte
	// comparison against the buffer the record already holds, so the walk
	// allocates nothing to answer it — and the box shrinks by the string
	// header at the same time. `name_eq` is the compare; `name_of` builds the
	// string for the rare caller that genuinely wants one.
	name_start int
	name_end   int
	// canonical reports that `src[start..end]`, with `rewrites` applied,
	// is exactly what the canonical renderer would produce.
	canonical bool
	// rewrites holds ABSOLUTE offsets of `"` bytes to emit as `'`, carried
	// INLINE (#804 leg 8) so a record costs no heap array of its own.
	rewrites RewriteSet
}

// new_lazy_record builds a lazy record from a completed canonical scan.
// Allocation-free beyond what the scan already produced — see the struct
// comment on why the memo cell is gone.
pub fn new_lazy_record(src []u8, start int, sc CanonicalScan) LazyRecord {
	return LazyRecord{
		src:        src
		start:      start
		end:        sc.end
		name_start: sc.name_start
		name_end:   sc.name_end
		canonical:  sc.canonical
		rewrites:   sc.rewrites
	}
}

// name_eq compares the record's element name with an ASCII literal without
// allocating (#804 leg 11). This is the streamed walk's per-record question.
@[inline]
pub fn (l LazyRecord) name_eq(lit string) bool {
	if l.name_end - l.name_start != lit.len {
		return false
	}
	for k in 0 .. lit.len {
		if l.src[l.name_start + k] != lit[k] {
			return false
		}
	}
	return true
}

// name_of materialises the element name as a string. Only for callers that
// genuinely need one — the hot compare is `name_eq`.
pub fn (l LazyRecord) name_of() string {
	return l.src[l.name_start..l.name_end].bytestr()
}

// span returns the record's source bytes.
@[inline]
pub fn (l LazyRecord) span() []u8 {
	return l.src[l.start..l.end]
}

// force materialises the record's typed AST.
//
// It does NOT memoise — callers that can hold the result do so. The binding
// path writes the forced Element back over the binding, which is the only
// repeated-read case that matters and costs nothing extra.
//
// A certified span parses by construction — that is leg 1's one-directional
// obligation, differentially pinned over the conformance corpus, the gate
// workload and a mutation corpus. A parse failure here is therefore not an
// input error to report but a broken invariant, and it says so rather than
// degrading into a plausible empty element.
pub fn (l LazyRecord) force() !Element {
	doc := parse(l.span().bytestr()) or {
		return error('lazy record: certified span failed to parse — the scan/parser ' +
			'agreement in child_scan.v is broken (#804 leg 1): ${err.msg()}')
	}
	if doc.elements.len != 1 {
		return error('lazy record: certified span produced ${doc.elements.len} top-level nodes, expected 1')
	}
	el := doc.elements[0]
	if el !is Element {
		return error('lazy record: certified span produced a non-element node')
	}
	return el as Element
}

// canonical_string materialises the canonical image as a String. Use it
// only OFF the hot path (the general emitters); streaming callers must use
// `write_canonical_to`, which does not allocate — see its comment for the
// measured cost of the difference.
pub fn (l LazyRecord) canonical_string() string {
	mut buf := []u8{cap: l.end - l.start}
	l.write_canonical_to(mut buf)
	return buf.bytestr()
}

// force_or_panic materialises the record for a caller that cannot report an
// error — the three general emitters are non-fallible by signature.
//
// A failure here is a BROKEN INVARIANT, not bad input: leg 1's obligation is
// that a certified span parses, pinned differentially over three corpora. The
// alternatives to panicking are both worse than a crash. Emitting the source
// bytes would write non-canonical output, and canonical output is the one
// thing this whole architecture may not move. Emitting nothing would drop a
// record silently. So this fails loudly and names where to look.
pub fn (l LazyRecord) force_or_panic() Element {
	return l.force() or { panic(err.msg()) }
}

// write_canonical_to writes the record's canonical image into `buf`,
// substituting `'` at each recorded rewrite offset.
//
// It is a WRITER and not a string function on purpose. The ceiling probe
// measured `apply_rewrites`, which returns a String and so copies the span
// once per rewritten record: on the gate workload every record is rewritten,
// and that single allocation costs 22% of the ceiling (315.8 -> 246.9 MB/s).
// Callers on the hot path must use this.
//
// Precondition: `canonical` is true. A non-canonical record has no image to
// write and must be forced and rendered instead.
pub fn (l LazyRecord) write_canonical_to(mut buf []u8) {
	mut at := l.start
	for i in 0 .. l.rewrites.len {
		r := l.rewrites.get(i)
		if r > at {
			buf << l.src[at..r]
		}
		buf << u8(`'`)
		at = r + 1
	}
	if l.end > at {
		buf << l.src[at..l.end]
	}
}
