module main

// ════════════════════════════════════════════════════════════════════════════
//  cxparse Phase-0 SPIKE — data-surface tokenization (gates D-ARCH)
// ════════════════════════════════════════════════════════════════════════════
//
// D-ARCH (spec/02-inprogress/cxparse_unification_PLAN.md §3) chose
// tokenize-then-parse with LEXER MODES. Its ONE acknowledged risk: the
// data-only surface — raw text, triple-quote, block-content / fenced-code
// injection, Markdown — is context-sensitive and does NOT tokenize cleanly
// into a flat stream of fine-grained tokens. The plan's mitigation: the
// tokenizer emits a single COARSE "raw-span" token per such region, and the
// PARSER (or a later mode pass) expands it. This spike must confirm that
// mitigation is tractable BEFORE Phase 1.
//
// THESIS PROVEN HERE: every context-sensitive data region is a DELIMITED RAW
// SPAN with an open + close marker that a single forward lexer pass can find
// using only BOUNDED LOOKAHEAD. A mode lexer therefore segments the input
// losslessly into coarse spans (raw regions stay verbatim; everything else is
// ordinary token soup). Round-trip = the spans tile the input exactly.
//
// Regions and their delimiters:
//   • quoted string   '…'  /  "…"     close = matching quote (\\-escaped)
//   • triple-quote    '''…'''/"""…""" close = matching triple (lookahead-on-close)
//   • raw text        [# … #]         close = `#]`  (disambiguated from [#-heading)
//   • block content   [| … |]         close = `|]`  (the fenced-code payload carrier)
//
// This is a STANDALONE prototype lexer (it deliberately does NOT import the
// production lexer) — the point is to demonstrate the segmentation algorithm
// in isolation, the way Phase 2's real tokenizer modes will work. The fact
// that code/lexer.v ALREADY reads triple-quotes + strings as raw spans today
// (read_triple_string / read_string) is independent corroboration that the
// mode-emits-raw-span pattern is real, not hypothetical.

enum SpanKind {
	normal        // ordinary CX token soup — tokenized normally by the real lexer
	quoted_str    // '…' or "…"
	triple_str    // '''…''' or """…"""
	raw_text      // [# … #]
	block_content // [| … |]
}

struct Span {
mut:
	kind  SpanKind
	start int // inclusive byte offset
	end   int // exclusive byte offset
}

// raw_payload returns the verbatim content of a raw region with its open/close
// delimiters stripped — what the unified parser would hand downstream.
fn (s Span) raw_payload(src string) string {
	return match s.kind {
		.quoted_str { src[s.start + 1..s.end - 1] }          // strip the 1-char quotes
		.triple_str { src[s.start + 3..s.end - 3] }          // strip the 3-char fences
		.raw_text { src[s.start + 2..s.end - 2] }            // strip `[#` … `#]`
		.block_content { src[s.start + 2..s.end - 2] }       // strip `[|` … `|]`
		.normal { src[s.start..s.end] }
	}
}

// is_triple reports a triple-quote opener `'''` / `"""` at pos.
fn is_triple(src string, pos int, q u8) bool {
	return pos + 3 <= src.len && src[pos] == q && src[pos + 1] == q && src[pos + 2] == q
}

// raw_text_close: starting just after `[#`, is this a `[# … #]` raw region
// (vs a `[#`-heading)? Scan for a depth-0 `#]` before a depth-0 closing `]`.
// Returns the index just past the closing `#]`, or -1 if not raw. This is the
// bounded-lookahead disambiguation the data parser uses (parser.v ~947).
fn raw_text_close(src string, after_hash int) int {
	mut scan := after_hash
	mut depth := 0
	for scan < src.len {
		b := src[scan]
		if b == `[` {
			depth++
		} else if b == `#` && depth == 0 && scan + 1 < src.len && src[scan + 1] == `]` {
			return scan + 2
		} else if b == `]` {
			if depth == 0 {
				return -1 // closed without a `#]` → it was a heading/element, not raw
			}
			depth--
		}
		scan++
	}
	return -1
}

// block_content_close: starting just after `[|`, find the `|]` terminator.
fn block_content_close(src string, after_pipe int) int {
	mut scan := after_pipe
	for scan < src.len {
		if src[scan] == `|` && scan + 1 < src.len && src[scan + 1] == `]` {
			return scan + 2
		}
		scan++
	}
	return -1
}

// quoted_close: starting just after the opening quote, find the matching close,
// honouring `\`-escapes (so `\'` does not close a `'…'`).
fn quoted_close(src string, after_quote int, q u8) int {
	mut scan := after_quote
	for scan < src.len {
		b := src[scan]
		if b == `\\` {
			scan += 2
			continue
		}
		if b == q {
			return scan + 1
		}
		scan++
	}
	return -1
}

// triple_close: starting just after the opening triple, find the matching
// closing triple, with the lookahead-on-close rule (a 4th quote → the first is
// content). Mirrors code/lexer.v read_triple_string.
fn triple_close(src string, after_triple int, q u8) int {
	mut scan := after_triple
	for scan < src.len {
		if src[scan] == q && scan + 3 <= src.len && src[scan + 1] == q && src[scan + 2] == q {
			if scan + 3 < src.len && src[scan + 3] == q {
				scan++ // 4th quote: this triple is content, re-scan past one
				continue
			}
			return scan + 3
		}
		scan++
	}
	return -1
}

// lex_spans is the prototype MODE LEXER. One forward pass; emits a coarse span
// per region. Normal bytes accumulate into `normal` spans between regions. The
// spans tile [0, len) exactly (lossless).
fn lex_spans(src string) []Span {
	mut spans := []Span{}
	mut pos := 0
	mut normal_start := 0

	flush_normal := fn (mut spans []Span, normal_start int, pos int) {
		if pos > normal_start {
			spans << Span{ kind: .normal, start: normal_start, end: pos }
		}
	}

	for pos < src.len {
		b := src[pos]
		mut region_end := -1
		mut kind := SpanKind.normal

		if b == `'` && is_triple(src, pos, `'`) {
			region_end = triple_close(src, pos + 3, `'`)
			kind = .triple_str
		} else if b == `"` && is_triple(src, pos, `"`) {
			region_end = triple_close(src, pos + 3, `"`)
			kind = .triple_str
		} else if b == `'` {
			region_end = quoted_close(src, pos + 1, `'`)
			kind = .quoted_str
		} else if b == `"` {
			region_end = quoted_close(src, pos + 1, `"`)
			kind = .quoted_str
		} else if b == `[` && pos + 1 < src.len && src[pos + 1] == `#` {
			rc := raw_text_close(src, pos + 2)
			if rc > 0 {
				region_end = rc
				kind = .raw_text
			}
		} else if b == `[` && pos + 1 < src.len && src[pos + 1] == `|` {
			region_end = block_content_close(src, pos + 2)
			kind = .block_content
		}

		if region_end > 0 {
			flush_normal(mut spans, normal_start, pos)
			spans << Span{ kind: kind, start: pos, end: region_end }
			pos = region_end
			normal_start = pos
		} else {
			pos++
		}
	}
	flush_normal(mut spans, normal_start, src.len)
	return spans
}

// reassemble proves the lossless property: concatenating every span's source
// slice (in order) reconstructs the input byte-for-byte.
fn reassemble(src string, spans []Span) string {
	mut b := []u8{}
	for s in spans {
		b << src[s.start..s.end].bytes()
	}
	return b.bytestr()
}

fn first_of(spans []Span, k SpanKind) ?Span {
	for s in spans {
		if s.kind == k {
			return s
		}
	}
	return none
}

// ── round-trip over a document that mixes ALL four context-sensitive regions ──
fn test_spike_roundtrip_all_regions() {
	src := "[doc\n" + "  [name 'Alice']\n" + "  [bio '''\n  multi\n  line\n''']\n" +
		"  [# verbatim <xml> & 1<2 #]\n" + "  [snippet [| code(); a|b |]]\n" +
		"  [p plain words here]\n" + "]"
	spans := lex_spans(src)
	// LOSSLESS: the coarse spans tile the input exactly.
	assert reassemble(src, spans) == src, 'round-trip mismatch'
	// Each raw region was found and its verbatim payload preserved.
	q := first_of(spans, .quoted_str) or { assert false, 'no quoted_str'; return }
	assert q.raw_payload(src) == 'Alice'
	t := first_of(spans, .triple_str) or { assert false, 'no triple_str'; return }
	assert t.raw_payload(src) == '\n  multi\n  line\n' // verbatim (dedent is a later pass)
	r := first_of(spans, .raw_text) or { assert false, 'no raw_text'; return }
	assert r.raw_payload(src) == ' verbatim <xml> & 1<2 ' // raw: angle/amp un-tokenized
	bc := first_of(spans, .block_content) or { assert false, 'no block_content'; return }
	assert bc.raw_payload(src) == ' code(); a|b ' // single `|` inside is content
}

// ── the [# heading] vs [# raw #] disambiguation is decidable by lookahead ──
fn test_spike_raw_vs_heading_disambiguation() {
	// `[# raw #]` → raw_text; `[# heading]` (no `#]`) → NOT raw (normal soup).
	raw := lex_spans('[# this is raw #]')
	assert first_of(raw, .raw_text) != none, 'expected raw_text span'

	heading := lex_spans('[# Heading One]')
	assert first_of(heading, .raw_text) == none, 'a [#-heading must NOT be a raw span'
	// still lossless even when classified as normal soup
	assert reassemble('[# Heading One]', heading) == '[# Heading One]'
}

// ── nested brackets inside a raw region do not fool the close scan ──
fn test_spike_nested_brackets_in_raw() {
	src := '[# a [b] c #]'
	spans := lex_spans(src)
	r := first_of(spans, .raw_text) or { assert false, 'no raw_text'; return }
	assert r.raw_payload(src) == ' a [b] c ' // the inner `]` did not close the region
	assert reassemble(src, spans) == src
}

// ── escapes inside quoted strings do not prematurely close ──
fn test_spike_escaped_quote_in_string() {
	src := r"[m 'it\'s fine']"
	spans := lex_spans(src)
	q := first_of(spans, .quoted_str) or { assert false, 'no quoted_str'; return }
	assert q.raw_payload(src) == r"it\'s fine"
	assert reassemble(src, spans) == src
}

// ── triple-quote lookahead-on-close (embedded trailing quotes) ──
fn test_spike_triple_embedded_quote() {
	// 5 trailing quotes = 2 content quotes + the 3-quote close (the
	// lookahead-on-close rule, matching code/lexer.v read_triple_string).
	src := "[m '''he said ''''']"
	spans := lex_spans(src)
	t := first_of(spans, .triple_str) or { assert false, 'no triple_str'; return }
	assert t.raw_payload(src) == "he said ''"
	assert reassemble(src, spans) == src
}
