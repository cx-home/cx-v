module main

import code

// ── Phase 3.11 public API surface ──────────────────────────────────────────
//
// Covers code.eval_code / code.eval_code_streaming —
// the V-side entry points the C ABI's cx_code_eval* family routes
// through. Tests pin the documented behaviour from
// spec/audits/code_abi_v1.md §3 (parameter contracts, error
// channel, streaming/one-shot byte-equivalence) without going
// through the C boundary.

fn test_eval_code_simple_find() {
	input := '[doc
		[order :id 1 :status "open"]
		[order :id 2 :status "closed"]
		[order :id 3 :status "open"]]'
	prog := '[?for [order \$m] [yield \$m]]'
	out := code.eval_code(input, prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	// Three orders; the pattern binds $m to each. Text target joins
	// with \n.
	lines := out.split('\n')
	assert lines.len == 3, 'expected 3 matches, got ${lines.len}: ${out}'
}

fn test_eval_code_for_comp() {
	prog := '[?for [in \$i (1, 2, 3)] [yield [item :n \$i]]]'
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return
	}
	lines := out.split('\n')
	assert lines.len == 3
	assert lines[0] == '[item :n 1]'
	assert lines[1] == '[item :n 2]'
	assert lines[2] == '[item :n 3]'
}

fn test_eval_code_empty_input_ok() {
	// Programs that don't consume \$doc work with empty input.
	out := code.eval_code('', '[?let [= \$x 42] [ok :value \$x]]', '') or {
		assert false, 'eval failed: ${err}'
		return
	}
	assert out == '[ok :value 42]'
}

fn test_eval_code_default_target_is_text() {
	// Empty output_target defaults to 'text'.
	a := code.eval_code('', '[ok :value 1]', '') or { '' }
	b := code.eval_code('', '[ok :value 1]', 'text') or { '' }
	assert a == b
	assert a == '[ok :value 1]'
}

fn test_eval_code_cx_target_renders_canonical() {
	out := code.eval_code('', '[ok :value "x"]', 'cx') or {
		assert false, 'eval failed: ${err}'
		return
	}
	// Canonical CX single-quotes strings (canonical.md §2 — "double quotes
	// are not used"); the `"x"` source string re-emits as `'x'`.
	assert out == "[ok :value 'x']"
}

fn test_eval_code_unknown_target_rejected() {
	if _ := code.eval_code('', '[ok]', 'protobuf') {
		assert false, 'unknown target should have raised CXER0100'
		return
	} else {
		assert err.msg().contains('cx-err:CXER0100')
		assert err.msg().contains('protobuf')
	}
}

fn test_eval_code_svg_target_emits_envelope() {
	// SVG diagram emission landed at Phase 4.2 (gate 9). With graphviz
	// `dot` on PATH the output is a rendered diagram; without it the
	// fallback envelope still carries the source via `<cx:source>`
	// metadata. Either way, the result MUST be a valid SVG document.
	out := code.eval_code('', '[?for [user $u] [yield $u]]', 'svg') or {
		assert false, 'svg target should not have raised: ${err}'
		return
	}
	assert out.contains('<svg')
	assert out.contains('cx:source')
}

fn test_eval_code_empty_program_rejected() {
	if _ := code.eval_code('', '', 'text') {
		assert false, 'empty program should have raised CXER0100'
		return
	} else {
		assert err.msg().contains('cx-err:CXER0100')
	}
}

fn test_eval_code_parse_error_routes_cxer0100() {
	if _ := code.eval_code('', '[?for', 'text') {
		assert false, 'unterminated bracket should have raised CXER0100'
		return
	} else {
		assert err.msg().contains('cx-err:CXER0100')
		assert err.msg().contains('parse')
	}
}

// ── Streaming variant ──────────────────────────────────────────────────────

struct StreamCollector {
mut:
	chunks []string
}

fn (mut c StreamCollector) append(chunk string) ! {
	c.chunks << chunk
}

fn test_eval_code_streaming_concat_equals_oneshot() {
	prog := '[?for [in \$i (10, 20, 30)] [yield [item :n \$i]]]'
	one_shot := code.eval_code('', prog, 'text') or {
		assert false, 'one-shot failed: ${err}'
		return
	}
	mut collector := &StreamCollector{}
	sink := fn [mut collector] (chunk string) ! {
		collector.append(chunk)!
	}
	code.eval_code_streaming('', prog, 'text', sink) or {
		assert false, 'streaming failed: ${err}'
		return
	}
	// Per the §3.3 contract: concatenated streaming output equals
	// one-shot output byte-for-byte.
	assert collector.chunks.join('') == one_shot
}

fn test_eval_code_streaming_sink_error_propagates() {
	prog := '[ok :value 1]'
	failing_sink := fn (chunk string) ! {
		return error('sink rejected chunk')
	}
	if _ := code.eval_code_streaming('', prog, 'text', failing_sink) {
		assert false, 'failing sink should have raised CXER0001'
		return
	} else {
		assert err.msg().contains('cx-err:CXER0001')
		assert err.msg().contains('sink callback failed')
	}
}
