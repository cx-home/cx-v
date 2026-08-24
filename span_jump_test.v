module cx

// #804 leg 10 — `jump_span_to` must compute exactly what `skip_span_to`'s byte
// loop computes.
//
// `skip_span_to` re-read every byte of a certified span purely to keep
// `line`/`col` accurate for a later error message — a second full pass over
// bytes the scan had just read. The scan now tallies newlines inside its own
// whitespace walk (free: that loop already reads the byte) and `jump_span_to`
// updates the position by arithmetic.
//
// THIS TEST COMPARES THE TWO FUNCTIONS DIRECTLY, and that is deliberate. I
// first wrote it at the engine level — malformed input, streamed vs
// materializing, assert the reported line:col agrees — and it was VACUOUS: an
// off-by-one injected into the tally left it green, because a streamed parse
// failure of that shape routes through a whole-document reparse whose positions
// are computed fresh and never touch this arithmetic. A test that cannot see
// the code it names is not evidence, so it was replaced by this one, which
// pins the arithmetic against the loop that defines it.
//
// (That the incremental position appears hard to observe through the engine is
// itself worth knowing — it means the byte loop's line/col accounting may be
// dead weight on the streamed path. Recorded on #804 rather than acted on.)
fn test_jump_span_to_matches_skip_span_to() {
	cases := [
		'[user :id 1 :name "a"]', // no newline
		'[user :id 1\n :name "a"]', // one newline
		'[user\n :id 1\n :name "a"\n]', // several
		'[a]', // minimal
		'[a\n]', // trailing newline before the close
		'[outer [inner\n 1]\n [inner\n 2]]', // nested, multiple runs
	]
	for span in cases {
		// The span sits after a prefix carrying its own newlines, so the test
		// exercises a non-1 starting line/col rather than only the easy case.
		prefix := 'xx\nyy\n'
		src := prefix + span + '\ntail'
		start := prefix.len
		end := start + span.len

		// Reference: the byte loop.
		mut pw := new_parser(src)
		pw.pos = start
		pw.line = 3
		pw.col = 1
		pw.skip_span_to(end)

		// Under test: the tally + arithmetic. The tally is collected the same
		// way the scan collects it — newlines within the span only.
		mut nl := 0
		mut last := -1
		for i in start .. end {
			if src[i] == `\n` {
				nl++
				last = i
			}
		}
		mut pj := new_parser(src)
		pj.pos = start
		pj.line = 3
		pj.col = 1
		pj.jump_span_to(end, nl, last)

		assert pj.pos == pw.pos, 'pos diverged on ${span}: jump ${pj.pos} vs walk ${pw.pos}'
		assert pj.line == pw.line, 'LINE diverged on ${span}: jump ${pj.line} vs walk ${pw.line}'
		assert pj.col == pw.col, 'COL diverged on ${span}: jump ${pj.col} vs walk ${pw.col}'
	}
}

// The tally the SCAN produces must equal a direct count over the span — the
// property that makes counting only whitespace runs exact inside a certified
// span (strings decline on a newline, `#` declines the child, names/numbers
// cannot contain one). If the certified subset ever widens to admit a newline
// elsewhere, this is what fails.
fn test_scan_newline_tally_equals_a_direct_count() {
	spans := [
		'[user :id 1 :name "a"]',
		'[user :id 1\n        :name "a"]',
		'[user\n :id 1\n :name "a"\n]',
		'[outer [inner\n 1]\n [inner\n 2]]',
	]
	for span in spans {
		src := span.bytes()
		sc := scan_child_canonical(src, 0) or {
			assert false, 'the probe span must certify: ${span}'
			continue
		}
		mut want := 0
		mut want_last := -1
		for i in 0 .. sc.end {
			if src[i] == `\n` {
				want++
				want_last = i
			}
		}
		assert sc.newlines == want,
			'newline tally wrong on ${span}: scan says ${sc.newlines}, direct count ${want}'
		assert sc.last_nl == want_last,
			'last-newline offset wrong on ${span}: scan says ${sc.last_nl}, direct ${want_last}'
	}
}
