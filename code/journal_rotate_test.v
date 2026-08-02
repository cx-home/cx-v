module code

import cx

// journal_rotate_test.v — #640: `journal-rotate` seals the live chain at a
// retention boundary and moves the hot window to a fresh store (snapshot →
// retain → compact composed), leaving a walkable SEGMENT INDEX in the new
// store. Rotation is copy-then-swap: the source is never mutated, the
// returned journal is the new hot, and a chain of rotations stays
// discoverable from the newest store alone.

const jrt_seed = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'

fn jrt_append(j cx.Node, event string) cx.Node {
	ev := cx.parse(event) or { panic('parse event') }.elements[0]
	attribution := cx.Element{
		name:  map_marker_name
		items: [
			cx.Node(cx.Element{
				name:  'actor'
				items: [cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue('did:key:test')
					data_type: cx.ScalarType.string_type
				})]
			}),
			cx.Node(cx.Element{
				name:  'authority'
				items: [cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue('test:suite')
					data_type: cx.ScalarType.string_type
				})]
			}),
		]
	}
	r := journal_stdlib_builtin('journal-append', [j, cx.Node(ev), cx.Node(attribution)]) or {
		panic('append: ${err.msg()}')
	}
	assert !is_err_value(r), 'append must succeed: ${render_canonical(r)}'
	return r
}

fn jrt_rotate(j cx.Node, keep_n int, target string) cx.Node {
	r := journal_stdlib_builtin('journal-rotate', [j, cx.Node(cx.Element{
		name:  map_marker_name
		items: [
			session_kv('keep-n', bus_int(keep_n)),
			session_kv('target', bus_str(target)),
			session_kv('signing-key', bus_str(jrt_seed)),
		]
	})]) or { panic('rotate: ${err.msg()}') }
	return r
}

fn test_journal_rotate_seals_and_moves_the_hot_window() {
	caps_set_all()
	j := journal_stdlib_builtin('journal-open', [store_str('mem://jrt-src'), store_str('acme')]) or {
		panic('open')
	}
	for i in 1 .. 6 {
		jrt_append(j, '[do :e${i}]')
	}

	// rotate keeping the last 2 → boundary 3, one sealed segment recorded.
	r := jrt_rotate(j, 2, 'mem://jrt-hot2')
	assert !is_err_value(r), 'rotate: ${render_canonical(r)}'
	rr := r as cx.Element
	assert rr.name == 'rotated', 'rotate returns [rotated …]: ${render_canonical(r)}'
	assert rr.attr('sealed') == '1' && rr.attr('streams') == '1', 'one stream sealed: ${render_canonical(r)}'
	assert rr.attr('segments') == '1', 'first rotation records ONE sealed segment: ${render_canonical(r)}'
	mut hot := cx.Node(cx.Element{})
	for it in rr.items {
		if it is cx.Element && it.name == 'journal' {
			hot = it
		}
	}

	// the new hot journal: seam at 3, head 5; the retained tail reads; the
	// sealed range is honestly out of range; the chain verifies from the seam.
	hd := journal_stdlib_builtin('journal-head', [hot]) or { panic('head') }
	assert render_canonical(hd).contains('seq=5'), 'hot head: ${render_canonical(hd)}'
	e4 := journal_stdlib_builtin('journal-read', [hot, cx.Node(bus_int(4))]) or { panic('read4') }
	assert render_canonical(e4).contains(':e4'), 'retained entry must read: ${render_canonical(e4)}'
	e2 := journal_stdlib_builtin('journal-read', [hot, cx.Node(bus_int(2))]) or { panic('read2') }
	assert !render_canonical(e2).contains(':e2'), 'a sealed seq must not read from the hot window: ${render_canonical(e2)}'
	v := journal_stdlib_builtin('journal-verify', [hot]) or { panic('verify') }
	assert render_canonical(v).contains('valid=true'), 'seam-anchored verify: ${render_canonical(v)}'

	// the SOURCE journal is untouched (copy-then-swap).
	sv := journal_stdlib_builtin('journal-verify', [j]) or { panic('src verify') }
	assert render_canonical(sv).contains('valid=true'), 'source stays intact: ${render_canonical(sv)}'
	shd := journal_stdlib_builtin('journal-head', [j]) or { panic('src head') }
	assert render_canonical(shd).contains('seq=5'), 'source head unchanged'

	// the chain CONTINUES on the new hot journal.
	r6 := jrt_append(hot, '[do :e6]')
	assert render_canonical(r6).contains('seq=6'), 'chain continues at 6: ${render_canonical(r6)}'

	// second rotation: the segment index carries the first segment forward.
	r2 := jrt_rotate(hot, 1, 'mem://jrt-hot3')
	assert !is_err_value(r2), 'rotate 2: ${render_canonical(r2)}'
	rr2 := r2 as cx.Element
	assert rr2.attr('sealed') == '1', 'second rotation seals again: ${render_canonical(r2)}'
	assert rr2.attr('segments') == '2', 'the index chains BOTH sealed segments: ${render_canonical(r2)}'
	mut hot3 := cx.Node(cx.Element{})
	for it in rr2.items {
		if it is cx.Element && it.name == 'journal' {
			hot3 = it
		}
	}
	v3 := journal_stdlib_builtin('journal-verify', [hot3]) or { panic('verify3') }
	assert render_canonical(v3).contains('valid=true'), 'second seam verifies: ${render_canonical(v3)}'
	e6 := journal_stdlib_builtin('journal-read', [hot3, cx.Node(bus_int(6))]) or { panic('read6') }
	assert render_canonical(e6).contains(':e6'), 'newest hot retains the tail: ${render_canonical(e6)}'
}

fn test_journal_rotate_refuses_without_cover_or_boundary() {
	caps_set_all()
	j := journal_stdlib_builtin('journal-open', [store_str('mem://jrt-ref'), store_str('acme')]) or {
		panic('open')
	}
	jrt_append(j, '[do :a]')
	jrt_append(j, '[do :b]')
	// no signing key and no snapshot → the §4.9 contract refuses.
	r := journal_stdlib_builtin('journal-rotate', [j, cx.Node(cx.Element{
		name:  map_marker_name
		items: [
			session_kv('keep-n', bus_int(1)),
			session_kv('target', bus_str('mem://jrt-ref2')),
		]
	})]) or { panic('rotate dispatch') }
	assert is_err_value(r), 'unsigned rotation must refuse'
	assert err_code_of(r) == 'cx-err:CXER4614', 'refusal is E_JOURNAL_SNAPSHOT_UNSIGNED: ${render_canonical(r)}'
	// a boundary that seals nothing refuses (keep-n >= head).
	r2 := journal_stdlib_builtin('journal-rotate', [j, cx.Node(cx.Element{
		name:  map_marker_name
		items: [
			session_kv('keep-n', bus_int(5)),
			session_kv('target', bus_str('mem://jrt-ref3')),
			session_kv('signing-key', bus_str(jrt_seed)),
		]
	})]) or { panic('rotate dispatch 2') }
	assert is_err_value(r2), 'a nothing-to-seal rotation must refuse'
}

// streams=all — the fabric mount-swap mode: every stream moves at its OWN
// boundary; a stream whose boundary floors at 0 is copied whole (nothing
// sealed for it, no index entry) so NOTHING vanishes from the hot window.
fn test_journal_rotate_all_streams() {
	caps_set_all()
	j := journal_stdlib_builtin('journal-open', [store_str('mem://jrt-all'), store_str('acme')]) or {
		panic('open')
	}
	// three entries on stream a, one on stream b (via the attribution map).
	for i in 1 .. 4 {
		ev := cx.parse('[do :a${i}]') or { panic('p') }.elements[0]
		attribution := cx.Element{
			name:  map_marker_name
			items: [
				session_kv('actor', bus_str('did:key:test')),
				session_kv('authority', bus_str('test:suite')),
				session_kv('stream', bus_str('a')),
			]
		}
		r := journal_stdlib_builtin('journal-append', [j, cx.Node(ev), cx.Node(attribution)]) or {
			panic('append a')
		}
		assert !is_err_value(r), 'append a${i}: ${render_canonical(r)}'
	}
	evb := cx.parse('[do :b1]') or { panic('p') }.elements[0]
	battr := cx.Element{
		name:  map_marker_name
		items: [
			session_kv('actor', bus_str('did:key:test')),
			session_kv('authority', bus_str('test:suite')),
			session_kv('stream', bus_str('b')),
		]
	}
	rb := journal_stdlib_builtin('journal-append', [j, cx.Node(evb), cx.Node(battr)]) or {
		panic('append b')
	}
	assert !is_err_value(rb), 'append b1: ${render_canonical(rb)}'

	r := journal_stdlib_builtin('journal-rotate', [j, cx.Node(cx.Element{
		name:  map_marker_name
		items: [
			session_kv('streams', bus_str('all')),
			session_kv('keep-n', bus_int(1)),
			session_kv('target', bus_str('mem://jrt-all2')),
			session_kv('signing-key', bus_str(jrt_seed)),
		]
	})]) or { panic('rotate all') }
	assert !is_err_value(r), 'rotate all: ${render_canonical(r)}'
	rr := r as cx.Element
	assert rr.attr('streams') == '2', 'both streams move: ${render_canonical(r)}'
	assert rr.attr('sealed') == '1', 'only stream a seals (b floors at 0): ${render_canonical(r)}'
	mut hot := cx.Node(cx.Element{})
	for it in rr.items {
		if it is cx.Element && it.name == 'journal' {
			hot = it
		}
	}
	// stream a: seam at 2, head 3; stream b: copied whole.
	ha := journal_stdlib_builtin('journal-head', [hot, cx.Node(bus_str('a'))]) or { panic('ha') }
	assert render_canonical(ha).contains('seq=3'), 'a head: ${render_canonical(ha)}'
	hb := journal_stdlib_builtin('journal-head', [hot, cx.Node(bus_str('b'))]) or { panic('hb') }
	assert render_canonical(hb).contains('seq=1'), 'b head: ${render_canonical(hb)}'
	sb := journal_stdlib_builtin('journal-since', [hot, cx.Node(bus_int(0)), cx.Node(bus_str('b'))]) or {
		panic('since b')
	}
	assert render_canonical(sb).contains(':b1'), 'b copied whole: ${render_canonical(sb)}'
}
