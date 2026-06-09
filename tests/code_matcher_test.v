module main

import cx
import code

// ── CX pattern matcher tests ────────────────────────────────────────────────
//
// Covers every ProgramPattern variant and every match-failure branch.
// Patterns are parsed from CX source via the parser, then matched
// against CX values built via `cx.parse(...)` — end-to-end-realistic
// test data.

// ── Helpers ─────────────────────────────────────────────────────────────────

fn pat(src string) cx.ProgramPattern {
	prog := cx.parse_program('[?for ${src} [yield $_]]') or {
		panic('parse failed for ${src}: ${err}')
	}
	body := prog.body
	if body is cx.ProgramForComp {
		if body.clauses.len >= 1 {
			clause := body.clauses[0]
			if source := clause.source {
				if source is cx.ProgramPattern {
					return source
				}
			}
		}
	}
	panic('expected pattern in [?for] body')
}

fn doc_root(cx_source string) cx.Element {
	doc := cx.parse(cx_source) or { panic('cx.parse failed: ${err}') }
	for i in 0 .. doc.elements.len {
		n := doc.elements[i]
		if n is cx.Element {
			return n
		}
	}
	panic('no Element at document root')
}

fn child(parent cx.Element, name string) cx.Element {
	for n in parent.items {
		if n is cx.Element && n.name == name {
			return n
		}
	}
	panic('no child element "${name}" in parent')
}

// ── Head matching ───────────────────────────────────────────────────────────

fn test_named_head_matches() {
	p := pat('[user]')
	v := doc_root('[user name=alice]')
	env := code.match_pattern(p, v) or {
		assert false, 'expected match'
		return
	}
	assert env.bindings.len == 0
}

fn test_named_head_no_match() {
	p := pat('[user]')
	v := doc_root('[admin name=root]')
	env := code.match_pattern(p, v)
	assert env == none
}

fn test_wildcard_head_matches() {
	p := pat('[*]')
	v := doc_root('[whatever]')
	env := code.match_pattern(p, v) or {
		assert false
		return
	}
	assert env.bindings.len == 0
}

fn test_wildcard_head_binds() {
	p := pat('[* $x]')
	v := doc_root('[user name=alice]')
	env := code.match_pattern(p, v) or {
		assert false
		return
	}
	assert 'x' in env.bindings
}

fn test_deep_head_matches() {
	p := pat('[** $x]')
	v := doc_root('[anything]')
	env := code.match_pattern(p, v) or {
		assert false
		return
	}
	assert 'x' in env.bindings
}

// ── Bind capture ────────────────────────────────────────────────────────────

fn test_head_bind_captures_subtree() {
	p := pat('[user $u]')
	v := doc_root('[user name=alice age=30]')
	env := code.match_pattern(p, v) or {
		assert false
		return
	}
	assert 'u' in env.bindings
	captured := env.bindings['u']
	if captured is cx.Element {
		assert captured.name == 'user'
	} else { assert false }
}

// ── Attribute predicates ────────────────────────────────────────────────────

fn test_attr_existence_present() {
	p := pat('[user @active]')
	v := doc_root('[user active=true name=alice]')
	env := code.match_pattern(p, v)
	assert env != none
}

fn test_attr_existence_absent_fails() {
	p := pat('[user @active]')
	v := doc_root('[user name=alice]')
	env := code.match_pattern(p, v)
	assert env == none
}

fn test_attr_absence_present_fails() {
	p := pat('[user @!banned]')
	v := doc_root('[user banned=true]')
	env := code.match_pattern(p, v)
	assert env == none
}

fn test_attr_absence_truly_absent() {
	p := pat('[user @!banned]')
	v := doc_root('[user name=alice]')
	env := code.match_pattern(p, v)
	assert env != none
}

fn test_attr_equality_string() {
	p := pat("[user @name='alice']")
	v := doc_root('[user name=alice]')
	env := code.match_pattern(p, v)
	assert env != none
}

fn test_attr_equality_string_mismatch_fails() {
	p := pat("[user @name='bob']")
	v := doc_root('[user name=alice]')
	env := code.match_pattern(p, v)
	assert env == none
}

fn test_attr_equality_int() {
	p := pat('[user @age=30]')
	v := doc_root('[user age=30]')
	env := code.match_pattern(p, v)
	assert env != none
}

fn test_attr_equality_bool_true() {
	p := pat('[user @active=true]')
	v := doc_root('[user active=true]')
	env := code.match_pattern(p, v)
	assert env != none
}

fn test_attr_comparison_gt() {
	p := pat('[order @total>100]')
	v := doc_root('[order total=200]')
	env := code.match_pattern(p, v)
	assert env != none
}

fn test_attr_comparison_gt_fails() {
	p := pat('[order @total>100]')
	v := doc_root('[order total=50]')
	env := code.match_pattern(p, v)
	assert env == none
}

fn test_attr_comparison_le() {
	p := pat('[order @total<=100]')
	v := doc_root('[order total=50]')
	env := code.match_pattern(p, v)
	assert env != none
}

// ── Body matching ───────────────────────────────────────────────────────────

fn test_body_child_pattern() {
	p := pat('[user [name $n]]')
	v := doc_root("[user [name 'alice']]")
	env := code.match_pattern(p, v) or {
		assert false
		return
	}
	assert 'n' in env.bindings
}

fn test_body_multiple_children() {
	p := pat('[user [name $n] [email $e]]')
	v := doc_root("[user [name 'alice'] [email 'a@x.com']]")
	env := code.match_pattern(p, v) or {
		assert false
		return
	}
	assert 'n' in env.bindings && 'e' in env.bindings
}

fn test_body_in_order_skips_non_matches() {
	// Non-:direct allows skipping intervening children.
	p := pat('[user [name $n] [email $e]]')
	v := doc_root("[user [name 'alice'] [phone '555'] [email 'a@x.com']]")
	env := code.match_pattern(p, v) or {
		assert false
		return
	}
	assert 'n' in env.bindings && 'e' in env.bindings
}

fn test_body_direct_requires_adjacency() {
	p := pat('[* direct=true [h2 $h] [p $first]]')
	v := doc_root("[doc [h2 'A'] [p 'after-A'] [h2 'B'] [div 'gap'] [p 'after-gap']]")
	env := code.match_pattern(p, v) or {
		assert false
		return
	}
	// h2-then-p adjacent at start → matches; binds [h2 'A'] and [p 'after-A'].
	assert 'h' in env.bindings && 'first' in env.bindings
}

fn test_body_direct_fails_when_not_adjacent() {
	p := pat('[* direct=true [h2 $h] [p $p]]')
	v := doc_root("[doc [h2 'B'] [div 'gap'] [p 'after-gap']]")
	env := code.match_pattern(p, v)
	assert env == none
}

fn test_body_deep_wildcard_finds_descendant() {
	p := pat('[doc **[para $p]]')
	v := doc_root("[doc [section [intro 'x'] [para 'found']]]")
	env := code.match_pattern(p, v) or {
		assert false
		return
	}
	assert 'p' in env.bindings
}

fn test_body_deep_wildcard_finds_at_root() {
	p := pat('[doc **[figure $f]]')
	v := doc_root("[doc [para 'x'] [figure id='f1']]")
	env := code.match_pattern(p, v) or {
		assert false
		return
	}
	assert 'f' in env.bindings
}

fn test_body_binding_no_path() {
	p := pat('[user $a $b]')
	v := doc_root("[user 'alice' 'extra']")
	env := code.match_pattern(p, v) or {
		assert false
		return
	}
	assert 'a' in env.bindings && 'b' in env.bindings
}

fn test_body_single_star_consumes_one() {
	p := pat('[user * [email $e]]')
	v := doc_root("[user [name 'alice'] [email 'a@x.com']]")
	env := code.match_pattern(p, v) or {
		assert false
		return
	}
	assert 'e' in env.bindings
}

// ── No-match cases ──────────────────────────────────────────────────────────

fn test_no_match_when_required_body_absent() {
	p := pat('[user [email $e]]')
	v := doc_root("[user [name 'alice']]")
	env := code.match_pattern(p, v)
	assert env == none
}

fn test_no_match_against_non_element() {
	p := pat('[user]')
	v := cx.Node(cx.ScalarNode{
		value:     cx.ScalarValue('not an element')
		data_type: cx.ScalarType.string_type
	})
	env := code.match_pattern(p, v)
	assert env == none
}

// ── Composite ───────────────────────────────────────────────────────────────

fn test_composite_pattern_attrs_plus_body() {
	p := pat('[user @active=true [email $e]]')
	v := doc_root("[user active=true [name 'alice'] [email 'a@x.com']]")
	env := code.match_pattern(p, v) or {
		assert false
		return
	}
	assert 'e' in env.bindings
}

fn test_composite_pattern_attr_fails_short_circuits() {
	p := pat('[user @active=true [email $e]]')
	v := doc_root("[user active=false [email 'a@x.com']]")
	env := code.match_pattern(p, v)
	assert env == none
}
