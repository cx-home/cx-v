module code

import cx

// store_modify_select_test.v — #134-1 (nested target via select) + #134-2
// (child-remove). Exercises the issue's exact repros against store_modify_apply.

fn parse_el(src string) cx.Element {
	doc := cx.parse(src) or { panic('parse ${src}: ${err}') }
	if doc.elements.len == 0 || doc.elements[0] !is cx.Element {
		panic('not an element: ${src}')
	}
	return doc.elements[0] as cx.Element
}

// #134-1: select="//t" sets the attr on the CHILD, not the root.
fn test_modify_select_targets_nested_child() {
	root := parse_el('[targets [t mmsi="111" sog="0"]]')
	act := parse_el('[set-attr select="//t" name=sog value="9"]')
	out := store_modify_apply(root, '//t', act) or { panic(err.msg()) }
	r := render_canonical(out)
	// the child t now has sog='9'
	assert r.contains("[t mmsi='111' sog='9']"), 'child not updated: ${r}'
	// the root targets did NOT get a stray sog attr
	assert r.starts_with('[targets ['), 'root gained a stray attr: ${r}'
	assert !r.contains("[targets sog="), 'sog leaked onto root: ${r}'
}

// #134-2: [remove select="//t"] deletes the matched child.
fn test_modify_remove_child() {
	root := parse_el('[targets [t mmsi="111"] [t mmsi="222"]]')
	act := parse_el('[remove select="//t"]')
	out := store_modify_apply(root, '//t', act) or { panic(err.msg()) }
	r := render_canonical(out)
	assert r == '[targets]', 'expected all t children removed, got: ${r}'
}

// #134-2: remove a specific keyed child (one of several) — descendant match.
fn test_modify_remove_is_scoped_to_matches() {
	root := parse_el('[doc [keep [v "k"]] [drop [v "d"]] [keep [v "k2"]]]')
	act := parse_el('[remove select="//drop"]')
	out := store_modify_apply(root, '//drop', act) or { panic(err.msg()) }
	r := render_canonical(out)
	assert !r.contains('drop'), 'drop not removed: ${r}'
	assert r.contains("[keep [v 'k']]") && r.contains("[keep [v 'k2']]"), 'keep nodes lost: ${r}'
}

// back-compat: no select edits the root element (the original behavior).
fn test_modify_no_select_edits_root() {
	root := parse_el('[targets [t mmsi="111"]]')
	act := parse_el('[set-attr name=count value="1"]')
	out := store_modify_apply(root, '', act) or { panic(err.msg()) }
	r := render_canonical(out)
	assert r.contains("[targets count='1'"), 'root not edited: ${r}'
}

// remove without a select is an error (can't remove the document root).
fn test_modify_remove_without_select_errors() {
	root := parse_el('[targets [t mmsi="111"]]')
	act := parse_el('[remove]')
	store_modify_apply(root, '', act) or { return } // expected error
	assert false, 'expected an error removing the root with no select'
}

// append into a nested match.
fn test_modify_append_nested() {
	root := parse_el('[doc [list [item "a"]]]')
	act := parse_el('[append select="//list" [item "b"]]')
	out := store_modify_apply(root, '//list', act) or { panic(err.msg()) }
	r := render_canonical(out)
	assert r.contains("[item 'a']") && r.contains("[item 'b']"), 'append into child failed: ${r}'
}
