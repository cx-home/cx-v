module main

import cx

// Tests for `Document.select_all_paths` / `Element.select_all_paths`
// and the `cx_select_all_paths` C ABI export (Phase 4 / CB-5).
//
// Paths are 0-based indices into Document.elements (depth 0) then
// Element.items (deeper). Order matches `select_all` (preorder).

fn test_select_all_paths_top_level_siblings() {
	src := '[root
  [a]
  [a]
  [b]
  [a]
]'
	doc := cx.parse(src) or { panic(err) }
	paths := doc.select_all_paths('//a')
	// All 'a' elements live inside [root] (which is doc.elements[0]).
	// Their positions in root.items are 0, 1, 3 (skipping [b] at 2).
	assert paths.len == 3, 'expected 3 matches, got ${paths.len}'
	assert paths[0] == [0, 0]
	assert paths[1] == [0, 1]
	assert paths[2] == [0, 3]
}

fn test_select_all_paths_nested_match_order_is_preorder() {
	// Both outer and inner [a] match //a; preorder => outer first.
	src := '[a
  [a]
]'
	doc := cx.parse(src) or { panic(err) }
	paths := doc.select_all_paths('//a')
	assert paths.len == 2, 'expected 2 matches, got ${paths.len}'
	assert paths[0] == [0]      // outer at top level
	assert paths[1] == [0, 0]   // inner at first child of outer
}

fn test_select_all_paths_with_predicate() {
	src := '[config
  [server name=auth port=8080]
  [server name=admin port=9000]
]'
	doc := cx.parse(src) or { panic(err) }
	paths := doc.select_all_paths('//server[@name=auth]')
	assert paths.len == 1
	assert paths[0] == [0, 0]
}

fn test_select_all_paths_empty_result() {
	src := '[config [server host=primary]]'
	doc := cx.parse(src) or { panic(err) }
	paths := doc.select_all_paths('//nonexistent')
	assert paths.len == 0
}

fn test_select_all_paths_navigation_round_trip() {
	// Following each returned path lands exactly on the matched element.
	src := '[root
  [a id=x]
  [b
    [a id=y]
  ]
  [a id=z]
]'
	doc := cx.parse(src) or { panic(err) }
	paths := doc.select_all_paths('//a')
	assert paths.len == 3

	for i, path in paths {
		assert path.len >= 1
		mut node := doc.elements[path[0]]
		for k in 1 .. path.len {
			el := node as cx.Element
			node = el.items[path[k]]
		}
		el := node as cx.Element
		assert el.name == 'a', 'path[${i}] = ${path}: expected a, got ${el.name}'
	}
}

fn test_select_all_paths_child_axis() {
	// Without the // descendant prefix, only direct children match.
	src := '[root
  [a]
  [b
    [a]
  ]
  [a]
]'
	doc := cx.parse(src) or { panic(err) }
	paths := doc.select_all_paths('root/a')
	// 'a' children of root: indices 0 and 2 in root.items.
	assert paths.len == 2, 'expected 2 matches, got ${paths.len}'
	assert paths[0] == [0, 0]
	assert paths[1] == [0, 2]
}

fn test_element_select_all_paths_relative() {
	// Paths from an Element start at depth 0 inside that element.
	src := '[root
  [body
    [p id=1]
    [q]
    [p id=2]
  ]
]'
	doc := cx.parse(src) or { panic(err) }
	root := doc.root() or { panic('no root') }
	body := root.get('body') or { panic('no body') }
	paths := body.select_all_paths('//p')
	assert paths.len == 2
	assert paths[0] == [0]   // first p
	assert paths[1] == [2]   // second p, after q
}
