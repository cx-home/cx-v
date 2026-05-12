// `cx select` subcommand — evaluate a CXPath against a CX document
// and print matches, one per line.
//
// Usage:
//   cx select '//user/@name' file.cx
//   cx select '//user[@role="admin"]' file.cx
//   cat file.cx | cx select '//item'

module main

import os
import cx

fn run_select(args []string) {
	if args.len < 1 {
		eprintln('Usage: cx select <cxpath-expr> [file.cx]')
		eprintln('       cat file.cx | cx select <cxpath-expr>')
		exit(2)
	}
	expr := args[0]
	src := if args.len >= 2 {
		os.read_file(args[1]) or { eprintln('cx select: ${err}'); exit(1) }
	} else {
		os.get_raw_lines_joined()
	}

	doc := cx.parse(src) or {
		eprintln('cx select: parse error: ${err}')
		exit(1)
	}

	matches := doc.select_all(expr)
	for e in matches {
		// Wrap match in a synthetic doc to use emit_cx
		text := cx.emit_cx(cx.Document{ elements: [cx.Node(e)] })
		println(text.trim_space())
	}
}
