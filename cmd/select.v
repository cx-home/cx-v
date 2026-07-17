// `cx select` subcommand (#462) — CXPath query over one document, per
// spec/03-approved/misc/cli.md §3.8.
//
//   cx select 'PATH' [FILE]
//
// PATH is a single CXPath value expression (spec/code.md §5.5); the document
// (FILE, or stdin when `-` / absent) is read via the DATA reading and bound
// as $doc / $input. Matches print one per line in canonical CX, in document
// order. Capability-neutral: a path read touches no effect point, so the
// subcommand accepts no --allow-* flags and installs the empty (pure-only)
// capability set.
//
// Exit codes: 0 — at least one node matched; 1 — empty match set;
// 2 — error (usage, unreadable FILE, document / path parse error).

module main

import os
import code

fn select_usage() {
	eprintln("Usage: cx select 'PATH' [FILE]")
	eprintln('Reads the document from FILE, or stdin if `-` / absent.')
	eprintln('Exit 0 if matched, 1 if the match set is empty, 2 on error.')
}

fn run_select(args []string) {
	mut path_src := ''
	mut file := ''
	mut have_path := false
	mut have_file := false
	for arg in args {
		// The flag namespace is empty (only the registry-uniform -h/--help,
		// handled before dispatch): anything dash-dash is unknown. A PATH
		// beginning with `/` or `$` never collides with this.
		if arg.starts_with('--') {
			eprintln('cx select: unknown flag ${arg}')
			select_usage()
			exit(2)
		}
		if !have_path {
			path_src = arg
			have_path = true
			continue
		}
		if !have_file {
			file = arg
			have_file = true
			continue
		}
		eprintln('cx select: unexpected extra argument ${arg}')
		select_usage()
		exit(2)
	}
	if !have_path {
		select_usage()
		exit(2)
	}
	doc_src := if !have_file || file == '-' {
		if !have_file && os.is_atty(0) != 0 {
			// No FILE and nothing piped: don't hang waiting on a TTY.
			select_usage()
			exit(2)
		}
		os.get_raw_lines_joined()
	} else {
		os.read_file(file) or {
			eprintln('cx select: error reading ${file}: ${err}')
			exit(2)
		}
	}
	// Pure query surface: install the empty capability set explicitly
	// (deny-by-default; a path evaluation reaches no effect point).
	code.caps_set_list([])
	res := code.select_path(doc_src, path_src) or {
		eprintln('cx select: ${err}')
		exit(2)
	}
	if res.rendered.len > 0 {
		println(res.rendered)
	}
	exit(if res.count > 0 { 0 } else { 1 })
}
