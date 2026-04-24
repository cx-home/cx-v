module main

import os
import cx

fn main() {
	args := os.args[1..]
	if args.len == 0 {
		eprintln('Usage: cx --ast|--cx|--xml|--json|--yaml|--toml|--md [--compact] [input_file]')
		eprintln('       cx --from=cx|xml|md --to=cx|xml|json|yaml|toml|md [--compact] [input_file]')
		exit(1)
	}

	// Determine input
	mut input := ''
	mut input_file := ''
	for arg in args {
		if !arg.starts_with('--') {
			input_file = arg
			input = os.read_file(arg) or {
				eprintln('error reading file ${arg}: ${err}')
				exit(1)
			}
			break
		}
	}
	if input.len == 0 {
		input = os.get_raw_lines_joined()
	}

	// Parse flags
	mut mode := ''
	mut compact := false
	mut explicit_from := false
	mut from_fmt := 'cx'
	mut to_fmt := 'cx'
	for arg in args {
		if arg == '--ast'     { mode = 'ast' }
		else if arg == '--cx'      { mode = 'cx' }
		else if arg == '--xml'     { mode = 'xml' }
		else if arg == '--json'    { mode = 'json' }
		else if arg == '--yaml'    { mode = 'yaml' }
		else if arg == '--toml'    { mode = 'toml' }
		else if arg == '--md'      { mode = 'md' }
		else if arg == '--compact' { compact = true }
		else if arg.starts_with('--from=') { from_fmt = arg[7..]; explicit_from = true }
		else if arg.starts_with('--to=') { to_fmt = arg[5..] }
	}

	// Auto-detect input format from file extension if not explicit
	if !explicit_from && input_file.len > 0 {
		if input_file.ends_with('.md')   { from_fmt = 'md' }
		else if input_file.ends_with('.xml')  { from_fmt = 'xml' }
		else if input_file.ends_with('.json') { from_fmt = 'json' }
		else if input_file.ends_with('.yaml') || input_file.ends_with('.yml') { from_fmt = 'yaml' }
		else if input_file.ends_with('.toml') { from_fmt = 'toml' }
	}

	if mode.len == 0 { mode = to_fmt }

	from := match from_fmt {
		'xml'  { cx.Format.xml }
		'json' { cx.Format.json }
		'yaml' { cx.Format.yaml }
		'toml' { cx.Format.toml }
		'md'   { cx.Format.md }
		else   { cx.Format.cx }
	}

	out := if mode == 'ast' {
		cx.to_ast(input) or { eprintln('error: ${err}'); exit(1) }
	} else if mode == 'cx' && compact {
		cx.to_cx_compact(input) or { eprintln('error: ${err}'); exit(1) }
	} else {
		to_fmt_enum := match mode {
			'cx'   { cx.Format.cx }
			'xml'  { cx.Format.xml }
			'json' { cx.Format.json }
			'yaml' { cx.Format.yaml }
			'toml' { cx.Format.toml }
			'md'   { cx.Format.md }
			else   { cx.Format.cx }
		}
		cx.convert(input, from, to_fmt_enum) or { eprintln('error: ${err}'); exit(1) }
	}
	println(out)
}
