module main

import os
import code
import cx

// `cx diagram program.cx [--format=mermaid|svg|png] [-o out.file]`
//
// Renders a CX program as a diagram using the reference renderer
// (Phase 4). Output goes to stdout by default; `-o PATH` writes to a
// file (recommended for SVG / PNG which are binary or contain
// markup that's hard to read in a terminal).
//
// All three formats embed the original source bytes (Mermaid
// `%%cx:<base64>%%` comment, SVG `<metadata><cx:source>` block, PNG
// tEXt chunk) so the round-trip property `reverse_parse_diagram` ↔
// `parse` produces a structurally equal AST (§11.6 gate 9).
//
// The same code path is reachable via
//   `cx eval program.cx --target=mermaid|svg|png`
// — `cx diagram` is the discoverable entry point for the visual
// surface, `cx eval --target=…` is the API-parity surface.
fn run_diagram(args []string) {
	mut format := 'mermaid'
	mut out_path := ''
	mut program_path := ''
	for i := 0; i < args.len; i++ {
		a := args[i]
		if a.starts_with('--format=') {
			format = a[9..]
		} else if a == '--format' && i + 1 < args.len {
			format = args[i + 1]
			i++
		} else if a == '-o' && i + 1 < args.len {
			out_path = args[i + 1]
			i++
		} else if a.starts_with('-o=') {
			out_path = a[3..]
		} else if !a.starts_with('-') {
			program_path = a
		}
	}
	if program_path == '' {
		eprintln('cx diagram: program file required')
		eprintln('Usage: cx diagram program.cx [--format=mermaid|svg|png] [-o out.file]')
		exit(1)
	}
	src := os.read_file(program_path) or {
		eprintln('cx diagram: read ${program_path}: ${err}')
		exit(1)
	}
	out := code.eval_code('', src, format) or {
		eprintln('cx diagram: ${err.msg()}')
		exit(1)
	}
	if out_path == '' {
		print(out)
	} else {
		os.write_file(out_path, out) or {
			eprintln('cx diagram: write ${out_path}: ${err}')
			exit(1)
		}
	}
}

// run_code_tree — `cx code-tree [FILE | -]` — Phase 2.11 surface for
// the Tree View JSON emitter. Reads source from FILE
// (or stdin when FILE is `-` or absent), prints JSON to stdout. The
// C ABI export `cx_code_tree` wraps the same V entry point.
fn run_code_tree(args []string) {
	mut input := ''
	if args.len > 0 && args[0] != '-' {
		input = os.read_file(args[0]) or {
			eprintln('cx code-tree: read ${args[0]}: ${err}')
			exit(1)
		}
	} else {
		input = os.get_raw_lines_joined()
	}
	out := cx.code_tree(input) or {
		eprintln('cx code-tree: ${err.msg()}')
		exit(1)
	}
	print(out)
}

// run_code_diagram — `cx code-diagram [FILE | -]` — Phase 2.10 surface
// for the auto-detecting Mermaid emitter (`flowchart TD`
// for code sources / `erDiagram` for data sources). Reads source
// from FILE; if FILE is `-` or absent, reads from stdin. Output goes
// to stdout. The C ABI export `cx_code_diagram` wraps the same V
// entry point (Phase 2.11 / Phase 7.1 wasm rebuild).
fn run_code_diagram(args []string) {
	mut input := ''
	mut level_str := 'compact'
	mut file_arg := ''
	for i := 0; i < args.len; i++ {
		a := args[i]
		if a.starts_with('--level=') {
			level_str = a[8..]
		} else if a == '--level' && i + 1 < args.len {
			level_str = args[i + 1]
			i++
		} else if file_arg == '' {
			file_arg = a
		}
	}
	if file_arg != '' && file_arg != '-' {
		input = os.read_file(file_arg) or {
			eprintln('cx code-diagram: read ${file_arg}: ${err}')
			exit(1)
		}
	} else {
		input = os.get_raw_lines_joined()
	}
	level := code.parse_code_diagram_level(level_str)
	out := code.code_diagram_with_level(input, level) or {
		eprintln('cx code-diagram: ${err.msg()}')
		exit(1)
	}
	print(out)
}
