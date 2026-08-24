module main

import os
import code
import cx

// `cx diagram program.cx [--format=mermaid|svg|png] [-o out.file]
//                        [--allow-subprocess]`
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
//   `cx eval --target=mermaid|svg|png program.cx`
// — `cx diagram` is the discoverable entry point for the visual
// surface, `cx eval --target=…` is the API-parity surface.
fn run_diagram(args []string) {
	mut format := 'mermaid'
	mut out_path := ''
	mut program_path := ''
	// RULED: DSC-1c (#890) — the graphviz formats demand an EXPLICIT
	// grant; this subcommand no longer grants `subprocess` to itself.
	// The vocabulary is the CLI's own (`--allow-<cap>` over
	// code.capability_names(), plus the two broad grants) — no new flag
	// shape.
	mut allow_all := false
	mut allow_common := false
	mut allow_caps := []string{}
	mut net_specs := []string{}
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
		} else if a == '--allow-all' {
			allow_all = true
		} else if a == '--allow-common' {
			allow_common = true
		} else if a.starts_with('--allow-') {
			// A misspelled grant is an unknown flag, never a silent
			// no-grant (spec/misc/cli.md §3.7 — same rule as `cx`).
			rest_cap := a['--allow-'.len..]
			cap_name := rest_cap.all_before('=')
			if cap_name == '' || cap_name !in code.capability_names() {
				mut grant_flags := code.capability_names().map('--allow-' + it)
				grant_flags << '--allow-common'
				grant_flags << '--allow-all'
				eprintln('cx diagram: unknown flag ${a}')
				eprintln('accepted capability grants: ${grant_flags.join(' ')}')
				exit(2)
			}
			allow_caps << cap_name
			// A scope must NARROW, never be dropped on the floor — same
			// handling as `cx` / `cx eval` (main.v).
			if cap_name == 'net' && rest_cap.contains('=') {
				net_specs << rest_cap.all_after('=')
			}
		} else if !a.starts_with('-') {
			program_path = a
		}
	}
	if program_path == '' {
		eprintln('cx diagram: program file required')
		eprintln('Usage: cx diagram program.cx [--format=mermaid[:min|compact|full]|svg|png] [-o out.file] [--allow-subprocess]')
		exit(1)
	}
	src := os.read_file(program_path) or {
		eprintln('cx diagram: read ${program_path}: ${err}')
		exit(1)
	}
	// The SVG/PNG formats render through graphviz, and after the DR-2a
	// cutover that hop is an ordinary `cx-stdlib/process` call charged
	// to `subprocess`. Under DSC-1c the caller pays for it explicitly;
	// without the grant the command REFUSES rather than quietly
	// substituting the dot-less envelope (which remains the answer for
	// `dot` being ABSENT — a granted caller on a machine with no
	// graphviz — a different condition with a different answer).
	// NOTE: security.md §2 specifies an *allowed executables*
	// constraint for this capability and the engine carries the field,
	// but the guard does not yet enforce it (consult finding C12);
	// when it does, this grant narrows to exactly `dot`.
	base_fmt := if i := format.index(':') { format[..i] } else { format }
	needs_dot := base_fmt == 'svg' || base_fmt == 'png'
	granted_subprocess := allow_all || allow_common || 'subprocess' in allow_caps
	if needs_dot && !granted_subprocess {
		eprintln('cx diagram: E_CAP_DENIED: subprocess capability required to run graphviz `dot` for the ${base_fmt} diagram format; none granted (grant via --allow-subprocess) (cx-err:CXER0271)')
		eprintln('  render it with:  cx diagram ${program_path} --format=${format} --allow-subprocess')
		eprintln('  or use --format=mermaid, which needs no capability.')
		exit(1)
	}
	if allow_all {
		code.caps_set_all()
	} else if allow_common {
		code.caps_set_common()
	} else if allow_caps.len > 0 {
		code.caps_set_list(allow_caps) or {
			eprintln('cx diagram: ${err.msg()}')
			exit(1)
		}
		if net_specs.len > 0 {
			code.caps_set_net_hosts(net_specs)
		}
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
// `--view` (RULED: DGX-1) selects the SUBJECT; `--level` still selects
// the rung. `auto` is the shipped auto-detection, byte for byte.
const code_diagram_views = ['auto', 'effects']

fn run_code_diagram(args []string) {
	mut input := ''
	mut level_str := 'compact'
	mut view := 'auto'
	mut file_arg := ''
	for i := 0; i < args.len; i++ {
		a := args[i]
		if a.starts_with('--level=') {
			level_str = a[8..]
		} else if a == '--level' && i + 1 < args.len {
			level_str = args[i + 1]
			i++
		} else if a.starts_with('--view=') {
			view = a[7..]
		} else if a == '--view' && i + 1 < args.len {
			view = args[i + 1]
			i++
		} else if file_arg == '' {
			file_arg = a
		}
	}
	// An unknown --view is a HARD error naming the accepted set — the
	// misc/cli.md §3.7 posture the capability flags already take. A
	// typo must not silently render the wrong subject.
	if view !in code_diagram_views {
		eprintln('cx code-diagram: unknown --view=${view} (accepted: ${code_diagram_views.join(', ')})')
		exit(1)
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
	out := if view == 'effects' {
		code.effect_graph_with_level(input, level) or {
			eprintln('cx code-diagram: ${err.msg()}')
			exit(1)
		}
	} else {
		code.code_diagram_with_level(input, level) or {
			eprintln('cx code-diagram: ${err.msg()}')
			exit(1)
		}
	}
	print(out)
}
