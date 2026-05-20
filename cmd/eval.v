// `cx eval` subcommand — evaluate a CXL template against a CX data
// document and print the rendered output.
//
// Usage:
//   cx eval template.cxl                                # template file, empty context
//   cx eval template.cxl --data=context.cx              # template + data file
//   cx eval template.cxl --data=-                       # data from stdin
//   cx eval -e 'CXL_INLINE'                             # inline template
//   cx eval -e 'CXL_INLINE' -d 'CX_INLINE'              # both inline
//   cx eval -e 'CXL_INLINE' --data=context.cx           # inline template, file data
//   cx eval template.cxl --target=text|cx|html          # pick output target

module main

import os
import cx

fn run_eval(args []string) {
	mut template_file := ''
	mut template_inline := ''
	mut data_file := ''
	mut data_inline := ''
	mut target := 'text'
	mut include_root := ''
	mut have_inline_template := false
	mut have_inline_data := false

	mut i := 0
	for i < args.len {
		arg := args[i]
		if arg.starts_with('--data=') {
			data_file = arg[7..]
			i++
			continue
		}
		if arg.starts_with('--target=') {
			target = arg[9..]
			i++
			continue
		}
		if arg.starts_with('--include-root=') {
			include_root = arg[15..]
			i++
			continue
		}
		if arg == '-e' || arg == '--expression' {
			if i + 1 >= args.len {
				eprintln('cx eval: ${arg} needs an argument')
				exit(2)
			}
			template_inline = args[i + 1]
			have_inline_template = true
			i += 2
			continue
		}
		if arg == '-d' || arg == '--data-text' {
			if i + 1 >= args.len {
				eprintln('cx eval: ${arg} needs an argument')
				exit(2)
			}
			data_inline = args[i + 1]
			have_inline_data = true
			i += 2
			continue
		}
		if !arg.starts_with('--') && template_file == '' {
			template_file = arg
			i++
			continue
		}
		eprintln('cx eval: unknown arg "${arg}"')
		exit(2)
	}

	if !have_inline_template && template_file == '' {
		eprintln('Usage: cx eval template.cxl [--data=context.cx] [--target=text|cx|html]')
		eprintln('       cx eval -e \'CXL\' [-d \'CX\']         # both inline')
		eprintln('       cx eval -e \'CXL\' --data=context.cx   # inline template, file data')
		exit(2)
	}

	mut program_cx := if have_inline_template {
		template_inline
	} else {
		os.read_file(template_file) or {
			eprintln('cx eval: error reading template "${template_file}": ${err}')
			exit(1)
		}
	}

	mut input_cx := if have_inline_data {
		data_inline
	} else if data_file == '' {
		''
	} else if data_file == '-' {
		os.get_raw_lines_joined()
	} else {
		os.read_file(data_file) or {
			eprintln('cx eval: error reading data "${data_file}": ${err}')
			exit(1)
		}
	}

	// --include-root has two effects:
	//   1. Parse-time `[?cx include=…]` directives in the program
	//      and data context resolve against the root (so build.cxl
	//      can splice in static partials via the GG1 resolver).
	//   2. Eval-time `[?include path]` directives in the program
	//      become live: `eval_cxl_with_include_root` carries the
	//      root through to env.include_root, the eval_include
	//      handler reads files relative to it (with the same
	//      containment + cycle rules as the parse-time resolver).
	if include_root != '' {
		program_cx = resolve_includes_text(program_cx, include_root) or {
			eprintln('cx eval: error resolving includes in template: ${err}')
			exit(1)
		}
		if input_cx.len > 0 {
			input_cx = resolve_includes_text(input_cx, include_root) or {
				eprintln('cx eval: error resolving includes in data: ${err}')
				exit(1)
			}
		}
	}

	// Canonicalise the include root to an absolute, symlink-resolved
	// path so the eval-time containment check can compare prefix-
	// wise against env.include_root (the parse-time resolver
	// canonicalises the same way in include.v).
	abs_include_root := if include_root == '' {
		''
	} else if os.is_abs_path(include_root) {
		os.real_path(include_root)
	} else {
		os.real_path(os.abs_path(include_root))
	}

	out := cx.eval_cxl_with_include_root(input_cx, program_cx, target,
		abs_include_root) or {
		eprintln('cx eval: ${err}')
		exit(1)
	}
	print(out)
}
