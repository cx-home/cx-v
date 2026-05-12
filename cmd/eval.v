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

	program_cx := if have_inline_template {
		template_inline
	} else {
		os.read_file(template_file) or {
			eprintln('cx eval: error reading template "${template_file}": ${err}')
			exit(1)
		}
	}

	input_cx := if have_inline_data {
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

	out := cx.eval_cxl(input_cx, program_cx, target) or {
		eprintln('cx eval: ${err}')
		exit(1)
	}
	print(out)
}
