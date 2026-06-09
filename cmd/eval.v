// `cx eval` subcommand — evaluate a CX program (per spec/code.md)
// against an optional CX data document and print the rendered output.
//
// Routes through code.eval_code (the unified CX code evaluator)
// rather than the legacy POC evaluator (deleted in Phase 7).
//
// Usage:
//   cx eval program.cx                                 # program file, empty input
//   cx eval program.cx --data=input.cx                 # program + input file
//   cx eval program.cx --data=-                        # input from stdin
//   echo 'PROGRAM' | cx eval                           # program from stdin (pipe)
//   cx eval -                                          # program from stdin (explicit)
//   cx eval -e 'PROGRAM'                               # inline program
//   cx eval -e 'PROGRAM' -d 'INPUT'                    # both inline
//   cx eval -e 'PROGRAM' --data=input.cx               # inline program, file input
//   cx eval program.cx --target=text|cx|json|…         # pick output target
//
// `-e` and `-d` arguments are passed verbatim to `cx eval`; cx never
// expands variables. BUT the SHELL invoking cx (or wrappers like
// `devbox run --`) may interpolate `$name` even inside single quotes.
// Programs containing `$bindings` are safest read from stdin (`echo
// '[\$count $xs]' | cx eval`) or escaped at the shell layer
// (`cx eval -e "[\\$count \$xs]"`), or just put in a file.

module main

import os
import code

fn run_eval(args []string) {
	mut program_file := ''
	mut program_inline := ''
	mut data_file := ''
	mut data_inline := ''
	mut target := 'text'
	mut have_inline_program := false
	mut have_inline_data := false
	// Capability grants (security.md §3 / cli.md §3.7). Deny-by-default:
	// with no --allow-* flag the eval runs pure-only (empty set), so any
	// effectful surface raises CXER0271. `--allow-all` is the trusted-local
	// opt-out; `--allow-<cap>[=<resource>]` grants one capability (the
	// resource scope is parsed but per-resource enforcement is a v1 follow-up).
	mut allow_all := false
	mut allow_caps := []string{}
	mut net_specs := []string{}

	mut i := 0
	for i < args.len {
		arg := args[i]
		if arg == '--allow-all' {
			allow_all = true
			i++
			continue
		}
		if arg.starts_with('--allow-') {
			rest := arg['--allow-'.len..]
			cap_name := rest.all_before('=')
			if cap_name != '' {
				allow_caps << cap_name
				if cap_name == 'net' && rest.contains('=') {
					net_specs << rest.all_after('=')
				}
			}
			i++
			continue
		}
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
			program_inline = args[i + 1]
			have_inline_program = true
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
		if !arg.starts_with('--') && program_file == '' {
			program_file = arg
			i++
			continue
		}
		eprintln('cx eval: unknown arg "${arg}"')
		exit(2)
	}

	// Program-from-stdin support (matches the convention documented in
	// docs-src/canonical/sections/00-quickstart.cxd and the global stdin
	// idiom in 08-tooling.cxd):
	//
	//   echo 'PROGRAM' | cx eval     →  program read from stdin (pipe detect)
	//   cx eval -                    →  program read from stdin (explicit -)
	//
	// We DON'T trigger stdin-read when stdin is a TTY (interactive shell)
	// — that would hang waiting for input. The current `--data=-` stdin
	// path keeps working unchanged.
	mut have_stdin_program := false
	if !have_inline_program && program_file == '-' {
		have_stdin_program = true
	}
	if !have_inline_program && program_file == '' && os.is_atty(0) == 0 {
		// No positional arg + no -e + stdin is a pipe → read program from stdin.
		have_stdin_program = true
	}

	if !have_inline_program && program_file == '' && !have_stdin_program {
		eprintln('Usage: cx eval program.cx [--data=input.cx] [--target=text|cx|json|yaml|xml|csv|tsv]')
		eprintln('       echo \'PROGRAM\' | cx eval                       # program from stdin')
		eprintln('       cx eval -                                       # program from stdin (explicit)')
		eprintln('       cx eval -e \'PROGRAM\' [-d \'INPUT\']            # both inline')
		eprintln('       cx eval -e \'PROGRAM\' --data=input.cx          # inline program, file input')
		eprintln('See spec/code.md for the CX code language reference.')
		exit(2)
	}

	program_cx := if have_inline_program {
		program_inline
	} else if have_stdin_program {
		os.get_raw_lines_joined()
	} else {
		os.read_file(program_file) or {
			eprintln('cx eval: error reading program "${program_file}": ${err}')
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

	// Install the capability set before eval (deny-by-default). The grant
	// holds for this process; the CLI is single-shot so no reset is needed.
	if allow_all {
		code.caps_set_all()
	} else {
		code.caps_set_list(allow_caps)
		if net_specs.len > 0 {
			code.caps_set_net_hosts(net_specs)
		}
	}

	out := code.eval_code(input_cx, program_cx, target) or {
		eprintln('cx eval: ${err}')
		exit(1)
	}
	print(out)
}
