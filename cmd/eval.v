// `cx eval` subcommand — evaluate a CX program (per spec/code.md)
// against an optional CX data document and print the rendered output.
//
// Routes through code.eval_code (the unified CX code evaluator)
// rather than the legacy POC evaluator (deleted in Phase 7).
//
// Usage (PYE-2, #926 — flags bind BEFORE the program resource; everything
// AFTER it is the program's argv, exactly as the bare run surface):
//   cx eval program.cx [args...]                       # program file, empty input
//   cx eval --data=input.cx program.cx                 # program + input file
//   cx eval --data=- program.cx                        # input from stdin
//   echo 'PROGRAM' | cx eval                           # program from stdin (pipe)
//   cx eval - [args...]                                # program from stdin (explicit)
//   cx eval -e 'PROGRAM' [args...]                     # inline program
//   cx eval -d 'INPUT' -e 'PROGRAM'                    # both inline
//   cx eval --data=input.cx -e 'PROGRAM'               # inline program, file input
//   cx eval --target=text|cx|json|… program.cx         # pick output target
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
	// opt-out; `--allow-common` is the same set WITHOUT `secret-reveal`
	// (#833 — the grant docs can recommend); `--allow-<cap>[=<resource>]`
	// grants one capability (the resource scope is parsed but per-resource
	// enforcement is a v1 follow-up).
	mut allow_all := false
	mut allow_common := false
	mut allow_caps := []string{}
	mut net_specs := []string{}

	// Program argv (PYE-2, #926): flag parsing STOPS at the program
	// resource; everything after it is the program's argv — same rule,
	// same argv[0] placeholders as the bare run surface ('-e' / 'stdin').
	mut prog_argv0 := ''
	mut prog_args := []string{}
	mut i := 0
	for i < args.len {
		arg := args[i]
		if arg == '--strict' {
			// The §12.7 strict dial (stream 16 W5) — same flag as the
			// run surface.
			code.set_strict_mode_cli(true)
			i++
			continue
		}
		if arg == '--allow-all' {
			allow_all = true
			i++
			continue
		}
		if arg == '--allow-common' {
			allow_common = true
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
			prog_argv0 = '-e'
			prog_args = args[i + 2..].clone()
			break
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
			prog_argv0 = if arg == '-' { 'stdin' } else { arg }
			prog_args = args[i + 1..].clone()
			break
		}
		eprintln('cx eval: unknown arg "${arg}"')
		exit(2)
	}

	// Install the program argv (PYE-2/PYE-3): [resource, ...program-args],
	// ungated — see cmd/main.v (the run surface) for the full rationale.
	if prog_argv0 == '' {
		prog_argv0 = 'stdin' // pipe fall-through / usage-error path
	}
	mut pargv := [prog_argv0]
	pargv << prog_args
	code.set_program_argv(pargv)

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
		eprintln('Usage: cx eval [--data=input.cx] [--target=text|cx|json|yaml|xml|csv|tsv] program.cx [args...]')
		eprintln('       echo \'PROGRAM\' | cx eval                       # program from stdin')
		eprintln('       cx eval - [args...]                             # program from stdin (explicit)')
		eprintln('       cx eval -d \'INPUT\' -e \'PROGRAM\'              # both inline')
		eprintln('       cx eval --data=input.cx -e \'PROGRAM\'          # inline program, file input')
		eprintln('flags bind BEFORE the program resource; everything after it is the')
		eprintln('program\'s argv ($env:argv) — PYE-2, same as the bare run surface.')
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
	} else if allow_common {
		code.caps_set_common()
	} else {
		code.caps_set_list(allow_caps) or {
			eprintln('cx: ${err.msg()}')
			exit(2)
		}
		if net_specs.len > 0 {
			code.caps_set_net_hosts(net_specs)
		}
	}

	eval_and_print(input_cx, program_cx, target, 'cx eval')
}

// eval_and_print evaluates `program` against `input` and writes the
// rendered output to stdout, delivering it INCREMENTALLY whenever the
// program's shape allows (#822). Shared by `cx eval` and the run
// surface so the two cannot drift.
//
// Every CLI eval used to build the ENTIRE rendered output as one string
// and print it. Measured on the 10 MB bench fixture with a pass-through
// comprehension: 514 MiB peak RSS, and the growth is linear — about
// 50 MiB + 45x the input size, so a 100 MB document would not fit on an
// ordinary machine. The streaming machinery already existed and was
// already wired to the C ABI; the CLI simply never adopted it.
//
// Output bytes are UNCHANGED: concatenating every chunk yields exactly
// what eval_code returned, and a shape that cannot stream falls back to
// the identical one-shot bytes.
//
// The one real behaviour change, documented rather than hidden: a
// STREAMED run can fail after bytes have already reached stdout, where
// the one-shot path printed nothing on error. That is the cost of not
// buffering the whole result, and it applies only to streaming-eligible
// shapes. code.eval_code_streamable(program, target) reports which path
// a given program takes (#821).
fn eval_and_print(input string, program string, target string, err_prefix string) {
	code.eval_code_streaming(input, program, target, fn (chunk string) ! {
		print(chunk)
	}) or {
		eprintln('${err_prefix}: ${err}')
		exit(1)
	}
	flush_stdout()
	// RULED R5.13 — a top-level err RESULT is a FAILING program: the rendered
	// err still goes to STDOUT (it is the program's answer, and pinned output
	// bytes do not move), but the process exits 1 so a supervisor, a `make`
	// target or CI can see it. Before this, a program that refused exited 0 and
	// was indistinguishable from one that succeeded — which is how a webhook
	// adapter could decline to start and still look like a clean shutdown.
	//
	// The discriminator lives in the evaluator, not here: a SOURCE-LITERAL
	// `[err …]` top-level form is DATA and stays exit 0 (code.md §6.4.1's
	// position rule, per R5.13). This is deliberately AFTER flush_stdout() —
	// the output is the program's result either way.
	if code.last_result_was_failure() {
		exit(1)
	}
}
