module main

// cx tools — the agent-tool verb family (stream 18, #690; the
// agent_tool_projection.md §4 offline lane).
//
// `cx tools export MODULE.cx` projects a module's command defs to the MCP
// tools/list array (2025-06-18 entries) WITHOUT running a server — the
// offline-registration lane, gated by golden files. The projection engine
// is the CX one (cx-x/tools + cx-x/mcp-server's tool-json-of): this verb
// EVALUATES the same adapter the live server uses — one engine, never a
// V-side reimplementation. The module's RAW BYTES ride into the program
// base64-encoded so the verbatim def text (the Tier-1 address basis) is
// never re-serialized on the way in.
//
// A projection failure (a command def without [fn-doc][summary], malformed
// source) is the adapter's [err …] value: the verb surfaces it on stderr
// and exits 2 — an offline registration must never emit a silently empty
// or partial tool set.

import os
import cx
import encoding.base64
import code

fn run_tools(args []string) {
	if args.len == 0 {
		eprintln('Usage: cx tools export [--output=FILE] MODULE.cx')
		eprintln('Sub-verbs: export (project a module\'s command defs to the MCP tools/list array — the offline registration lane)')
		exit(2)
	}
	match args[0] {
		'export' { run_tools_export(args[1..]) }
		else {
			eprintln("cx tools: unknown sub-verb '${args[0]}' (expected: export)")
			exit(2)
		}
	}
}

fn run_tools_export(args []string) {
	mut files := []string{}
	mut output := ''
	for arg in args {
		if arg.starts_with('--output=') {
			output = arg.all_after('--output=')
		} else if arg.starts_with('-') {
			eprintln("cx tools export: unknown flag '${arg}'")
			exit(2)
		} else {
			files << arg
		}
	}
	if files.len != 1 {
		eprintln('Usage: cx tools export [--output=FILE] MODULE.cx')
		exit(2)
	}
	src := os.read_file(files[0]) or {
		eprintln('cx tools export: ${err}')
		exit(2)
	}
	b64 := base64.encode_str(src)
	program := "[?lib 'cx-x/mcp-server' :as srv]\n" +
		"[?lib 'cx-stdlib/json' :as json]\n" +
		"[?lib 'cx-stdlib/bytes' :as bytes]\n" +
		'[\$json:emit [\$srv:tools-for [\$bytes:to-string-utf8 [\$bytes:from-base64 "${b64}"]]]]'
	rendered := code.eval_code('', program, 'text') or {
		eprintln('cx tools export: ${files[0]}: ${err.msg()}')
		exit(2)
	}
	// The eval result is the JSON string rendered CANONICALLY (quoted).
	// Recover the raw bytes by reading the scalar back; anything that is
	// not a single string scalar is the adapter's [err …] — fail loud.
	doc := cx.parse(rendered) or {
		eprintln('cx tools export: ${files[0]}: internal: unreadable eval result: ${err}')
		exit(2)
	}
	if doc.elements.len == 1 {
		el := doc.elements[0]
		if el is cx.ScalarNode {
			v := el.value
			if v is string {
				out := v + '\n'
				if output != '' {
					os.write_file(output, out) or {
						eprintln('cx tools export: ${err}')
						exit(2)
					}
				} else {
					print(out)
					flush_stdout()
				}
				return
			}
		}
	}
	eprintln('cx tools export: ${files[0]}: projection refused:')
	eprintln(rendered)
	exit(2)
}
