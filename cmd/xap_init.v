module main

import os

// `cx xap init NAME [--dir D] [--client]` — scaffold a XAP project.
//
// The layout is the one xap_authoring_process.md §3.1 specifies and the
// in-family reference application (`reference/shop/`) demonstrates: three
// authored layers plus, optionally, a SEPARATE client project beside the
// XAP rather than inside it (N-CLIENT-2 — a XAP never embeds its renderer).
//
// What it emits is a working two-base-plus-composite skeleton, not empty
// files. That is deliberate: the thing a new author most needs to see is
// that a COMPOSITE joins two independent bases over a shared key, because
// it is the shape the compose gate exists to protect and the one that is
// hard to guess from a blank page. The generated project composes and
// passes W1-W6 immediately — `cx --allow-read <dir>/compose.cx` proves it
// before a line is edited.
//
// The scaffolded rules deliberately sit where the gate allows them: the
// cross-feature ordering rule is on the COMPOSITE, not on a base, with the
// comment explaining why. That is the single most common authoring mistake
// (a base naming another feature's verb is a W4 conflict), so the skeleton
// gets it right and says so.

const xap_init_usage = [
	'Usage: cx xap init NAME [--dir DIR] [--client]',
	'       cx xap check-surface [DIR]',
	'',
	'init scaffolds a XAP project: two base features, one composite that',
	'joins them, the xap wiring layer, and a surface. The result composes',
	'through the W1-W6 gate as generated — nothing to fix before it runs.',
	'',
	'  --dir DIR   where to create it (default: ./NAME)',
	'  --client    also scaffold NAME-web-client/ as a SEPARATE project',
	'              (N-CLIENT-2: a XAP never embeds its renderer). It RUNS',
	'              as generated: serve.cx renders each pane as a generic',
	'              table derived from the surface\'s `shows` declarations —',
	'              a floor to replace with your own views, never final UX.',
	'',
	'check-surface verifies every *.surface.cxd in DIR (default .) is a',
	'faithful DERIVATION of the xap + feature specs beside it — the classes',
	'the shape schema cannot see. `cx xap check-surface --help` lists them.',
	'',
	'Then:',
	'  cx --allow-read DIR/compose.cx        # the gate + bare-term resolution',
	'  cx validate --schema=… DIR/*.cxd      # each layer against its schema',
	'  cx xap check-surface DIR              # the surface derivation check',
]

fn xap_init_die(msg string) {
	eprintln('cx xap init: ${msg}')
	for l in xap_init_usage {
		eprintln(l)
	}
	exit(2)
}

fn run_xap(args []string) {
	if args.len == 0 || args[0] in ['-h', '--help'] {
		for l in xap_init_usage {
			println(l)
		}
		exit(if args.len == 0 { 2 } else { 0 })
	}
	if args[0] == 'check-surface' {
		run_xap_check_surface(args[1..])
		return
	}
	if args[0] != 'init' {
		xap_init_die('unknown action `${args[0]}` — actions: init, check-surface')
	}
	if args.len < 2 {
		xap_init_die('missing NAME')
	}
	name := args[1]
	if name == '' || name.starts_with('-') {
		xap_init_die('NAME must be a plain project name, got `${name}`')
	}
	// The name becomes a XAP name and file stems, so hold it to the same
	// shape a feature name has to satisfy — better to refuse here than to
	// emit a project whose own schema rejects it.
	for c in name {
		if !((c >= `a` && c <= `z`) || (c >= `0` && c <= `9`) || c == `-`) {
			xap_init_die('NAME must be lowercase letters, digits and dashes, got `${name}`')
		}
	}
	mut dir := './${name}'
	mut want_client := false
	mut i := 2
	for i < args.len {
		match args[i] {
			'--client' {
				want_client = true
				i++
			}
			'--dir' {
				if i + 1 >= args.len {
					xap_init_die('--dir needs a directory')
				}
				dir = args[i + 1]
				i += 2
			}
			else {
				xap_init_die('unknown flag `${args[i]}`')
			}
		}
	}
	if os.exists(dir) && os.ls(dir) or { [] }.len > 0 {
		// Refuse rather than merge: scaffolding into a populated directory
		// is how a half-overwritten project happens.
		eprintln('cx xap init: ${dir} already exists and is not empty')
		exit(1)
	}
	os.mkdir_all(dir) or {
		eprintln('cx xap init: cannot create ${dir}: ${err}')
		exit(1)
	}

	mut written := []string{}
	for f, body in xap_init_files(name) {
		p := os.join_path(dir, f)
		os.write_file(p, body) or {
			eprintln('cx xap init: cannot write ${p}: ${err}')
			exit(1)
		}
		written << p
	}
	if want_client {
		cdir := '${dir}-web-client'
		os.mkdir_all(os.join_path(cdir, 'shell', 'static')) or {
			eprintln('cx xap init: cannot create ${cdir}: ${err}')
			exit(1)
		}
		for f, body in xap_init_client_files(name) {
			p := os.join_path(cdir, f)
			os.write_file(p, body) or {
				eprintln('cx xap init: cannot write ${p}: ${err}')
				exit(1)
			}
			written << p
		}
	}
	for p in written {
		println(p)
	}
	println('')
	println('Next: cx --allow-read ${os.join_path(dir, 'compose.cx')}')
	if want_client {
		println('')
		println('${dir}-web-client/ RUNS as generated — from that directory:')
		println('  cx --allow-read --allow-env --allow-net=127.0.0.1:8791 serve.cx')
		println('Its panes are generic tables derived from the surface\'s `shows`')
		println('declarations — a floor to replace with your own views, never final UX.')
	}
}
