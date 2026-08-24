module main

import os
import fixtures

// I2 extraction-gate CLI lane — the second half of the Ring-0 byte-for-byte
// gate (partition spec §7): drives the MONOLITH `cx` and the `data`-profile
// `cx` over every Ring-0-tagged conformance case through their SHARED
// surface, and requires stdout, stderr, and exit code identical per
// invocation.
//
// The shared surface is the verb set (canonical/hash/eq/diff/validate) plus
// the EXPLICIT `--from=` convert pipeline. The bare `cx FILE` surface is
// deliberately NOT compared: on the monolith it is the run surface
// (evaluates), on the data profile it is the data reading (parses inert) —
// a ruled profile difference, not drift (partition spec §4).
//
// Usage: extraction_gate_cli <monolith cx> <data-profile cx> [corpus dir]

struct Diverge {
	suite string
	cid   string
	argv  string
	what  string
}

struct Gate {
mut:
	mono    string
	data    string
	tmp     string
	n_inv   int
	divergs []Diverge
	suite   string
	cid     string
}

struct RunResult {
	rc  int
	out string
	err string
}

fn run_bin(bin string, args []string, stdin_data string) RunResult {
	mut pr := os.new_process(bin)
	pr.set_args(args)
	// Spawn in the scratch dir, never the checkout: a candidate binary that
	// MISBEHAVES can execute a side-effectful verb for real — measured
	// 2026-08-23 red-proofing against a stale three-releases-old monolith, whose bare
	// `lock` refusal probe RAN and wrote ./cx.lock into the repo root
	// (failing release-verify's tree-clean row a run later).
	pr.set_work_folder(os.join_path(os.temp_dir(), 'cx_extraction_gate_cli'))
	pr.set_redirect_stdio()
	pr.run()
	if stdin_data != '' {
		pr.stdin_write(stdin_data)
	}
	os.fd_close(pr.stdio_fd[0])
	out := pr.stdout_slurp()
	errs := pr.stderr_slurp()
	pr.wait()
	return RunResult{
		rc:  pr.code
		out: out
		err: errs
	}
}

fn (mut g Gate) compare(args []string, stdin_data string) {
	mut a := run_bin(g.mono, args, stdin_data)
	mut b := run_bin(g.data, args, stdin_data)
	g.n_inv++
	if a.rc == b.rc && a.out == b.out && a.err == b.err {
		return
	}
	// A REAL divergence is deterministic (two fixed binaries over fixed
	// input); one that vanishes on retry is a spawn-level flake under
	// system load. Measured 2026-08-23 inside release-verify's fully
	// parallel `make test`: ONE case of 1838 diverged (rc 1, empty stdout,
	// 27 B stderr on the monolith side) and the same invocation passed
	// standalone — the gate then failed the record run with no stderr
	// content kept, so the cause needed a re-run to even guess at. Retry
	// once, loudly; report the flake without failing.
	a2 := run_bin(g.mono, args, stdin_data)
	b2 := run_bin(g.data, args, stdin_data)
	if a2.rc == b2.rc && a2.out == b2.out && a2.err == b2.err {
		eprintln('extraction_gate_cli: TRANSIENT flake (agreed on retry) ${g.suite}#${g.cid} :: ${args.join(' ')} — first run: rc ${a.rc} vs ${b.rc}, stderr A ${diverge_payload(a.err)} B ${diverge_payload(b.err)}')
		return
	}
	a = a2
	b = b2
	mut what := ''
	if a.rc != b.rc {
		what += 'rc ${a.rc}≠${b.rc} '
	}
	if a.out != b.out {
		what += 'stdout diverges (${a.out.len}B vs ${b.out.len}B) '
	}
	if a.err != b.err {
		// Lengths alone made the 27-byte failure above unguessable —
		// carry the payloads.
		what += 'stderr diverges (A ${diverge_payload(a.err)} vs B ${diverge_payload(b.err)})'
	}
	g.divergs << Diverge{
		suite: g.suite
		cid:   g.cid
		argv:  args.join(' ')
		what:  what
	}
}

// diverge_payload renders a bounded, newline-escaped view of a stream so a
// divergence report carries its evidence instead of just a byte count.
fn diverge_payload(s string) string {
	if s == '' {
		return '<empty>'
	}
	mut t := s
	if t.len > 200 {
		t = t[..200] + '…'
	}
	return '<${t.len}B: ' + t.replace('\n', '\\n') + '>'
}

fn (mut g Gate) tmpfile(name string, content string) string {
	path := os.join_path(g.tmp, name)
	os.write_file(path, content) or { panic('cannot write ${path}: ${err}') }
	return path
}

fn (mut g Gate) run_case(c fixtures.FixtureCase) {
	if in_cx := c.sections['in_cx'] {
		g.compare(['canonical'], in_cx)
		g.compare(['hash'], in_cx)
		// explicit --from selects the convert pipeline on BOTH binaries
		g.compare(['--from=cx', '--to=json'], in_cx)
		g.compare(['--from=cx', '--to=xml'], in_cx)
		g.compare(['--from=cx', '--to=cx'], in_cx)
		f := g.tmpfile('doc.cx', in_cx)
		g.compare(['eq', f, f], '')
		if schema := c.sections['schema_cxs'] {
			s := g.tmpfile('schema.cxs', schema)
			g.compare(['validate', f, '--schema=${s}'], '')
			g.compare(['validate', f, '--schema=${s}', '--apply-defaults'], '')
		}
	}
	for key, from in {
		'in_xml':  'xml'
		'in_json': 'json'
		'in_yaml': 'yaml'
		'in_toml': 'toml'
		'in_md':   'md'
	} {
		if input := c.sections[key] {
			g.compare(['--from=${from}', '--to=cx'], input)
			g.compare(['--from=${from}', '--to=json'], input)
		}
	}
	if in_a := c.sections['in_a'] {
		if in_b := c.sections['in_b'] {
			fa := g.tmpfile('a.cx', in_a)
			fb := g.tmpfile('b.cx', in_b)
			g.compare(['diff', '--no-color', fa, fb], '')
			g.compare(['diff', '--format=json', fa, fb], '')
			g.compare(['eq', fa, fb], '')
		}
	}
}

fn main() {
	mut positional := []string{}
	mut min_cases := 0
	for a in os.args[1..] {
		if a.starts_with('--min-cases=') {
			min_cases = a.all_after('=').int()
		} else if a.starts_with('--') {
			eprintln('extraction_gate_cli: unknown flag ${a}')
			exit(2)
		} else {
			positional << a
		}
	}
	if positional.len < 2 {
		eprintln('usage: extraction_gate_cli <monolith cx> <data-profile cx> [corpus dir] [--min-cases=N]')
		exit(2)
	}
	mut g := Gate{
		mono: positional[0]
		data: positional[1]
		tmp:  os.join_path(os.temp_dir(), 'cx_extraction_gate_cli')
	}
	corpus := if positional.len > 2 { positional[2] } else { 'conformance' }
	os.mkdir_all(g.tmp) or { panic('cannot mkdir ${g.tmp}: ${err}') }
	// Pin the binaries under test (#902 doctrine: which build is under test
	// is a DECISION, not a race). Under the fully parallel `make test`,
	// build-vcx stamps -d cx_build_date=<now> into the compile line, so any
	// recursive $(MAKE) build-vcx (guide-check runs one) RELINKS
	// vcx/target/cx unconditionally — while this lane is exec'ing it
	// thousands of times over several minutes. Measured 2026-08-23 (twice):
	// one invocation pair of 10579 died with 'Exec format error; code: 8'
	// mid-relink and failed the record run. Exec private COPIES taken at
	// gate start; a concurrent relink of the originals is then invisible.
	// rm before cp: macOS caches signature validity per vnode — overwriting
	// a previous run's pin in place re-arms the Code Signature Invalid kill
	// (#883's second half). A fresh inode every run.
	pinned_mono := os.join_path(g.tmp, 'pinned-mono-cx')
	pinned_data := os.join_path(g.tmp, 'pinned-data-cx')
	os.rm(pinned_mono) or {}
	os.rm(pinned_data) or {}
	os.cp(g.mono, pinned_mono) or { panic('cannot pin ${g.mono}: ${err}') }
	os.cp(g.data, pinned_data) or { panic('cannot pin ${g.data}: ${err}') }
	os.chmod(pinned_mono, 0o755) or { panic('cannot chmod ${pinned_mono}: ${err}') }
	os.chmod(pinned_data, 0o755) or { panic('cannot chmod ${pinned_data}: ${err}') }
	g.mono = pinned_mono
	g.data = pinned_data

	mut files := os.ls(corpus) or { panic('cannot list ${corpus}: ${err}') }
	files.sort()
	mut n_cases := 0
	for f in files {
		if !f.ends_with('.cxd') {
			continue
		}
		suite := fixtures.load_suite(os.join_path(corpus, f))
		if suite.ring == '' {
			continue
		}
		for c in suite.cases {
			if suite.case_ring(c) != '0' {
				continue
			}
			g.suite = f
			g.cid = c.name
			g.run_case(c)
			n_cases++
		}
	}
	// Profile-refusal shape: every monolith-only verb word must refuse (rc 2,
	// refusal text) on the data binary — never fall through to the FILE
	// reading (#426). Asserted against the data binary alone; the monolith
	// legitimately dispatches these.
	for verb in ['fmt', 'lint', 'eval', 'select', 'diagram', 'code-diagram', 'code-tree',
		'table', 'scaffold', 'demo', 'lock', 'lsp', 'store-serve', 'fabric-serve',
		'store-health', 'store-token', 'store-rotate-kek'] {
		r := run_bin(g.data, [verb], '')
		if r.rc != 2 || !r.err.contains('not available in the data profile') {
			g.divergs << Diverge{
				suite: '<profile>'
				cid:   verb
				argv:  verb
				what:  'expected rc=2 profile refusal, got rc=${r.rc}'
			}
		}
	}

	if g.divergs.len > 0 {
		eprintln('extraction_gate_cli: ${g.divergs.len} DIVERGENCES over ${n_cases} cases / ${g.n_inv} invocation pairs:')
		cap_n := if g.divergs.len > 50 { 50 } else { g.divergs.len }
		for d in g.divergs[..cap_n] {
			eprintln('  ${d.suite}#${d.cid} :: cx ${d.argv} → ${d.what}')
		}
		exit(1)
	}
	if min_cases > 0 && n_cases < min_cases {
		eprintln('extraction_gate_cli: FATAL — case-count floor violated: ${n_cases} Ring-0 cases < required ${min_cases} (audit F-15 vacuous-pass defense)')
		exit(1)
	}
	println('extraction_gate_cli: OK — ${n_cases} Ring-0 cases (floor ${min_cases}), ${g.n_inv} invocation pairs byte-identical (stdout+stderr+rc) + ${17} profile refusals verified')
}
