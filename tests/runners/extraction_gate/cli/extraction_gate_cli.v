module main

import os
import crypto.sha256
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
	// VERDICT TRANSCRIPT (RULED: VC-29). The ABI lane has always been provable
	// byte-for-byte — its two transcripts are `cmp`d and the hash recorded.
	// THIS lane, the expensive one (10,579 invocation pairs, 91% of the
	// extraction gate's wall clock), reported only counts and an exit code. So
	// a refactor of it could not be shown verdict-identical: dropping a
	// comparison, reordering one, or comparing less would all still print OK
	// with the same count. That is not an acceptable basis for changing the
	// lane that certifies `libcx-core == libcx`.
	//
	// One line per invocation pair, in encounter order: case identity, argv,
	// the agreed rc, and content hashes of both streams. The digest of the
	// whole thing prints in the OK line on EVERY run, so a change shows up in
	// the gate log with nobody opting in.
	tx []TxLine
	// PROCESS SHARDING (RULED: VC-32). Threads are unavailable here: a bounded
	// worker pool deadlocked vgc's stop-the-world, because a thread parked in a
	// blocking read never reaches a safepoint (#973). Separate PROCESSES have
	// separate heaps and no shared collector, so the same parallelism is
	// available without that hazard.
	//
	// Every shard walks the corpus identically and advances `widx` on every
	// comparison — including ones it will not run — so a work item's global
	// index is the same in all shards and the parent can restore exact serial
	// order. `active` is what gates execution; a shard owns a whole CASE, never
	// part of one, so the fixture files a case writes are written by exactly one
	// shard.
	widx   int
	active bool = true
}

// tx_line records one comparison. Scratch paths are stripped: they embed
// os.temp_dir(), which would make the digest host-specific and useless for
// comparing a before/after or one machine against another.
fn (mut g Gate) tx_line(idx int, args []string, a RunResult, b RunResult) {
	argv := args.join(' ').replace(g.tmp + '/', '').replace(g.tmp, '')
	agree := if a.rc == b.rc && a.out == b.out && a.err == b.err { '=' } else { 'DIVERGE' }
	// The index is carried ALONGSIDE the body, never inside it. The transcript
	// FILE gets `idx<TAB>body` so the parent can restore serial order; the
	// DIGEST is taken over bodies alone, in both modes, so a sharded digest and
	// a serial one are the same number for the same verdict. (Folding the index
	// into the body made the two modes disagree with each other and with the
	// recorded baseline — caught by the digest doing its job.)
	g.tx << TxLine{
		idx:  idx
		body: '${g.suite}#${g.cid}\t${argv}\t${a.rc}\t${sha256.hexhash(a.out)}\t${sha256.hexhash(a.err)}\t${agree}'
	}
}

struct RunResult {
	rc  int
	out string
	err string
}

fn run_bin(bin string, args []string, stdin_data string, wd string) RunResult {
	mut pr := os.new_process(bin)
	pr.set_args(args)
	// Spawn in the scratch dir, never the checkout: a candidate binary that
	// MISBEHAVES can execute a side-effectful verb for real — measured
	// 2026-08-23 red-proofing against a stale three-releases-old monolith, whose bare
	// `lock` refusal probe RAN and wrote ./cx.lock into the repo root
	// (failing release-verify's tree-clean row a run later).
	// MUST be the caller's own scratch dir, not a fixed path. Fixture files are
	// written there and passed as RELATIVE names, so a wrong cwd silently
	// resolves them somewhere else. Measured while building the sharded mode: a
	// hardcoded root here, with shards writing into .../shard-N, made 271
	// comparisons read a STALE doc.cx left by an earlier run — both binaries
	// agreed on the leftover, so the gate reported OK while comparing the wrong
	// file. A green gate testing nothing.
	pr.set_work_folder(wd)
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
	// Advance the global index in EVERY shard, then execute only if this shard
	// owns the case. Skipping the increment would desynchronise the shards'
	// indices and the merge would silently reorder the transcript.
	idx := g.widx
	g.widx++
	if !g.active {
		return
	}
	mut a := run_bin(g.mono, args, stdin_data, g.tmp)
	mut b := run_bin(g.data, args, stdin_data, g.tmp)
	g.n_inv++
	g.tx_line(idx, args, a, b)
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
	a2 := run_bin(g.mono, args, stdin_data, g.tmp)
	b2 := run_bin(g.data, args, stdin_data, g.tmp)
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

// tmpfile writes into this shard's scratch dir and returns the BARE NAME, not
// the absolute path. That is deliberate and load-bearing: run_bin sets the
// child's working folder to the same scratch dir, so a relative name resolves
// identically, and no absolute path enters the child's argv.
//
// Why it matters: several `validate` diagnostics ECHO the file path they were
// given. With absolute paths, a shard's output embedded `…/shard-3/doc.cx`
// while the serial run embedded `…/doc.cx` — same verdict, different bytes, so
// the verdict digest moved for a reason that had nothing to do with the
// verdict. Measured: 6 of 10,579 lines differed, stdout hash only, every one a
// `validate` case, and both binaries agreed within each mode. Relative names
// make the digest path-independent, hence comparable across shard counts and
// across machines.
//
// Only WRITES for a case this shard owns; an inactive case still needs the name
// so argv (and therefore the global index walk) stays identical across shards,
// but writing it would have every shard racing on the same four filenames.
fn (mut g Gate) tmpfile(name string, content string) string {
	if g.active {
		path := os.join_path(g.tmp, name)
		os.write_file(path, content) or { panic('cannot write ${path}: ${err}') }
	}
	return name
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

struct TxLine {
	idx  int
	body string
}

// run_sharded is the PARENT (RULED: VC-32). It spawns K copies of itself, each
// owning every Kth case, then merges their transcript slices back into serial
// order and takes the digest — which must equal the serial baseline, or the
// parallelism has changed the verdict and is wrong.
//
// The parent is deliberately SINGLE-THREADED and does NOT redirect the
// children's stdio. Both matter: reading K pipes would need K readers, and a
// thread blocked in a read while another allocates is exactly the vgc STW
// deadlock (#973) that killed the worker-pool attempt. Inheriting stdio also
// means a child's divergence report reaches the operator directly.
fn run_sharded(mono string, data string, corpus string, min_cases int, jobs int, tx_path string) {
	self := os.executable()
	root := os.join_path(os.temp_dir(), 'cx_extraction_gate_cli')
	os.mkdir_all(root) or { panic('cannot mkdir ${root}: ${err}') }
	mut parts := []string{}
	mut procs := []&os.Process{}
	for i in 0 .. jobs {
		part := os.join_path(root, 'shard-${i}.tx')
		os.rm(part) or {}
		parts << part
		mut p := os.new_process(self)
		p.set_args([mono, data, corpus, '--min-cases=${min_cases}', '--shard=${i}/${jobs}',
			'--transcript=${part}'])
		p.run()
		procs << p
	}
	mut failed := 0
	for i, mut p in procs {
		p.wait()
		if p.code != 0 {
			eprintln('extraction_gate_cli: shard ${i}/${jobs} exited ${p.code}')
			failed++
		}
	}
	if failed > 0 {
		eprintln('extraction_gate_cli: ${failed} of ${jobs} shard(s) FAILED — verdict is red (see the shard output above)')
		exit(1)
	}
	// Merge by global index. A missing or duplicated index means a shard
	// silently skipped or repeated work, which would weaken the gate while
	// still looking green — so both are fatal rather than tolerated.
	mut lines := []TxLine{}
	for part in parts {
		body := os.read_file(part) or {
			eprintln('extraction_gate_cli: shard transcript missing: ${part}')
			exit(1)
		}
		for ln in body.split('\n') {
			if ln == '' {
				continue
			}
			tab := ln.index('\t') or {
				eprintln('extraction_gate_cli: malformed transcript line in ${part}')
				exit(1)
			}
			lines << TxLine{
				idx:  ln[..tab].int()
				body: ln[tab + 1..]
			}
		}
	}
	lines.sort(a.idx < b.idx)
	mut seen := map[int]bool{}
	for l in lines {
		if l.idx in seen {
			eprintln('extraction_gate_cli: FATAL — work index ${l.idx} appears in more than one shard')
			exit(1)
		}
		seen[l.idx] = true
	}
	mut merged := []string{cap: lines.len}
	for i, l in lines {
		if l.idx != i {
			eprintln('extraction_gate_cli: FATAL — merged transcript has a GAP: expected index ${i}, found ${l.idx}. A comparison was lost.')
			exit(1)
		}
		merged << l.body
	}
	tx_body := merged.join('\n') + '\n'
	if tx_path != '' {
		os.write_file(tx_path, tx_body) or {
			eprintln('extraction_gate_cli: cannot write transcript ${tx_path}: ${err}')
			exit(1)
		}
	}
	println('extraction_gate_cli: OK — ${jobs} shards, ${merged.len} invocation pairs byte-identical (stdout+stderr+rc); verdict-digest ${sha256.hexhash(tx_body)}')
}

fn main() {
	mut positional := []string{}
	mut min_cases := 0
	mut tx_path := ''
	mut shard_i := 0
	mut shard_k := 1
	mut jobs := 0
	for a in os.args[1..] {
		if a.starts_with('--min-cases=') {
			min_cases = a.all_after('=').int()
		} else if a.starts_with('--transcript=') {
			tx_path = a.all_after('=')
		} else if a.starts_with('--shard=') {
			spec := a.all_after('=').split('/')
			if spec.len != 2 {
				eprintln('extraction_gate_cli: --shard expects I/K')
				exit(2)
			}
			shard_i = spec[0].int()
			shard_k = spec[1].int()
			if shard_k < 1 || shard_i < 0 || shard_i >= shard_k {
				eprintln('extraction_gate_cli: bad --shard=${a.all_after('=')}')
				exit(2)
			}
		} else if a.starts_with('--jobs=') {
			jobs = a.all_after('=').int()
		} else if a.starts_with('--') {
			eprintln('extraction_gate_cli: unknown flag ${a}')
			exit(2)
		} else {
			positional << a
		}
	}
	if positional.len < 2 {
		eprintln('usage: extraction_gate_cli <monolith cx> <data-profile cx> [corpus dir] [--min-cases=N] [--transcript=PATH]')
		exit(2)
	}
	corpus := if positional.len > 2 { positional[2] } else { 'conformance' }
	if jobs > 1 {
		run_sharded(positional[0], positional[1], corpus, min_cases, jobs, tx_path)
		return
	}
	mut g := Gate{
		mono: positional[0]
		data: positional[1]
		// Per-shard scratch root. The transcript strips this prefix, so the
		// recorded argv is `doc.cx` either way and a sharded digest stays
		// comparable to the serial baseline.
		tmp:  if shard_k > 1 {
			os.join_path(os.temp_dir(), 'cx_extraction_gate_cli', 'shard-${shard_i}')
		} else {
			os.join_path(os.temp_dir(), 'cx_extraction_gate_cli')
		}
	}
	// Start from an EMPTY scratch dir. Fixture files are passed as relative
	// names, so any leftover from a previous run is readable by a later one —
	// and a stale-but-valid `doc.cx` is the worst kind of leftover, because both
	// binaries read it, agree, and the gate reports OK over a file no fixture
	// wrote (measured: 271 comparisons, all of them cases that exist to prove
	// malformed input is REJECTED). Correct cwd fixes the cause; wiping the dir
	// removes the class.
	os.rmdir_all(g.tmp) or {}
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
			// A shard owns whole cases, so a case's fixture files are written
			// by exactly one shard while every shard still walks the same
			// index sequence.
			g.active = n_cases % shard_k == shard_i
			g.run_case(c)
			n_cases++
		}
	}
	// Profile-refusal shape: every monolith-only verb word must refuse (rc 2,
	// refusal text) on the data binary — never fall through to the FILE
	// reading (#426). Asserted against the data binary alone; the monolith
	// legitimately dispatches these.
	// A shard skips these: the parent runs them once (they are 18 spawns, and
	// running them K times would report the same verdict K times).
	verbs := if shard_k > 1 {
		[]string{}
	} else {
		['fmt', 'lint', 'eval', 'select', 'diagram', 'code-diagram', 'code-tree',
			'table', 'scaffold', 'demo', 'lock', 'lsp', 'store-serve', 'fabric-serve',
			'store-health', 'store-rotate-kek', 'store-mint-principal']
	}
	for verb in verbs {
		r := run_bin(g.data, [verb], '', g.tmp)
		if r.rc != 2 || !r.err.contains('not available in the data profile') {
			g.divergs << Diverge{
				suite: '<profile>'
				cid:   verb
				argv:  verb
				what:  'expected rc=2 profile refusal, got rc=${r.rc}'
			}
		}
	}
	// RULED: CO-6 — a RETIRED verb word (store-token) answers with its
	// retirement in EVERY profile: rc 2 and the word 'retired', never the
	// profile refusal (which implies availability elsewhere) and never the
	// file-argument fall-through. Probed on the data binary here; the
	// monolith side is pinned by cli_umbrella_test.v's #970/CO-6 section.
	if shard_k <= 1 {
		r := run_bin(g.data, ['store-token'], '', g.tmp)
		if r.rc != 2 || !r.err.contains('retired') {
			g.divergs << Diverge{
				suite: '<profile>'
				cid:   'store-token'
				argv:  'store-token'
				what:  'expected rc=2 retirement notice, got rc=${r.rc}'
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
	mut bodies := []string{cap: g.tx.len}
	mut indexed := []string{cap: g.tx.len}
	for l in g.tx {
		bodies << l.body
		indexed << '${l.idx}\t${l.body}'
	}
	tx_body := bodies.join('\n') + '\n'
	if tx_path != '' {
		os.write_file(tx_path, indexed.join('\n') + '\n') or {
			eprintln('extraction_gate_cli: cannot write transcript ${tx_path}: ${err}')
			exit(1)
		}
		eprintln('extraction_gate_cli: transcript written to ${tx_path} (${g.tx.len} lines)')
	}
	if shard_k > 1 {
		// A shard says nothing on success. It ran a SLICE, so its own counts and
		// digest describe part of the verdict — printing them would put nine
		// "OK … verdict-digest X" lines in the gate log with only one of them
		// authoritative, which is how the wrong number gets read. Divergences
		// still go to stderr, and a nonzero exit still reds the parent.
		return
	}
	println('extraction_gate_cli: OK — ${n_cases} Ring-0 cases (floor ${min_cases}), ${g.n_inv} invocation pairs byte-identical (stdout+stderr+rc) + ${17} profile refusals verified; verdict-digest ${sha256.hexhash(tx_body)}')
}
