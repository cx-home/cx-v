module main

import os
import dl

// ABI GC-liveness gate (remediation R3.8 discovery, 2026-08-07).
//
// Pins the defect class where a libcx-shaped SHARED artifact runs with its
// collector disabled: V only emitted `vgc_init()` (which sets
// `gc_enabled=1`) in generated C main() paths, so a dlopen'd/linked libcx
// built with `-gc e` NEVER collected — unbounded heap growth in every
// embedder, plus a pathological empty-pool span scan that made large ABI
// parses ~75x slower than the same code in the cx binary. The fix emits
// `vgc_init()` in the shared library's `_vinit_caller` load constructor
// (and the no-main export path), mirroring the Boehm init that was already
// there.
//
// Mechanics: the parent re-execs ITSELF (--child) with VGC_GCTRACE=1 so the
// artifact's vgc pacer trace goes to a captured stderr. The child dlopens
// ONE artifact and churns well past the default pacer goal (~21 MB) through
// cx_canonical. If the artifact carries vgc (detected via `nm` for the
// local vgc symbols — dev-shape artifacts are unstripped), at least one
// `[gc N]` trace line MUST appear; none means the collector is disabled in
// exactly the shipped-defect way. Non-vgc artifacts (CX_GC='-gc boehm'
// override) skip loudly — this lane pins the vgc wiring, not Boehm's.
//
// Usage: abi_gc_gate <libcx path>          (parent / gate mode)
//        abi_gc_gate --child <libcx path>  (churn worker, internal)

type FnInit = fn () int

type FnFree = fn (&char)

type Fn1 = fn (&char, &&char) &char

const churn_iterations = 40

fn child(lib_path string) {
	h := dl.open_opt(lib_path, dl.rtld_now) or { panic('cannot dlopen ${lib_path}: ${err}') }
	init := unsafe { FnInit(dl.sym_opt(h, 'cx_init') or { panic('missing cx_init') }) }
	init()
	free_fn := unsafe { FnFree(dl.sym_opt(h, 'cx_free') or { panic('missing cx_free') }) }
	canon := unsafe { Fn1(dl.sym_opt(h, 'cx_canonical') or { panic('missing cx_canonical') }) }
	// ~200 KB document; the parse tree churns a few MB per iteration, so
	// churn_iterations crosses the default pacer goal many times over.
	mut cells := []string{cap: 50002}
	cells << '[d'
	for i in 0 .. 50000 {
		cells << i.str()
	}
	cells << ']'
	doc := cells.join(' ')
	for _ in 0 .. churn_iterations {
		mut e := &char(unsafe { nil })
		res := canon(doc.str, &e)
		if isnil(res) {
			msg := if isnil(e) { '' } else { unsafe { cstring_to_vstring(e) } }
			panic('cx_canonical failed in churn loop: ${msg}')
		}
		free_fn(res)
	}
	println('child done: ${churn_iterations} iterations over ${doc.len}-byte doc')
}

fn artifact_carries_vgc(lib_path string) bool {
	res := os.execute('nm ${os.quoted_path(lib_path)}')
	if res.exit_code != 0 {
		eprintln('abi_gc_gate: nm failed on ${lib_path} (rc=${res.exit_code}) — cannot type the artifact')
		exit(2)
	}
	return res.output.contains('vgc_gc_start')
}

fn main() {
	if os.args.len >= 3 && os.args[1] == '--child' {
		child(os.args[2])
		return
	}
	if os.args.len < 2 {
		eprintln('usage: abi_gc_gate <libcx path>')
		exit(2)
	}
	lib_path := os.args[1]
	if !artifact_carries_vgc(lib_path) {
		println('abi-gc-gate SKIP — ${lib_path} does not carry vgc (nm: no vgc_gc_start); this lane pins the vgc shared-artifact wiring only')
		return
	}
	self := os.executable()
	mut pr := os.new_process(self)
	pr.set_args(['--child', lib_path])
	pr.set_environment({
		'VGC_GCTRACE': '1'
	})
	pr.set_redirect_stdio()
	pr.run()
	child_out := pr.stdout_slurp()
	child_err := pr.stderr_slurp()
	pr.wait()
	if pr.code != 0 {
		eprintln('abi-gc-gate FAILED — churn child exited rc=${pr.code}')
		eprintln(child_err)
		exit(1)
	}
	if !child_err.contains('[gc ') {
		eprintln('abi-gc-gate FAILED — ${lib_path}: collector NEVER ran in the dlopen\'d artifact (no [gc N] pacer trace across ${churn_iterations} churn iterations well past the pacer goal). This is the disabled-collector shared-artifact defect: unbounded embedder heap growth.')
		eprintln('child stdout: ${child_out.trim_space()}')
		exit(1)
	}
	n_cycles := child_err.count('[gc ')
	println('abi-gc-gate OK — ${lib_path}: collector live in the dlopen\'d artifact (${n_cycles} gc cycles during churn)')
}
