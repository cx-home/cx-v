module main

// address_baseline — the stream-2 C9 byte-identity gate (planar_algebra.md
// §"Identity-epoch membership"; ledger partition_I5_stream2_planar.md W2/W7).
//
// The L100 ONE-walk retirement re-implements identity-bearing traversals,
// including the Tier-2 emitter's. Output fixtures pin OUTPUTS, not addresses
// (W-22 is the standing proof that an emitter re-implementation can move
// every hash while staying green), so this runner is the address-side
// guard: it computes the TIER-2 hash of EVERY [?def] reachable in the
// conformance corpus (every suite's in-code + in-cx program text) and
// compares against a recorded baseline. Tier-1 (canonical-byte) identity
// is NOT computed here — the extraction gate pins it strictly stronger
// (full output/canonical bytes over every Ring-0 case, ABI + CLI lanes),
// which is the evidence the exit clause's Tier-1 half rides on (W7 audit
// truing: this comment previously claimed a Tier-1 lane this runner
// never had).
//
// Modes:
//   --capture   write the baseline manifest (BEFORE any walker retires)
//   (default)   recompute and DIFF against the manifest; any moved or
//               missing address fails, LOUD. No re-bless is available to
//               stream 2 — a moved hash is a defect, never a blessing.
//
// The manifest is deterministic (sorted by def key), so a re-capture on an
// unchanged tree is a no-op diff.

import cx
import code
import fixtures
import os

const manifest_path = 'vcx/tests/runners/address_baseline/tier2_addresses.txt'

// collect_defs returns sorted "suite::case::defname\t<tier2-hash>" lines over
// the whole corpus. A program that fails to yield Tier-2 hashes (no defs, or
// a parse the tier2 pass rejects) contributes nothing — the baseline records
// only real def addresses, and a def that STOPS being hashable is caught as a
// missing key at check time.
fn collect_defs() []string {
	mut lines := []string{}
	conf_dir := os.real_path(os.join_path(os.dir(@FILE), '..', '..', '..', '..', 'conformance'))
	mut suites := []string{}
	for f in (os.ls(conf_dir) or { [] }) {
		if f.ends_with('.cxd') {
			suites << os.join_path(conf_dir, f)
		}
	}
	for sub in ['stdlib'] {
		d := os.join_path(conf_dir, sub)
		for f in (os.ls(d) or { [] }) {
			if f.ends_with('.cxd') {
				suites << os.join_path(d, f)
			}
		}
	}
	suites.sort()
	for suite in suites {
		sname := os.file_name(suite).all_before_last('.cxd')
		cases := fixtures.load_fixtures(suite)
		for c in cases {
			for key in ['in_code', 'in_cx'] {
				src := c.sections[key] or { continue }
				if !src.contains('[?def') {
					continue
				}
				hashes := code.cx_program_tier2_hashes(src) or { continue }
				for defname, h in hashes {
					lines << '${sname}::${c.name}::${key}::${defname}\t${h}'
				}
			}
		}
	}
	lines.sort()
	return lines
}

fn main() {
	code.caps_set_all()
	capture := '--capture' in os.args
	lines := collect_defs()
	if capture {
		os.write_file(manifest_path, lines.join('\n') + '\n') or {
			eprintln('address-baseline: cannot write ${manifest_path}: ${err}')
			exit(1)
		}
		println('address-baseline: captured ${lines.len} Tier-2 def addresses → ${manifest_path}')
		return
	}
	recorded := os.read_file(manifest_path) or {
		eprintln('address-baseline: no baseline at ${manifest_path} — run with --capture first (W2)')
		exit(1)
	}
	mut want := map[string]string{}
	for ln in recorded.split_into_lines() {
		if ln.trim_space() == '' {
			continue
		}
		k := ln.all_before('\t')
		v := ln.all_after('\t')
		want[k] = v
	}
	mut got := map[string]string{}
	for ln in lines {
		got[ln.all_before('\t')] = ln.all_after('\t')
	}
	mut moved := []string{}
	mut missing := []string{}
	for k, wv in want {
		gv := got[k] or {
			missing << k
			continue
		}
		if gv != wv {
			moved << '${k}: ${wv} → ${gv}'
		}
	}
	mut added := []string{}
	for k, _ in got {
		if k !in want {
			added << k
		}
	}
	if moved.len > 0 || missing.len > 0 {
		eprintln('ADDRESS-BASELINE FAILED (stream-2 C9 — no re-bless available):')
		for m in moved {
			eprintln('  MOVED   ${m}')
		}
		for m in missing {
			eprintln('  MISSING ${m}')
		}
		eprintln('A moved or vanished Tier-2 address is a DEFECT (planar_algebra.md §C9).')
		exit(1)
	}
	// Added keys are fine (new corpus defs); report so a capture-refresh is
	// a deliberate, reviewed act, never silent drift.
	extra := if added.len > 0 { ' (+${added.len} new def(s) — re-capture to fold them in)' } else { '' }
	println('address-baseline: ${want.len} Tier-2 def addresses byte-identical to baseline${extra}')
}
