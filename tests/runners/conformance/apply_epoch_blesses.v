module main

// apply_epoch_blesses — the offline rewriter for the I1 epoch re-bless
// (CX_BLESS=epoch records emitted by conformance_run.v's ebless()).
// Section-aware twin of scripts/apply_blesses.cx: each record names a case
// id + a fixture SECTION (out-hash / out-cx / out-canonical / …) and the
// adopted bytes; this program rewrites that section's `[# … #]` body inside
// the case's span, in place. Purely mechanical — it never invents output,
// only adopts what the runner produced; the audit is the git diff reviewed
// against the ledger's red-class table.
//
// Usage: v run apply_epoch_blesses.v [/tmp/cx_epoch_blesses.txt] [CONF_DIR]

import os

struct Rec {
	id      string
	section string
	body    string
}

fn parse_records(text string) []Rec {
	mut recs := []Rec{}
	mut rest := text
	for {
		start := rest.index('<<<EBLESS ') or { break }
		hdr_end := rest.index_after('>>>', start) or { break }
		hdr := rest[start + 10..hdr_end]
		endm := rest.index_after('<<<ENDEBLESS>>>', hdr_end) or { break }
		body := rest[hdr_end + 4..endm].trim_right('\n')
		mut id := ''
		mut section := ''
		for part in hdr.split(' ') {
			if part.starts_with('id=') {
				id = part[3..]
			} else if part.starts_with('section=') {
				section = part[8..]
			}
		}
		if id != '' && section != '' {
			recs << Rec{
				id:      id
				section: section
				body:    body
			}
		}
		rest = rest[endm + 15..]
	}
	return recs
}

// apply_one rewrites `[<section> [# … #]]` inside the `[case id=<id> …]`
// span of `src`. Returns none when the case or section is not found.
fn apply_one(src string, r Rec) ?string {
	opener := src.index('[case id=${r.id} ') or {
		src.index('[case id=${r.id}\n') or { return none }
	}
	// The span ends at the next case opener (or EOF).
	mut span_end := src.len
	if nxt := src.index_after('[case id=', opener + 8) {
		span_end = nxt
	}
	span := src[opener..span_end]
	sec_open := span.index('[${r.section} [#') or { return none }
	body_start := sec_open + r.section.len + 4
	body_end := span.index_after('#]]', body_start) or { return none }
	new_span := span[..body_start] + '\n' + r.body + '\n' + span[body_end..]
	return src[..opener] + new_span + src[span_end..]
}

fn main() {
	rec_path := if os.args.len > 1 { os.args[1] } else { '/tmp/cx_epoch_blesses.txt' }
	conf_dir := if os.args.len > 2 { os.args[2] } else { '../../../conformance' }
	text := os.read_file(rec_path) or {
		eprintln('no records at ${rec_path}')
		exit(1)
	}
	recs := parse_records(text)
	mut files := []string{}
	for d in [conf_dir, os.join_path(conf_dir, 'stdlib')] {
		entries := os.ls(d) or { continue }
		for e in entries {
			if e.ends_with('.cxd') {
				files << os.join_path(d, e)
			}
		}
	}
	mut applied := 0
	mut missed := []string{}
	for r in recs {
		mut done := false
		for f in files {
			src := os.read_file(f) or { continue }
			if !src.contains('[case id=${r.id}') {
				continue
			}
			if out := apply_one(src, r) {
				os.write_file(f, out) or {
					eprintln('write failed: ${f}')
					exit(1)
				}
				applied++
				done = true
			}
			break
		}
		if !done {
			missed << '${r.id}/${r.section}'
		}
	}
	println('applied ${applied}/${recs.len} epoch-bless records')
	if missed.len > 0 {
		println('${missed.len} NOT applied:')
		for m in missed {
			println('  ${m}')
		}
	}
}
