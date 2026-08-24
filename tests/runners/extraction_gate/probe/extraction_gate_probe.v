module main

import os
import dl
import fixtures
import crypto.sha256
import strings

// I2 extraction-gate probe — the ABI half of the Ring-0 byte-for-byte gate
// (partition spec §7; phase ledger ledger/partition_I2_extraction.md).
//
// The probe dlopens ONE libcx-shaped artifact (monolith `libcx` or extracted
// `libcx-core`), feeds every Ring-0-tagged conformance case input through a
// fixed battery of C-ABI calls, and writes a deterministic transcript of
// every result — outputs, canonical bytes, hashes, AND error texts — to
// stdout. The make target runs it twice (once per artifact) and byte-compares
// the two transcripts: identity of transcripts IS the exit-gate assertion, so
// the probe never needs to know what a case *expects* — the monolith is the
// oracle.
//
// Ring selection: per-case `ring=` overrides the suite header's (the corpus
// audit §2 Q2 resolution order); only effective-ring-0 cases run. The
// `code.cxd` eval lane (eval-ring=1) is excluded by construction — the probe
// has no evaluator to call; its 991 in-cx documents ride the full battery as
// inert trees (partition spec §2 homoiconicity).
//
// One process = one artifact: the two GC-carrying dylibs are never loaded
// into the same process (transcript comparison happens in `cmp`, outside).
//
// Usage: extraction_gate_probe <libcx path> [corpus dir]   (default corpus/)

// ── C ABI shapes (spec/abi.md; vcx/cx/cabi.v) ───────────────────────────────
type FnInit = fn () int

type FnFree = fn (&char)

type Fn1 = fn (&char, &&char) &char // (input, err) → text or framed

type Fn2 = fn (&char, &char, &&char) &char // (a, b, err)

type Fn3 = fn (&char, &char, &char, &&char) &char // (a, b, c, err)

type FnVal2 = fn (&char, &char, &&char, &&char) &char // validate_apply_defaults

type FnWOpen = fn (&char, &&char) voidptr

type FnWClose = fn (voidptr, &&char) &char

type FnWDiscard = fn (voidptr)

type FnW0 = fn (voidptr, &&char) &char

type FnW1 = fn (voidptr, &char, &&char) &char

type FnW2 = fn (voidptr, &char, &char, &&char) &char

type FnWStartEl = fn (voidptr, &char, &char, &char, &char, &char, &&char) &char

type FnROpenFd = fn (int, &&char) voidptr // cx_table_reader_open_fd

type FnWOpenFd = fn (&char, int, &&char) voidptr // cx_table_writer_open_fd

struct Lib {
mut:
	h    voidptr
	free_fn FnFree
}

fn (l Lib) sym(name string) voidptr {
	p := dl.sym_opt(l.h, name) or { panic('missing symbol ${name} in artifact') }
	return p
}

fn (l Lib) f1(name string) Fn1 {
	return unsafe { Fn1(l.sym(name)) }
}

// ── transcript ───────────────────────────────────────────────────────────────

struct Probe {
mut:
	lib   Lib
	out   []string
	suite string
	cid   string
}

fn (mut p Probe) record(call string, status string, body string) {
	p.out << '»»» ${p.suite}#${p.cid}#${call}'
	p.out << '${status} ${body.len}'
	p.out << body
}

// call1 runs a (input, err)→text call and records it. Returns the raw result
// pointer (nil on error) for round-trip chaining; caller must NOT free — we
// free here after copying, so chained calls copy the V string first.
fn (mut p Probe) call1(call string, f Fn1, input string) ?string {
	mut errp := &char(unsafe { nil })
	res := f(input.str, &errp)
	if isnil(res) {
		msg := if isnil(errp) { '' } else { unsafe { cstring_to_vstring(errp) } }
		p.record(call, 'err', msg)
		if !isnil(errp) {
			p.lib.free_fn(errp)
		}
		return none
	}
	out := unsafe { cstring_to_vstring(res) }
	p.lib.free_fn(res)
	p.record(call, 'ok', out)
	return out
}

// call1_framed runs a (input, err)→framed-bytes call, records hex, and
// returns the framed buffer VERBATIM (frame included) for chaining into
// framed-input consumers (cx_from_data_bin, cx_data_bin_to_json, …).
fn (mut p Probe) call1_framed(call string, f Fn1, input string) ?[]u8 {
	mut errp := &char(unsafe { nil })
	res := f(input.str, &errp)
	if isnil(res) {
		msg := if isnil(errp) { '' } else { unsafe { cstring_to_vstring(errp) } }
		p.record(call, 'err', msg)
		if !isnil(errp) {
			p.lib.free_fn(errp)
		}
		return none
	}
	size := unsafe { *(&u32(res)) }
	payload := unsafe { &u8(res) }
	mut framed := []u8{len: int(size) + 4}
	unsafe { vmemcpy(framed.data, payload, int(size) + 4) }
	p.lib.free_fn(res)
	p.record(call, 'ok', framed[4..].hex())
	return framed
}

// call1_framed_digest is call1_framed for multi-megabyte outputs (the R3.8
// synth lanes): it records `sha256:<hex> len=<n>` over the unframed payload
// instead of the raw hex, and returns the framed buffer for chaining.
fn (mut p Probe) call1_framed_digest(call string, f Fn1, input string) ?[]u8 {
	mut errp := &char(unsafe { nil })
	res := f(input.str, &errp)
	if isnil(res) {
		msg := if isnil(errp) { '' } else { unsafe { cstring_to_vstring(errp) } }
		p.record(call, 'err', msg)
		if !isnil(errp) {
			p.lib.free_fn(errp)
		}
		return none
	}
	size := unsafe { *(&u32(res)) }
	payload := unsafe { &u8(res) }
	mut framed := []u8{len: int(size) + 4}
	unsafe { vmemcpy(framed.data, payload, int(size) + 4) }
	p.lib.free_fn(res)
	p.record(call, 'ok', digest_line(framed[4..]))
	return framed
}

// read_back_chunked opens a streaming table reader over a framed chunked
// buffer and records the col-spec, the per-group digest chain, and the
// group count — the ch-005 2^20-boundary structure lands in the transcript
// as (group_count, digest-of-group-digests) without raw megabytes.
fn (mut p Probe) read_back_chunked(prefix string, framed []u8) {
	r_open := unsafe { FnWOpen(p.lib.sym('cx_table_reader_open')) }
	mut e := &char(unsafe { nil })
	h := r_open(unsafe { tos_clone_framed(framed) }.str, &e)
	if isnil(h) {
		msg := if isnil(e) { '' } else { unsafe { cstring_to_vstring(e) } }
		p.record('${prefix}.open', 'err', msg)
		if !isnil(e) {
			p.lib.free_fn(e)
		}
		return
	}
	r_schema := unsafe { FnWClose(p.lib.sym('cx_table_reader_schema')) }
	mut se := &char(unsafe { nil })
	sres := r_schema(h, &se)
	if isnil(sres) {
		msg := if isnil(se) { '' } else { unsafe { cstring_to_vstring(se) } }
		p.record('${prefix}.schema', 'err', msg)
		if !isnil(se) {
			p.lib.free_fn(se)
		}
	} else {
		ssize := unsafe { *(&u32(sres)) }
		mut sframed := []u8{len: int(ssize) + 4}
		unsafe { vmemcpy(sframed.data, sres, int(ssize) + 4) }
		p.lib.free_fn(sres)
		p.record('${prefix}.schema', 'ok', sframed[4..].hex())
	}
	p.read_groups(prefix, h)
	r_close := unsafe { FnWDiscard(p.lib.sym('cx_table_reader_close')) }
	r_close(h)
}

// read_groups drains cx_table_reader_next on an open reader handle and
// records `groups=<n> digests=sha256:<hex>` (digest over the concatenated
// per-group payload digests — order-sensitive, size-compact).
fn (mut p Probe) read_groups(prefix string, h voidptr) {
	r_next := unsafe { FnWClose(p.lib.sym('cx_table_reader_next')) }
	mut n := 0
	mut chain := strings.new_builder(256)
	for {
		mut ne := &char(unsafe { nil })
		g := r_next(h, &ne)
		if isnil(g) {
			if !isnil(ne) {
				msg := unsafe { cstring_to_vstring(ne) }
				p.lib.free_fn(ne)
				p.record('${prefix}.groups', 'err', msg)
				return
			}
			break // EOF
		}
		gsize := unsafe { *(&u32(g)) }
		mut gframed := []u8{len: int(gsize) + 4}
		unsafe { vmemcpy(gframed.data, g, int(gsize) + 4) }
		p.lib.free_fn(g)
		chain.write_string(sha256.sum256(gframed[4..]).hex())
		n++
	}
	p.record('${prefix}.groups', 'ok', 'groups=${n} digests=sha256:${sha256.sum256(chain.str().bytes()).hex()}')
}

// run_fd_writer_lane covers cmp-005's fd-streaming write path through the
// ABI: synthesize one rows_per_group-row table, pull its col-spec and
// row-group payload back out through the in-memory reader, then emit that
// payload n_groups times through cx_table_writer_open_fd into a temp file,
// digest the file bytes, and read the file back through
// cx_table_reader_open_fd. The temp path never enters the transcript.
fn (mut p Probe) run_fd_writer_lane(schema_cx string, rows_per_group int, n_groups int) {
	table_cx := synth_table_text(schema_cx, rows_per_group) or {
		probe_fatal('${p.suite}#${p.cid}: fd lane synth: ${err}')
	}
	framed := p.call1_framed_digest('synth.fd.cx_to_data_bin_chunked', p.lib.f1('cx_to_data_bin_chunked'),
		table_cx) or { return }
	// col-spec + the single row-group payload via the in-memory reader
	r_open := unsafe { FnWOpen(p.lib.sym('cx_table_reader_open')) }
	mut e := &char(unsafe { nil })
	rh := r_open(unsafe { tos_clone_framed(framed) }.str, &e)
	if isnil(rh) {
		msg := if isnil(e) { '' } else { unsafe { cstring_to_vstring(e) } }
		p.record('synth.fd.reader_open', 'err', msg)
		if !isnil(e) {
			p.lib.free_fn(e)
		}
		return
	}
	r_close := unsafe { FnWDiscard(p.lib.sym('cx_table_reader_close')) }
	r_schema := unsafe { FnWClose(p.lib.sym('cx_table_reader_schema')) }
	mut se := &char(unsafe { nil })
	sres := r_schema(rh, &se)
	if isnil(sres) {
		msg := if isnil(se) { '' } else { unsafe { cstring_to_vstring(se) } }
		p.record('synth.fd.schema', 'err', msg)
		if !isnil(se) {
			p.lib.free_fn(se)
		}
		r_close(rh)
		return
	}
	ssize := unsafe { *(&u32(sres)) }
	mut col_spec := []u8{len: int(ssize) + 4}
	unsafe { vmemcpy(col_spec.data, sres, int(ssize) + 4) }
	p.lib.free_fn(sres)
	r_next := unsafe { FnWClose(p.lib.sym('cx_table_reader_next')) }
	mut ge := &char(unsafe { nil })
	g := r_next(rh, &ge)
	if isnil(g) {
		msg := if isnil(ge) { '' } else { unsafe { cstring_to_vstring(ge) } }
		p.record('synth.fd.first_group', 'err', msg)
		if !isnil(ge) {
			p.lib.free_fn(ge)
		}
		r_close(rh)
		return
	}
	gsize := unsafe { *(&u32(g)) }
	mut group := []u8{len: int(gsize) + 4}
	unsafe { vmemcpy(group.data, g, int(gsize) + 4) }
	p.lib.free_fn(g)
	r_close(rh)

	// fd write: n_groups copies of the payload, end-of-table on close
	path := os.join_path(os.temp_dir(), 'cx_egp_fd_${os.getpid()}.cxcol')
	mut fw := os.create(path) or {
		probe_fatal('${p.suite}#${p.cid}: fd lane cannot create temp file: ${err}')
	}
	w_open_fd := unsafe { FnWOpenFd(p.lib.sym('cx_table_writer_open_fd')) }
	mut we := &char(unsafe { nil })
	wh := w_open_fd(unsafe { tos_clone_framed(col_spec) }.str, fw.fd, &we)
	if isnil(wh) {
		msg := if isnil(we) { '' } else { unsafe { cstring_to_vstring(we) } }
		p.record('synth.fd.writer_open', 'err', msg)
		if !isnil(we) {
			p.lib.free_fn(we)
		}
		fw.close()
		os.rm(path) or {}
		return
	}
	w_emit := unsafe { FnW1(p.lib.sym('cx_table_writer_emit_row_group')) }
	w_close := unsafe { FnWDiscard(p.lib.sym('cx_table_writer_close')) }
	for i in 0 .. n_groups {
		// NULL-on-success ABI: success is res==nil with err unset
		mut ee := &char(unsafe { nil })
		res := w_emit(wh, unsafe { tos_clone_framed(group) }.str, &ee)
		if !isnil(res) {
			p.lib.free_fn(res)
		}
		if !isnil(ee) {
			msg := unsafe { cstring_to_vstring(ee) }
			p.lib.free_fn(ee)
			p.record('synth.fd.emit', 'err', 'group ${i}: ${msg}')
			w_close(wh)
			fw.close()
			os.rm(path) or {}
			return
		}
	}
	w_close(wh) // flushes the end-of-table marker to the fd
	fw.close()
	file_bytes := os.read_bytes(path) or {
		probe_fatal('${p.suite}#${p.cid}: fd lane cannot read back temp file: ${err}')
	}
	p.record('synth.fd.file', 'ok', digest_line(file_bytes))

	// fd read-back: group structure through cx_table_reader_open_fd
	mut fr := os.open(path) or {
		probe_fatal('${p.suite}#${p.cid}: fd lane cannot reopen temp file: ${err}')
	}
	r_open_fd := unsafe { FnROpenFd(p.lib.sym('cx_table_reader_open_fd')) }
	mut re := &char(unsafe { nil })
	rh2 := r_open_fd(fr.fd, &re)
	if isnil(rh2) {
		msg := if isnil(re) { '' } else { unsafe { cstring_to_vstring(re) } }
		p.record('synth.fd.reader_open_fd', 'err', msg)
		if !isnil(re) {
			p.lib.free_fn(re)
		}
	} else {
		p.read_groups('synth.fd.read_back', rh2)
		r_close(rh2)
	}
	fr.close()
	os.rm(path) or {}
}

// synth_table_text mirrors the conformance runner's synth_table_document
// row rule (HH3) as CX text: int/i64/i32 → row index; float/f64/f32 → row
// index; bool → i % 2 == 0; string → "r_<i>". The schema text's column
// list is taken verbatim from its `[table[...]]` header, so the generated
// document parses under the exact declared column types. Any other column
// type is a probe-capability gap → error (the caller hard-fails; F-15
// forbids silent skips).
fn synth_table_text(schema_cx string, n_rows int) !string {
	hdr_start := schema_cx.index('[table[') or {
		return error('schema lacks a [table[...]] header')
	}
	cols_start := hdr_start + '[table['.len
	cols_end := schema_cx.index_after(']]', cols_start) or {
		return error('unterminated [table[...]] header')
	}
	cols_src := schema_cx[cols_start..cols_end]
	root_start := schema_cx.index('[') or { return error('schema lacks a root element') }
	mut root_name := ''
	for i := root_start + 1; i < schema_cx.len; i++ {
		ch := schema_cx[i]
		if ch == ` ` || ch == `\t` || ch == `\n` || ch == `[` {
			break
		}
		root_name += ch.ascii_str()
	}
	if root_name == '' {
		return error('schema root element has no name')
	}
	mut col_types := []string{}
	for tok in cols_src.split_any(' \t\n,').filter(it.trim_space().len > 0) {
		t := tok.all_after('::')
		col_types << if t == tok { 'string' } else { t }
	}
	if col_types.len == 0 {
		return error('[table[...]] header declares no columns')
	}
	for t in col_types {
		if t !in ['int', 'i64', 'i32', 'float', 'f64', 'f32', 'bool', 'string'] {
			return error('synth lane does not support column type "${t}" — extend synth_table_text')
		}
	}
	mut sb := strings.new_builder(n_rows * (col_types.len * 8 + 2) + 64)
	sb.write_string('[${root_name} [table[${cols_src}]]\n')
	for i in 0 .. n_rows {
		for j, t in col_types {
			if j > 0 {
				sb.write_u8(` `)
			}
			match t {
				'int', 'i64', 'i32' { sb.write_string(i.str()) }
				'float', 'f64', 'f32' { sb.write_string('${i}.0') }
				'bool' { sb.write_string(if i % 2 == 0 { 'true' } else { 'false' }) }
				else { sb.write_string('r_${i}') }
			}
		}
		sb.write_u8(`\n`)
	}
	sb.write_string(']')
	return sb.str()
}

fn digest_line(payload []u8) string {
	return 'sha256:${sha256.sum256(payload).hex()} len=${payload.len}'
}

@[noreturn]
fn probe_fatal(msg string) {
	eprintln('extraction_gate_probe: FATAL — ${msg}')
	exit(1)
}

// ── battery ──────────────────────────────────────────────────────────────────

const text_battery_cx = ['cx_to_cx', 'cx_to_cx_compact', 'cx_canonical', 'cx_hash', 'cx_fmt',
	'cx_to_xml', 'cx_to_json', 'cx_to_yaml', 'cx_to_toml', 'cx_to_ast', 'cx_to_events',
	'cx_to_csv', 'cx_to_tsv', 'cx_to_psv']

const from_format_batteries = {
	'in_xml':  ['cx_xml_to_cx', 'cx_xml_to_xml', 'cx_xml_to_ast', 'cx_xml_to_json',
		'cx_xml_to_yaml', 'cx_xml_to_toml']
	'in_json': ['cx_json_to_cx', 'cx_json_to_xml', 'cx_json_to_ast', 'cx_json_to_json',
		'cx_json_to_yaml', 'cx_json_to_toml']
	'in_yaml': ['cx_yaml_to_cx', 'cx_yaml_to_xml', 'cx_yaml_to_ast', 'cx_yaml_to_json',
		'cx_yaml_to_yaml', 'cx_yaml_to_toml']
	'in_toml': ['cx_toml_to_cx', 'cx_toml_to_xml', 'cx_toml_to_ast', 'cx_toml_to_json',
		'cx_toml_to_yaml', 'cx_toml_to_toml']
}

fn (mut p Probe) run_case(c fixtures.FixtureCase) {
	if in_cx := c.sections['in_cx'] {
		for call in text_battery_cx {
			p.call1(call, p.lib.f1(call), in_cx)
		}
		mut errp := &char(unsafe { nil })
		lint := unsafe { Fn3(p.lib.sym('cx_lint')) }
		lres := lint(in_cx.str, c'json', c'', &errp)
		p.record_ptr('cx_lint', lres, errp)

		// binary lanes + decoder round-trips
		if ast_bin := p.call1_framed('cx_to_ast_bin', p.lib.f1('cx_to_ast_bin'), in_cx) {
			p.call1('cx_ast_bin_to_cx', p.lib.f1('cx_ast_bin_to_cx'), unsafe { tos_clone_framed(ast_bin) })
		}
		p.call1_framed('cx_to_events_bin', p.lib.f1('cx_to_events_bin'), in_cx)
		if data_bin := p.call1_framed('cx_to_data_bin', p.lib.f1('cx_to_data_bin'), in_cx) {
			p.call1('cx_from_data_bin', p.lib.f1('cx_from_data_bin'), unsafe { tos_clone_framed(data_bin) })
			p.call1('cx_data_bin_to_json', p.lib.f1('cx_data_bin_to_json'), unsafe { tos_clone_framed(data_bin) })
		}
		p.call1_framed('cx_to_data_bin_chunked', p.lib.f1('cx_to_data_bin_chunked'), in_cx)

		// schema lanes
		if schema := c.sections['schema_cxs'] {
			mut e1 := &char(unsafe { nil })
			validate := unsafe { Fn2(p.lib.sym('cx_validate')) }
			vres := validate(in_cx.str, schema.str, &e1)
			p.record_ptr('cx_validate', vres, e1)
			mut e2 := &char(unsafe { nil })
			mut modp := &char(unsafe { nil })
			vad := unsafe { FnVal2(p.lib.sym('cx_validate_apply_defaults')) }
			vres2 := vad(in_cx.str, schema.str, &modp, &e2)
			p.record_ptr('cx_validate_apply_defaults', vres2, e2)
			if !isnil(modp) {
				mod := unsafe { cstring_to_vstring(modp) }
				p.lib.free_fn(modp)
				p.record('cx_validate_apply_defaults.modified', 'ok', mod)
			}
		}
	}
	for key, battery in from_format_batteries {
		if input := c.sections[key] {
			for call in battery {
				p.call1(call, p.lib.f1(call), input)
			}
		}
	}
	if in_csv := c.sections['in_csv'] {
		p.call1('cx_from_csv', p.lib.f1('cx_from_csv'), in_csv)
		p.call1_framed('cx_csv_to_data_bin', p.lib.f1('cx_csv_to_data_bin'), in_csv)
	}
	if in_tsv := c.sections['in_tsv'] {
		p.call1('cx_from_tsv', p.lib.f1('cx_from_tsv'), in_tsv)
	}
	if in_psv := c.sections['in_psv'] {
		p.call1('cx_from_psv', p.lib.f1('cx_from_psv'), in_psv)
	}
	if hexs := c.sections['in_data_bin_hex'] {
		mut compact := ''
		for line in hexs.split_into_lines() {
			t := line.trim_space()
			if t.starts_with('#') {
				continue
			}
			compact += t.replace(' ', '').replace('\t', '')
		}
		if payload := decode_hex(compact) {
			framed := frame(payload)
			p.call1('cx_from_data_bin', p.lib.f1('cx_from_data_bin'), unsafe { tos_clone_framed(framed) })
			p.call1('cx_data_bin_to_json', p.lib.f1('cx_data_bin_to_json'), unsafe { tos_clone_framed(framed) })
		} else {
			p.record('in_data_bin_hex', 'err', 'probe: bad hex payload')
		}
	}
	if in_a := c.sections['in_a'] {
		if in_b := c.sections['in_b'] {
			diff := unsafe { Fn3(p.lib.sym('cx_diff')) }
			for f in ['unified', 'json', 'summary'] {
				mut e := &char(unsafe { nil })
				r := diff(in_a.str, in_b.str, f.str, &e)
				p.record_ptr('cx_diff.${f}', r, e)
			}
			mut e := &char(unsafe { nil })
			eqf := unsafe { Fn2(p.lib.sym('cx_eq')) }
			r := eqf(in_a.str, in_b.str, &e)
			p.record_ptr('cx_eq', r, e)
		}
	}
	if events := c.sections['events'] {
		if format := c.sections['format'] {
			p.run_events_writer(events, format.trim_space())
		}
	}

	// ── synthesized-table lanes (remediation R3.8, audit F-15) ──────────────
	// `synth-table-schema` + `synth-table-rows` declare a generated corpus
	// (HH3; same deterministic row rule as the conformance runner's
	// synth_table_document). The probe synthesizes the table as CX text,
	// routes it through the chunked encoder + streaming reader ABI, and
	// records DIGESTS (sha-256 of the payload bytes) rather than raw
	// multi-megabyte payloads — cross-artifact identity is what the gate
	// compares, so digest identity carries the full assertion without
	// inflating the transcript. Probe-capability gaps (unsupported column
	// type, non-canonical chunk_at) hard-fail the whole probe — a new synth
	// case shape must extend this lane, never silently skip it (F-15).
	if raw_rows := c.sections['synth_table_rows'] {
		schema_cx := (c.sections['synth_table_schema'] or {
			probe_fatal('${p.suite}#${p.cid}: synth-table-rows without synth-table-schema')
		}).trim_space()
		n_rows := raw_rows.trim_space().int()
		if n_rows <= 0 {
			probe_fatal('${p.suite}#${p.cid}: synth-table-rows must be > 0, got "${raw_rows.trim_space()}"')
		}
		chunk_at := (c.meta['chunk_at'] or { '0' }).int()
		if chunk_at != 0 && chunk_at != (1 << 20) && n_rows > chunk_at {
			// the C ABI's chunked encoder has no chunk-size parameter; a
			// non-canonical chunk_at that actually BINDS (more rows than the
			// declared chunk) cannot be honored through the ABI — refuse
			// loudly rather than compare the wrong grouping. Non-binding
			// chunk_at (fewer rows than one chunk) groups identically under
			// the canonical 2^20 size, so those cases proceed.
			probe_fatal('${p.suite}#${p.cid}: synth lane cannot honor binding chunk_at=${chunk_at} through the ABI (canonical 2^20 only)')
		}
		table_cx := synth_table_text(schema_cx, n_rows) or {
			probe_fatal('${p.suite}#${p.cid}: synth-table-schema: ${err}')
		}
		if framed := p.call1_framed_digest('synth.cx_to_data_bin_chunked', p.lib.f1('cx_to_data_bin_chunked'),
			table_cx)
		{
			p.read_back_chunked('synth.reader', framed)
		}
	}

	// cmp-005 fd-streaming lane: drive the fd writer + fd reader through the
	// ABI with the case-declared row-group shape. The bounded-memory RATIO
	// assertion itself is a runtime property owned by the conformance lane
	// (conformance_run.v HH4); here the fd write/read byte behavior is what
	// must be identical across artifacts.
	if raw_bm := c.sections['assert_streaming_write_bounded_memory'] {
		toks := raw_bm.split_any(' \t\r\n').filter(it.trim_space().len > 0)
		if toks.len != 4 {
			probe_fatal('${p.suite}#${p.cid}: assert-streaming-write-bounded-memory needs 4 tokens, got ${toks.len}')
		}
		rows_per_group := toks[0].int()
		n_groups := toks[1].int() + toks[2].int() // warmup + stress emits
		if rows_per_group <= 0 || n_groups <= 0 {
			probe_fatal('${p.suite}#${p.cid}: assert-streaming-write-bounded-memory: non-positive counts')
		}
		schema_cx := (c.sections['synth_table_schema'] or {
			probe_fatal('${p.suite}#${p.cid}: fd lane needs synth-table-schema')
		}).trim_space()
		p.run_fd_writer_lane(schema_cx, rows_per_group, n_groups)
	}

	// ── schema-pair content-hash lane (remediation R3.8, audit F-15;
	// sd-006) ────────────────────────────────────────────────────────────────
	// `schema-cxs-a` + `schema-cxs-b`: the schema content hash IS the Tier-1
	// canonical-text hash (data-bin.md §3.13.1 / I1 stream 1), so `cx_hash`
	// over each schema text exercises the exact identity computation. The
	// computed equality is recorded in-transcript; the semantic expectation
	// (equal) is asserted by the conformance lane's sd_assert_hash_equal.
	if schema_a := c.sections['schema_cxs_a'] {
		if schema_b := c.sections['schema_cxs_b'] {
			mut a_hash := ''
			mut b_hash := ''
			if v := p.call1('schema_pair.cx_hash_a', p.lib.f1('cx_hash'), schema_a) {
				a_hash = v
			}
			if v := p.call1('schema_pair.cx_hash_b', p.lib.f1('cx_hash'), schema_b) {
				b_hash = v
			}
			eq := if a_hash != '' && a_hash == b_hash { 'true' } else { 'false' }
			p.record('schema_pair.hash_eq', 'ok', eq)
		}
	}
}

// record_ptr records an ok/err result from a raw call and frees both sides.
fn (mut p Probe) record_ptr(call string, res &char, errp &char) {
	if isnil(res) {
		msg := if isnil(errp) { '' } else { unsafe { cstring_to_vstring(errp) } }
		p.record(call, 'err', msg)
		if !isnil(errp) {
			p.lib.free_fn(errp)
		}
		return
	}
	out := unsafe { cstring_to_vstring(res) }
	p.lib.free_fn(res)
	p.record(call, 'ok', out)
}

// ── streaming-write event interpreter (mirrors lang/python conformance.py) ──

fn dequote(s string) string {
	t := s.trim_space()
	if t.starts_with('"') && t.ends_with('"') && t.len >= 2 {
		return t[1..t.len - 1]
	}
	return t
}

fn (mut p Probe) run_events_writer(events string, format string) {
	w_open := unsafe { FnWOpen(p.lib.sym('cx_events_writer_open')) }
	mut e := &char(unsafe { nil })
	h := w_open(format.str, &e)
	if isnil(h) {
		msg := if isnil(e) { '' } else { unsafe { cstring_to_vstring(e) } }
		p.record('events_writer.open', 'err', msg)
		if !isnil(e) {
			p.lib.free_fn(e)
		}
		return
	}
	f0 := unsafe { FnW0(p.lib.sym('cx_events_writer_start_doc')) }
	f_end_doc := unsafe { FnW0(p.lib.sym('cx_events_writer_end_doc')) }
	f_end_table := unsafe { FnW0(p.lib.sym('cx_events_writer_end_table')) }
	f_start_el := unsafe { FnWStartEl(p.lib.sym('cx_events_writer_start_element')) }
	f_end_el := unsafe { FnW1(p.lib.sym('cx_events_writer_end_element')) }
	f_text := unsafe { FnW1(p.lib.sym('cx_events_writer_text')) }
	f_scalar := unsafe { FnW2(p.lib.sym('cx_events_writer_scalar')) }
	f_comment := unsafe { FnW1(p.lib.sym('cx_events_writer_comment')) }
	f_pi := unsafe { FnW2(p.lib.sym('cx_events_writer_pi')) }
	f_entity := unsafe { FnW1(p.lib.sym('cx_events_writer_entity_ref')) }
	f_raw := unsafe { FnW1(p.lib.sym('cx_events_writer_raw_text')) }
	f_alias := unsafe { FnW1(p.lib.sym('cx_events_writer_alias')) }
	f_start_table := unsafe { FnW1(p.lib.sym('cx_events_writer_start_table')) }
	f_row_group := unsafe { FnW1(p.lib.sym('cx_events_writer_row_group')) }
	f_discard := unsafe { FnWDiscard(p.lib.sym('cx_events_writer_close')) }

	mut failed := false
	for raw_line in events.split_into_lines() {
		line := raw_line.trim_space()
		if line == '' || line.starts_with('#') {
			continue
		}
		op := line.all_before(' ')
		rest := if line.contains(' ') { line.all_after(' ') } else { '' }
		mut res := &char(unsafe { nil })
		mut ep := &char(unsafe { nil })
		match op {
			'StartDoc' {
				res = f0(h, &ep)
			}
			'EndDoc' {
				res = f_end_doc(h, &ep)
			}
			'EndTable' {
				res = f_end_table(h, &ep)
			}
			'StartElement' {
				toks := rest.split(' ').filter(it != '')
				name := toks[0]
				mut anchor := ''
				mut data_type := ''
				mut merge := ''
				for t in toks[1..] {
					if t.starts_with('anchor=') {
						anchor = t[7..]
					} else if t.starts_with('data_type=') {
						data_type = t[10..]
					} else if t.starts_with('merge=') {
						merge = t[6..]
					}
				}
				res = f_start_el(h, name.str, anchor.str, data_type.str, merge.str, c'', &ep)
			}
			'EndElement' {
				res = f_end_el(h, rest.trim_space().str, &ep)
			}
			'Text' {
				res = f_text(h, dequote(rest).str, &ep)
			}
			'Scalar' {
				typ := rest.all_before(':').trim_space()
				val := rest.all_after(':')
				res = f_scalar(h, typ.str, val.str, &ep)
			}
			'Comment' {
				res = f_comment(h, dequote(rest).str, &ep)
			}
			'PI' {
				toks := rest.split_nth(' ', 2)
				target := toks[0]
				mut data := ''
				if toks.len > 1 && toks[1].trim_space().starts_with('data=') {
					data = dequote(toks[1].trim_space()[5..])
				}
				res = f_pi(h, target.str, data.str, &ep)
			}
			'EntityRef' {
				res = f_entity(h, rest.trim_space().str, &ep)
			}
			'RawText' {
				res = f_raw(h, dequote(rest).str, &ep)
			}
			'Alias' {
				res = f_alias(h, rest.trim_space().str, &ep)
			}
			'StartTable', 'RowGroup' {
				payload := decode_hex(rest.trim_space()) or {
					p.record('events_writer.${op}', 'err', 'probe: bad hex payload')
					failed = true
					break
				}
				framed := frame(payload)
				fw := if op == 'StartTable' { f_start_table } else { f_row_group }
				res = fw(h, unsafe { tos_clone_framed(framed) }.str, &ep)
			}
			else {
				p.record('events_writer.${op}', 'err', 'probe: unknown event op')
				failed = true
				break
			}
		}
		if isnil(res) {
			msg := if isnil(ep) { '' } else { unsafe { cstring_to_vstring(ep) } }
			p.record('events_writer.${op}', 'err', msg)
			if !isnil(ep) {
				p.lib.free_fn(ep)
			}
			failed = true
			break
		} else {
			p.lib.free_fn(res)
		}
	}
	if failed {
		f_discard(h)
		return
	}
	get := unsafe { FnWClose(p.lib.sym('cx_events_writer_close_get_bytes')) }
	mut ge := &char(unsafe { nil })
	res := get(h, &ge)
	if isnil(res) {
		msg := if isnil(ge) { '' } else { unsafe { cstring_to_vstring(ge) } }
		p.record('events_writer.close_get_bytes', 'err', msg)
		if !isnil(ge) {
			p.lib.free_fn(ge)
		}
		return
	}
	size := unsafe { *(&u32(res)) }
	mut framed := []u8{len: int(size) + 4}
	unsafe { vmemcpy(framed.data, res, int(size) + 4) }
	p.lib.free_fn(res)
	p.record('events_writer.close_get_bytes', 'ok', framed[4..].bytestr())
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn decode_hex(s string) ?[]u8 {
	if s.len % 2 != 0 {
		return none
	}
	mut out := []u8{cap: s.len / 2}
	for i := 0; i < s.len; i += 2 {
		hi := hex_val(s[i]) or { return none }
		lo := hex_val(s[i + 1]) or { return none }
		out << u8(hi << 4 | lo)
	}
	return out
}

fn hex_val(c u8) ?int {
	if c >= `0` && c <= `9` {
		return int(c - `0`)
	}
	if c >= `a` && c <= `f` {
		return int(c - `a`) + 10
	}
	if c >= `A` && c <= `F` {
		return int(c - `A`) + 10
	}
	return none
}

fn frame(payload []u8) []u8 {
	mut framed := []u8{len: 4 + payload.len}
	framed[0] = u8(payload.len & 0xff)
	framed[1] = u8((payload.len >> 8) & 0xff)
	framed[2] = u8((payload.len >> 16) & 0xff)
	framed[3] = u8((payload.len >> 24) & 0xff)
	unsafe { vmemcpy(&u8(framed.data) + 4, payload.data, payload.len) }
	return framed
}

// tos_clone_framed views framed bytes as a V string so framed-input ABI
// calls (which take &char and read the u32 length themselves) can receive
// the buffer through the same Fn1 shape. The buffer may contain NULs —
// the callee never relies on NUL-termination for framed inputs.
@[unsafe]
fn tos_clone_framed(b []u8) string {
	return unsafe { tos(&u8(b.data), b.len) }
}

fn main() {
	mut positional := []string{}
	mut min_cases := 0
	for a in os.args[1..] {
		if a.starts_with('--min-cases=') {
			min_cases = a.all_after('=').int()
		} else if a.starts_with('--') {
			eprintln('extraction_gate_probe: unknown flag ${a}')
			exit(2)
		} else {
			positional << a
		}
	}
	if positional.len < 1 {
		eprintln('usage: extraction_gate_probe <libcx path> [corpus dir] [--min-cases=N]')
		exit(2)
	}
	lib_path := positional[0]
	corpus := if positional.len > 1 { positional[1] } else { 'conformance' }

	h := dl.open_opt(lib_path, dl.rtld_now) or { panic('cannot dlopen ${lib_path}: ${err}') }
	mut lib := Lib{
		h:    h
		free_fn: unsafe { FnFree(dl.sym_opt(h, 'cx_free') or { panic('missing cx_free') }) }
	}
	init := unsafe { FnInit(dl.sym_opt(h, 'cx_init') or { panic('missing cx_init') }) }
	init()

	mut files := os.ls(corpus) or { panic('cannot list ${corpus}: ${err}') }
	files.sort()
	mut p := Probe{
		lib: lib
	}
	mut n_cases := 0
	mut n_md_excluded := 0
	mut uncovered := []string{}
	for f in files {
		if !f.ends_with('.cxd') {
			continue
		}
		path := os.join_path(corpus, f)
		suite := fixtures.load_suite(path)
		if suite.ring == '' {
			// untagged suite = tagging-completeness failure upstream
			// (ring-tag-gate owns that); skip here.
			continue
		}
		for c in suite.cases {
			if suite.case_ring(c) != '0' {
				continue
			}
			p.suite = f
			p.cid = c.name
			before := p.out.len
			p.run_case(c)
			n_cases++
			if p.out.len == before {
				// Zero-record case: it counted toward n_cases but nothing of
				// it was compared — the F-15 vacuous-coverage class. The ONLY
				// intentional exclusion is the markdown input family: the C
				// ABI exposes no md conversion surface, and the CLI lane
				// covers those cases via `--from=md` (extraction_gate_cli.v).
				// Anything else uncovered fails the probe loudly.
				if 'in_md' in c.sections {
					n_md_excluded++
				} else {
					uncovered << '${f}#${c.name}'
				}
			}
		}
	}
	println(p.out.join('\n'))
	if uncovered.len > 0 {
		eprintln('extraction_gate_probe: FATAL — ${uncovered.len} Ring-0 case(s) produced no transcript records and are not intentional ABI-lane exclusions (audit F-15):')
		for u in uncovered {
			eprintln('  ${u}')
		}
		exit(1)
	}
	if min_cases > 0 && n_cases < min_cases {
		eprintln('extraction_gate_probe: FATAL — case-count floor violated: ${n_cases} Ring-0 cases < required ${min_cases} (audit F-15 vacuous-pass defense)')
		exit(1)
	}
	eprintln('extraction_gate_probe: ${n_cases} Ring-0 cases through ${lib_path} (floor ${min_cases}; ${n_md_excluded} md cases ABI-excluded, covered by the CLI lane)')
}
