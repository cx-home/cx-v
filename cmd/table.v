// `cx table` subcommand §D1.
//
// Verbs:
// cx table info FILE — column count / row count / types / size
// cx table dump FILE --to=cx — round-trip CX → canonical CX (Table API)
// cx table load FILE --to=cx — symmetric inverse (currently same as dump)
// cx table dump FILE --to=parquet — native Parquet via libcx_arrow (dlopen)
// cx table dump FILE --to=arrow — native Arrow IPC via libcx_arrow (dlopen)
// cx table load FILE --from=parquet|arrow — native import (symmetric)
//
// Parquet / Arrow I/O is live (libcx_arrow Phase C, -d cx_arrow_files). The CLI
// stays Arrow-free and dlopens libcx_arrow only when those formats are used;
// see table_arrow.v. Requires libcx_arrow built with -d cx_arrow_files (and the
// user-supplied libarrow/libparquet) — otherwise a clear "rebuild" error.

module main

import os
import cx

fn run_table(args []string) {
	if args.len == 0 {
		eprintln('Usage: cx table <verb> [args...]')
		eprintln(' cx table info FILE')
		eprintln(' cx table dump FILE [--to=cx|parquet|arrow] [--output=FILE]')
		eprintln(' cx table load FILE [--to=cx|parquet|arrow] [--output=FILE]')
		exit(2)
	}
	verb := args[0]
	rest := args[1..]
	match verb {
		'info' { run_table_info(rest); return }
		'dump' { run_table_dump(rest); return }
		'load' { run_table_load(rest); return }
		else {
			eprintln('cx table: unknown verb "${verb}"; expected info|dump|load')
			exit(2)
		}
	}
}

// ── Shared option parsing ────────────────────────────────────────────────────

struct TableOpts {
mut:
	input_file string
	to_fmt string // cx | parquet | arrow
	from_fmt string // cx | parquet | arrow (currently only cx)
	output string
	strict bool
}

fn parse_table_opts(args []string) TableOpts {
	mut o := TableOpts{ to_fmt: 'cx' }
	for arg in args {
		if arg.starts_with('--to=') { o.to_fmt = arg[5..] }
		else if arg.starts_with('--from=') { o.from_fmt = arg[7..] }
		else if arg.starts_with('--output=') { o.output = arg[9..] }
		else if arg == '--strict' { o.strict = true }
		else if !arg.starts_with('--') { o.input_file = arg }
	}
	// Auto-infer --from from extension.
	if o.from_fmt == '' && o.input_file.len > 0 {
		o.from_fmt = infer_format(o.input_file)
	}
	if o.from_fmt == '' { o.from_fmt = 'cx' }
	return o
}

fn infer_format(path string) string {
	// #705: governance §12.2 renamed `.cxcol` → `.cxbin`; the old spelling
	// stays a DEPRECATED ALIAS (the review's word) rather than being cut,
	// so existing files keep opening.
	if path.ends_with('.cx') || path.ends_with('.cxbin') || path.ends_with('.cxcol') {
		return 'cx'
	}
	if path.ends_with('.parquet') || path.ends_with('.pq') { return 'parquet' }
	if path.ends_with('.arrow') || path.ends_with('.ipc') { return 'arrow' }
	return ''
}

fn read_input_text(o &TableOpts) string {
	if o.input_file == '' {
		return os.get_raw_lines_joined()
	}
	return os.read_file(o.input_file) or {
		eprintln('cx table: error reading file "${o.input_file}": ${err}')
		exit(1)
	}
}

fn write_output_text(o &TableOpts, body string) {
	if o.output == '' {
		print(body)
		if !body.ends_with('\n') { println('') }
		return
	}
	os.write_file(o.output, body) or {
		eprintln('cx table: error writing output "${o.output}": ${err}')
		exit(1)
	}
}

// ── info ─────────────────────────────────────────────────────────────────────

fn run_table_info(args []string) {
	o := parse_table_opts(args)
	if o.from_fmt != 'cx' {
		eprintln('cx table info: ${o.from_fmt} input not supported (Parquet/Arrow info defers to libcx_arrow Phase C)')
		exit(2)
	}
	src := read_input_text(&o)
	tables := cx.tables_from_cx(src) or {
		eprintln('cx table info: ${err}')
		exit(1)
	}
	if tables.len == 0 {
		eprintln('cx table info: no :table block found in input')
		exit(1)
	}
	println('tables: ${tables.len}')
	println('byte_size: ${src.len}')
	for i, t in tables {
		println('')
		println('table[${i}]:')
		println(' rows: ${t.row_count()}')
		println(' cols: ${t.col_count()}')
		cols := t.cols()
		types := t.types()
		for c in 0 .. cols.len {
			tn := if types[c] == '' { '_' } else { types[c] }
			println(' ${cols[c]}: ${tn}')
		}
	}
}

// ── dump ─────────────────────────────────────────────────────────────────────

fn run_table_dump(args []string) {
	o := parse_table_opts(args)
	if o.from_fmt != 'cx' {
		eprintln('cx table dump: --from=${o.from_fmt} not supported (use load to import non-CX)')
		exit(2)
	}
	src := read_input_text(&o)
	tables := cx.tables_from_cx(src) or {
		eprintln('cx table dump: ${err}')
		exit(1)
	}
	if tables.len == 0 {
		eprintln('cx table dump: no :table block found in input')
		exit(1)
	}
	match o.to_fmt {
		'cx' {
			// Round-trip via Table API: parse all → re-emit canonical.
			mut buf := ''
			for t in tables { buf += t.to_cx() }
			write_output_text(&o, buf)
		}
		'parquet' {
			// X1: delegate Parquet emit to the Python binding's
			// cxlib.parquet module, which wraps pyarrow.parquet. The CLI
			// path stays runtime-free for non-Parquet users; pyarrow is
			// installed only when callers actually request Parquet output.
			run_table_dump_parquet(&o, tables) or {
				eprintln('cx table dump --to=parquet: ${err}')
				exit(1)
			}
		}
		'arrow' {
			// W2: delegate Arrow IPC emit to the Python binding's
			// cxlib.arrow module.
			run_table_dump_arrow(&o, tables) or {
				eprintln('cx table dump --to=arrow: ${err}')
				exit(1)
			}
		}
		else {
			eprintln('cx table dump: unknown --to=${o.to_fmt}; expected cx|parquet|arrow')
			exit(2)
		}
	}
}

// run_table_dump_parquet writes the supplied tables to a Parquet file at
// o.output natively via libcx_arrow (no Python/pyarrow). Tables are serialised
// to CXCol data_bin, then handed to the dlopen'd native writer.
fn run_table_dump_parquet(o &TableOpts, tables []cx.Table) ! {
	out_path := if o.output != '' { o.output } else { 'out.parquet' }
	native_arrow_write('parquet', table_cxcol_bytes(tables)!, out_path)!
}

// run_table_dump_arrow writes the supplied tables to an Arrow IPC file at
// o.output natively via libcx_arrow (no Python/pyarrow).
fn run_table_dump_arrow(o &TableOpts, tables []cx.Table) ! {
	out_path := if o.output != '' { o.output } else { 'out.arrow' }
	native_arrow_write('arrow', table_cxcol_bytes(tables)!, out_path)!
}

// table_cxcol_bytes serialises tables to CXCol chunked-table data_bin bytes.
fn table_cxcol_bytes(tables []cx.Table) ![]u8 {
	mut combined := ''
	for t in tables {
		combined += t.to_cx()
	}
	doc := cx.parse(combined)!
	return cx.emit_data_bin_chunked(doc, cx.ChunkedEmitOptions{})!
}

// ── load ─────────────────────────────────────────────────────────────────────

fn run_table_load(args []string) {
	o := parse_table_opts(args)
	match o.from_fmt {
		'cx' {
			// Symmetric: same as dump --to=cx for now.
			src := read_input_text(&o)
			tables := cx.tables_from_cx(src) or {
				eprintln('cx table load: ${err}')
				exit(1)
			}
			if tables.len == 0 {
				eprintln('cx table load: no :table block found in input')
				exit(1)
			}
			mut buf := ''
			for t in tables { buf += t.to_cx() }
			write_output_text(&o, buf)
		}
		'parquet' {
			run_table_load_parquet(&o) or {
				eprintln('cx table load --from=parquet: ${err}')
				exit(1)
			}
		}
		'arrow' {
			run_table_load_arrow(&o) or {
				eprintln('cx table load --from=arrow: ${err}')
				exit(1)
			}
		}
		else {
			eprintln('cx table load: unknown --from=${o.from_fmt}; expected cx|parquet|arrow')
			exit(2)
		}
	}
}

// run_table_load_parquet reads a Parquet file natively via libcx_arrow (no
// Python/pyarrow) into CXCol data_bin, then re-emits as canonical CX text.
fn run_table_load_parquet(o &TableOpts) ! {
	if o.input_file == '' {
		return error('cx table load --from=parquet requires an input FILE')
	}
	framed := native_arrow_read('parquet', o.input_file)!
	write_output_text(o, cx.from_data_bin(framed)!)
}

fn run_table_load_arrow(o &TableOpts) ! {
	if o.input_file == '' {
		return error('cx table load --from=arrow requires an input FILE')
	}
	framed := native_arrow_read('arrow', o.input_file)!
	write_output_text(o, cx.from_data_bin(framed)!)
}
