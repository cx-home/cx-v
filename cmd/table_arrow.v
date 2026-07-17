module main

import os
import dl

// Native Parquet / Arrow IPC for `cx table`, via the optional libcx_arrow
// (built with -d cx_arrow_files). The cx CLI stays Arrow-free: it dlopens
// libcx_arrow only when a caller actually requests parquet/arrow, and reports
// clearly if the lib (or its file-I/O support) isn't present. This replaces the
// earlier python3 -m cxlib.* shell-out — no Python/pyarrow dependency.

type ArrowWriteFn = fn (fmt &char, data &u8, data_len int, path &char, err_out &&char) int
type ArrowReadFn = fn (fmt &char, path &char, out_len &int, err_out &&char) &u8

// cx_arrow_lib_path resolves libcx_arrow: $CX_ARROW_LIB, else next to the cx
// binary (install + dev target/ layouts), else the loader's default search.
fn cx_arrow_lib_path() string {
	name := 'libcx_arrow' + dl.dl_ext
	if p := os.getenv_opt('CX_ARROW_LIB') {
		return p
	}
	exe_dir := os.dir(os.executable())
	for cand in [os.join_path(exe_dir, name), os.join_path(exe_dir, 'target', name),
		os.join_path(exe_dir, '..', 'lib', name)] {
		if os.exists(cand) {
			return cand
		}
	}
	return name
}

fn native_arrow_write(fmt string, cxcol []u8, path string) ! {
	lib := cx_arrow_lib_path()
	h := dl.open_opt(lib, dl.rtld_now) or {
		return error('cannot load ${lib} (set CX_ARROW_LIB or build lib-arrow-files): ${err}')
	}
	defer {
		dl.close(h)
	}
	sym := dl.sym_opt(h, 'cx_arrow_write_table_file') or {
		return error('libcx_arrow lacks native ${fmt} support — rebuild it with -d cx_arrow_files')
	}
	f := unsafe { ArrowWriteFn(sym) }
	mut errp := &char(unsafe { nil })
	rc := f(&char(fmt.str), &u8(cxcol.data), cxcol.len, &char(path.str), &errp)
	if rc != 0 {
		msg := if errp != unsafe { nil } { unsafe { cstring_to_vstring(errp) } } else { 'unknown error' }
		return error(msg)
	}
}

fn native_arrow_read(fmt string, path string) ![]u8 {
	lib := cx_arrow_lib_path()
	h := dl.open_opt(lib, dl.rtld_now) or {
		return error('cannot load ${lib} (set CX_ARROW_LIB or build lib-arrow-files): ${err}')
	}
	defer {
		dl.close(h)
	}
	sym := dl.sym_opt(h, 'cx_arrow_read_table_file') or {
		return error('libcx_arrow lacks native ${fmt} support — rebuild it with -d cx_arrow_files')
	}
	f := unsafe { ArrowReadFn(sym) }
	mut out_len := 0
	mut errp := &char(unsafe { nil })
	ptr := f(&char(fmt.str), &char(path.str), &out_len, &errp)
	if ptr == unsafe { nil } {
		msg := if errp != unsafe { nil } { unsafe { cstring_to_vstring(errp) } } else { 'unknown error' }
		return error(msg)
	}
	out := unsafe { ptr.vbytes(out_len) }.clone()
	unsafe {
		free(voidptr(ptr))
	}
	return out
}
