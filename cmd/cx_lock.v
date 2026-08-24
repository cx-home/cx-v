// cx_lock.v — `cx lock` CLI subcommand (Phase 2.18).
//
// Generates / updates / verifies `cx.lock` from a project's [?lib]
// directives and spec/lockfile.md.
//
// Surface:
//
//   cx lock [FILE...]           — generate/update cx.lock from FILEs
//                                  (or every *.cx in cwd if none).
//   cx lock --check [FILE...]   — verify existing cx.lock matches the
//                                  resolved state; exits 1 on drift.
//   cx lock --update NAME [FILE...]
//                              — refresh a single module's entry.
//   cx lock --output PATH      — write to PATH instead of ./cx.lock.
//
// Resolution rules (Phase 2.18):
//
//   - file_path resolver  → :resolved is the resolver string verbatim
//                            (e.g. `./local-helpers.cx`). No :sri.
//
//   - registered_name resolver:
//       a. If the name is in the bundled cx-stdlib surface (per
//          code.bundled_stdlib_names()), emit
//          :resolved "bundled:<cx_bundled_stdlib_version>" with no :sri.
//       b. Otherwise the resolver is a non-bundled registered name —
//          if an existing cx.lock entry pinned it, preserve the
//          :resolved + :sri + :version fields (the lock-file is the
//          source of truth for these). If no prior entry exists, the
//          loader cannot pin the bytes from `cx lock` alone — emit
//          a placeholder :resolved equal to the resolver string and
//          let the user fill in the canonical URL (warn on stdout).
//
//   - https_url resolver  → :resolved is the URL itself; :sri is
//                            preserved from any existing cx.lock
//                            entry (HTTPS fetch + recompute SRI is
//                            Phase 2.x graft per status.md row 2.14).
//
// --check returns:
//   - exit 0 if every directly-scanned `[?lib]` resolves to a cx.lock
//     entry whose :resolved + :sri + :version matches the freshly-
//     computed value (or the preserved entry, for HTTPS).
//   - exit 1 otherwise; prints a unified diff-style report of the
//     mismatches.
//   - exit 2 on I/O or parse failure.
//
// Cross-references:
// lockfile shape, generate/update CLI surface.
//   - spec/lockfile.md §3 (format), §4 (module entries), §7 (worked
//     example).
//   - vcx/cx/lockfile_reader.v — read side (Phase 2.12 Part 3).
//   - vcx/code/stdlib_bundle.v — bundled-stdlib resolver names.

module main

import os
import cx
import code

struct CxLockOpts {
mut:
	check       bool
	update_name string
	output_path string
	files       []string
	// --pin-schema NAME=FILE.cxs — bind NAME to the schema file's
	// content-hash in the [schemas] block (stream 16 W4; names are
	// hints, hashes are identity). Repeatable.
	pin_schemas []string
}

fn parse_cx_lock_opts(args []string) CxLockOpts {
	mut o := CxLockOpts{
		output_path: 'cx.lock'
	}
	mut i := 0
	for i < args.len {
		a := args[i]
		match true {
			a == '--check' {
				o.check = true
				i++
			}
			a == '--update' {
				if i + 1 >= args.len {
					eprintln('cx lock: --update requires a module name')
					exit(2)
				}
				o.update_name = args[i + 1]
				i += 2
			}
			a.starts_with('--update=') {
				o.update_name = a[9..]
				i++
			}
			a == '--output' {
				if i + 1 >= args.len {
					eprintln('cx lock: --output requires a path')
					exit(2)
				}
				o.output_path = args[i + 1]
				i += 2
			}
			a.starts_with('--output=') {
				o.output_path = a[9..]
				i++
			}
			a.starts_with('--pin-schema=') {
				o.pin_schemas << a['--pin-schema='.len..]
				i++
			}
			a == '--pin-schema' {
				if i + 1 >= args.len {
					eprintln('cx lock: --pin-schema requires NAME=FILE.cxs')
					exit(2)
				}
				o.pin_schemas << args[i + 1]
				i += 2
			}
			a.starts_with('--') {
				eprintln('cx lock: unknown flag ${a}')
				print_cx_lock_usage()
				exit(2)
			}
			else {
				o.files << a
				i++
			}
		}
	}
	return o
}

fn print_cx_lock_usage() {
	eprintln('Usage: cx lock [opts] [FILE...]')
	eprintln('       cx lock --check [FILE...]')
	eprintln('       cx lock --update NAME [FILE...]')
	eprintln('       cx lock --output PATH [FILE...]')
	eprintln('       cx lock --pin-schema NAME=FILE.cxs [FILE...]')
	eprintln('')
	eprintln('Generates / verifies cx.lock from a project\'s [?lib] directives.')
	eprintln('FILE may be one or more *.cx source files; defaults to *.cx in cwd.')
	eprintln('--pin-schema binds NAME to the schema file\'s content-hash in the')
	eprintln('[schemas] block (repeatable; validate-against resolves these pins).')
}

// run_cx_lock is the `cx lock` subcommand entry point — dispatched
// from cmd/main.v under the `lock` arm.
pub fn run_cx_lock(args []string) {
	opts := parse_cx_lock_opts(args)

	// Resolve source files.
	source_files := if opts.files.len > 0 {
		opts.files.clone()
	} else {
		discover_cx_files('.')
	}
	if source_files.len == 0 {
		eprintln('cx lock: no .cx source files supplied and none found in cwd')
		exit(2)
	}

	// Scan every source for [?lib] directives.
	mut libs := []cx.LibNode{}
	for f in source_files {
		src := os.read_file(f) or {
			eprintln('cx lock: cannot read ${f}: ${err}')
			exit(2)
		}
		scanned := scan_lib_directives(src) or {
			eprintln('cx lock: parse error in ${f}: ${err}')
			exit(2)
		}
		libs << scanned
	}

	// Read existing cx.lock if present (used to preserve HTTPS :sri /
	// :version and non-bundled :resolved values).
	mut prior := map[string]cx.ModuleLock{}
	if os.exists(opts.output_path) {
		lf := cx.read_lockfile(opts.output_path) or {
			eprintln('cx lock: cannot read existing ${opts.output_path}: ${err}')
			exit(2)
		}
		for ml in lf.modules {
			prior[ml.name] = ml
		}
	}

	// Compute the desired lockfile entries.
	mut entries := []cx.ModuleLock{}
	mut seen := map[string]bool{}
	for lib in libs {
		name := lib.resolver_source
		if name in seen {
			continue
		}
		seen[name] = true

		// --update NAME : only refresh the named module; keep all
		// others verbatim from the prior lockfile.
		if opts.update_name != '' && name != opts.update_name {
			if existing := prior[name] {
				entries << existing
				continue
			}
		}

		entry := resolve_lib_to_module_lock(lib, prior) or {
			eprintln('cx lock: cannot resolve [?lib] `${name}`: ${err}')
			exit(2)
		}
		entries << entry
	}

	// Include any prior entries for modules referenced only transitively
	// (i.e. not in our scanned `libs` list but already pinned in the
	// previous lockfile). Phase 2.18 keeps these byte-identical;
	// transitive-graph closure check + unpinned-dep detection
	// (CXER0211) is the Phase 2.x graft per status.md row 2.14.
	for k, ml in prior {
		if k in seen {
			continue
		}
		entries << ml
		seen[k] = true
	}

	// Schema pins: prior [schemas] entries carry forward verbatim
	// (pins are AUTHORED state, not derivable from source scanning);
	// --pin-schema NAME=FILE.cxs adds or re-pins by name.
	mut pins := []cx.SchemaLock{}
	if os.exists(opts.output_path) {
		if plf := cx.read_lockfile(opts.output_path) {
			pins = plf.schemas.clone()
		}
	}
	for spec_arg in opts.pin_schemas {
		eq := spec_arg.index('=') or {
			eprintln('cx lock: --pin-schema takes NAME=FILE.cxs, got `${spec_arg}`')
			exit(2)
		}
		pname := spec_arg[..eq]
		pfile := spec_arg[eq + 1..]
		if pname == '' || pfile == '' {
			eprintln('cx lock: --pin-schema takes NAME=FILE.cxs, got `${spec_arg}`')
			exit(2)
		}
		ptext := os.read_file(pfile) or {
			eprintln('cx lock: --pin-schema ${pname}: cannot read ${pfile}: ${err}')
			exit(2)
		}
		phash := cx.schema_content_hash(ptext) or {
			eprintln('cx lock: --pin-schema ${pname}: ${pfile}: ${err}')
			exit(2)
		}
		hex := phash.hex()
		mut replaced := false
		for mut existing_pin in pins {
			if existing_pin.name == pname {
				existing_pin.hash = hex
				replaced = true
			}
		}
		if !replaced {
			pins << cx.SchemaLock{
				name: pname
				hash: hex
			}
		}
	}
	pins.sort(a.name < b.name)

	new_text := emit_cx_lock(entries, pins)

	if opts.check {
		// Compare freshly-computed text against existing file.
		if !os.exists(opts.output_path) {
			eprintln('cx lock --check: ${opts.output_path} does not exist')
			exit(1)
		}
		existing := os.read_file(opts.output_path) or {
			eprintln('cx lock --check: cannot read ${opts.output_path}: ${err}')
			exit(2)
		}
		if existing.trim_space() != new_text.trim_space() {
			eprintln('cx lock --check: ${opts.output_path} is out of date')
			eprintln('---- expected (computed) ----')
			eprintln(new_text)
			eprintln('---- actual (on disk) ----')
			eprintln(existing)
			exit(1)
		}
		exit(0)
	}

	os.write_file(opts.output_path, new_text) or {
		eprintln('cx lock: cannot write ${opts.output_path}: ${err}')
		exit(2)
	}
}

// discover_cx_files lists every `*.cx` file in `dir` (non-recursive)
// in lexicographic order — used when no positional FILE args are
// supplied to `cx lock`.
fn discover_cx_files(dir string) []string {
	mut out := []string{}
	entries := os.ls(dir) or { return out }
	for name in entries {
		if !name.ends_with('.cx') {
			continue
		}
		// Skip cx.lock itself (which ends with .cx by extension? no,
		// it's cx.lock — but defensive).
		if name == 'cx.lock' {
			continue
		}
		out << os.join_path(dir, name)
	}
	out.sort()
	return out
}

// scan_lib_directives scans a CX source string for top-level `[?lib]`
// directives and parses each via `cx.parse_lib`. Mirrors the
// bracket-balanced + comment-tolerant scanner in
// vcx/code/module_loader.v but is exported here so the CLI can avoid
// running the full two-pass loader (which would also recurse into
// HTTPS resolvers — Phase 2.x graft).
fn scan_lib_directives(source string) ![]cx.LibNode {
	mut out := []cx.LibNode{}
	src := source.bytes()
	mut i := 0
	for i < src.len {
		c := src[i]
		if c == ` ` || c == `\t` || c == `\n` || c == `\r` {
			i++
			continue
		}
		if i + 1 < src.len && c == `[` && src[i + 1] == `;` {
			// CX block comment `[; … ]` — skip depth-aware over nested `[`…`]`.
			// Body is OPAQUE prose, so NOT quote-shielded (an apostrophe must not
			// open a string span and swallow the close). Mirrors
			// module_loader_scan_directives and the reader's read_until_close.
			// (`[- a b]` is the subtraction operator post-migration, not a comment.)
			mut depth := 1
			i += 2
			for i < src.len && depth > 0 {
				if src[i] == `[` {
					depth++
				} else if src[i] == `]` {
					depth--
				}
				i++
			}
			continue
		}
		if c != `[` {
			i++
			continue
		}
		// Find the close `]` for this directive.
		end := find_close_bracket_quote_shielded(src, i)!
		text := src[i..end + 1].bytestr()
		if text.starts_with('[?lib') && text.len > 5
			&& (text[5] == ` ` || text[5] == `\t` || text[5] == `\n`
			|| text[5] == `\r` || text[5] == `]`) {
			n := cx.parse_lib(text) or {
				return error('parse_lib failed for `${text}`: ${err}')
			}
			out << n
		}
		i = end + 1
	}
	return out
}

fn find_close_bracket_quote_shielded(src []u8, start int) !int {
	if start >= src.len || src[start] != `[` {
		return error('scanner asked to balance non-`[` byte at position ${start}')
	}
	mut depth := 0
	mut i := start
	mut in_str := u8(0)
	for i < src.len {
		b := src[i]
		if in_str != 0 {
			if b == `\\` && i + 1 < src.len {
				i += 2
				continue
			}
			if b == in_str {
				in_str = 0
			}
			i++
			continue
		}
		if b == `'` || b == `"` {
			in_str = b
			i++
			continue
		}
		if b == `[` {
			depth++
		} else if b == `]` {
			depth--
			if depth == 0 {
				return i
			}
		}
		i++
	}
	return error('unbalanced `[` starting at position ${start}')
}

// resolve_lib_to_module_lock computes the cx.lock `[module]` entry
// for one `[?lib]` directive, consulting any existing `prior` entries
// for fields the CLI cannot otherwise reconstruct (HTTPS :sri,
// non-bundled :resolved).
fn resolve_lib_to_module_lock(lib cx.LibNode, prior map[string]cx.ModuleLock) !cx.ModuleLock {
	name := lib.resolver_source
	match lib.resolver_kind {
		.file_path {
			return cx.ModuleLock{
				name:     name
				resolved: name
			}
		}
		.registered_name {
			// Is this a bundled-stdlib resolver?
			if is_bundled_stdlib_name(name) {
				return cx.ModuleLock{
					name:     name
					resolved: 'bundled:${code.cx_bundled_stdlib_version}'
				}
			}
			// Non-bundled registered name — preserve from prior lockfile
			// if available; otherwise emit a placeholder.
			if existing := prior[name] {
				return existing
			}
			eprintln('cx lock: warning — registered name `${name}` has no prior cx.lock entry; emitting placeholder :resolved')
			return cx.ModuleLock{
				name:     name
				resolved: name
			}
		}
		.https_url {
			// HTTPS — preserve :sri + :version from prior if any.
			if existing := prior[name] {
				return existing
			}
			eprintln('cx lock: warning — HTTPS resolver `${name}` has no prior :sri; recorded resolved-only (Phase 2.x graft: real fetch + SRI compute)')
			return cx.ModuleLock{
				name:     name
				resolved: name
			}
		}
		.pkg_url {
			// pkg: refs are self-locking — the reference IS the resolution
			// (registry-verified at load; the #hash form pins exactly, and a
			// deployment doc's pins are the lockfile of record — distribution
			// spec §6.2).
			return cx.ModuleLock{
				name:     name
				resolved: name
			}
		}
	}
}

fn is_bundled_stdlib_name(name string) bool {
	for n in code.bundled_stdlib_names() {
		if n == name {
			return true
		}
	}
	// Also match the bare `cx-stdlib` parent per spec/stdlib.md §2.
	if name == 'cx-stdlib' {
		return true
	}
	return false
}

// emit_cx_lock renders the lockfile in the wire form documented by
// vcx/cx/lockfile_reader.v (attribute syntax: `name="value"`).
// The shape mirrors spec/lockfile.md §7 worked example, except
// attribute syntax follows the existing CX-data grammar [55] rather
// than the editorial `:name VALUE` form.
fn emit_cx_lock(entries []cx.ModuleLock, pins []cx.SchemaLock) string {
	mut b := []string{}
	b << '[cx.lock version="1"'
	b << '  [modules'
	for i, ml in entries {
		mut parts := []string{}
		parts << '    [module name=${quote_attr(ml.name)} resolved=${quote_attr(ml.resolved)}'
		if v := ml.version {
			parts << '      version=${quote_attr(v)}'
		}
		if s := ml.integrity {
			parts << '      sri=${quote_attr(s)}'
		}
		// Close the entry — terminating `]` on its own indent so the
		// emitted file matches the §7 worked-example shape closely.
		joined := parts.join('\n') + ']'
		// Trailing punctuation: last entry closes [modules] too.
		if i == entries.len - 1 {
			b << joined + ']'
		} else {
			b << joined
		}
	}
	if entries.len == 0 {
		// Empty [modules] block — close it.
		b[b.len - 1] = b[b.len - 1] + ']'
	}
	if pins.len > 0 {
		b << '  [schemas'
		for i, pin in pins {
			line := '    [schema name=${quote_attr(pin.name)} hash=${quote_attr(pin.hash)}]'
			if i == pins.len - 1 {
				b << line + ']'
			} else {
				b << line
			}
		}
	}
	b << ']'
	return b.join('\n') + '\n'
}

fn quote_attr(s string) string {
	// Backslash-escape embedded `"` chars; the lockfile is a CX-data
	// document so double-quoted attribute values follow the standard
	// CX string-literal escaping rules.
	mut out := '"'
	for c in s {
		match c {
			`"` { out += '\\"' }
			`\\` { out += '\\\\' }
			else { out += c.ascii_str() }
		}
	}
	out += '"'
	return out
}
