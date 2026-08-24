module code

import cx
import crypto.sha256
import crypto.blake3
import crypto.sha512
import encoding.base64
import os

// module_loader.v — two-pass module load + cx.lock SRI verification
// per spec/lockfile.md §4.4 (Phase 2.13 + 2.14 partial).
//
// This is the Phase 2.13 + 2.14 standalone evaluator surface — it
// builds on the Phase 2.12 Part 3 AST + parser foundations:
//
//   - LibNode + parse_lib    (vcx/cx/lib_node.v + vcx/cx/lib_parser.v)
//   - DefNode + parse_def    (vcx/cx/def_node.v + vcx/cx/def_parser.v)
//   - ConstNode + parse_const(vcx/cx/const_node.v + vcx/cx/const_parser.v)
//   - Lockfile reader        (vcx/cx/lockfile_reader.v)
//
// What this file provides:
//
//   - `pub struct Module` — the in-memory representation of a loaded
//     module: name + defs map + consts map (in topological evaluation
//     order) + libs list. All symbols are exposed as public for now;
//     `:scope public/private` enforcement is Phase 2.15 territory.
//
//   - `pub struct ModuleTable` — the loader's working state: the map
//     of resolved modules by name + the in-flight set used for cycle
// detection across cross-module imports.
//
//   - `pub fn load_module(source, name, mut table) !&Module` — main
// entry. Runs the two-pass load:
//
//       Pass 1: declaration registration. Walks the source string
//               scanning top-level `[?lib]`/`[?def]`/`[?const]`
//               directives, parsing each into its AST node and
//               registering it in the module's binding tables.
//       Pass 2: topological const evaluation. Builds the reference
//               graph over `[?const]` declarations (edge `A → B`
//               iff A's value_source references B by bareword
//               token), topologically sorts, and reorders the
//               module's `const_order` slot. Lazy consts are
//               registered as thunks (not actually evaluated here —
//               full cx.ProgramExpr evaluation is the Phase 2.x graft).
//       Pass 3: module is callable — the constructed `&Module` is
//               returned and registered in `table.modules`.
//
//   - `pub fn resolve_lib(node, mut table) !&Module` — recursive
//     transitive module resolution. Handles the three resolver
// shapes:
//
//       - file_path        : reads the file from disk (relative paths
//                            resolved against table.base_dir).
//       - registered_name  : looks up the source in
//                            `table.registered_sources` (the test
//                            harness pre-registers cx-stdlib /
//                            synthetic fixtures here).
//       - https_url        : the Phase-2.14 graft (register R3.12,
//                            RULED (b) 2026-08-09): lockfile-pinned
//                            resolution — cx.lock entry REQUIRED
//                            (else MODULE_UNPINNED/CXER0211); bytes
//                            from the in-memory registry seam, the
//                            on-disk (url, sri) cache, or a live TLS
//                            GET (http-client pack); verified against
//                            the pinned sri (mismatch = CXER0209,
//                            never cached).
//
//     Cycle detection: the function adds the requested module name to
//     `table.in_flight` before recursing; if a recursive resolve_lib
//     re-enters for a name already in the set, MODULE_CYCLE_DETECTED
//     is raised carrying the cycle path (surfaces as `CXER0210` at
// the loader boundary).
//
//   - `pub fn verify_sri(integrity, content) !bool` — verifies a
//     `<algo>-<base64-of-binary-digest>` SRI string against the given
//     content bytes per spec/lockfile.md §4.4. Accepts `sha384` /
//     `sha512`. Returns true on match. Malformed SRI shape raises
//     `MODULE_SRI_MALFORMED`. Mismatched digest raises
//     `MODULE_SRI_MISMATCH` (surfaces as `CXER0209` at the loader
//     boundary).
//
// Scope simplifications at Phase 2.13 + 2.14 partial — the fetch/cache/
// lockfile items CLOSED by the Phase-2.14 graft (register R3.12, RULED (b)
// 2026-08-09):
//
//   - HTTPS fetch: LIVE (module_fetch_https_live, http-client pack; TLS
//     always on; net-capability-gated; engines without the pack refuse
//     loudly and keep cache/registry loads).
//   - On-disk module cache: LIVE ((url, sri)-keyed per lockfile.md §5;
//     $CX_MODULE_CACHE override; verified bytes only).
//   - `:scope public/private` visibility enforcement landed at Phase
//     2.15 — see `is_def_public` / `is_const_public` / `lookup_def` /
//     `lookup_const` below, plus the `:only` selective-import check
//     wired into `resolve_lib`. Module-private is the default per
// importers must use a `:scope public` symbol or
//     receive `MODULE_SYMBOL_NOT_PUBLIC`. (No CXER0* wire code is
//     allocated for visibility violations currently — the Module-
//     system range CXER0204..CXER0215 is fully claimed; a future
//     spec amendment may add CXER0216+ for this case.)
//   - Full cx.ProgramExpr evaluation of const bodies is the Phase 2.x
//     cx.ProgramExpr graft — consts are sorted topologically here but
//     not actually evaluated; their value_source bytes are kept on
//     ConstNode and the topological order is exposed via
//     `Module.const_order` so a downstream evaluator can walk them
//     in dependency order.
//   - Lockfile-driven SRI verification: LIVE — the loader lazily reads
//     `<base_dir>/cx.lock` (module_lock_load; malformed/unknown-schema
//     refuses CXER0212) and looks up entries by literal name
//     (module_lock_entry, lockfile.md §4.1/§4.3.1); HTTPS-resolved
//     entries verify on every load.
//
// Cross-references:
//   - spec/lockfile.md §4.4 (SRI integrity format)
//   - vcx/code/match_eval.v (Phase 2.7-standalone pattern — same
//     "standalone evaluator surface" convention applied here)

// ── Errors ────────────────────────────────────────────────────────────────────

// MODULE_* error-code constants. The loader surfaces these as
// `error('MODULE_*: …')`; the dispatcher-integration follow-up maps
// them to the canonical `CXER0*` spec error codes.
//
// MODULE_UNPINNED — an HTTPS-resolved module has no matching cx.lock
// entry (or the entry lacks the required sri). Surfaces as CXER0211
// E_LIB_UNPINNED at the boundary. (MODULE_HTTPS_FETCH_DEFERRED is
// RETIRED — the Phase-2.14 graft made the fetch real.)
//
// MODULE_CYCLE_DETECTED — the in-flight set already contained the
// requested module name when a recursive resolve_lib call entered.
// Surfaces as CXER0210 E_LIB_IMPORT_CYCLE at the boundary.
//
// MODULE_SRI_MALFORMED — the SRI string did not have the
// `<algo>-<base64>` shape per spec/lockfile.md §4.4 / W3C SRI.
//
// MODULE_SRI_MISMATCH — the SRI algo + base64 shape is well-formed
// but the computed digest of the supplied content bytes did not
// match. Surfaces as CXER0209 E_LIB_INTEGRITY_MISMATCH at the
// boundary.
//
// MODULE_UNKNOWN_REGISTERED — a registered-name resolver did not
// have a corresponding entry in `ModuleTable.registered_sources`.
//
// MODULE_FILE_NOT_FOUND — a file-path resolver could not be read
// from disk under `ModuleTable.base_dir`.
//
// MODULE_SYMBOL_NOT_PUBLIC — a cross-module symbol lookup
// (`lookup_def` / `lookup_const` / `[?lib … :only (name)]`) named a
// symbol that exists in the target module but is module-private
// per (default visibility). The error message names
// both the owning module and the requested symbol. No CXER0* wire
// code is allocated for this case currently (module-system range
// CXER0204..CXER0215 is full).
//
// MODULE_SYMBOL_NOT_FOUND — a cross-module symbol lookup named a
// symbol that does not exist in the target module's defs / consts
// tables at all. Distinct from the not-public case so callers can
// distinguish "no such name" from "name exists but is private".

// ── Structs ───────────────────────────────────────────────────────────────────

// Module is the in-memory representation of a successfully loaded
// module. After `load_module` returns, the
// caller can:
//
//   - look up a `[?def]` by name in `defs`,
//   - look up a `[?const]` by name in `consts` (the value_source is
//     verbatim; structural evaluation is the Phase 2.x graft),
//   - inspect the declared `[?lib]` imports in `libs` to walk the
//     transitive graph,
//   - walk `const_order` to evaluate consts in topological order
//     (Phase 2.x graft point).
//
// All defs / consts are stored regardless of `:scope`; visibility
// enforcement is Phase 2.15 territory. The `scope` slot on the
// node is preserved on the AST.
pub struct Module {
pub mut:
	name        string
	source      string
	defs        map[string]cx.DefNode
	consts      map[string]cx.ConstNode
	libs        []cx.LibNode
	// const_order is the topologically-sorted list of `[?const]` names
	// A downstream evaluator MUST walk this list
	// in order when computing eager const values to honour the const-
	// to-const reference graph.
	const_order []string
	// scope is the module's lexical Scope (its bare defs + consts + the prefixed
	// members of its own imports), built once on first import and shared by all
	// importers — a member's body resolves its free names here (#19/#22). nil
	// until ensure_module_scope builds it.
	scope &Scope = unsafe { nil }
}

// ModuleTable is the loader's working state across a load_module
// call. The struct is intentionally cheap to construct (`mut t :=
// code.new_module_table()`); callers thread it through transitive
// resolve_lib calls so cycle detection sees the in-flight set.
//
// `modules` holds successfully-loaded modules keyed by the
// resolver_source string per spec/lockfile.md §4.1.
//
// `in_flight` is the set of module names currently being loaded —
// the cycle-detection oracle.
//
// `registered_sources` is the in-memory map of registered-name
// resolvers → source. At Phase 2.14 partial this is the test-
// harness pre-population point for cx-stdlib + synthetic fixtures.
// The Phase 2.x graft replaces this with a real cx-stdlib bundle.
//
// `base_dir` is the filesystem directory against which relative
// file-path resolvers are resolved. Defaults to the current working
// directory.
//
// `lockfile` is the optional parsed Lockfile per Phase 2.12 Part 3
// — used to look up SRI hashes during HTTPS resolution. Optional;
// the loader handles missing lockfile gracefully (file-path and
// registered-name resolvers work without one).
pub struct ModuleTable {
pub mut:
	modules            map[string]&Module
	in_flight          map[string]bool
	in_flight_order    []string
	registered_sources map[string]string
	base_dir           string
	lockfile           ?cx.Lockfile
	// lock_probed: `<base_dir>/cx.lock` is loaded at most once per table
	// (Phase 2.14 graft); a harness-seeded `lockfile` sets this itself.
	lock_probed        bool
	// alias_modules maps an import call-prefix (`:as ALIAS` or the
	// derived last-segment, spec/code.md §12.1.1) to the module it
	// resolved to. Populated by eval_lib at import time. The QName
	// call path consults this so a `[$alias:member]` reference to a
	// member that EXISTS but is module-private (or not entry-file
	// re-exported, §12.4.4) raises CXER0216 (E_VISIBILITY) — distinct
	// from CXER0213 (resolver matches no module).
	alias_modules      map[string]&Module
	// module_scopes caches each module's lexical Scope (keyed by resolver_source),
	// built once on first import and shared by all importers (#19/#22). Holds the
	// module's bare defs + consts + the prefixed members of its own imports.
	module_scopes      map[string]&Scope
}

// new_module_table constructs an empty ModuleTable rooted at the
// caller-supplied base directory (or the empty string for "no
// filesystem access"). Convenience for the common test shape.
pub fn new_module_table() ModuleTable {
	return ModuleTable{
		modules:            map[string]&Module{}
		in_flight:          map[string]bool{}
		in_flight_order:    []string{}
		registered_sources: map[string]string{}
		base_dir:           ''
		alias_modules:      map[string]&Module{}
		module_scopes:      map[string]&Scope{}
	}
}

// register_source pre-populates a registered-name resolver → source
// mapping. Used by the test harness (and, eventually, by the cx-
// stdlib bundler) to make registered-name imports resolvable
// without filesystem or network access.
pub fn (mut t ModuleTable) register_source(name string, source string) {
	t.registered_sources[name] = source
}

// ── Visibility — :scope public/private (Phase 2.15) ─────────────────────────

// scope_is_public returns true iff the given `:scope` slot is the
// explicit string `"public"`. Per spec/code.md §12.6,
// module-private is the default: a `[?def]` / `[?const]` with no
// `:scope` modifier OR with `:scope private` is private. Only the
// explicit `:scope public` opts a symbol into the import surface.
//
// The argument is the verbatim `?string` slot captured by
// `cx.parse_def` / `cx.parse_const`. The parser already validates
// the value is `"public"` or `"private"` (raising CXDEF_PARSE /
// CXCONST_PARSE on anything else), so this function only needs to
// distinguish public from everything-else-treated-as-private.
pub fn scope_is_public(scope ?string) bool {
	if s := scope {
		return s == 'public'
	}
	return false
}

// is_def_public returns true iff the named `[?def]` is declared
// `:scope public` in this module. False when the
// def is absent OR module-private (default).
pub fn (m Module) is_def_public(name string) bool {
	if name !in m.defs {
		return false
	}
	d := m.defs[name] or { return false }
	return scope_is_public(d.scope)
}

// is_const_public returns true iff the named `[?const]` is declared
// `:scope public` in this module (matched to D12.4
// for `[?const]`). False when the const is absent OR module-private
// (default).
pub fn (m Module) is_const_public(name string) bool {
	if name !in m.consts {
		return false
	}
	c := m.consts[name] or { return false }
	return scope_is_public(c.scope)
}

// lookup_def returns the named `[?def]` for use by an importer
// (`requesting_module`). The visibility rule:
//
//   - Same-module reads (requesting_module == this module's name)
//     resolve regardless of `:scope` — the module's own code sees
//     all its own definitions.
//   - Cross-module reads require `:scope public` on the def;
//     otherwise MODULE_SYMBOL_NOT_PUBLIC is raised.
//
// MODULE_SYMBOL_NOT_FOUND is raised when the name is absent from
// the defs table entirely (distinct from the not-public case).
pub fn (m Module) lookup_def(name string, requesting_module string) !cx.DefNode {
	d := m.defs[name] or {
		return error('MODULE_SYMBOL_NOT_FOUND: `[?def ${name}]` not declared in module `${m.name}`')
	}
	if requesting_module == m.name {
		return d
	}
	if !scope_is_public(d.scope) {
		return error('MODULE_SYMBOL_NOT_PUBLIC: `[?def ${name}]` in module `${m.name}` is private (default — add `:scope public` to export) — referenced from module `${requesting_module}`')
	}
	return d
}

// lookup_const returns the named `[?const]` for use by an importer
// (`requesting_module`). Same visibility rule as `lookup_def`: own-
// module reads ignore `:scope`; cross-module reads require `:scope
// public`. Errors: MODULE_SYMBOL_NOT_FOUND / MODULE_SYMBOL_NOT_PUBLIC.
pub fn (m Module) lookup_const(name string, requesting_module string) !cx.ConstNode {
	c := m.consts[name] or {
		return error('MODULE_SYMBOL_NOT_FOUND: `[?const ${name}]` not declared in module `${m.name}`')
	}
	if requesting_module == m.name {
		return c
	}
	if !scope_is_public(c.scope) {
		return error('MODULE_SYMBOL_NOT_PUBLIC: `[?const ${name}]` in module `${m.name}` is private (default — add `:scope public` to export) — referenced from module `${requesting_module}`')
	}
	return c
}

// public_def_names returns the sorted list of `[?def]` names this
// module exports per `:scope public`. Convenience for tooling and
// the import-surface diff at module-load time.
pub fn (m Module) public_def_names() []string {
	mut out := []string{}
	for name, d in m.defs {
		if scope_is_public(d.scope) {
			out << name
		}
		_ = d
	}
	out.sort()
	return out
}

// public_const_names returns the sorted list of `[?const]` names
// this module exports per `:scope public`. Convenience for tooling
// and the import-surface diff at module-load time.
pub fn (m Module) public_const_names() []string {
	mut out := []string{}
	for name, c in m.consts {
		if scope_is_public(c.scope) {
			out << name
		}
		_ = c
	}
	out.sort()
	return out
}

// ── Public entry: load_module ────────────────────────────────────────────────

// load_module runs the two-pass load over the
// given source string. The returned `&Module` is also registered
// in `table.modules` under `name` so transitive resolution sees
// it.
//
// Pre-condition: `name` is NOT already in `table.in_flight`. If
// `name` is in flight when this function is called, the loader is
// in the middle of a cyclic import — see `resolve_lib` which
// raises MODULE_CYCLE_DETECTED. Direct callers wanting cycle-
// safety should funnel through `resolve_lib` rather than calling
// `load_module` recursively themselves.
pub fn load_module(source string, name string, mut table ModuleTable) !&Module {
	if name in table.modules {
		// Already loaded — idempotent. Return the cached pointer.
		return table.modules[name] or { return error('MODULE_INTERNAL: lost cached module ${name}') }
	}
	if table.in_flight[name] {
		// This branch is normally reached via resolve_lib; surface
		// the cycle path for the error message.
		path := module_loader_cycle_path(table, name)
		return error('MODULE_CYCLE_DETECTED: ${path}')
	}
	table.in_flight[name] = true
	table.in_flight_order << name
	defer {
		table.in_flight.delete(name)
		// pop the last entry (LIFO; load_module respects nesting)
		if table.in_flight_order.len > 0 && table.in_flight_order.last() == name {
			table.in_flight_order = table.in_flight_order[..table.in_flight_order.len - 1]
		}
	}

	// ── Pass 1: declaration registration ─────────────────────────────────
	directives := module_loader_scan_directives(source)!
	mut mod := &Module{
		name:        name
		source:      source
		defs:        map[string]cx.DefNode{}
		consts:      map[string]cx.ConstNode{}
		libs:        []cx.LibNode{}
		const_order: []string{}
	}
	for d in directives {
		match d.kind {
			.lib {
				n := cx.parse_lib(d.text) or {
					return error('MODULE_PARSE: [?lib] parse failed in module `${name}`: ${err}')
				}
				mod.libs << n
			}
			.def {
				n := cx.parse_def(d.text) or {
					return error('MODULE_PARSE: [?def] parse failed in module `${name}`: ${err}')
				}
				if n.name in mod.defs || n.name in mod.consts {
					return error('MODULE_DUPLICATE_NAME: `${n.name}` declared more than once in module `${name}` (CXER0205)')
				}
				mod.defs[n.name] = n
			}
			.const_ {
				n := cx.parse_const(d.text) or {
					return error('MODULE_PARSE: [?const] parse failed in module `${name}`: ${err}')
				}
				if n.name in mod.defs || n.name in mod.consts {
					return error('MODULE_DUPLICATE_NAME: `${n.name}` declared more than once in module `${name}` (CXER0205)')
				}
				mod.consts[n.name] = n
			}
		}
	}

	// ── Recursive transitive resolution of `[?lib]` directives ───────────
	// Per this happens at Pass 1 (declaration
	// registration); we recurse into resolve_lib here so any
	// transitive cycle surfaces before Pass 2.
	for lib in mod.libs {
		resolve_lib(lib, mut table) or {
			// Propagate cycle / parse / fetch errors with module
			// context attached for easier debugging.
			return error('MODULE_LIB_RESOLVE_FAILED: in module `${name}`: ${err}')
		}
	}

	// ── Pass 2: topological const ordering ──────────────────────────────
	mod.const_order = module_loader_toposort_consts(mod.consts) or {
		return error('MODULE_CONST_CYCLE: in module `${name}`: ${err}')
	}

	// ── Pass 3: module callable ──────────────────────────────────────────
	table.modules[name] = mod
	return mod
}

// ── Public entry: resolve_lib ────────────────────────────────────────────────

// resolve_lib resolves a `[?lib]` directive to a loaded `&Module`,
// recursively loading the target module if not already cached.
// Handles cycle detection and the three resolver
// shapes.
//
// Returns the resolved `&Module` on success.
//
// Errors:
//   - MODULE_CYCLE_DETECTED      : `node.resolver_source` is already
//                                  in `table.in_flight`. Surfaces as
//                                  CXER0210 at the boundary.
//   - MODULE_UNPINNED            : HTTPS-resolved module with no
//                                  cx.lock entry / no sri (CXER0211).
//   - MODULE_SRI_MISMATCH        : resolved bytes fail the pinned sri
//                                  (CXER0209; never cached).
//   - MODULE_LOCKFILE_MALFORMED  : cx.lock unparseable or unknown
//                                  schema version (CXER0212).
//   - MODULE_UNKNOWN_REGISTERED  : registered-name resolver not in
//                                  `table.registered_sources`.
//   - MODULE_FILE_NOT_FOUND      : file-path resolver could not be
//                                  read from disk under `base_dir`.
//   - any error raised by the recursive `load_module` call.
pub fn resolve_lib(node cx.LibNode, mut table ModuleTable) !&Module {
	name := node.resolver_source
	if name in table.modules {
		return table.modules[name] or { return error('MODULE_INTERNAL: lost cached module ${name}') }
	}
	if table.in_flight[name] {
		path := module_loader_cycle_path(table, name)
		return error('MODULE_CYCLE_DETECTED: ${path} (CXER0210)')
	}
	source := match node.resolver_kind {
		.file_path {
			// In-memory test sources (conformance fixtures) take precedence
			// over disk: a fixture registers `'./local-helpers.cx'` keyed by
			// its literal path so the gate stays hermetic (no filesystem
			// dependency). Falls through to disk when not registered.
			if s := table.registered_sources[name] {
				s
			} else {
				module_loader_read_file(name, table.base_dir) or {
					return error('MODULE_FILE_NOT_FOUND: `${name}` not readable: ${err}')
				}
			}
		}
		.registered_name {
			// Phase 2.14 graft (register R3.12, RULED (b) 2026-08-09): the
			// lockfile may map a registered NAME to HTTPS-resolved bytes
			// (lockfile.md §4.2 — "resolves to an HTTPS URL … via lockfile",
			// code.md §12.1.3); that path carries the full pin + verify
			// discipline. A name with no lock entry (or a file/bundled-
			// resolved one) keeps the registry path — §4.4: sri is required
			// only for HTTPS-resolved modules.
			module_lock_load(mut table)!
			if ml := module_lock_entry(table, name) {
				if ml.resolved.starts_with('https://') {
					module_https_resolve_entry(mut table, name, ml)!
				} else {
					s := table.registered_sources[name] or {
						return error('MODULE_UNKNOWN_REGISTERED: registered name `${name}` has no in-memory source (CXER0213)')
					}
					s
				}
			} else {
				s := table.registered_sources[name] or {
					return error('MODULE_UNKNOWN_REGISTERED: registered name `${name}` has no in-memory source (CXER0213)')
				}
				s
			}
		}
		.https_url {
			// Phase 2.14 graft (register R3.12, RULED (b) 2026-08-09; spec
			// code.md §12.1.3 / lockfile.md §4.4, §5): the lockfile is the
			// AUTHORITY — an HTTPS resolver without a matching cx.lock entry
			// is unpinned remote code and refuses (CXER0211); a present
			// entry's sri is REQUIRED and verified against the resolved
			// bytes wherever they came from (the harness's in-memory
			// registry, the on-disk (url, sri) cache, or a live TLS GET).
			// Mismatched bytes are NEVER cached.
			module_https_resolve(mut table, name)!
		}
		.pkg_url {
			// distribution spec §6.2: resolve through the bound registry with
			// the full §3 verify chain; the module source is the verified
			// tree's <name>.cx code entry. In-memory test sources keyed by
			// the literal reference take precedence (hermetic fixtures).
			if s := table.registered_sources[name] {
				s
			} else if g_ring2_pkg_source.len > 0 {
				// I3: the pkg: resolver is the Ring-2 distribution
				// engine, reached through the registry slot.
				g_ring2_pkg_source[0](name)!
			} else {
				return error('pkg: module source requires the distribution engine (platform profile): ${name}')
			}
		}
	}
	loaded := load_module(source, name, mut table)!
	// Phase 2.15: visibility check on `:only` selective-import list.
	// When the LibNode carries `:only (a b c)`, each name MUST resolve
	// to a public symbol in the target module (either a `:scope public`
	// def or const). Private / absent names raise at load time so the
	// importer fails fast rather than at first-use.
	if names := node.only_imports {
		for sym in names {
			has_def := sym in loaded.defs
			has_const := sym in loaded.consts
			if !has_def && !has_const {
				return error('MODULE_SYMBOL_NOT_FOUND: `:only` requested `${sym}` from `${name}` but no `[?def]` / `[?const]` with that name is declared')
			}
			if has_def && !loaded.is_def_public(sym) {
				return error('MODULE_SYMBOL_NOT_PUBLIC: `:only` requested `${sym}` from `${name}` but `[?def ${sym}]` is private (default — add `:scope public` to export)')
			}
			if has_const && !loaded.is_const_public(sym) {
				return error('MODULE_SYMBOL_NOT_PUBLIC: `:only` requested `${sym}` from `${name}` but `[?const ${sym}]` is private (default — add `:scope public` to export)')
			}
		}
	}
	return loaded
}

// ── Phase 2.14: lockfile-pinned HTTPS resolution (register R3.12, RULED (b)) ──

// module_lock_load lazily loads `<base_dir>/cx.lock` into the table, once.
// A harness-seeded lockfile (table.lockfile already set) wins; an absent
// file is fine (programs with no remote modules need no lockfile — the
// first HTTPS resolver will then refuse UNPINNED); a malformed file or an
// unrecognized schema version refuses loudly (lockfile.md §3.1, CXER0212).
fn module_lock_load(mut table ModuleTable) ! {
	if table.lock_probed {
		return
	}
	table.lock_probed = true
	if _ := table.lockfile {
		return
	}
	base := if table.base_dir == '' { '.' } else { table.base_dir }
	p := os.join_path(base, 'cx.lock')
	if !os.exists(p) {
		return
	}
	lf := cx.read_lockfile(p) or {
		return error('MODULE_LOCKFILE_MALFORMED: ${p}: ${err.msg()} (CXER0212)')
	}
	if lf.schema_version != '1' {
		return error('MODULE_LOCKFILE_MALFORMED: ${p}: unrecognized cx.lock schema version `${lf.schema_version}` — this loader reads version=1 (lockfile.md §3.1, no graceful degrade) (CXER0212)')
	}
	table.lockfile = lf
}

// module_lock_entry finds the `[module]` entry for a resolver string by
// literal name match (lockfile.md §4.1). §4.3.1's selection rule: the
// entry with NO version field wins; when every match carries a version
// (and the `[?lib]` has no hotfix override — not yet parsed into LibNode),
// there is no selectable entry and the caller refuses UNPINNED.
fn module_lock_entry(table ModuleTable, name string) ?cx.ModuleLock {
	lf := table.lockfile or { return none }
	for ml in lf.modules {
		if ml.name != name {
			continue
		}
		if _ := ml.version {
			continue
		}
		return ml
	}
	return none
}

// module_https_resolve — the direct-URL entry: pin lookup, then the shared
// entry path.
fn module_https_resolve(mut table ModuleTable, name string) !string {
	module_lock_load(mut table)!
	ml := module_lock_entry(table, name) or {
		return error('MODULE_UNPINNED: HTTPS module `${name}` has no matching cx.lock entry — remote code must be integrity-pinned (code.md §12.1.3 / lockfile.md §4.4) (CXER0211)')
	}
	return module_https_resolve_entry(mut table, name, ml)
}

// module_https_resolve_entry retrieves + verifies HTTPS-resolved bytes for
// a lock entry: sri REQUIRED (§4.4), bytes from the in-memory registry /
// the (url, sri) cache / a live TLS GET, verified byte-identically, and
// cached ONLY after verification succeeds (a poisoned fetch is never
// cached, §4.4).
fn module_https_resolve_entry(mut table ModuleTable, name string, ml cx.ModuleLock) !string {
	sri := ml.integrity or {
		return error('MODULE_UNPINNED: cx.lock entry for `${name}` carries no sri — required for HTTPS-resolved modules (lockfile.md §4.4) (CXER0211)')
	}
	verify_sri_shape(sri) or {
		return error('MODULE_SRI_MALFORMED: lockfile sri for `${name}` is malformed: ${err.msg()}')
	}
	url := if ml.resolved.starts_with('https://') { ml.resolved } else { name }
	bytes, live := module_https_bytes(mut table, url, sri)!
	ok := verify_sri(sri, bytes)!
	if !ok {
		return error('MODULE_SRI_MISMATCH: `${name}` resolved bytes do not match the cx.lock sri (CXER0209)')
	}
	if live {
		module_cache_store(url, sri, bytes)
	}
	return bytes
}

// module_https_bytes returns (bytes, fetched-live). Source precedence:
// the harness's in-memory registry (the hermetic conformance seam — the
// caller still verifies, which is exactly how the tampered fixtures
// refuse), then the on-disk (url, sri) cache, then the live transport.
fn module_https_bytes(mut table ModuleTable, url string, sri string) !(string, bool) {
	if s := table.registered_sources[url] {
		return s, false
	}
	cpath := module_cache_path(url, sri)
	if os.exists(cpath) {
		c := os.read_file(cpath) or {
			return error('MODULE_CACHE_UNREADABLE: ${cpath}: ${err.msg()}')
		}
		return c, false
	}
	b := module_fetch_transport(url)!
	return b, true
}

// module_fetch_transport — the live GET. The http-client PACK carries the
// real transport (module_fetch_https_live, in the pack-gated sibling
// file); an engine composed without the pack refuses loudly here — the
// on-disk cache and pre-registered pinned sources stay loadable (they
// need no network).
fn module_fetch_transport(url string) !string {
	$if cx_no_pack_http_client ? {
		return error('MODULE_HTTPS_FETCH_UNAVAILABLE: this engine composition carries no http-client pack — only cached or pre-registered pinned modules are loadable (resolver=`${url}`)')
	} $else {
		return module_fetch_https_live(url)
	}
}

// module_cache_dir — `$CX_MODULE_CACHE` override (tests / hermetic CI),
// else the user cache dir. The key is the (url, sri) PAIR (lockfile.md
// §5): bumping the sri in cx.lock is a fresh cache miss by construction.
fn module_cache_dir() string {
	env := os.getenv('CX_MODULE_CACHE')
	if env != '' {
		return env
	}
	return os.join_path(os.cache_dir(), 'cx', 'modules')
}

fn module_cache_path(url string, sri string) string {
	key := sha256.hexhash('${url}\x00${sri}')
	return os.join_path(module_cache_dir(), '${key}.cx')
}

// module_cache_path_for_test exposes the (url, sri) cache path to the
// loader's own test battery (cache seeding under $CX_MODULE_CACHE).
pub fn module_cache_path_for_test(url string, sri string) string {
	return module_cache_path(url, sri)
}

// module_cache_store persists verified bytes. A failed write is a lost
// OPTIMIZATION only (the next resolve re-fetches and re-verifies), so it
// degrades silently by design — correctness never depends on the cache.
fn module_cache_store(url string, sri string, content string) {
	dir := module_cache_dir()
	os.mkdir_all(dir) or { return }
	os.write_file(module_cache_path(url, sri), content) or {}
}

// make_sri computes the W3C SRI string for content under `algo` — the
// producer-side complement of verify_sri (same registry), used by the
// conformance seeding, tests, and `cx lock` tooling.
pub fn make_sri(algo string, content string) !string {
	digest := match algo {
		'sha256' { sha256.sum256(content.bytes())[..] }
		'sha384' { sha512.sum384(content.bytes())[..] }
		'sha512' { sha512.sum512(content.bytes())[..] }
		'blake3' { blake3.sum256(content.bytes())[..] }
		else {
			return error('MODULE_SRI_MALFORMED: unsupported algo `${algo}` (registry: sha256, sha384, sha512, blake3)')
		}
	}
	return '${algo}-${base64.encode(digest)}'
}

// ── Public entry: verify_sri ─────────────────────────────────────────────────

// verify_sri verifies an SRI integrity string per spec/lockfile.md
// §4.4 against the given content bytes. Returns true on match,
// false on shape-valid mismatch (the caller decides whether to
// raise CXER0209). Malformed SRI shape raises MODULE_SRI_MALFORMED.
//
// The SRI string MUST have the W3C form `<algo>-<base64>` with
// `algo` ∈ {`sha384`, `sha512`}. The base64 segment MUST decode to
// the expected digest length for the algorithm (48 bytes for
// sha384; 64 bytes for sha512).
pub fn verify_sri(integrity string, content string) !bool {
	parsed := verify_sri_shape(integrity)!
	// I1 stream 19 (L35): the SRI algo set is UNIFIED with the stdlib lane
	// against the one registry — sha256/sha384/sha512/blake3 (W3C dash
	// spelling; the divergence had the loader rejecting what the stdlib
	// accepted).
	computed_digest := match parsed.algo {
		'sha256' { sha256.sum256(content.bytes()) }
		'sha384' { sha512.sum384(content.bytes()) }
		'sha512' {
			d := sha512.sum512(content.bytes())
			d
		}
		'blake3' { blake3.sum256(content.bytes()) }
		else {
			return error('MODULE_SRI_MALFORMED: unsupported algo `${parsed.algo}` (registry: sha256, sha384, sha512, blake3)')
		}
	}
	if computed_digest.len != parsed.expected_digest.len {
		return false
	}
	for i, b in computed_digest {
		if b != parsed.expected_digest[i] {
			return false
		}
	}
	return true
}

// SriShape is the parsed shape of an SRI integrity string — the
// algo identifier plus the decoded binary digest bytes.
pub struct SriShape {
pub:
	algo            string
	expected_digest []u8
}

// verify_sri_shape parses an SRI integrity string and validates its
// structural shape (algo prefix + dash + base64 segment with correct
// decoded length). Does NOT compare against any content — that's
// the job of `verify_sri`. Used by `resolve_lib` to validate SRI
// shape pre-fetch even when the bytes are not yet available.
pub fn verify_sri_shape(integrity string) !SriShape {
	if integrity.len == 0 {
		return error('MODULE_SRI_MALFORMED: empty integrity string')
	}
	dash := integrity.index('-') or {
		return error('MODULE_SRI_MALFORMED: missing `-` separator in `${integrity}`')
	}
	if dash == 0 {
		return error('MODULE_SRI_MALFORMED: empty algo in `${integrity}`')
	}
	algo := integrity[..dash]
	b64 := integrity[dash + 1..]
	if b64.len == 0 {
		return error('MODULE_SRI_MALFORMED: empty base64 segment in `${integrity}`')
	}
	expected_len := match algo {
		'sha256' { 32 }
		'sha384' { 48 }
		'sha512' { 64 }
		'blake3' { 32 }
		else {
			return error('MODULE_SRI_MALFORMED: unsupported algo `${algo}` (registry: sha256, sha384, sha512, blake3)')
		}
	}
	decoded := base64.decode(b64)
	if decoded.len != expected_len {
		return error('MODULE_SRI_MALFORMED: ${algo} digest must decode to ${expected_len} bytes, got ${decoded.len}')
	}
	return SriShape{
		algo:            algo
		expected_digest: decoded
	}
}

// ── Internals: directive scanner ─────────────────────────────────────────────

// ModuleLoaderDirectiveKind discriminates the three top-level
// directive shapes the loader walks at Pass 1.
pub enum ModuleLoaderDirectiveKind {
	lib
	def
	const_
}

pub struct ModuleLoaderDirective {
pub:
	kind ModuleLoaderDirectiveKind
	text string
}

// ModuleLoaderSpanKind discriminates EVERY top-level bracket span the
// scanner walks: the three loader directives, any other `[?…]`
// directive (e.g. `[?cx …]`), and plain (non-directive) elements —
// the module's co-located doc blocks ([module-doc]/[fn-doc]) among
// them. Stream 18: `cx:ast` serves the plain spans as its `docs`
// array (verbatim source — each span parses cleanly as DATA on its
// own, where a whole-module data parse chokes on program-bearing
// def bodies).
pub enum ModuleLoaderSpanKind {
	lib
	def
	const_
	other_directive
	plain
}

pub struct ModuleLoaderSpan {
pub:
	kind ModuleLoaderSpanKind
	text string
}

// module_loader_scan_directives walks the module source string and
// returns the list of top-level `[?lib …]` / `[?def …]` /
// `[?const …]` directive forms in source order. Skips comments
// (`[; … ]`) and whitespace between directives. Other top-level
// content is permitted and silently ignored at Phase 2.13 partial
// (a future hardening pass will raise on stray text).
//
// The scanner is bracket-counting: it tracks `[` / `]` nesting and
// returns the verbatim outer-bracket span for each recognised
// directive. The directive head is matched by literal-prefix
// comparison against `[?lib`, `[?def`, `[?const`. (Layered over
// module_loader_scan_spans — ONE scanner, two views.)
pub fn module_loader_scan_directives(source string) ![]ModuleLoaderDirective {
	spans := module_loader_scan_spans(source)!
	mut out := []ModuleLoaderDirective{}
	for sp in spans {
		k := match sp.kind {
			.lib { ModuleLoaderDirectiveKind.lib }
			.def { ModuleLoaderDirectiveKind.def }
			.const_ { ModuleLoaderDirectiveKind.const_ }
			else { continue }
		}
		out << ModuleLoaderDirective{
			kind: k
			text: sp.text
		}
	}
	return out
}

// module_loader_scan_spans is the kinds-preserving scan: every
// top-level bracket span in source order, classified. Same skipping
// rules (whitespace, `#` line comments, `[; … ]` block comments,
// `[# … #]` raw blocks) and the same stray-`]` refusal.
pub fn module_loader_scan_spans(source string) ![]ModuleLoaderSpan {
	mut out := []ModuleLoaderSpan{}
	src := source.bytes()
	mut i := 0
	for i < src.len {
		c := src[i]
		// Skip whitespace.
		if c == ` ` || c == `\t` || c == `\n` || c == `\r` {
			i++
			continue
		}
		// Skip CX `#` line comments to end-of-line (#20): a commented-out
		// `[?lib]` / `[?def]` / `[?const]` must NOT be scanned as a real
		// directive on import, exactly as the direct-run lexer ignores it. At
		// the scanner's top level a `#` always begins a line comment (directives
		// are `[…]`, raw `[# … #]` blocks are skipped as a balanced span below).
		if c == `#` {
			for i < src.len && src[i] != `\n` {
				i++
			}
			continue
		}
		// Skip CX `[; … ]` block comments (the current comment form, depth-aware
		// over nested `[`…`]`). The body is OPAQUE prose, so — unlike a directive
		// span — it is NOT quote-shielded: an apostrophe in the prose (e.g.
		// "draft's") must not open a string span and swallow the closing `]`.
		// Mirrors the data reader's read_until_close (parser.v). Without this a
		// `[; … ]` comment fell through to find_close_bracket and mis-balanced.
		if i + 1 < src.len && c == `[` && src[i + 1] == `;` {
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
		if c == `]` {
			// A stray top-level `]` has no matching `[` — the module is
			// structurally malformed (grammar GR-STRAY-CLOSE; BareValue [L70]
			// excludes `]`, so it can never be prose either). Fail LOUDLY at
			// load: `cx fmt` and direct eval already reject this shape, and
			// silently skipping it here made the loader serve modules the
			// other entry points refuse (#289 — the xap-marine composer.cx
			// stray closer loaded and ran for weeks).
			return error('MODULE_PARSE: stray top-level `]` with no matching `[` at byte ${i} (GR-STRAY-CLOSE)')
		}
		if c != `[` {
			// Stray non-directive token at top level — skip ahead to
			// the next `[` to remain forward-tolerant. Future
			// hardening pass MAY raise.
			i++
			continue
		}
		// Classify the span by head prefix.
		mut kind := ModuleLoaderSpanKind.plain
		if i + 1 < src.len && src[i + 1] == `?` {
			kind = .other_directive
			if module_loader_starts_with(src, i, '[?lib') {
				// Disambiguate `[?lib` vs `[?libx`: require space or `]` after.
				next := if i + 5 < src.len { src[i + 5] } else { u8(0) }
				if next == ` ` || next == `\t` || next == `\n` || next == `\r` || next == `]` {
					kind = .lib
				}
			}
			if kind == .other_directive && module_loader_starts_with(src, i, '[?def') {
				next := if i + 5 < src.len { src[i + 5] } else { u8(0) }
				if next == ` ` || next == `\t` || next == `\n` || next == `\r` || next == `]` {
					kind = .def
				}
			}
			if kind == .other_directive && module_loader_starts_with(src, i, '[?const') {
				next := if i + 7 < src.len { src[i + 7] } else { u8(0) }
				if next == ` ` || next == `\t` || next == `\n` || next == `\r` || next == `]` {
					kind = .const_
				}
			}
		}
		// Locate end of bracket-balanced span (with quote-shielding).
		end := module_loader_find_close_bracket(src, i)!
		out << ModuleLoaderSpan{
			kind: kind
			text: src[i..end + 1].bytestr()
		}
		i = end + 1
	}
	return out
}

fn module_loader_starts_with(src []u8, pos int, lit string) bool {
	lb := lit.bytes()
	if pos + lb.len > src.len {
		return false
	}
	for j, b in lb {
		if src[pos + j] != b {
			return false
		}
	}
	return true
}

// module_loader_find_close_bracket returns the byte index of the
// `]` that closes the bracket opened at `start`. Handles nested
// brackets and shields against `[` / `]` appearing inside single-
// or double-quoted string literals. `#` line comments, `[; … ]`
// block comments, and `[#…#]` raw text inside the span are OPAQUE
// (#289): an apostrophe in a comment (`no-op'd`) must not open a
// string span and swallow the rest of the module — the shared
// recognizers in cx/lexical.v keep this scan byte-identical to the
// program lexer's skipping.
fn module_loader_find_close_bracket(src []u8, start int) !int {
	if start >= src.len || src[start] != `[` {
		return error('MODULE_PARSE: scanner asked to balance non-`[` byte at position ${start}')
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
		if cx.hash_line_comment_at(src, i) {
			i = cx.line_comment_end(src, i)
			continue
		}
		if i > start && cx.block_comment_open_at(src, i) {
			i = cx.block_comment_end(src, i) or {
				return error('MODULE_PARSE: unterminated `[; … ]` comment inside form starting at position ${start}')
			}
			continue
		}
		if i > start && cx.raw_span_open_at(src, i) {
			i = cx.raw_span_end(src, i) or {
				return error('MODULE_PARSE: unterminated `[#…#]` raw text inside form starting at position ${start}')
			}
			continue
		}
		// Triple-quoted raw string `"""…"""` — skip its whole span. Raw
		// (no escapes), so a `[`/`]` (or a `[?def`-looking token) inside a
		// co-located doc example is NOT counted toward bracket balance.
		if b == `"` && i + 2 < src.len && src[i + 1] == `"` && src[i + 2] == `"` {
			i += 3
			for i + 2 < src.len && !(src[i] == `"` && src[i + 1] == `"` && src[i + 2] == `"`) {
				i++
			}
			i += 3
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
	return error('MODULE_PARSE: unbalanced `[` starting at position ${start}')
}

// ── Internals: const toposort ────────────────────────────────────────────────

// module_loader_toposort_consts builds the reference graph over the
// `[?const]` declarations and returns a topological ordering per
//
// Edge construction: scan each const's value_source for bareword
// tokens; for every token that matches another const's name,
// record an edge `current → other`. This is a conservative
// over-approximation (it can pick up name collisions with locally-
// scoped barewords) but is sufficient at Phase 2.13 partial for
// the dependency-order contract — full cx.ProgramExpr scope-aware
// reference extraction is the Phase 2.x graft.
//
// Topological sort: Kahn's algorithm. Stable wrt source order when
// no dependency edges constrain the result.
//
// Errors:
//   - "MODULE_CONST_CYCLE: ..."  : the const reference graph contains
//                                  a cycle. Surfaces as CXER0214 at
// the boundary.
fn module_loader_toposort_consts(consts map[string]cx.ConstNode) ![]string {
	mut names := []string{}
	for k, _ in consts {
		names << k
	}
	// Edges: name → list-of-deps (names referenced by name's body).
	mut deps := map[string][]string{}
	for k, c in consts {
		mut my_deps := []string{}
		tokens := module_loader_extract_barewords(c.value_source)
		for tok in tokens {
			if tok == k {
				continue
			}
			if tok in consts {
				my_deps << tok
			}
		}
		deps[k] = my_deps
	}
	// In-degree count.
	mut indeg := map[string]int{}
	for n in names {
		indeg[n] = 0
	}
	for n in names {
		for d in deps[n] {
			indeg[d] = (indeg[d] or { 0 }) + 1
		}
	}
	// Kahn: repeatedly emit nodes with zero in-degree.
	mut out := []string{}
	mut ready := []string{}
	for n in names {
		if (indeg[n] or { 0 }) == 0 {
			ready << n
		}
	}
	for ready.len > 0 {
		// Pop deterministically (use source-order stability by
		// scanning the ready list for the lexicographically smallest
		// — guarantees test determinism without an explicit source-
		// order index).
		mut best := 0
		for j in 1 .. ready.len {
			if ready[j] < ready[best] {
				best = j
			}
		}
		n := ready[best]
		ready.delete(best)
		out << n
		for d in deps[n] {
			indeg[d] = (indeg[d] or { 0 }) - 1
			if indeg[d] == 0 {
				ready << d
			}
		}
	}
	if out.len != names.len {
		// At least one cycle remains.
		mut stuck := []string{}
		for n in names {
			if (indeg[n] or { 0 }) > 0 {
				stuck << n
			}
		}
		return error('MODULE_CONST_CYCLE: cyclic [?const] dependency among ${stuck.join(" → ")} (CXER0214)')
	}
	// Reverse: Kahn's algorithm as written emits roots first (consts
	// with no inbound edges). For evaluation order we want
	// dependencies-first — so emit in reverse: leaves first.
	mut rev := []string{cap: out.len}
	for j := out.len - 1; j >= 0; j-- {
		rev << out[j]
	}
	return rev
}

// module_loader_extract_barewords returns the list of bareword
// tokens (`[A-Za-z_][A-Za-z0-9_?!-]*`) in the given source string.
// Quote-shielded: tokens inside `'…'` / `"…"` are NOT extracted.
// Used by toposort to identify const-to-const reference edges.
fn module_loader_extract_barewords(src string) []string {
	mut out := []string{}
	bytes := src.bytes()
	mut i := 0
	mut in_str := u8(0)
	for i < bytes.len {
		b := bytes[i]
		if in_str != 0 {
			if b == `\\` && i + 1 < bytes.len {
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
		if module_loader_is_name_start(b) {
			start := i
			i++
			for i < bytes.len && module_loader_is_name_cont(bytes[i]) {
				i++
			}
			out << bytes[start..i].bytestr()
			continue
		}
		i++
	}
	return out
}

@[inline]
fn module_loader_is_name_start(b u8) bool {
	return (b >= `a` && b <= `z`) || (b >= `A` && b <= `Z`) || b == `_`
}

@[inline]
fn module_loader_is_name_cont(b u8) bool {
	return module_loader_is_name_start(b) || (b >= `0` && b <= `9`) || b == `-` || b == `?`
		|| b == `!`
}

// ── Internals: file I/O ──────────────────────────────────────────────────────

// module_loader_read_file resolves a file-path resolver under
// `base_dir`. Absolute paths (leading `/`) are read as-is;
// relative paths (`./…` / `../…`) are joined to `base_dir`. Empty
// `base_dir` falls back to the V process's CWD.
fn module_loader_read_file(path string, base_dir string) !string {
	full := if path.starts_with('/') {
		path
	} else if base_dir == '' {
		path
	} else {
		os.join_path(base_dir, path)
	}
	if !os.exists(full) {
		return error('file `${full}` does not exist')
	}
	return os.read_file(full)
}

// ── Internals: cycle path formatter ──────────────────────────────────────────

// module_loader_cycle_path builds the human-readable cycle path
// `A → B → C → A` for the MODULE_CYCLE_DETECTED error message.
// The current `in_flight_order` is the load-stack at the point of
// detection; `name` is the just-attempted re-entry that closes the
// cycle.
fn module_loader_cycle_path(table ModuleTable, name string) string {
	mut parts := []string{}
	mut started := false
	for n in table.in_flight_order {
		if n == name {
			started = true
		}
		if started {
			parts << n
		}
	}
	if parts.len == 0 {
		// Fallback — cycle root not in current stack (shouldn't
		// happen but stay defensive).
		parts << name
	}
	parts << name
	return parts.join(' → ')
}

// ── Hidden-fix: silence unused-import warning if sha256 not used ─────────────

// Reference sha256 so the import survives a future hashing-API
// change. The crypto.sha256 import is currently load-bearing for
// disjoint-domain hashing across the AST layer; we don't compute
// SHA-256 here but keep the import paired with sha512 for symmetry
// with the future hash-suite expansion.
const _module_loader_sha256_guard = sha256.sum256('cx.module-loader'.bytes()).hex()
