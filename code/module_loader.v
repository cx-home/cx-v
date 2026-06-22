module code

import cx
import crypto.sha256
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
//       - https_url        : returns MODULE_HTTPS_FETCH_DEFERRED. The
//                            SRI shape is still verified pre-fetch
//                            against the lockfile (validates the
//                            algo-base64 form per spec/lockfile.md
//                            §4.4).
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
// Scope simplifications at Phase 2.13 + 2.14 partial (deferred):
//
//   - HTTPS fetch is deferred (returns MODULE_HTTPS_FETCH_DEFERRED).
//     SRI shape is still verified pre-fetch.
//   - No on-disk module cache (Phase 2.x graft).
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
//   - Lockfile-driven SRI verification is wired through `verify_sri`
//     but the loader does not yet consult the lockfile to look up
//     the recorded SRI for a given resolver — the harness drives
//     `verify_sri` directly at Phase 2.14 partial.
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
// MODULE_HTTPS_FETCH_DEFERRED — the loader has resolved the HTTPS
// resolver shape (and validated any associated SRI shape) but
// declines to actually fetch the bytes at this phase. Phase 2.14
// graft replaces this with a real HTTP client + on-disk cache.
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
//   - MODULE_HTTPS_FETCH_DEFERRED: the resolver_kind is `https_url`.
//                                  SRI shape (if a lockfile entry
//                                  exists) is still validated before
//                                  raising this.
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
			s := table.registered_sources[name] or {
				return error('MODULE_UNKNOWN_REGISTERED: registered name `${name}` has no in-memory source (CXER0213)')
			}
			s
		}
		.https_url {
			// SRI shape validation — pre-fetch. If the lockfile carries
			// a `:sri` entry for this resolver, ensure its shape parses.
			if lf := table.lockfile {
				for ml in lf.modules {
					if ml.name == name {
						if sri := ml.integrity {
							verify_sri_shape(sri) or {
								return error('MODULE_SRI_MALFORMED: lockfile :sri for `${name}` is malformed: ${err}')
							}
						}
					}
				}
			}
			// In-memory test source for a pinned HTTPS resolver: an
			// in-memory test module keyed by its literal URL, NOT a live
			// fetch (real HTTPS fetch + on-disk cache is deferred per
			// §12.4.2). When no in-memory source is registered, the fetch
			// is still deferred.
			if s := table.registered_sources[name] {
				s
			} else {
				return error('MODULE_HTTPS_FETCH_DEFERRED: HTTPS fetch deferred to Phase 2.14 graft (resolver=`${name}`)')
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
	computed_digest := match parsed.algo {
		'sha384' { sha512.sum384(content.bytes()) }
		'sha512' {
			d := sha512.sum512(content.bytes())
			d
		}
		else {
			return error('MODULE_SRI_MALFORMED: unsupported algo `${parsed.algo}` (expected sha384 or sha512)')
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
		'sha384' { 48 }
		'sha512' { 64 }
		else {
			return error('MODULE_SRI_MALFORMED: unsupported algo `${algo}` (expected sha384 or sha512)')
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
enum ModuleLoaderDirectiveKind {
	lib
	def
	const_
}

struct ModuleLoaderDirective {
	kind ModuleLoaderDirectiveKind
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
// comparison against `[?lib`, `[?def`, `[?const`.
fn module_loader_scan_directives(source string) ![]ModuleLoaderDirective {
	mut out := []ModuleLoaderDirective{}
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
		if c != `[` {
			// Stray non-directive token at top level — skip ahead to
			// the next `[` to remain forward-tolerant. Future
			// hardening pass MAY raise.
			i++
			continue
		}
		// Identify directive kind by head prefix.
		mut kind := ?ModuleLoaderDirectiveKind(none)
		if module_loader_starts_with(src, i, '[?lib') {
			// Disambiguate `[?lib` vs `[?libx`: require space or `]` after.
			next := if i + 5 < src.len { src[i + 5] } else { u8(0) }
			if next == ` ` || next == `\t` || next == `\n` || next == `\r` || next == `]` {
				kind = ModuleLoaderDirectiveKind.lib
			}
		}
		if kind == none && module_loader_starts_with(src, i, '[?def') {
			next := if i + 5 < src.len { src[i + 5] } else { u8(0) }
			if next == ` ` || next == `\t` || next == `\n` || next == `\r` || next == `]` {
				kind = ModuleLoaderDirectiveKind.def
			}
		}
		if kind == none && module_loader_starts_with(src, i, '[?const') {
			next := if i + 7 < src.len { src[i + 7] } else { u8(0) }
			if next == ` ` || next == `\t` || next == `\n` || next == `\r` || next == `]` {
				kind = ModuleLoaderDirectiveKind.const_
			}
		}
		// Locate end of bracket-balanced span (with quote-shielding).
		end := module_loader_find_close_bracket(src, i)!
		if k := kind {
			text := src[i..end + 1].bytestr()
			out << ModuleLoaderDirective{
				kind: k
				text: text
			}
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
// or double-quoted string literals.
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
