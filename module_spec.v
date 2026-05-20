module cx

// ── ModuleSpec catalog ───────────────────────────────────────────────────────
//
// Per ADR 0023 §D2 (revised per Amendment #2 R3): the v0.7.0 module
// surface (cx:, log:, inspect:, plus existing fn:/map:/array:/math:)
// is described by a parallel read-only catalog populated alongside —
// not replacing — the flat filter-dispatch switch at cxl.v:2014-2236.
//
// The catalog is the metadata surface that
//   * inspect:module-available / inspect:module-version / inspect:functions
//   * [?cx use-module=...] activation
//   * [?cx pure-only] determinism enforcement
//   * cx:eval module-pass-through gate (M4)
// read at runtime. The dispatch table is still where the call lands.
//
// Population is intentionally minimal at EE1:
//   * Every v0.7.0 module gets a ModuleSpec row with its default purity
//     and activation mode.
//   * cx: and log: get full per-function listings (DD/FF rows) so that
//     EE4's pure-only enforcement and inspect:functions("cx") can answer
//     correctly before DD/FF lands the actual dispatch arms.
//   * fn:/map:/array:/math: get module-level default purity only.
//     Per-function purity overrides for fn: (current-dateTime, doc, …)
//     are added incrementally as EE4 needs them; for v0.7.0 the
//     module-level Pure default is correct for the vast majority and
//     ReadOnly outliers are flagged in fn_purity_overrides.
//
// Mutation policy: the catalog is built once and treated as immutable.
// At v0.7.0 there is no runtime registration path — foreign-callback
// host extension is D12 / out of scope. v0.8.0+ may evolve the catalog
// into a true registry; the v0.7.0 read-only API is forward-compatible.

pub enum Purity {
	pure_fn      // deterministic; inputs → output, no ambient state read or mutated
	read_only    // reads ambient state (clock, env, fs) but does not mutate
	side_effect  // mutates or emits to ambient state
}

pub enum Activation {
	always           // module is callable without [?cx use-module=...]
	on_declaration   // module must be activated via [?cx use-module=...] before use
}

// FunctionSpec records the metadata for one callable in a module.
// arity_max == -1 signals an unbounded variadic tail. purity may
// differ from the parent module's default_purity (e.g. log:level is
// ReadOnly inside an otherwise SideEffect module).
pub struct FunctionSpec {
pub:
	local_name string
	arity_min  int
	arity_max  int    // -1 → unbounded
	purity     Purity
}

pub struct ModuleSpec {
pub:
	ns_prefix       string
	version         string
	default_purity  Purity
	activation      Activation
	functions       []FunctionSpec
}

// build_module_catalog constructs the v0.7.0 module catalog. Called
// once per process at first lookup (see module_catalog_cached).
fn build_module_catalog() map[string]ModuleSpec {
	mut catalog := map[string]ModuleSpec{}

	// ── cx: self-host module (DD1–DD22, ADR 0023 §D1) ──────────────────
	catalog['cx'] = ModuleSpec{
		ns_prefix:      'cx'
		version:        '0.7.0'
		default_purity: .pure_fn
		activation:     .always
		functions: [
			// Must (DD1–DD10)
			FunctionSpec{ local_name: 'parse',              arity_min: 1, arity_max: 1, purity: .pure_fn }
			FunctionSpec{ local_name: 'serialize',          arity_min: 1, arity_max: 1, purity: .pure_fn }
			FunctionSpec{ local_name: 'canonical',          arity_min: 1, arity_max: 1, purity: .pure_fn }
			FunctionSpec{ local_name: 'hash',               arity_min: 1, arity_max: 1, purity: .pure_fn }
			FunctionSpec{ local_name: 'diff',               arity_min: 2, arity_max: 2, purity: .pure_fn }
			FunctionSpec{ local_name: 'patch',              arity_min: 2, arity_max: 2, purity: .pure_fn }
			FunctionSpec{ local_name: 'to-format',          arity_min: 2, arity_max: 2, purity: .pure_fn }
			FunctionSpec{ local_name: 'from-format',        arity_min: 2, arity_max: 2, purity: .pure_fn }
			FunctionSpec{ local_name: 'equal',              arity_min: 2, arity_max: 2, purity: .pure_fn }
			FunctionSpec{ local_name: 'select',             arity_min: 2, arity_max: 2, purity: .pure_fn }
			// Should (DD11–DD18)
			FunctionSpec{ local_name: 'eval',               arity_min: 2, arity_max: 3, purity: .side_effect }
			FunctionSpec{ local_name: 'render',             arity_min: 2, arity_max: 2, purity: .side_effect }
			FunctionSpec{ local_name: 'schema-of',          arity_min: 1, arity_max: 1, purity: .pure_fn }
			FunctionSpec{ local_name: 'validate',           arity_min: 2, arity_max: 2, purity: .pure_fn }
			FunctionSpec{ local_name: 'anchors',            arity_min: 1, arity_max: 1, purity: .pure_fn }
			FunctionSpec{ local_name: 'ids',                arity_min: 1, arity_max: 1, purity: .pure_fn }
			FunctionSpec{ local_name: 'references',         arity_min: 1, arity_max: 1, purity: .pure_fn }
			FunctionSpec{ local_name: 'resolve-includes',   arity_min: 2, arity_max: 2, purity: .read_only }
			// Nice (DD19–DD22)
			FunctionSpec{ local_name: 'merge',              arity_min: 2, arity_max: 3, purity: .pure_fn }
			FunctionSpec{ local_name: 'strip-comments',     arity_min: 1, arity_max: 1, purity: .pure_fn }
			FunctionSpec{ local_name: 'strip-attrs',        arity_min: 2, arity_max: 2, purity: .pure_fn }
			FunctionSpec{ local_name: 'pretty-print',       arity_min: 1, arity_max: 2, purity: .pure_fn }
		]
	}

	// ── log: structured-logging module (FF1–FF7, ADR 0023 §D10) ────────
	catalog['log'] = ModuleSpec{
		ns_prefix:      'log'
		version:        '0.7.0'
		default_purity: .side_effect
		activation:     .always
		functions: [
			FunctionSpec{ local_name: 'trace',         arity_min: 1, arity_max: 2, purity: .side_effect }
			FunctionSpec{ local_name: 'debug',         arity_min: 1, arity_max: 2, purity: .side_effect }
			FunctionSpec{ local_name: 'info',          arity_min: 1, arity_max: 2, purity: .side_effect }
			FunctionSpec{ local_name: 'warn',          arity_min: 1, arity_max: 2, purity: .side_effect }
			FunctionSpec{ local_name: 'error',         arity_min: 1, arity_max: 2, purity: .side_effect }
			FunctionSpec{ local_name: 'level',         arity_min: 0, arity_max: 0, purity: .read_only }
			FunctionSpec{ local_name: 'with-context',  arity_min: 2, arity_max: 2, purity: .side_effect }
		]
	}

	// ── inspect: module-discovery module (DD13 / EE7 reference) ───────
	// Per ADR 0023 §D4-revised: per-module presence lives at the cxl
	// level (inspect:) rather than at the ABI level. Surface registered
	// here so EE6 binding wiring can expose it through the C ABI.
	catalog['inspect'] = ModuleSpec{
		ns_prefix:      'inspect'
		version:        '0.7.0'
		default_purity: .pure_fn
		activation:     .always
		functions: [
			FunctionSpec{ local_name: 'module-available',  arity_min: 1, arity_max: 1, purity: .pure_fn }
			FunctionSpec{ local_name: 'module-version',    arity_min: 1, arity_max: 1, purity: .pure_fn }
			FunctionSpec{ local_name: 'functions',         arity_min: 1, arity_max: 1, purity: .pure_fn }
		]
	}

	// ── fn: XQuery 4.0 standard library (C row, ~80 functions) ────────
	// Module-level default Pure is correct for ~95% of fn: callables.
	// ReadOnly outliers (clock/env/fs) listed for EE4 enforcement;
	// per-function exhaustive enumeration is deferred — fn_function_spec
	// returns a synthetic Pure FunctionSpec for any unlisted local name
	// dispatched through the flat switch.
	catalog['fn'] = ModuleSpec{
		ns_prefix:      'fn'
		version:        '0.7.0'
		default_purity: .pure_fn
		activation:     .always
		functions: [
			// Clock / time (C14/C15) — ReadOnly
			FunctionSpec{ local_name: 'current-date',     arity_min: 0, arity_max: 0, purity: .read_only }
			FunctionSpec{ local_name: 'current-time',     arity_min: 0, arity_max: 0, purity: .read_only }
			FunctionSpec{ local_name: 'current-dateTime', arity_min: 0, arity_max: 0, purity: .read_only }
			// Environment (C21) — ReadOnly
			FunctionSpec{ local_name: 'environment-variable', arity_min: 1, arity_max: 1, purity: .read_only }
			// Document I/O (C21) — ReadOnly (no-ops at v0.7.0 per ADR 0023 R4)
			FunctionSpec{ local_name: 'doc',              arity_min: 1, arity_max: 1, purity: .read_only }
			FunctionSpec{ local_name: 'doc-available',    arity_min: 1, arity_max: 1, purity: .read_only }
			// fn:trace (C17) — SideEffect technically, but pure-only-exempt
			// per ADR 0023 §D10 / spec/modules/log.md §3. Reflected here as
			// SideEffect; the exemption logic lives in pure-only enforcement.
			FunctionSpec{ local_name: 'trace',            arity_min: 1, arity_max: 2, purity: .side_effect }
			FunctionSpec{ local_name: 'error',            arity_min: 0, arity_max: 3, purity: .side_effect }
		]
	}

	// ── map: XPath 3.1 maps (D1, 8 functions, all Pure) ────────────────
	catalog['map'] = ModuleSpec{
		ns_prefix:      'map'
		version:        '0.7.0'
		default_purity: .pure_fn
		activation:     .always
		functions: []  // module-level default is sufficient at v0.7.0
	}

	// ── array: XPath 3.1 arrays (D2, 11 functions, all Pure) ───────────
	catalog['array'] = ModuleSpec{
		ns_prefix:      'array'
		version:        '0.7.0'
		default_purity: .pure_fn
		activation:     .always
		functions: []
	}

	// ── math: XPath 3.0 math (C16, 15 functions, all Pure) ─────────────
	catalog['math'] = ModuleSpec{
		ns_prefix:      'math'
		version:        '0.7.0'
		default_purity: .pure_fn
		activation:     .always
		functions: []
	}

	return catalog
}

// module_catalog returns the v0.7.0 module catalog. The catalog is
// rebuilt on each call at v0.7.0 — cost is dominated by ~30 struct
// literals (~microseconds). EE4 may move to a cached singleton once
// pure-only enforcement starts calling this on the hot path. Tests
// rely on the rebuild-each-call shape, which lets fixture-time
// catalog manipulation stay scoped.
pub fn module_catalog() map[string]ModuleSpec {
	return build_module_catalog()
}

// module_spec returns the ModuleSpec for ns_prefix, or none if no
// module of that name is registered at v0.7.0. Used by EE2
// activation-directive enforcement and DD13 inspect:module-available.
pub fn module_spec(ns_prefix string) ?ModuleSpec {
	catalog := build_module_catalog()
	return catalog[ns_prefix] or { return none }
}

// function_spec returns the FunctionSpec for ns_prefix:local_name,
// or none if neither the module nor the function is registered.
//
// Resolution order:
//   1. Look up module by ns_prefix; none → return none.
//   2. Scan module.functions for matching local_name; hit → return it.
//   3. Fall through to a synthetic FunctionSpec inheriting the
//      module's default_purity. This is the "fn:/map:/array:/math:
//      unlisted local" case — the flat dispatch still answers the
//      call; the catalog just reports the module-level purity.
//      arity_min/max are 0/-1 (unbounded) on the synthetic record
//      because we don't enumerate fn: function arities here.
pub fn function_spec(ns_prefix string, local_name string) ?FunctionSpec {
	mod := module_spec(ns_prefix) or { return none }
	for f in mod.functions {
		if f.local_name == local_name {
			return f
		}
	}
	return FunctionSpec{
		local_name: local_name
		arity_min:  0
		arity_max:  -1
		purity:     mod.default_purity
	}
}

// purity_label returns the lowercase canonical name of a Purity tag,
// for use in error messages and the inspect: surface. Matches the
// vocabulary used by [?cx pure-only] enforcement and the cx-err:
// CXER0040 error message.
pub fn purity_label(p Purity) string {
	return match p {
		.pure_fn     { 'pure' }
		.read_only   { 'read-only' }
		.side_effect { 'side-effect' }
	}
}

// is_module_active reports whether ns_prefix is callable in the
// current document scope. At v0.7.0 every registered module has
// activation == .always, so this is a presence check; v0.8.0+ on-
// demand modules will additionally consult the document's active
// module set (per [?cx use-module=...]).
pub fn is_module_active(ns_prefix string, declared_modules []string) bool {
	mod := module_spec(ns_prefix) or { return false }
	if mod.activation == .always {
		return true
	}
	return ns_prefix in declared_modules
}
