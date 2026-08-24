@[has_globals]
module code

import cx

// ring_registry.v — the Ring-1 side of the I3 Ring-1/2 dispatch seam
// (#651/#516, cx_partition.md §3; ledger census note N1).
//
// Before I3, stdlib_builtin (stdlib_dispatch.v) and stdlib_builtin_env
// (eval.v) were STATIC chains of direct calls — the evaluator held
// compile-time references to every Ring-2 pack (store, sql, net, http,
// bus, journal, fabric, session, authz, did, vc, xap, xsp, …), which
// inverts the §3 import contract (Ring 1 MUST NOT import Ring 2). This
// registry turns those references around: Ring-2 packs REGISTER their
// dispatch entries here at module-init time (ring2_register.v today;
// the Ring-2 module's own init() once the files move out), and the
// Ring-1 chains probe the registry at the positions the direct calls
// used to occupy.
//
// Ordering note (why one probe point per chain is enough): every
// registered entry is name-gated — it returns `none` unless the verb
// name belongs to its own pack, and pack name-sets are disjoint by
// construction (module-prefixed primitive names). Collapsing the
// interleaved chain positions into one probe point therefore changes
// no observable dispatch outcome; the registry preserves the ORIGINAL
// relative order of the ring-2 entries regardless, so even a future
// (accidental) overlap resolves exactly as the pre-split chain did.
//
// Two env lists exist because the pre-split chains had two
// compositions: the MAIN chain (stdlib_builtin_env) probed serve-file
// + store's env paths, the closure-callback chain
// (try_stdlib_builtin_env) did not. The split preserves that split —
// behavior-identical refactor, no reachability widening.

pub type Ring2Builtin = fn (name string, args []cx.Node) ?cx.Node

pub type Ring2BuiltinEnv = fn (name string, args []cx.Node, mut env MatchEnv) ?cx.Node

// Ring2Directive — a [?directive] handler (the services family: the
// eval_directive match probes the map for names it does not own).
pub type Ring2Directive = fn (d cx.ProgramDirective, mut env MatchEnv) !cx.Node

// Ring2WaitForService — the [?wait-for :service] arm.
pub type Ring2WaitForService = fn (handle_node cx.ProgramNode, mut env MatchEnv) !cx.Node

// Ring2ClientCall — the [http-client] postfix-call dispatcher probed by
// dispatch_call_fallback when the first argument is an [http-client].
pub type Ring2ClientCall = fn (name string, target_val cx.Node, args []cx.Node, mut env MatchEnv) ?cx.Node

// Ring2PkgSource — the pkg: module-source resolver (distribution
// engine); the module loader probes it for .pkg_url references.
pub type Ring2PkgSource = fn (ref string) !string

// Ring2EnvReset — a per-program server-held-state reset run by new_env.
pub type Ring2EnvReset = fn ()

// Ring2IterWalk / Ring2IterWalkStreamed — live-source iterator walkers
// ([?for] over net accept / http accept / SSE frames / net lines /
// chunks), keyed by cx.IteratorSourceKind. The Ring-1 kinds
// (.iter_iterate / .iter_unfold) never enter the registry.
pub type Ring2IterWalk = fn (source_val cx.IteratorNode, c cx.ProgramForClause, clauses []cx.ProgramForClause, idx int, spec YieldSpec, mut env MatchEnv, mut out []cx.Node, mut limit_state ForLimitState) !

pub type Ring2IterWalkStreamed = fn (source_val cx.IteratorNode, c cx.ProgramForClause, clauses []cx.ProgramForClause, idx int, spec YieldSpec, mut env MatchEnv, mut ctx StreamCtx, mut limit_state ForLimitState) !

// Ring2SubOps — the delivery.md §4 consumption seam: a Ring-2 subscription
// kind claims the core consumption verbs for its handle element (keyed by
// element name, e.g. 'live-sub'), so `[?receive]` and `[?select]`'s
// receive-readiness accept the handle exactly as they accept a channel.
// `[?close]` needs no arm here: a registered subscription handle carries the
// `__cx_close_id__` close-contract stamp (SAP §5.1), and [?close] fires it.
// First consumer: cx-stdlib/live's observe handle (stream 3, #675); #762
// generalizes the same arms across every §4 instance.
//   receive: max=0 → the unbatched form (one delivery); max>0 → the U1.12a
//   batch form (returns the sequence received, up to max, waiting up to
//   deadline_ms; deadline_ms=-1 → no deadline).
//   ready: answers "is a delivery available without blocking" (the §4
//   readiness clause) — MUST NOT consume.
pub struct Ring2SubOps {
pub:
	receive fn (sub cx.Node, max int, deadline_ms i64, mut env MatchEnv) cx.Node = unsafe { nil }
	ready   fn (sub cx.Node, mut env MatchEnv) bool = unsafe { nil }
}

__global (
	g_ring2_impure_names     map[string]bool
	g_ring2_builtins         []Ring2Builtin
	g_ring2_env_shared       []Ring2BuiltinEnv
	g_ring2_env_main         []Ring2BuiltinEnv
	g_ring2_directives       map[string]Ring2Directive
	g_ring2_wait_for_service []Ring2WaitForService
	g_ring2_client_call      []Ring2ClientCall
	g_ring2_pkg_source       []Ring2PkgSource
	g_ring2_env_resets       []Ring2EnvReset
	g_ring2_iter_walks          map[int]Ring2IterWalk
	g_ring2_iter_walks_streamed map[int]Ring2IterWalkStreamed
	g_ring2_sub_ops             map[string]Ring2SubOps
)

// ring_registry_init makes every registry container live. Called FIRST
// from the module init(), before any registration (maps need an explicit
// make; the array zero value is usable but is initialized here too so
// the registry has exactly one lifecycle).
fn ring_registry_init() {
	g_ring2_builtins = []Ring2Builtin{}
	g_ring2_env_shared = []Ring2BuiltinEnv{}
	g_ring2_env_main = []Ring2BuiltinEnv{}
	g_ring2_directives = map[string]Ring2Directive{}
	g_ring2_wait_for_service = []Ring2WaitForService{}
	g_ring2_client_call = []Ring2ClientCall{}
	g_ring2_pkg_source = []Ring2PkgSource{}
	g_ring2_env_resets = []Ring2EnvReset{}
	g_ring2_iter_walks = map[int]Ring2IterWalk{}
	g_ring2_iter_walks_streamed = map[int]Ring2IterWalkStreamed{}
	g_ring2_sub_ops = map[string]Ring2SubOps{}
}

// ring2_builtin_register appends an env-free pack dispatcher
// (`<mod>_stdlib_builtin` shape) to the chain stdlib_builtin probes.
pub fn ring2_builtin_register(f Ring2Builtin) {
	g_ring2_builtins << f
}

// ring2_env_register_shared appends an env-aware pack dispatcher probed
// by BOTH stdlib_builtin_env and try_stdlib_builtin_env (the pre-split
// membership of http/bus/journal/fabric/xap).
pub fn ring2_env_register_shared(f Ring2BuiltinEnv) {
	g_ring2_env_shared << f
}

// ring2_env_register_main appends an env-aware pack dispatcher probed
// ONLY by the main stdlib_builtin_env chain (pre-split membership:
// serve-file, store's modify-doc closure path).
pub fn ring2_env_register_main(f Ring2BuiltinEnv) {
	g_ring2_env_main << f
}

// ring2_stdlib_builtin probes the registered env-free chain.
fn ring2_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	for f in g_ring2_builtins {
		if r := f(name, args) {
			return r
		}
	}
	return none
}

// ring2_stdlib_builtin_env_main probes main-only entries, then shared.
fn ring2_stdlib_builtin_env_main(name string, args []cx.Node, mut env MatchEnv) ?cx.Node {
	for f in g_ring2_env_main {
		if r := f(name, args, mut env) {
			return r
		}
	}
	for f in g_ring2_env_shared {
		if r := f(name, args, mut env) {
			return r
		}
	}
	return none
}

// ring2_stdlib_builtin_env_shared probes shared entries only (the
// closure-callback chain's pre-split membership).
fn ring2_stdlib_builtin_env_shared(name string, args []cx.Node, mut env MatchEnv) ?cx.Node {
	for f in g_ring2_env_shared {
		if r := f(name, args, mut env) {
			return r
		}
	}
	return none
}

// ── directive / slot hooks ───────────────────────────────────────────

// ring2_directive_register claims a [?name] the pure-functional
// evaluator subset does not own.
pub fn ring2_directive_register(name string, f Ring2Directive) {
	g_ring2_directives[name] = f
}

pub fn ring2_wait_for_service_register(f Ring2WaitForService) {
	g_ring2_wait_for_service << f
}

pub fn ring2_client_call_register(f Ring2ClientCall) {
	g_ring2_client_call << f
}

pub fn ring2_pkg_source_register(f Ring2PkgSource) {
	g_ring2_pkg_source << f
}

// ring2_env_reset_register adds a per-program state reset run by
// new_env (the pre-split direct calls: session, authz).
pub fn ring2_env_reset_register(f Ring2EnvReset) {
	g_ring2_env_resets << f
}

// ring2_run_env_resets — new_env's probe.
fn ring2_run_env_resets() {
	for f in g_ring2_env_resets {
		f()
	}
}

// ring2_iter_walk_register claims a live-source iterator kind (both
// variants registered together — every Ring-2 source has both).
pub fn ring2_iter_walk_register(kind cx.IteratorSourceKind, w Ring2IterWalk, ws Ring2IterWalkStreamed) {
	g_ring2_iter_walks[int(kind)] = w
	g_ring2_iter_walks_streamed[int(kind)] = ws
}

// ring2_sub_ops_register claims a subscription handle element name for the
// delivery.md §4 consumption verbs.
pub fn ring2_sub_ops_register(kind string, ops Ring2SubOps) {
	g_ring2_sub_ops[kind] = ops
}

// ring2_sub_ops_for probes the registry by the value's element name —
// [?receive]/[?select]/[?close]'s subscription arm.
fn ring2_sub_ops_for(n cx.Node) ?Ring2SubOps {
	if n is cx.Element {
		if ops := g_ring2_sub_ops[n.name] {
			return ops
		}
	}
	return none
}

// ring2_impure_register feeds Ring-2 pack verb names into the Ring-1
// purity classification (stream 10, the anti-2PC guard's discovery: an
// UNCLASSIFIED callee defaults to pure, so a fold fn reaching a Ring-2
// verb — [$journal:read] inside a reducer, the 2PC-shaped coordinator
// read — slipped the CXER4611 guard and deadlocked on the pack's own
// mutex instead of refusing loud). The same seam pattern as the dispatch
// registration: Ring 2 declares, Ring 1 consults, no ring names cross.
pub fn ring2_impure_register(names []string) {
	for n in names {
		g_ring2_impure_names[n] = true
	}
}

pub fn ring2_is_impure(name string) bool {
	return g_ring2_impure_names[name] or { false }
}

// ring2_impure_names returns every Ring-2 verb the packs have declared
// impure, sorted. Exposed for the DGX-1 effect graph
// (ledger/rulings_2026_08_21_diagram_capabilities.md): a Ring-2 verb's
// CAPABILITY charge is made inside the pack and is not in the static
// §2.1 effect-point table, so the graph must render it as an explicit
// opacity source rather than classify it — which it can only do if it
// can tell a Ring-2 verb apart from an ordinary pure name.
pub fn ring2_impure_names() []string {
	mut out := []string{}
	for n, _ in g_ring2_impure_names {
		out << n
	}
	out.sort()
	return out
}
