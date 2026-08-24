module platform
import code {
	Ring2SubOps,
	ring2_builtin_register,
	ring2_impure_register,
	ring2_client_call_register,
	ring2_directive_register,
	ring2_env_register_main,
	ring2_env_register_shared,
	ring2_env_reset_register,
	ring2_iter_walk_register,
	ring2_pkg_source_register,
	ring2_sub_ops_register,
	ring2_wait_for_service_register,
}

// ring2_register.v — the Ring-2 side of the I3 dispatch seam
// (#651/#516; see ring_registry.v for the design and the ordering
// argument). This file is RING 2: it names every Ring-2 pack
// dispatcher and wires it into the Ring-1 registry. It lives in
// `module code` only until the Ring-2 module split lands — then it
// moves out verbatim and becomes (part of) that module's init(),
// at which point `code` retains zero compile-time references to any
// symbol in this list and the §3 import gate can enforce the seam
// textually.
//
// Registration order = the pre-split chain order, preserved exactly
// (stdlib_dispatch.v's chain for the env-free list; eval.v's
// stdlib_builtin_env for the env lists).

// ring2_register_all wires every Ring-2 pack dispatcher. Called once
// from the module init() (stdlib_codec.v) before any evaluation.
fn ring2_register_all() {
	// Purity classification (stream 10): the IMPURE verb names of the
	// journal + store packs, from each wrapping [?def]'s declared purity
	// in stdlib/{journal,store}.cx — so a pure-required context (a fold
	// reducer, a pure [?def]) reaching one refuses loud instead of
	// slipping the unclassified-callee=pure default. The remaining packs'
	// lists ride the completeness sweep (filed at stream-10 W5).
	ring2_impure_register([
		// journal (everything except the pure reads: head, fold-value,
		// temporal-slice, upcast, lineage-path, overlaps, contains-instant)
		'journal-open', 'journal-attach', 'journal-close', 'journal-append',
		'journal-read', 'journal-slice', 'journal-since', 'journal-query',
		'journal-source', 'journal-head-fresh', 'journal-subscribe',
		'journal-seq-at', 'journal-streams', 'journal-fold',
		'journal-fold-slice', 'journal-legal-holds', 'journal-erase-subject',
		'journal-ingest-stream', 'journal-register-replica',
		'journal-deregister-replica', 'journal-apply-erasures',
		'journal-saga-run', 'journal-saga-status', 'journal-shred-generation',
		'journal-replay', 'journal-dry-run', 'journal-verify',
		'journal-verify-slice', 'journal-coherence', 'journal-snapshot',
		'journal-snapshot-verify', 'journal-fold-from', 'journal-resnapshot',
		'journal-retain', 'journal-compact',
		// store (the whole verb surface is impure — mutable in-process state)
		'store-open', 'store-open-opts', 'store-put-doc', 'store-put-doc-stream',
		'store-get-doc', 'store-put-doc-text', 'store-get-doc-text',
		'store-list-docs', 'store-iter-docs', 'store-query', 'store-source',
		'store-explain-query', 'store-modify-doc', 'store-put-blob',
		'store-get-blob', 'store-delete-doc', 'store-exists',
		'store-capabilities', 'store-close', 'store-set-alias',
		'store-get-alias', 'store-list-aliases', 'store-delete-alias',
		'store-migrate', 'store-clone', 'store-push', 'store-pull',
		'store-pull-report', 'store-fetch', 'store-status', 'store-mounts',
		'store-config-reload', 'store-log', 'store-verify', 'store-gc',
		'store-prune', 'store-rotate-kek', 'store-diff', 'store-reconcile',
		'store-reconcile-report', 'store-branch', 'store-branch-force',
	])
	// The completeness sweep (#788, batch #796): every REMAINING Ring-2
	// pack's impure verbs, derived from each wrapping [?def]'s declared
	// purity in stdlib/*.cx — the same derivation the journal + store
	// lists above used. Until this landed, a fold reducer (or any
	// pure-required context) reaching one of these slipped the guard on
	// the unclassified-callee=pure default, exactly as the anti-2PC row
	// found for journal.
	//
	// The parity gate (eval_semantics_umbrella_test.v,
	// test_ring2_impure_registration_parity) asserts every impure-declared
	// stdlib def reaches a callee the engine CLASSIFIES impure, so a new
	// verb added to any pack below cannot silently slip back to the pure
	// default — it fails the gate instead of deadlocking in production.
	ring2_impure_register([
		// bus
		'bus-close', 'bus-emit', 'bus-off', 'bus-on',
		// fabric
		'fabric-ack', 'fabric-close', 'fabric-emit', 'fabric-observe',
		'fabric-open', 'fabric-publish', 'fabric-request', 'fabric-respond',
		'fabric-serve', 'fabric-subscribe',
		// session
		'session-attach', 'session-attach-cookie', 'session-attach-did',
		'session-attach-guest', 'session-attach-token', 'session-attach-xsp',
		'session-by-client',
		'session-by-id', 'session-by-name', 'session-csrf-verify',
		'session-detach', 'session-detach-client', 'session-from-cookie',
		'session-list', 'session-of', 'session-rotate', 'session-set-cookie',
		'session-touch',
		// authz
		'authz-allocate', 'authz-allocation-expire', 'authz-approve',
		'authz-close', 'authz-commit', 'authz-debit', 'authz-delegate',
		'authz-grant-guardian', 'authz-meters', 'authz-resolve-cap',
		'authz-revoke', 'authz-store', 'authz-verify-tier',
		// did / vc
		'did-resolve', 'vc-revoke', 'vc-revoked-set',
		// xap (+ the dist half)
		'xap-coord-publish', 'xap-coord-read', 'xap-derive', 'xap-dial', 'xap-emit',
		'xap-host', 'xap-host-push', 'xap-license-verify', 'xap-on',
		'xap-pkg-catalog', 'xap-pkg-fetch', 'xap-pkg-install',
		'xap-pkg-publish', 'xap-pkg-requires-closure', 'xap-pkg-seal',
		'xap-pkg-verify', 'xap-render', 'xap-resolve', 'xap-resolve-respond',
		'xap-revoke', 'xap-run', 'xap-serve', 'xap-state', 'xap-why-allowed',
		// live
		'live-adapt-poll', 'live-ingest', 'live-read',
		// net
		'net-accept', 'net-accept-iter', 'net-chunk-iter', 'net-close',
		'net-dial', 'net-dial-dtls', 'net-dial-tcp', 'net-dial-tls',
		'net-dial-udp', 'net-dial-unix', 'net-flush', 'net-is-eof',
		'net-is-open', 'net-line-iter', 'net-listen', 'net-listen-dtls',
		'net-listen-tcp', 'net-listen-tls', 'net-listen-udp',
		'net-listen-unix', 'net-local-addr', 'net-peer-cert', 'net-read-all',
		'net-read-all-bytes', 'net-read-bytes', 'net-read-exact',
		'net-read-line', 'net-recv', 'net-recv-from', 'net-remote-addr',
		'net-resolve', 'net-send', 'net-send-to', 'net-set-deadline',
		'net-set-opt', 'net-shutdown', 'net-tls-accept', 'net-tls-info',
		'net-tls-wrap', 'net-write-bytes', 'net-write-line',
		'net-write-string',
		// http — the SERVE half only (seam H: the client half is the
		// Ring-1 http-client pack, classified through the Ring-1 table).
		'http-accept-iter', 'http-exchange-request', 'http-heartbeat',
		'http-listen', 'http-respond', 'http-send-event', 'http-serve',
		'http-sse', 'http-sse-publish', 'http-stop',
		// io — the WATCH handle only (iowatch_ring2_builtin; the rest of
		// the io pack is Ring 1).
		'io-watch-close',
		// ft — the store-coupled verb relocated from the Ring-1 ft pack.
		'ft-search-store',
	])
	// ── env-free chain (stdlib_builtin) ──────────────────────────────
	ring2_builtin_register(store_stdlib_builtin)
	ring2_builtin_register(sql_stdlib_builtin)
	$if cx_db_redis ? {
		ring2_builtin_register(redis_stdlib_builtin)
	}
	ring2_builtin_register(email_stdlib_builtin)
	ring2_builtin_register(net_stdlib_builtin)
	// seam H: only the SERVE half of http is Ring 2 — the client half
	// (http_client_stdlib_builtin) is the Ring-1 http-client pack,
	// chained directly in stdlib_dispatch.v.
	ring2_builtin_register(http_serve_stdlib_builtin)
	ring2_builtin_register(bus_stdlib_builtin)
	ring2_builtin_register(journal_stdlib_builtin)
	ring2_builtin_register(fabric_stdlib_builtin)
	ring2_builtin_register(session_stdlib_builtin)
	ring2_builtin_register(authz_stdlib_builtin)
	ring2_env_register_main(authz_stdlib_builtin_env) // stream 6 W6b: authz-commit executes the command body
	ring2_builtin_register(did_stdlib_builtin)
	ring2_builtin_register(vc_stdlib_builtin)
	ring2_builtin_register(xap_stdlib_builtin)
	ring2_builtin_register(xap_dist_stdlib_builtin)
	ring2_builtin_register(xsp_stdlib_builtin)
	ring2_builtin_register(xsp_auth_stdlib_builtin)
	// ── env-aware, both chains (stdlib_builtin_env + try_…) ──────────
	ring2_env_register_shared(http_stdlib_builtin_env)
	ring2_env_register_shared(bus_stdlib_builtin_env)
	ring2_env_register_shared(journal_stdlib_builtin_env)
	ring2_env_register_shared(fabric_stdlib_builtin_env)
	// #762 V4: the closeable-constructing io-watch arm.
	ring2_env_register_shared(iowatch_env_ring2_arm)
	ring2_env_register_shared(xap_stdlib_builtin_env)
	// ── env-aware, main chain only ───────────────────────────────────
	ring2_env_register_main(try_eval_serve_file)
	ring2_env_register_main(store_stdlib_builtin_env)
	// live modes (stream 3, #675) — env-aware: the L99 executor threads env.
	ring2_env_register_main(live_stdlib_builtin_env)
	// the delivery.md §4 consumption seam: live-sub is the FIRST registered
	// subscription kind — [?receive]/[?select]/[?close] accept the observe
	// handle (#762 generalizes the same arms across every §4 instance).
	ring2_sub_ops_register('live-sub', Ring2SubOps{
		receive: live_sub_receive
		ready:   live_sub_ready
	})
	// #762 V2: the local journal tail-follow (U1.13a).
	ring2_sub_ops_register('journal-sub', Ring2SubOps{
		receive: jrn_sub_receive
		ready:   jrn_sub_ready
	})
	// #762 V2: fabric's durable-plane subscription + the io watch handle.
	ring2_sub_ops_register('fabric-sub', Ring2SubOps{
		receive: fab_sub_contract_receive
		ready:   fab_sub_contract_ready
	})
	ring2_sub_ops_register('watch', Ring2SubOps{
		receive: iowatch_sub_receive
		ready:   iowatch_sub_ready
	})
	// ── store-coupled ft verb (relocated from the Ring-1 ft pack) ────
	ring2_builtin_register(store_ft_ring2_builtin)
	// live's env-free arm (the pure ingest helpers — lower).
	ring2_builtin_register(live_stdlib_builtin)
	// ── io watch (§3.7; carries its own read-cap gate) ───────────────
	ring2_builtin_register(iowatch_ring2_builtin)
	// ── the services directive family (eval's match probes the map) ──
	ring2_directive_register('http-service', eval_http_service)
	ring2_directive_register('service-handle', eval_service_handle)
	ring2_directive_register('stop', eval_stop)
	ring2_directive_register('http-client', eval_http_client)
	ring2_directive_register('test-service-client', eval_test_service_client)
	ring2_directive_register('test-tls-config', eval_test_tls_config_directive)
	// ── single-slot hooks ────────────────────────────────────────────
	ring2_wait_for_service_register(wait_for_service)
	ring2_client_call_register(dispatch_client_call)
	ring2_pkg_source_register(xap_pkg_module_source)
	// ── per-program state resets (new_env) ───────────────────────────
	// (live's subscription registry is NOT here: new_env is also the L99
	// sandbox constructor — planar_query_execute builds one per execution —
	// and a receive executes the query, so a reset here would wipe the
	// registry mid-subscription. live-subs are process-global handles,
	// exactly like fabric's.)
	ring2_env_reset_register(session_reset_state)
	ring2_env_reset_register(authz_reset_state)
	// ── live-source iterator walkers (iter_walks_net_http.v) ────────
	// (.iter_sse_events is NOT here: the SSE client is the Ring-1
	// http-client pack — its walkers dispatch directly, seam H.)
	ring2_iter_walk_register(.iter_net_accept, iter_net_accept_walk, iter_net_accept_walk_streamed)
	ring2_iter_walk_register(.iter_http_accept, iter_http_accept_walk, iter_http_accept_walk_streamed)
	ring2_iter_walk_register(.iter_net_line, iter_net_line_walk, iter_net_line_walk_streamed)
	ring2_iter_walk_register(.iter_net_chunk, iter_net_chunk_walk, iter_net_chunk_walk_streamed)
}

// ── the Ring-2 half of the §2.1 effect-point mirror (#827) ─────────────
//
// RULED tables-1a: security.md §2.1 is the normative closed effect-point
// table and the implementation is its MIRROR — a row lands in the spec
// first, and a gate asserts equality in both directions.
//
// Ring 1's half of that mirror is `code.capability_gated_prims()`. It
// cannot carry these: the gated socket surface lives in Ring 2, and
// Ring 1 may not import Ring 2 (cx_partition.md §3). Bending the import
// contract to make the gate convenient is not on the table, so Ring 2
// exposes its own half here and the GATE unions the two — legitimate,
// because tests and tooling may import anything (§3).
//
// Both lists charge `net`, verified at their guard sites: stdlib_net.v
// gates every name in net_gated_prims with cap_guard('net', resource)
// before any work, and stdlib_http_serve.v does the same for the serve
// half. The capability-free members of both packs (net parse-addr /
// addr->string / close / is-open / local-addr / remote-addr, and the
// http-serve introspection prims) are deliberately absent from those
// lists and therefore from this map.
pub fn platform_capability_gated_prims() map[string]string {
	mut t := map[string]string{}
	for n in net_gated_prims {
		t[n] = 'net'
	}
	for n in http_serve_gated_prims {
		t[n] = 'net'
	}
	return t
}
