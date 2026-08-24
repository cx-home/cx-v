module code

// effect_alignment.v — the single source of truth for the §6.5.1
// capability-alignment invariant (spec/core/code.md §6.5.1; SAP §4.1).
//
// The invariant is ONE-WAY: **capability-gated ⇒ impure**. Every effect
// point that calls `cap_guard` (security.md §4) is reachable only through a
// builtin the purity checker classifies `impure`. The converse does NOT
// hold — an `impure`-without-capability builtin is allowed, but only if it
// appears in a closed, enumerated exception table (state-bearing PRNG, mock
// clock, spec-classified-but-impl-pending, …).
//
// This file exposes that invariant's two halves as data:
//
//   - `capability_gated_prims()` — every cap-gated primitive → its
//     capability. `builtin_purity_table()` (purity_checker.v) folds these
//     keys to `impure_` so direction (1) holds **by construction**.
//   - `impure_without_capability_exceptions()` — the closed exception table
//     for direction (2): impure prims that are deliberately NOT cap-gated.
//
// The gate (`make check-effect-alignment`, vcx/tests/effect_alignment_test.v)
// asserts both directions + drift canaries over these maps. Adding a new
// cap-gated effect point requires adding its prim here (or the checker's
// direction-1 assertion fails); making a new prim impure-without-cap requires
// an exception-table row (or direction-2 fails).
//
// Each family below cites the LIVE gating site so the table cannot silently
// drift from the dispatchers. The const-backed families reference the same
// `module code` consts the dispatchers read; the arm-level / prefix-gated
// families are listed literally with a pointer to their guard.

// ── Pack cap-name tables (I4, #651/#516) ──────────────────────────────────────
// These const lists are PROFILE-INVARIANT purity data: builtin_purity_table()
// folds them to `impure_`, and a name's purity classification must not vary
// with the artifact's pack composition (an embed-profile artifact still
// classifies `io-read-file` impure — the name is simply not callable there).
// They therefore live HERE, outside the `-d cx_no_pack_*`-gated pack files;
// the pack dispatchers read these same consts for their cap_guard fences, so
// the drift-canary property (table == live guard list) still holds by
// construction.

// io_read_caps / io_write_caps name the read-path / write-path primitives
// (io.md §7 table, minus open which is mode-derived, and close which needs
// none). The cap_guard at the top of io dispatch fail-closes BEFORE any work.
const io_read_caps = ['io-read-file', 'io-read-file-bytes', 'io-read-file-lines',
	'io-read-all', 'io-read-all-bytes', 'io-read-bytes', 'io-read-line', 'io-line-iter',
	'io-stat', 'io-exists', 'io-is-file', 'io-is-directory', 'io-is-symlink', 'io-is-eof',
	'io-list-dir', 'io-glob', 'io-glob-iter', 'io-walk', 'io-readlink', 'io-size',
	'io-created-time', 'io-modified-time', 'io-tell', 'io-seek', 'io-system-temp-dir',
	'io-temp-dir'] // io-watch / io-watch-next gate themselves in iowatch_ring2_builtin (I3)

const io_write_caps = ['io-open-with-opts', 'io-write-bytes', 'io-write-file',
	'io-write-file-bytes', 'io-write-file-lines', 'io-write-line', 'io-write-string',
	'io-append-file', 'io-append-file-bytes', 'io-make-dir', 'io-make-dirs', 'io-remove',
	'io-remove-dir', 'io-remove-tree', 'io-rename', 'io-copy', 'io-copy-tree', 'io-symlink',
	'io-lock', 'io-unlock', 'io-flush', 'io-temp-file']

// env_uncapped_prims are the capability-FREE env names: pure accessors over
// parsed-args/spec shapes plus the ambient process basics env.md §7 makes
// "never gated" (standard streams, process identity, argv, CPU count,
// exit/abort; parse-args is argv-derived).
const env_uncapped_prims = ['env-os-name', 'env-os-arch', 'env-flag', 'env-positional',
	'env-remaining', 'env-usage', 'env-parse-args', 'env-stdin', 'env-stdout', 'env-stderr',
	'env-pid', 'env-ppid', 'env-argv', 'env-cpu-count', 'env-exit', 'env-abort']

// time_clock_prims are the impure wall-clock reads gated under the `clock`
// capability (security.md §2). Pure calendar/duration math and the `*-mock`
// variants need no capability.
const time_clock_prims = ['time-now', 'time-today', 'time-instant-now',
	'time-monotonic-now', 'time-utc-now', 'time-system-timezone']

// random_entropy_prims are the crypto-random surfaces drawing OS/CSPRNG
// entropy — gated under the `random` capability (security.md §2). The
// seeded PRNG (xoshiro) is deterministic and needs no capability.
const random_entropy_prims = ['random-crypto-bytes', 'random-crypto-int',
	'random-crypto-hex', 'random-crypto-base64-url', 'random-crypto-token-urlsafe']

// ── Direction 1: capability-gated ⇒ impure ────────────────────────────────────

// gated_env_prims / read_env_prims are every `env-*` dispatcher arm EXCEPT
// `env_uncapped_prims` (stdlib_env.v ~905), split by the capability each
// charges (`env_stdlib_builtin` ~917). Listed literally so the drift canary
// can assert: every purity-table `env-` name not in `env_uncapped_prims` is
// gated under the right cap, and vice versa.
//
// `env` cap — environment/identity reads.
// http CLIENT pack (Ring 1) — every verb that touches a socket, gated on
// `net` by cap_guard inside the pack (http_gated_prims + the two SSE impls).
// Mirrored here the way io/env already are: the pack file is conditionally
// compiled (`-d cx_no_pack_http_client`), so this map cannot reference the
// pack's own const directly.
//
// These rows landed in security.md §2.1 first (RULED: tables-1a, #827) —
// the spec table is the normative closed set and this map is its mirror, so
// the fold below may only name effect points the spec declares.
//
// `http-client` / `http-close` are deliberately NOT here: they are
// connection-pool bookkeeping that touches no socket, and the pack documents
// them as intentionally ungated. They are impure all the same (pool state) —
// see the direction-2 exception table.
const http_client_gated_prims = ['http-get', 'http-post', 'http-put', 'http-del',
	'http-patch', 'http-head', 'http-options', 'http-request', 'http-send',
	'http-sse-connect', 'http-sse-events']

const gated_env_prims = ['env-has-var', 'env-hostname', 'env-username', 'env-var',
	'env-var-bool', 'env-var-float', 'env-var-int', 'env-var-or-default',
	'env-var-required', 'env-vars']

// `read` cap — filesystem-layout disclosure (env.md §7 `read` row).
const read_env_prims = ['env-cwd', 'env-executable-path']

// The ambient process basics (env-stdin/stdout/stderr/pid/ppid/argv/cpu-count/
// exit/abort) and argv-derived parse-args are NOT gated: env.md §7 makes them
// "never gated", so they are impure-WITHOUT-capability and live in the §6.5.1
// exception table below.

// gated_process_prims is every `process-*` primitive: the dispatcher gates
// the whole prefix (stdlib_process.v ~812-816, cap `subprocess`). Listed
// literally so the drift canary can assert every purity-table `process-`
// name is gated.
const gated_process_prims = ['process-close', 'process-kill', 'process-kill-group',
	'process-pid', 'process-pipeline', 'process-poll', 'process-pty', 'process-run',
	'process-send-signal', 'process-set-window-size', 'process-spawn', 'process-spawn-pty',
	'process-stderr', 'process-stdin', 'process-stdout', 'process-terminate',
	'process-wait', 'process-wait-timeout', 'process-window-size']

// gated_prof_prims are the clock-reading prof primitives (arm-level guards,
// stdlib_prof.v ~378/384/515/699/725, cap `clock`). The non-clock prof
// surface (mem/counter/histogram) is in-process and ungated.
const gated_prof_prims = ['prof-now-ns', 'prof-now-cpu-ns', 'prof-trace',
	'prof-time-fn', 'prof-time-and-trace']

// capability_gated_prims returns every capability-gated primitive mapped to
// the capability it is gated under. `builtin_purity_table()` iterates these
// keys → `impure_`, making direction (1) of §6.5.1 true by construction.
//
// Const-backed families reference the LIVE dispatcher consts directly (same
// `module code`): random/time/uuid/io/crypto. Arm-level / prefix-gated
// families (env/process/prof/i18n/testkit/store-open + path) are listed via
// the consts above or literally, each with a pointer to its guard site.
pub fn capability_gated_prims() map[string]string {
	mut t := map[string]string{}

	// env — prefix-gated minus env_uncapped_prims (stdlib_env.v ~917). Cap
	// `env` for environment/identity reads, `read` for cwd / executable-path.
	for n in gated_env_prims {
		t[n] = 'env'
	}
	for n in read_env_prims {
		t[n] = 'read'
	}

	// http client — every socket-touching verb (#827; §2.1 rows landed first).
	for n in http_client_gated_prims {
		t[n] = 'net'
	}

	// io-edit-file — the one primitive requiring BOTH read and write, so it
	// self-guards at its dispatch site rather than riding io_read_caps /
	// io_write_caps. Listed under its nominal capability `read`, matching the
	// §2.1 scoping note (#827).
	t['io-edit-file'] = 'read'

	// random — CSPRNG/entropy surfaces (stdlib_random.v ~524). Cap `random`.
	// The seeded/state-bearing PRNG (random-next-*, -seed, -shuffle, …) is
	// deterministic and NOT gated → it lives in the direction-2 exceptions.
	for n in random_entropy_prims {
		t[n] = 'random'
	}

	// time — wall-clock reads (stdlib_time.v ~1266). Cap `clock`. The mock
	// clock (time-mock-set/-advance) reads no real clock → exceptions.
	for n in time_clock_prims {
		t[n] = 'clock'
	}

	// uuid — random-backed generators v4/v7 (stdlib_uuid.v ~456). Cap
	// `random`. Name-based v3/v5 are pure and ungated.
	for n in uuid_random_prims {
		t[n] = 'random'
	}

	// io — read-path / write-path primitives (stdlib_io.v ~476/480). Caps
	// `read` / `write`. `io-open` derives its cap from the requested mode
	// (~471); it gates either read or write, so it IS cap-gated → recorded
	// here. `io-close` needs no cap and is absent from both lists.
	for n in io_read_caps {
		t[n] = 'read'
	}
	for n in io_write_caps {
		t[n] = 'write'
	}
	// io-open: mode-derived (read|write). The cap value here is nominal —
	// direction-1 only needs it classified impure; the actual charged cap is
	// computed per-call from the requested mode (stdlib_io.v ~471).
	t['io-open'] = 'read'

	// crypto — entropy-drawing surfaces (stdlib_crypto.v ~245). Cap `random`.
	for n in crypto_entropy_prims {
		t[n] = 'random'
	}
	// #828 (RULED: 828-1a) — the two surfaces that were classified impure
	// but ungated now charge, so they move OUT of the direction-2 exception
	// table and IN here. mime-multipart-boundary draws OS entropy like every
	// other entropy surface; locale-default-locale reads an environment
	// variable, which env.md §7 states flatly requires `env`.
	t['mime-multipart-boundary'] = 'random'
	t['locale-default-locale'] = 'env'

	// crypto — jwks-fetch GETs the JWKS over cx-stdlib/http (stdlib_crypto.v
	// crypto_stdlib_builtin head). Cap `net` (same grant http uses; §3.10/§7).
	t['crypto-jwks-fetch'] = 'net'

	// process — whole prefix gated (stdlib_process.v ~816). Cap `subprocess`.
	for n in gated_process_prims {
		t[n] = 'subprocess'
	}

	// prof — clock-reading arms (stdlib_prof.v). Cap `clock`.
	for n in gated_prof_prims {
		t[n] = 'clock'
	}

	// io-watch / io-watch-next — filesystem watch (Ring 2,
	// stdlib_iowatch.v; the live adapters route through the same
	// dispatch). Cap `read`. They gate themselves in
	// iowatch_ring2_builtin — previously listed only as a comment on
	// io_read_caps, which left them outside BOTH alignment directions
	// (the drift-canary hole the stream-6 EV-EFFECT-SET move closed:
	// the normative security.md §2.1 table lists them, so the mirror
	// must too).
	t['io-watch'] = 'read'
	t['io-watch-next'] = 'read'

	// i18n — load-catalog reads a sibling file (stdlib_i18n.v ~1008). Cap
	// `read`. Every other i18n surface is pure in-memory message work.
	t['i18n-load-catalog'] = 'read'

	// testkit — fixture-LOAD reads a file (stdlib_testkit.v ~410). Cap
	// `read`. NOTE: plain `test-fixture` (~383) builds an in-memory sequence
	// with no cap_guard → it is genuinely pure and is NOT listed here.
	t['test-fixture-load'] = 'read'

	// store-open — the file:// backend needs read|write, remote schemes need
	// net (stdlib_store.v ~216/232, via store_open_impl). Both store-open and
	// store-open-opts route through store_open_impl, so both are cap-gated.
	// Nominal cap `read` (the actual cap is url+mode-derived per call).
	t['store-open'] = 'read'
	t['store-open-opts'] = 'read'

	// path — path-absolute resolves against the real cwd; path-canonical
	// touches the filesystem to resolve symlinks. Both gated under `read`
	// (stdlib_path.v ~670/679) per SAP C2 / D010 — CX-sound (they observe the
	// real filesystem) and consistent with deny-by-default.
	t['path-absolute'] = 'read'
	t['path-canonical'] = 'read'

	// live — executing a QUOTED planar comprehension is dynamic execution
	// (the L99 [?eval] posture, live.md §1): every verb cap_guards `eval` on
	// every path that executes (stdlib_live.v; stream 3, #675) — observe at
	// creation (the anchor replay) and again on each [?receive] poll;
	// materialize at creation (the seed fold) and advance on every tick.
	// live-read is NOT here: its normal path is a checkpoint doc read; the
	// derived-state replay branch alone carries an inline eval guard (a
	// conditional execution path, same posture as store modify-doc's
	// closure arm).
	t['live-changes-since'] = 'eval'
	t['live-observe'] = 'eval'
	t['live-materialize'] = 'eval'
	t['live-advance'] = 'eval'
	// live-adapt-watch creates the watched directory — an unconditional
	// write effect at the prim. (live-adapt-poll and live-ingest are NOT
	// here: their execution guards fire inside the changes-since core they
	// call per tick, and ingest's read guard is the watch-path conditional
	// — the live-read posture.)
	t['live-adapt-watch'] = 'write'

	return t
}

// ── Accessors for the drift canaries (effect_alignment_test.v) ─────────────────
// The dispatcher consts are module-private to `code`; these pub views let the
// `module main` test assert the gated map agrees with the LIVE dispatcher
// lists (so the table cannot drift from the guards it mirrors).

// alignment_io_read_caps / alignment_io_write_caps expose the io read/write
// cap lists (stdlib_io.v) verbatim.
pub fn alignment_io_read_caps() []string {
	return io_read_caps.clone()
}

pub fn alignment_io_write_caps() []string {
	return io_write_caps.clone()
}

// alignment_env_pure_prims exposes the capability-FREE env names
// (stdlib_env.v) — the complement of the gated env surface (pure accessors
// plus the never-gated ambient process basics).
pub fn alignment_env_pure_prims() []string {
	return env_uncapped_prims.clone()
}

// alignment_gated_process_prims exposes the gated process surface verbatim.
pub fn alignment_gated_process_prims() []string {
	return gated_process_prims.clone()
}

// ── Direction 2: impure-without-capability — the CLOSED exception table ────────

// impure_without_capability_exceptions returns the closed table of builtins
// that are classified `impure` yet are NOT capability-gated, each with the
// reason it is cap-free. Direction (2) of §6.5.1 asserts every impure entry
// of the purity table is EITHER gated (in capability_gated_prims()) OR in
// this table — nothing else may be impure-without-capability.
//
// The buckets (spec §6.5.1 closed exception table rows a/b/c):
//   (a) state-bearing PRNG — process-global generator state, deterministic
//       given seed, draws no OS entropy and needs no `random` capability.
//   (b) mock clock — test-clock state, reads no real wall clock.
//   (c) spec-classified-but-impl-pending — bare-name builtins the spec
//       classifies impure whose handler is not yet wired (print, now, uuid,
//       …). The classification is load-bearing for purity fixtures (e.g.
//       pred-015 uses `[$uuid]`). They WILL be cap-gated at impl time.
//   (d) ambient process basics — standard streams, process identity, argv,
//       CPU count, and process exit/abort. env.md §7 makes them "intrinsic
//       to the running process and never gated": effectful, hence impure,
//       but capability-free by spec. (Supersedes the post-C2 empty row.)
pub fn impure_without_capability_exceptions() map[string]string {
	mut t := map[string]string{}

	// (a) state-bearing PRNG (stdlib_random.v): process-global generator,
	// deterministic given seed, no entropy capability.
	for n in [
		'random-choose',
		'random-choose-weighted',
		'random-exponential',
		'random-float-range',
		'random-gaussian',
		'random-int-range',
		'random-next-bool',
		'random-next-float',
		'random-next-floats',
		'random-next-int',
		'random-next-ints',
		'random-poisson',
		'random-sample',
		'random-sample-weighted',
		'random-seed',
		'random-shuffle',
	] {
		t[n] = '(a) state-bearing PRNG: process-global generator state, deterministic given seed, draws no OS entropy'
	}

	// (b) mock clock (stdlib_time.v): test-clock state, reads no real clock.
	for n in ['time-mock-advance', 'time-mock-set'] {
		t[n] = '(b) mock clock: test-clock state, reads no real wall clock'
	}

	// (f) capability introspection (stdlib_caps.v, security.md C4 / L104):
	// [$caps] reads the ACTIVE grant set — a program can only OBSERVE its
	// own authority, never exceed it (§3 narrow-only), so the read is not
	// a gated effect; impure so pure bodies stay cap-set-invariant (§6.5.1).
	t['caps'] = '(f) capability introspection: reads the active grant set — observation of own authority, never a gated effect'

	// (d) ambient process basics (stdlib_env.v): standard streams, process
	// identity, argv, CPU count, exit/abort. env.md §7 `(none)` row — never
	// gated; effectful (impure) but capability-free.
	for n in [
		'env-stdin',
		'env-stdout',
		'env-stderr',
		'env-pid',
		'env-ppid',
		'env-argv',
		'env-cpu-count',
		'env-exit',
		'env-abort',
		'env-parse-args',
	] {
		t[n] = '(d) ambient process basics: intrinsic to the running process, never gated (env.md §7); parse-args is argv-derived'
	}

	// (c) spec-classified bare-name builtins whose handler is impl-pending
	// (purity_checker.v builtin_purity_table I/O / time-source / random rows).
	// Classification is load-bearing for purity fixtures; will be cap-gated
	// at impl time.
	for n in [
		'print',
		'read-file',
		'write-file',
		'read-line',
		'now',
		'today',
		'instant-now',
		'monotonic-now',
		'random',
		'random-int',
		'uuid',
		'random-bytes',
	] {
		t[n] = '(c) spec-classified impure; impl-pending; will be cap-gated at impl time'
	}

	// (g) Ring-1 pack state, capability-free (#818). Each of these is impure
	// — it reads or mutates process-global state — but crosses no gated
	// effect point, so it belongs here rather than in the gated map. The
	// wrapping [?def]s declare `impure` in stdlib/*.cx; before #818 the
	// classifier read their bodies as PURE, which is the CXER4611 slip #788
	// closed for the Ring-2 packs.
	for n in [
		// the OBJECT PRNG (stdlib_random ~642): a handle-scoped generator,
		// SEEDED FROM AN ARGUMENT (random_arg_int), never from OS entropy —
		// the same rationale as bucket (a)'s process-global twin.
		'random-new', 'random-free', 'random-gen-bool', 'random-gen-choose',
		'random-gen-choose-weighted', 'random-gen-exponential', 'random-gen-float',
		'random-gen-float-range', 'random-gen-floats', 'random-gen-gaussian',
		'random-gen-int', 'random-gen-int-range', 'random-gen-ints',
		'random-gen-poisson', 'random-gen-sample', 'random-gen-sample-weighted',
		'random-gen-shuffle',
	] {
		t[n] = '(g) object PRNG: handle-scoped generator seeded from an argument, draws no OS entropy'
	}
	for n in [
		'test-assert', 'test-assert-contains', 'test-assert-equal',
		'test-assert-match', 'test-assert-near', 'test-assert-not-equal',
		'test-assert-shape', 'test-assert-snapshot', 'test-assert-throws',
		'test-before-all', 'test-before-each', 'test-after-all', 'test-after-each',
		'test-configure', 'test-fail', 'test-skip',
	] {
		t[n] = '(g) test harness: per-run assertion / hook / config state, in-process only'
	}
	for n in [
		'prof-counter-add', 'prof-counter-all', 'prof-counter-get',
		'prof-counter-inc', 'prof-counter-reset', 'prof-flamegraph-emit',
		'prof-gc-trigger', 'prof-histogram-observe', 'prof-histogram-reset',
		'prof-histogram-stats', 'prof-mem-snapshot', 'prof-prof-configure',
		'prof-trace-flush',
	] {
		t[n] = '(g) profiler: process-global counters / histograms / GC + trace control'
	}
	for n in [
		'log-configure', 'log-current-scope', 'log-debug', 'log-emit-raw',
		'log-error', 'log-fatal', 'log-info', 'log-log', 'log-warn',
	] {
		t[n] = '(g) logging: sink writes + scope state; the sink is a standard stream, which env.md §7 keeps capability-free'
	}
	for n in [
		'sched-after', 'sched-at', 'sched-cancel', 'sched-cron', 'sched-every',
		'sched-recur', 'sched-restore', 'sched-test-clock-advance',
	] {
		t[n] = '(g) scheduler: in-process timer registry + the test clock (bucket (b) twin)'
	}
	for n in ['mime-load-mime-types', 'mime-register-type'] {
		t[n] = '(g) mime registry: process-global type-table mutators'
	}
	// http pool bookkeeping — the pack documents these as intentionally
	// ungated (no socket is touched); impure because the pool is state.
	for n in ['http-client', 'http-close'] {
		t[n] = '(g) http connection-pool bookkeeping: pool state, touches no socket'
	}
	// io-close — stdlib_io ~742 states it outright: "§7: no capability.
	// Idempotent." Impure because it mutates handle state.
	t['io-close'] = '(g) io handle close: documented capability-free and idempotent (io.md §7)'



	return t
}
