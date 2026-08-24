module code

import cx

// stdlib_bundle.v — bundled `cx-stdlib` sub-package skeleton (Phase 2.17).
//
// The `cx-stdlib` namespace is bundled with the CX binary
// D7 + spec/stdlib.md §2: its bytes are part of the binary itself, no
// HTTPS fetch, no SRI verification, no version pin beyond the
// `bundled:<binary-version>` tag in cx.lock.
//
// This file ships the **signature-only skeleton** — each of the
// 14 frozen sub-packages from spec/stdlib.md §3 is represented by a
// single CX source file whose [?def] declarations expose the public
// surface only. Bodies are `null` placeholders + TODO markers; full
// implementations land per the Phase 3.x per-sub-package companion
// specs (spec/stdlib_strings.md, spec/stdlib_json.md, etc.).
//
// The canonical, human-readable source files live under `/stdlib/` at
// the repo root and are the SINGLE SOURCE OF TRUTH. Each
// `stdlib_src_<name>` const below is `$embed_file('../stdlib/<name>.cx')`
// — the bundled bytes ARE the on-disk file, embedded at compile time.
// Edit `/stdlib/<name>.cx`; there is no second copy to keep in sync.
//
// ── Registration surface ────────────────────────────────────────────
//
//   `register_bundled_stdlib(mut table)` populates every
//   `cx-stdlib/<name>` registered-name resolver into the supplied
//   ModuleTable. The loader's existing registered-name path
//   (module_loader.v::resolve_lib) handles them as ordinary in-memory
//   sources from there.
//
//   `bundled_stdlib_names()` returns the canonical list of the 14
//   bundled sub-package resolver names. Tests + tooling consume this
//   to assert surface completeness against spec/stdlib.md §3.
//
//   `bundled_stdlib_source(name)` returns the source bytes for one
//   sub-package by registered-name. Used by Phase 2.18's `cx lock`
//   subcommand when materialising the `[modules]` entry for a
//   bundled-stdlib import.
//
// ── Spec cross-references ───────────────────────────────────────────
//
// bundling rule.
//   - spec/stdlib.md §3 — frozen sub-package surface.
//   - spec/lockfile.md §4.2 — `bundled:<version>` :resolved shape.

// CX_BUNDLED_STDLIB_VERSION matches the CX binary version — the
// `bundled:<v>` tag emitted into cx.lock entries for cx-stdlib
// imports tracks this value verbatim. Bumped lock-step with the
// binary; no independent stdlib version per spec/stdlib.md §2.
pub const cx_bundled_stdlib_version = '0.8.0'

// ── Bundled source bytes ────────────────────────────────────────────
//
// One const per sub-package, each `$embed_file`-d from `/stdlib/<name>.cx`
// (the canonical on-disk source). The path is relative to THIS .v file
// (`vcx/code/` → `../../stdlib/`). Editing the on-disk file is the only
// way to change the bundled bytes.

const stdlib_src_strings = $embed_file('../stdlib/strings.cx').to_string()

const stdlib_src_json = $embed_file('../stdlib/json.cx').to_string()

const stdlib_src_http = $embed_file('../stdlib/http.cx').to_string()

const stdlib_src_re = $embed_file('../stdlib/re.cx').to_string()

const stdlib_src_time = $embed_file('../stdlib/time.cx').to_string()

const stdlib_src_math = $embed_file('../stdlib/math.cx').to_string()

const stdlib_src_io = $embed_file('../stdlib/io.cx').to_string()

const stdlib_src_net = $embed_file('../stdlib/net.cx').to_string()

const stdlib_src_process = $embed_file('../stdlib/process.cx').to_string()

const stdlib_src_bytes = $embed_file('../stdlib/bytes.cx').to_string()

const stdlib_src_format = $embed_file('../stdlib/format.cx').to_string()

const stdlib_src_path = $embed_file('../stdlib/path.cx').to_string()

const stdlib_src_log = $embed_file('../stdlib/log.cx').to_string()

const stdlib_src_url = $embed_file('../stdlib/url.cx').to_string()

const stdlib_src_crypto = $embed_file('../stdlib/crypto.cx').to_string()

const stdlib_src_mime = $embed_file('../stdlib/mime.cx').to_string()

const stdlib_src_email = $embed_file('../stdlib/email.cx').to_string()

// stdlib_src_hash lives in vcx/code/stdlib_hash.v (per-module ownership).

// I4 (#651/#516): the env / random / sched embeds moved HERE from their
// pack files — module-loader source embeds are DATA and profile-invariant
// (the ring-2 store/journal/xap/fabric embeds below set the precedent at
// seam H). In an artifact built without a pack (-d cx_no_pack_*), loading
// the CX wrapper module still works; its bodies bottom out in builtins
// that refuse as undefined callables.
const stdlib_src_env = $embed_file('../stdlib/env.cx').to_string()
const stdlib_src_random = $embed_file('../stdlib/random.cx').to_string()
const stdlib_src_sched = $embed_file('../stdlib/sched.cx').to_string()

// stdlib_src_env lives in vcx/code/stdlib_env.v (per-module ownership).

const stdlib_src_test = $embed_file('../stdlib/test.cx').to_string()

const stdlib_src_csv = $embed_file('../stdlib/csv.cx').to_string()

const stdlib_src_geo = $embed_file('../stdlib/geo.cx').to_string()

const stdlib_src_i18n = $embed_file('../stdlib/i18n.cx').to_string()

const stdlib_src_prof = $embed_file('../stdlib/prof.cx').to_string()

const stdlib_src_fp = $embed_file('../stdlib/fp.cx').to_string()

const stdlib_src_bus = $embed_file('../stdlib/bus.cx').to_string()

const stdlib_src_session = $embed_file('../stdlib/session.cx').to_string()

const stdlib_src_authz = $embed_file('../stdlib/authz.cx').to_string()

// did/vc — deferred trust additions (std-lib/README §3.2; issue #26).
const stdlib_src_did = $embed_file('../stdlib/did.cx').to_string()

const stdlib_src_vc = $embed_file('../stdlib/vc.cx').to_string()

// xsp — XAP Stream Protocol frame codec (spec/03-approved/xap/xsp.md; issue #31).
const stdlib_src_xsp = $embed_file('../stdlib/xsp.cx').to_string()

const stdlib_src_jsonrpc = $embed_file('../stdlib/jsonrpc.cx').to_string()

// jsonschema — JSON Schema 2020-12 validation (MCP-tool-schema subset; #6 S7).
const stdlib_src_jsonschema = $embed_file('../stdlib/jsonschema.cx').to_string()

// diagram — the §10.1.2 reference diagram renderer in pure CX (#758,
// RULED DR-1…DR-11 2026-08-20; wave 1 = Mermaid + all-format extract).
const stdlib_src_diagram = $embed_file('../stdlib/diagram.cx').to_string()

// map + array (#925, RULED: PYE-1): the XPath 3.1 §17 operation families
// over CXDM maps and arrays — the registered-but-sourceless gap this
// bundle entry closes. Wrappers over the map-/arr- natives
// (vcx/code/stdlib_map.v / stdlib_array.v).
const stdlib_src_map = $embed_file('../stdlib/map.cx').to_string()

const stdlib_src_array = $embed_file('../stdlib/array.cx').to_string()

// live — the live modes over the one planar comprehension (campaign stream 3,
// #675; live_modes.md L129 + pack spec spec/03-approved/std-lib/live.md). Like
// store/journal, the CX surface is data; the native prims are the Ring-2
// pack (vcx/platform/stdlib_live.v via ring2_register.v).
const stdlib_src_live = $embed_file('../stdlib/live.cx').to_string()

// supervise (SUP-1, #765): restart policies over monitored workers —
// graduated + implemented 2026-08-20 with the module.
const stdlib_src_supervise = $embed_file('../stdlib/supervise.cx').to_string()

// store/journal/xap/fabric — these four consts historically lived beside
// their native packs; relocated here at I3 seam H so this Ring-1 file
// holds NO reference into a Ring-2 pack file (#651/#516 — the embedded CX
// surface is data; the packs' NATIVE primitives register via
// ring2_register.v, and an artifact without them refuses at call time).
const stdlib_src_store = $embed_file('../stdlib/store.cx').to_string()

const stdlib_src_journal = $embed_file('../stdlib/journal.cx').to_string()

const stdlib_src_xap = $embed_file('../stdlib/xap.cx').to_string()

const stdlib_src_fabric = $embed_file('../stdlib/fabric.cx').to_string()

// ── x/ experimental tier (spec/03-approved/std-lib/README.md D3) ──────────
// In-tree, bundled, gated — but EXEMPT from the frozen-`std` stability promise
// (semver-breaking allowed; marked in the module header + the guide). Kept in a
// SEPARATE names list from bundled_stdlib_names() so the frozen-surface canary
// (v08_stdlib_skeleton_test.v) never counts experimental modules. Sources live
// under the repo-root `x/` directory (parallel to `stdlib/`), so the tier is
// visible in the layout, not only the resolver name.
const x_src_run = $embed_file('../x/run.cx').to_string()

// llm — minimal LLM provider, the first Runnable (#6 S10; Ollama /api/chat).
const x_src_llm = $embed_file('../x/llm.cx').to_string()

// mcp — minimal MCP client (#6 S9; JSON-RPC 2.0 over Streamable HTTP).
const x_src_mcp = $embed_file('../x/mcp.cx').to_string()

// mcp-server — minimal MCP server helpers (#6 Y1; cap-gated tools, ties #7 PEP).
const x_src_mcp_server = $embed_file('../x/mcp-server.cx').to_string()

// a2a — minimal A2A (Agent-to-Agent) protocol client (#6 Y2; JSON-RPC over HTTP).
const x_src_a2a = $embed_file('../x/a2a.cx').to_string()

// a2a-xap — A2A tasks over the xap substrate (#6 Y2b; tasks→journal, replayable).
const x_src_a2a_xap = $embed_file('../x/a2a-xap.cx').to_string()

// term — native raw-mode terminal input (#30; termios + VT/ANSI key decoder).
const x_src_term = $embed_file('../x/term.cx').to_string()

// adjudicate — out-of-band agent adjudicator for the similar review band
// (#376; similar.md §5.3 ruling Q4 follow-up — produces resolutions-table rows).
const x_src_adjudicate = $embed_file('../x/adjudicate.cx').to_string()

// tools — the agent-tool projection: command defs → tool descriptors
// (#690 stream 18; the ONE descriptor model both MCP and A2A adapters consume).
const x_src_tools = $embed_file('../x/tools.cx').to_string()

// ux — the SEMANTIC CORE of the THIRD projection of the typed surface (#787).
// XSP projects [?def] commands onto the wire, cx-x/tools projects them to
// agent tools, cx-x/ux projects them to a renderer-agnostic semantic tree:
// the vocabulary, fragment addressing, the command/query/feature-grammar
// projections, the hint claims, the patch algebra a live feed lowers onto,
// and the surface document's routing correspondence. It contains NO renderer.
// x/-tier because #787's DP1 is an explicit go/kill — the surface may not
// claim frozen-std stability until it passes.
const x_src_ux = $embed_file('../x/ux.cx').to_string()

// ux-web / ux-tui — the TWO RENDERERS over that one vocabulary, peers rather
// than a privileged one plus a fallback. ux-web lowers to HTML/htmx (sole
// author of a pinned attribute subset, strict CSP, the token stylesheet, the
// SRI-pinned kernel); ux-tui lowers to a full-screen terminal surface over
// cx-x/term. R5's claim that the semantic vocabulary is renderable by a
// non-browser renderer is TRUE only if the second one exists and agrees with
// the first, which is what the module split and the equivalence fixtures make
// checkable rather than asserted.
const x_src_ux_web = $embed_file('../x/ux-web.cx').to_string()

const x_src_ux_tui = $embed_file('../x/ux-tui.cx').to_string()

// ── Public surface ──────────────────────────────────────────────────

// bundled_stdlib_names returns the 14 frozen `cx-stdlib/*` resolver
// names per spec/stdlib.md §3. Order is the §3-table order.
pub fn bundled_stdlib_names() []string {
	return [
		'cx-stdlib/strings',
		'cx-stdlib/json',
		'cx-stdlib/http',
		'cx-stdlib/re',
		'cx-stdlib/time',
		'cx-stdlib/math',
		'cx-stdlib/io',
		'cx-stdlib/net',
		'cx-stdlib/bytes',
		'cx-stdlib/format',
		'cx-stdlib/path',
		'cx-stdlib/log',
		'cx-stdlib/hash',
		'cx-stdlib/env',
		'cx-stdlib/test',
		'cx-stdlib/random',
		'cx-stdlib/uuid',
		'cx-stdlib/store',
		'cx-stdlib/csv',
		'cx-stdlib/url',
		'cx-stdlib/crypto',
		'cx-stdlib/geo',
		'cx-stdlib/mime',
		'cx-stdlib/validate',
		'cx-stdlib/email',
		'cx-stdlib/html',
		'cx-stdlib/i18n',
		'cx-stdlib/locale',
		'cx-stdlib/ft',
		'cx-stdlib/similar',
		'cx-stdlib/prof',
		'cx-stdlib/process',
		'cx-stdlib/fp',
		'cx-stdlib/bus',
		'cx-stdlib/journal',
		'cx-stdlib/session',
		'cx-stdlib/authz',
		'cx-stdlib/sched',
		'cx-stdlib/did',
		'cx-stdlib/vc',
		'cx-stdlib/xsp',
		'cx-stdlib/jsonrpc',
		'cx-stdlib/jsonschema',
		'cx-stdlib/live',
		'cx-stdlib/supervise',
		'cx-stdlib/diagram',
		'cx-stdlib/map',
		'cx-stdlib/array',
	]
}

// bundled_stdlib_source returns the source bytes for a single bundled
// sub-package by its resolver name (e.g. `cx-stdlib/strings`).
// Returns `none` for any name not in `bundled_stdlib_names()`.
pub fn bundled_stdlib_source(name string) ?string {
	return match name {
		'cx-stdlib/strings' { stdlib_src_strings }
		'cx-stdlib/json'    { stdlib_src_json }
		'cx-stdlib/http'    { stdlib_src_http }
		'cx-stdlib/re'      { stdlib_src_re }
		'cx-stdlib/time'    { stdlib_src_time }
		'cx-stdlib/math'    { stdlib_src_math }
		'cx-stdlib/io'      { stdlib_src_io }
		'cx-stdlib/net'     { stdlib_src_net }
		'cx-stdlib/bytes'   { stdlib_src_bytes }
		'cx-stdlib/format'  { stdlib_src_format }
		'cx-stdlib/path'    { stdlib_src_path }
		'cx-stdlib/log'     { stdlib_src_log }
		'cx-stdlib/hash'    { stdlib_src_hash }
		'cx-stdlib/env'     { stdlib_src_env }
		'cx-stdlib/test'    { stdlib_src_test }
		'cx-stdlib/random'  { stdlib_src_random }
		'cx-stdlib/uuid'    { stdlib_src_uuid }
		'cx-stdlib/store'   { stdlib_src_store }
		'cx-stdlib/csv'     { stdlib_src_csv }
		'cx-stdlib/url'     { stdlib_src_url }
		'cx-stdlib/crypto'  { stdlib_src_crypto }
		'cx-stdlib/geo'     { stdlib_src_geo }
		'cx-stdlib/mime'    { stdlib_src_mime }
		'cx-stdlib/validate' { stdlib_src_validate }
		'cx-stdlib/email'   { stdlib_src_email }
		'cx-stdlib/html'    { stdlib_src_html }
		'cx-stdlib/i18n'     { stdlib_src_i18n }
		'cx-stdlib/locale'  { stdlib_src_locale }
		'cx-stdlib/ft'      { stdlib_src_ft }
		'cx-stdlib/similar' { stdlib_src_similar }
		'cx-stdlib/prof'    { stdlib_src_prof }
		'cx-stdlib/process' { stdlib_src_process }
		'cx-stdlib/fp'      { stdlib_src_fp }
		'cx-stdlib/bus'     { stdlib_src_bus }
		'cx-stdlib/journal' { stdlib_src_journal }
		'cx-stdlib/session' { stdlib_src_session }
		'cx-stdlib/authz'   { stdlib_src_authz }
		'cx-stdlib/sched'   { stdlib_src_sched }
		'cx-stdlib/did'     { stdlib_src_did }
		'cx-stdlib/vc'      { stdlib_src_vc }
		'cx-stdlib/xsp'     { stdlib_src_xsp }
		'cx-stdlib/jsonrpc' { stdlib_src_jsonrpc }
		'cx-stdlib/jsonschema' { stdlib_src_jsonschema }
		'cx-stdlib/live'    { stdlib_src_live }
		'cx-stdlib/supervise' { stdlib_src_supervise }
		'cx-stdlib/diagram' { stdlib_src_diagram }
		'cx-stdlib/map'     { stdlib_src_map }
		'cx-stdlib/array'   { stdlib_src_array }
		else                { none }
	}
}

// ── x/ experimental tier surface (D3) ────────────────────────────────────────

// bundled_x_names returns the bundled `cx-x/<name>` experimental-tier resolver
// names. SEPARATE from bundled_stdlib_names() — these are exempt from the frozen
// stability promise and MUST NOT be counted by the frozen-surface canary.
pub fn bundled_x_names() []string {
	return [
		'cx-x/run',
		'cx-x/llm',
		'cx-x/mcp',
		'cx-x/mcp-server',
		'cx-x/a2a',
		'cx-x/a2a-xap',
		'cx-x/term',
		'cx-x/adjudicate',
		'cx-x/tools',
		'cx-x/ux',
		'cx-x/ux-web',
		'cx-x/ux-tui',
	]
}

// bundled_x_source returns the source bytes for one bundled x/-tier module by
// resolver name (e.g. `cx-x/run`). Returns `none` for an unknown name.
pub fn bundled_x_source(name string) ?string {
	return match name {
		'cx-x/run' { x_src_run }
		'cx-x/llm' { x_src_llm }
		'cx-x/mcp' { x_src_mcp }
		'cx-x/mcp-server' { x_src_mcp_server }
		'cx-x/a2a' { x_src_a2a }
		'cx-x/a2a-xap' { x_src_a2a_xap }
		'cx-x/term' { x_src_term }
		'cx-x/adjudicate' { x_src_adjudicate }
		'cx-x/tools' { x_src_tools }
		'cx-x/ux' { x_src_ux }
		'cx-x/ux-web' { x_src_ux_web }
		'cx-x/ux-tui' { x_src_ux_tui }
		else       { none }
	}
}

// register_bundled_x registers every `cx-x/<name>` experimental-tier resolver
// into `table` (same in-memory registered-name path as the frozen tier).
pub fn register_bundled_x(mut table ModuleTable) {
	for name in bundled_x_names() {
		src := bundled_x_source(name) or { continue }
		table.register_source(name, src)
	}
}

// register_bundled_stdlib registers every `cx-stdlib/<name>`
// resolver from `bundled_stdlib_names()` into the supplied
// `ModuleTable`. The loader's existing registered-name resolution
// path (module_loader.v::resolve_lib) handles them as ordinary
// in-memory sources from there.
//
// Per: the loader's HTTPS fetch path is bypassed; no
// SRI verification; no transitive lockfile gate for bundled-↔-bundled
// edges. Callers wiring this into the lockfile path emit the
// `:resolved "bundled:<cx_bundled_stdlib_version>"` shape per
// spec/lockfile.md §4.2.
pub fn register_bundled_stdlib(mut table ModuleTable) {
	for name in bundled_stdlib_names() {
		src := bundled_stdlib_source(name) or { continue }
		table.register_source(name, src)
	}
}

// ── Codec module surfaces (core, registry-driven — design D2/D3/D6) ──────────
//
// Codecs are CORE (spec/03-approved/core/codec.md), not stdlib modules: they
// are deliberately ABSENT from `bundled_stdlib_names()` (the frozen 37-surface)
// and have no std-lib/*.md `[module-meta]`. But codec.md §3 mandates an
// in-program surface `[$<codec>:parse|emit|parse-bytes|emit-bytes]`, reached via
// `[?lib 'cx-stdlib/<codec>']`. We register those module sources here, SYNTHESIZED
// uniformly from the codec name — there are no committed per-codec source files
// and nothing can drift from the registry (the synthesis IS the single source).
//
// Only the text codecs that lack a dedicated stdlib module are registered here;
// json/csv/url/html already ship richer dedicated modules, and the binary codecs
// (cxcol/data-bin/ast) are bytes-only ABI/CLI surfaces, not `[?lib]` targets.
fn bundled_codec_module_names() []string {
	return ['cx', 'xml', 'yaml', 'toml', 'md']
}

// codec_module_source synthesizes the uniform `[$<fmt>:…]` codec module surface
// (codec.md §3). Bodies forward to the registry-driven native primitives
// (`<fmt>-parse` etc., vcx/code/stdlib_codec.v → vcx/cx/codec.v node entry
// points). `pure` per §5 — codecs charge no capability.
//
// The `cx` codec additionally carries the `cx:` self-host core surface
// (spec/modules/cx.md §2.1, #437): serialize / canonical / hash / diff /
// patch / to-format / from-format / equal / select forward to the native
// primitives in vcx/code/stdlib_cx.v. The same primitives are also reachable
// with NO [?lib] at all (modules/cx.md §1 activation "Always") through the
// call-fallback chain; the [?def]s here keep `[?lib 'cx-stdlib/cx' as=…]`
// aliasing working like every other module.
fn codec_module_source(fmt string) string {
	mut src := '[; cx-stdlib/${fmt} — codec surface (core; codec.md §3). Synthesized
   from the codec registry; bodies forward to registry-driven native
   primitives. The CX tree is the universal pivot (codec.md §1). ]
[?def parse        scope=public pure [returns any]    (\$s::string) [\$${fmt}-parse \$s]]
[?def parse-bytes  scope=public pure [returns any]    (\$b::bytes)  [\$${fmt}-parse-bytes \$b]]
[?def emit         scope=public pure [returns string] (\$v::any)    [\$${fmt}-emit \$v]]
[?def emit-bytes   scope=public pure [returns bytes]  (\$v::any)    [\$${fmt}-emit-bytes \$v]]
'
	if fmt == 'cx' {
		src += '[?def serialize    scope=public pure [returns string] (\$v::any)    [\$cx-serialize \$v]]
[?def canonical    scope=public pure [returns string] (\$v::any)    [\$cx-canonical \$v]]
[?def hash         scope=public pure [returns string] (\$v::any)    [\$cx-hash \$v]]
[?def diff         scope=public pure [returns any]    (\$a::any \$b::any) [\$cx-diff \$a \$b]]
[?def patch        scope=public pure [returns any]    (\$v::any \$d::any) [\$cx-patch \$v \$d]]
[?def to-format    scope=public pure [returns string] (\$v::any \$fmt::string) [\$cx-to-format \$v \$fmt]]
[?def from-format  scope=public pure [returns any]    (\$t::string \$fmt::string) [\$cx-from-format \$t \$fmt]]
[?def equal        scope=public pure [returns bool]   (\$a::any \$b::any) [\$cx-equal \$a \$b]]
[?def select       scope=public pure [returns any]    (\$v::any \$p::string) [\$cx-select \$v \$p]]
'
	}
	return src
}

// register_bundled_codecs registers every `cx-stdlib/<codec>` module source
// (synthesized) into `table`, so `[?lib 'cx-stdlib/cx']` etc. resolve.
pub fn register_bundled_codecs(mut table ModuleTable) {
	for fmt in bundled_codec_module_names() {
		table.register_source('cx-stdlib/${fmt}', codec_module_source(fmt))
	}
}

// new_seeded_module_table builds a fresh ModuleTable pre-seeded with
// every bundled cx-stdlib sub-package source, ready for [?lib]
// resolution at program-eval time. This is the per-program loader state
// stored on ProgramState (see matcher.v new_env).
pub fn new_seeded_module_table() ModuleTable {
	mut t := new_module_table()
	register_bundled_stdlib(mut t)
	register_bundled_x(mut t)
	register_bundled_codecs(mut t)
	// cx-xap: its OWN bundled package (not a cx-stdlib name) — registered here
	// directly rather than via bundled_stdlib_names(); the experience-layer
	// orchestrator over the cx-stdlib primitives (spec/03-approved/xap/xap.md §0).
	t.register_source('cx-xap', stdlib_src_xap)
	// cx-fabric: likewise its OWN bundled package — platform eventing composed
	// over journal/bus/store (spec/03-approved/xap/fabric.md, #518/#531).
	t.register_source('cx-fabric', stdlib_src_fabric)
	// The conformance fixture module sources are NOT registered here (#701):
	// they carry file-path / HTTPS resolver keys, and resolve_lib gives
	// registered sources precedence over disk — registering them in the
	// production constructor made `[?lib './local-helpers.cx']` silently
	// resolve to embedded fixture code instead of the user's own file.
	// The conformance gate registers them EXPLICITLY per-env
	// (register_conformance_test_modules, called by
	// vcx/tests/code_eval_fixtures_test.v); the production pin is
	// vcx/tests/module_loader_shadowing_test.v.
	return t
}

// ── Conformance test modules (in-memory, no filesystem / no live fetch) ──
//
// The module-system conformance fixtures (conformance/code.cxd §12) import
// modules by file-path / registered-name / HTTPS-URL resolvers whose sources
// have no on-disk or network presence. To keep the gate hermetic and
// deterministic — and to satisfy the spec's resolver-shape contracts without
// a real HTTP client (deferred per §12.4.2) — we register each fixture's
// module source IN MEMORY keyed by its literal resolver string. The loader's
// registered-name path already consults `registered_sources`; the resolver
// extension below (module_loader.v) routes the file-path / HTTPS shapes to
// the same in-memory map when an entry exists, so `'./local-helpers.cx'` and
// `'https://cdn.example.com/regex-helpers-1.2.3.zip'` resolve from these
// sources rather than disk / network.
//
// These are NOT bundled stdlib; they live under fixture-only resolver keys
// (`./*.cx`, `github.com/example/*`, `https://cdn.example.com/*`,
// `cx-stdlib/json/encoder`) and never clash with the 14 frozen names.

// ./local-helpers.cx — module-lib-resolver-file: `greet(name)`.
const testmod_src_local_helpers = '[?def greet scope=public ($name) [\$concat "hello, " \$name]]'

// The L139 approval-binding pair (stream 18 W2) — same name/params/body
// (⇒ same Tier-2), [effects] widened in v2 (⇒ different Tier-1 text).
const testmod_src_cmd_v1 = '[?def refund-order scope=public impure [effects] [returns int] (\$order::string \$amount::int 10) \$amount]'

const testmod_src_cmd_v2 = '[?def refund-order scope=public impure [effects [net]] [returns int] (\$order::string \$amount::int 10) \$amount]'

// ./public-only-module.cx — module-visibility-public / -private:
// one exported fn (identity) + one private helper (exists → CXER0216).
const testmod_src_public_only = '[?def exported-fn scope=public (\$x) \$x]
[?def private-helper (\$x) \$x]'

// ./mixed-module.cx — module-visibility-mixed: two public + one private.
const testmod_src_mixed = '[?def pub-a scope=public (\$x) \$x]
[?def pub-b scope=public (\$x) \$x]
[?def priv-c (\$x) \$x]'

// github.com/example/level-{a,b,c} — module-transitive-3-deep:
// a → b → c; `[\$a:call-through]` returns level-c\'s answer.
const testmod_src_level_a = '[?lib \'github.com/example/level-b\' as=b]
[?def call-through scope=public () [\$b:call-through]]'
const testmod_src_level_b = '[?lib \'github.com/example/level-c\' as=c]
[?def call-through scope=public () [\$c:call-through]]'
const testmod_src_level_c = '[?def call-through scope=public () from-level-c]'

// regex-helpers — module-lockfile-roundtrip / -lib-resolver-https /
// -https-fetch-sri-ok. Registered under BOTH the github name and the
// pinned HTTPS URL (an in-memory test source, not a live fetch).
const testmod_src_regex_helpers = '[?def compile scope=public (\$p) [regex pattern=\$p]]
[?def source scope=public (\$r) \$r/@pattern]
[?def version scope=public () "1.2.3"]'

// Phase 2.14 (register R3.12, RULED (b) 2026-08-09) — the tampered/unpinned
// battery. The in-memory registry is the loader's TRANSPORT seam only; the
// seeded lockfile below carries the pins, so verification runs for real:
// module-https-fetch-sri-mismatch / module-lockfile-integrity-mismatch
// register bytes that DIFFER from the pinned sri (one comment of drift) and
// must refuse CXER0209; module-https-fetch-unpinned pins the direct module
// but its dependency URL has NO lock entry — CXER0211 at the transitive
// resolve, before any transport is consulted.
const testmod_src_regex_helpers_tampered = '[?def compile scope=public (\$p) [regex pattern=\$p]]
[?def source scope=public (\$r) \$r/@pattern]
[?def version scope=public () "1.2.3"]
[; tampered — one line of drift the SRI pin must catch ]'

const testmod_src_needs_unpinned = '[?lib \'https://cdn.example.com/unpinned-dep-9.9.9.zip\' as=dep]
[?def use-it scope=public () [\$dep:anything]]'

// cx-stdlib/json/encoder — module-subpath-public: the manifest-declared
// public sub-path re-exporting `encode`.
const testmod_src_json_encoder = '[?def encode scope=public (\$v::any) [\$format-canonical \$v]]'

// ./scope-frames-module.cx — module-scope-through-frames (#646): a [?fn]
// created under a [?let]/HOF frame INSIDE a module def must capture the
// module\'s defining scope (sibling defs resolvable, dollar and bare form),
// not the importing program\'s scope. Before the fix the derived frames
// dropped in_function_body/cur_defining_scope, so these failed with
// `no callable "bump"` (dollar form) / silently built `[bump …]` data
// elements (bare form) when imported — while running green as a program.
const testmod_src_scope_frames = '[?def offset () 7]
[?def bump (\$x) [+ \$x [\$offset]]]
[?def fold-bump scope=public (\$a \$b \$c)
  [?let [= \$total [\$reduce (\$a, \$b, \$c) [?fn (\$acc \$e) [+ \$acc [\$bump \$e]]] 0]]
    [total n=\$total]]]
[?def label-of scope=public (\$v)
  [?let [= \$f [?fn (\$p) [?let [= \$o [\$offset]] [?str \'v={\$p}|o={\$o}\']]]]
    [\$f \$v]]]
[?def bare-call scope=public (\$v)
  [?let [= \$f [?fn (\$p) [bump \$p]]]
    [\$f \$v]]]'

// register_conformance_test_modules seeds the in-memory sources every
// module-system fixture imports. Idempotent; safe to call on any fresh
// seeded table.
pub fn register_conformance_test_modules(mut table ModuleTable) {
	table.register_source('./local-helpers.cx', testmod_src_local_helpers)
	// Stream-18 W2 (L139): the approval-binds-Tier-1 pair — two versions
	// of the SAME command def (name/params/body identical → same Tier-2
	// computes-as, cmd-011's clause-exclusion invariance) differing ONLY
	// in the [effects] clause (OUTSIDE Tier-2 by S0). v1 declares the
	// empty clause; v2 widens to [net]. An approval minted against v1's
	// proposal must never admit v2 — Tier-1 def text is the trust key.
	table.register_source('./cmd-v1.cx', testmod_src_cmd_v1)
	table.register_source('./cmd-v2-widened.cx', testmod_src_cmd_v2)
	table.register_source('./public-only-module.cx', testmod_src_public_only)
	table.register_source('./mixed-module.cx', testmod_src_mixed)
	table.register_source('github.com/example/level-a', testmod_src_level_a)
	table.register_source('github.com/example/level-b', testmod_src_level_b)
	table.register_source('github.com/example/level-c', testmod_src_level_c)
	table.register_source('github.com/example/regex-helpers', testmod_src_regex_helpers)
	table.register_source('https://cdn.example.com/regex-helpers-1.2.3.zip', testmod_src_regex_helpers)
	table.register_source('cx-stdlib/json/encoder', testmod_src_json_encoder)
	table.register_source('./scope-frames-module.cx', testmod_src_scope_frames)
	// Phase 2.14 transport-seam bytes for the pin-verification battery.
	table.register_source('https://cdn.example.com/regex-helpers-tampered.zip', testmod_src_regex_helpers_tampered)
	table.register_source('https://cdn.example.com/needs-unpinned-dep.zip', testmod_src_needs_unpinned)
	table.register_source('https://cdn.example.com/tampered-helpers-1.0.0.zip', testmod_src_regex_helpers_tampered)
	// The seeded lockfile — the pins the loader now REQUIRES for every
	// HTTPS-resolved module (code.md §12.1.3). SRIs are computed here from
	// the true sources (never hardcoded), so the seed can't drift; the two
	// tampered entries deliberately pin the UNTAMPERED bytes' sri.
	sri_true := make_sri('sha384', testmod_src_regex_helpers) or { '' }
	sri_needs := make_sri('sha384', testmod_src_needs_unpinned) or { '' }
	lock_text := '[cx.lock version=1
  [modules
    [module name="https://cdn.example.com/regex-helpers-1.2.3.zip" resolved="https://cdn.example.com/regex-helpers-1.2.3.zip" sri="${sri_true}"]
    [module name="https://cdn.example.com/regex-helpers-tampered.zip" resolved="https://cdn.example.com/regex-helpers-tampered.zip" sri="${sri_true}"]
    [module name="https://cdn.example.com/needs-unpinned-dep.zip" resolved="https://cdn.example.com/needs-unpinned-dep.zip" sri="${sri_needs}"]
    [module name="github.com/example/tampered-helpers" resolved="https://cdn.example.com/tampered-helpers-1.0.0.zip" sri="${sri_true}"]]]'
	table.lockfile = cx.parse_lockfile_text(lock_text) or { cx.Lockfile{} }
	table.lock_probed = true
}
