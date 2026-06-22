module code

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

// xsp — XAP Stream Protocol frame codec (spec/02-working/xsp.md; issue #31).
const stdlib_src_xsp = $embed_file('../stdlib/xsp.cx').to_string()

const stdlib_src_jsonrpc = $embed_file('../stdlib/jsonrpc.cx').to_string()

// jsonschema — JSON Schema 2020-12 validation (MCP-tool-schema subset; #6 S7).
const stdlib_src_jsonschema = $embed_file('../stdlib/jsonschema.cx').to_string()

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
fn codec_module_source(fmt string) string {
	return '[; cx-stdlib/${fmt} — codec surface (core; codec.md §3). Synthesized
   from the codec registry; bodies forward to registry-driven native
   primitives. The CX tree is the universal pivot (codec.md §1). ]
[?def parse        scope=public pure [returns any]    (\$s::string) [\$${fmt}-parse \$s]]
[?def parse-bytes  scope=public pure [returns any]    (\$b::bytes)  [\$${fmt}-parse-bytes \$b]]
[?def emit         scope=public pure [returns string] (\$v::any)    [\$${fmt}-emit \$v]]
[?def emit-bytes   scope=public pure [returns bytes]  (\$v::any)    [\$${fmt}-emit-bytes \$v]]
'
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
	register_conformance_test_modules(mut t)
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

// cx-stdlib/json/encoder — module-subpath-public: the manifest-declared
// public sub-path re-exporting `encode`.
const testmod_src_json_encoder = '[?def encode scope=public (\$v::any) [\$format-canonical \$v]]'

// register_conformance_test_modules seeds the in-memory sources every
// module-system fixture imports. Idempotent; safe to call on any fresh
// seeded table.
pub fn register_conformance_test_modules(mut table ModuleTable) {
	table.register_source('./local-helpers.cx', testmod_src_local_helpers)
	table.register_source('./public-only-module.cx', testmod_src_public_only)
	table.register_source('./mixed-module.cx', testmod_src_mixed)
	table.register_source('github.com/example/level-a', testmod_src_level_a)
	table.register_source('github.com/example/level-b', testmod_src_level_b)
	table.register_source('github.com/example/level-c', testmod_src_level_c)
	table.register_source('github.com/example/regex-helpers', testmod_src_regex_helpers)
	table.register_source('https://cdn.example.com/regex-helpers-1.2.3.zip', testmod_src_regex_helpers)
	table.register_source('cx-stdlib/json/encoder', testmod_src_json_encoder)
}
