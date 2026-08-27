module code

import cx

// stdlib_dispatch.v — native-primitive dispatch for cx-stdlib modules.
//
// Many cx-stdlib functions cannot be expressed as pure CX `[?def]`
// bodies (regex, hashing, time, random, OS-path/glob, byte codecs, …).
// Their bodies bottom out in native primitives implemented in V. Rather
// than crowd the language-core `invoke_builtin` set, each module
// contributes its primitives in its own `vcx/code/stdlib_<mod>.v` file
// as a function `<mod>_stdlib_builtin(name, args) ?cx.Node`. A RING-1
// module adds one line to the chain below; a RING-2 pack registers via
// ring2_register.v into the I3 registry probe instead (cx_partition.md
// §3 — the evaluator holds no direct reference to Ring-2 dispatchers).
//
// `stdlib_builtin` is consulted by `dispatch_call` AFTER the core
// `invoke_builtin` set, so a core builtin always wins on a name clash.
// A module function reached here is always called in the qualified
// `prefix/fn(args)` call form (the bundle bodies use call syntax), so
// these primitives never need `builtin_dispatchable` registration.
//
// NOTE on filenames: V treats a trailing `_<word>.v` suffix as a
// conditional-compilation platform/arch guard and may EXCLUDE the file
// from the build (this file was originally `stdlib_native.v`, silently
// dropped because `native` was read as a guard). Per-module files like
// `stdlib_path.v` / `stdlib_bytes.v` are safe (path/bytes are not
// platform words); avoid `_native` / `_test` / OS / arch suffixes.
//
// stdlib_builtin is the chain HEAD: it brackets the module chain with the
// R-A8 (#955) operand-kind fault slot. The slot is cleared here so a
// recorded fault can only ever describe THIS dispatch, and an end-of-chain
// miss with a fault standing is converted into the CXER0100 err naming the
// function as written (see stdlib_operand_fault.v). A miss with no fault
// standing still returns `none` — "this dispatcher does not own this name"
// — so the `user-undefined` / `no callable "…"` lane is untouched.
fn stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	clear_operand_fault()
	if r := stdlib_builtin_chain(name, args) {
		return r
	}
	if e := operand_fault_err(name, args) {
		return e
	}
	return none
}

fn stdlib_builtin_chain(name string, args []cx.Node) ?cx.Node {
	// ── module primitive chains (one `if r := <mod>_stdlib_builtin…` per
	//    module is inserted here as each module lands) ─────────────────
	if r := math_stdlib_builtin(name, args) { return r }
	if r := strings_stdlib_builtin(name, args) { return r }
	if r := bytes_stdlib_builtin(name, args) { return r }
	if r := path_stdlib_builtin(name, args) { return r }
	if r := hash_stdlib_builtin(name, args) { return r }
	if r := diagram_stdlib_builtin(name, args) { return r }
	// Ring-1 local-effect packs (§4; I4 profile gates): each chain entry is
	// compiled out with its pack (`-d cx_no_pack_<name>`), so an excluded
	// pack's names fall through to the undefined-callable refusal — the same
	// not-in-subset class as Ring-2 names in a platform-less artifact.
	$if !cx_no_pack_env ? {
		if r := env_stdlib_builtin(name, args) { return r }
	}
	$if !cx_no_pack_random ? {
		if r := random_stdlib_builtin(name, args) { return r }
	}
	if r := uuid_stdlib_builtin(name, args) { return r }
	if r := format_stdlib_builtin(name, args) { return r }
	$if !cx_no_pack_time ? {
		if r := time_stdlib_builtin(name, args) { return r }
	}
	// Ring-2 packs (store/sql/redis/email/net/http/bus/journal/fabric/
	// session/authz/did/vc/xap/xap-dist/xsp/xsp-auth) dispatch through
	// the I3 registry — registered at init by ring2_register.v, probed
	// once here in the pre-split chain order (entries are name-gated
	// and pack name-sets disjoint, so the collapsed position is
	// behavior-identical; see ring_registry.v).
	if r := ring2_stdlib_builtin(name, args) { return r }
	// http CLIENT pack (Ring 1, §4 cli profile — seam H): the serve half
	// registers via ring2_register.v; name sets are disjoint, so sitting
	// after the registry probe is behavior-identical.
	$if !cx_no_pack_http_client ? {
		if r := http_client_stdlib_builtin(name, args) { return r }
	}
	if r := json_stdlib_builtin(name, args) { return r }
	if r := re_stdlib_builtin(name, args) { return r }
	if r := csv_stdlib_builtin(name, args) { return r }
	if r := url_stdlib_builtin(name, args) { return r }
	if r := crypto_stdlib_builtin(name, args) { return r }
	if r := geo_stdlib_builtin(name, args) { return r }
	if r := mime_stdlib_builtin(name, args) { return r }
	if r := validate_stdlib_builtin(name, args) { return r }
	if r := html_stdlib_builtin(name, args) { return r }
	if r := i18n_stdlib_builtin(name, args) { return r }
	if r := locale_stdlib_builtin(name, args) { return r }
	if r := ft_stdlib_builtin(name, args) { return r }
	if r := similar_stdlib_builtin(name, args) { return r }
	$if !cx_no_pack_log ? {
		if r := log_stdlib_builtin(name, args) { return r }
	}
	if r := test_stdlib_builtin(name, args) { return r }
	$if !cx_no_pack_io ? {
		if r := io_stdlib_builtin(name, args) { return r }
	}
	if r := prof_stdlib_builtin(name, args) { return r }
	$if !cx_no_pack_process ? {
		if r := process_stdlib_builtin(name, args) { return r }
	}
	$if !cx_no_pack_sched ? {
		if r := sched_stdlib_builtin(name, args) { return r }
	}
	$if !cx_no_pack_term ? {
		if r := term_stdlib_builtin(name, args) { return r }
	}
	if r := jsonschema_stdlib_builtin(name, args) { return r }
	// Registry-driven codec surface (cx/xml/yaml/toml/md + binary). Chained
	// LAST so a dedicated module (json/csv/url/html) wins any name clash.
	if r := codec_registry_dispatch(name, args) { return r }
	return none
}
