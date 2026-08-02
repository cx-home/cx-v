module code

import cx

// stdlib_dispatch.v — native-primitive dispatch for cx-stdlib modules.
//
// Many cx-stdlib functions cannot be expressed as pure CX `[?def]`
// bodies (regex, hashing, time, random, OS-path/glob, byte codecs, …).
// Their bodies bottom out in native primitives implemented in V. Rather
// than crowd the language-core `invoke_builtin` set, each module
// contributes its primitives in its own `vcx/code/stdlib_<mod>.v` file
// as a function `<mod>_stdlib_builtin(name, args) ?cx.Node`, and adds one
// line to the chain below.
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
fn stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	// ── module primitive chains (one `if r := <mod>_stdlib_builtin…` per
	//    module is inserted here as each module lands) ─────────────────
	if r := math_stdlib_builtin(name, args) { return r }
	if r := strings_stdlib_builtin(name, args) { return r }
	if r := bytes_stdlib_builtin(name, args) { return r }
	if r := path_stdlib_builtin(name, args) { return r }
	if r := hash_stdlib_builtin(name, args) { return r }
	if r := env_stdlib_builtin(name, args) { return r }
	if r := random_stdlib_builtin(name, args) { return r }
	if r := uuid_stdlib_builtin(name, args) { return r }
	if r := format_stdlib_builtin(name, args) { return r }
	if r := time_stdlib_builtin(name, args) { return r }
	if r := store_stdlib_builtin(name, args) { return r }
	if r := sql_stdlib_builtin(name, args) { return r }
	$if cx_db_redis ? {
		if r := redis_stdlib_builtin(name, args) { return r }
	}
	if r := json_stdlib_builtin(name, args) { return r }
	if r := re_stdlib_builtin(name, args) { return r }
	if r := csv_stdlib_builtin(name, args) { return r }
	if r := url_stdlib_builtin(name, args) { return r }
	if r := crypto_stdlib_builtin(name, args) { return r }
	if r := geo_stdlib_builtin(name, args) { return r }
	if r := mime_stdlib_builtin(name, args) { return r }
	if r := validate_stdlib_builtin(name, args) { return r }
	if r := email_stdlib_builtin(name, args) { return r }
	if r := html_stdlib_builtin(name, args) { return r }
	if r := i18n_stdlib_builtin(name, args) { return r }
	if r := locale_stdlib_builtin(name, args) { return r }
	if r := ft_stdlib_builtin(name, args) { return r }
	if r := similar_stdlib_builtin(name, args) { return r }
	if r := log_stdlib_builtin(name, args) { return r }
	if r := test_stdlib_builtin(name, args) { return r }
	if r := io_stdlib_builtin(name, args) { return r }
	if r := net_stdlib_builtin(name, args) { return r }
	if r := http_stdlib_builtin(name, args) { return r }
	if r := prof_stdlib_builtin(name, args) { return r }
	if r := process_stdlib_builtin(name, args) { return r }
	if r := bus_stdlib_builtin(name, args) { return r }
	if r := journal_stdlib_builtin(name, args) { return r }
	if r := fabric_stdlib_builtin(name, args) { return r }
	if r := session_stdlib_builtin(name, args) { return r }
	if r := authz_stdlib_builtin(name, args) { return r }
	if r := did_stdlib_builtin(name, args) { return r }
	if r := vc_stdlib_builtin(name, args) { return r }
	if r := sched_stdlib_builtin(name, args) { return r }
	if r := term_stdlib_builtin(name, args) { return r }
	if r := xap_stdlib_builtin(name, args) { return r }
	if r := xap_dist_stdlib_builtin(name, args) { return r }
	if r := xsp_stdlib_builtin(name, args) { return r }
	if r := xsp_auth_stdlib_builtin(name, args) { return r }
	if r := jsonschema_stdlib_builtin(name, args) { return r }
	// Registry-driven codec surface (cx/xml/yaml/toml/md + binary). Chained
	// LAST so a dedicated module (json/csv/url/html) wins any name clash.
	if r := codec_registry_dispatch(name, args) { return r }
	return none
}
