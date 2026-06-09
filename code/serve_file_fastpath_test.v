module code

import cx
import os

// Verifies the static-file fast-path DETECTION (static_serve_file_spec) only
// fires for a bare `[$serve-file]` / `[$serve-file "PATH"]` resource body and
// never for anything that would behave differently through the eval path.
// End-to-end byte correctness of the served responses is covered by
// v08_http_service_real_socket_test.v (which now routes through the fast path).

fn sf_call(args []cx.ProgramNode) cx.ProgramNode {
	return cx.ProgramCall{
		name: 'serve-file'
		args: args
	}
}

fn str_lit(s string) cx.ProgramNode {
	return cx.ProgramLiteral{
		kind:    .string_lit
		str_val: s
	}
}

fn test_detects_bare_serve_file() {
	no_cl := map[string]Closure{}
	no_bn := map[string]cx.Node{}

	// `[$serve-file]` → no-literal spec.
	spec0 := static_serve_file_spec(sf_call([]cx.ProgramNode{}), no_cl, no_bn) or {
		assert false, 'bare [\$serve-file] should be detected'
		return
	}
	assert spec0.has_literal == false

	// `[$serve-file "index.html"]` → literal spec.
	spec1 := static_serve_file_spec(sf_call([str_lit('index.html')]), no_cl, no_bn) or {
		assert false, 'literal [\$serve-file "index.html"] should be detected'
		return
	}
	assert spec1.has_literal == true
	assert spec1.literal == 'index.html'
}

fn test_rejects_non_static_bodies() {
	no_cl := map[string]Closure{}
	no_bn := map[string]cx.Node{}

	// A different builtin call → not a serve-file.
	if _ := static_serve_file_spec(cx.ProgramCall{ name: 'concat' }, no_cl, no_bn) {
		assert false, 'non-serve-file call must not be detected'
	}

	// serve-file with a `!`/`?` postfix → slow path (conservative).
	if _ := static_serve_file_spec(cx.ProgramCall{ name: 'serve-file', must_succeed: true },
		no_cl, no_bn) {
		assert false, '[\$serve-file]! must not be fast-pathed'
	}
	if _ := static_serve_file_spec(cx.ProgramCall{ name: 'serve-file', fallible: true },
		no_cl, no_bn) {
		assert false, '[\$serve-file]? must not be fast-pathed'
	}

	// More than one arg, or a non-literal arg → slow path.
	if _ := static_serve_file_spec(sf_call([str_lit('a'), str_lit('b')]), no_cl, no_bn) {
		assert false, 'multi-arg serve-file must not be fast-pathed'
	}
	non_lit := cx.ProgramCall{ name: 'request-path' }
	if _ := static_serve_file_spec(sf_call([non_lit]), no_cl, no_bn) {
		assert false, 'serve-file with a computed arg must not be fast-pathed'
	}

	// A non-call body (e.g. an element literal) → not a serve-file.
	if _ := static_serve_file_spec(cx.ProgramLiteral{ kind: .cx_element, name: 'response' },
		no_cl, no_bn) {
		assert false, 'non-call body must not be detected'
	}
}

// serve_file_outcome honors use_cache: default off stores nothing (always
// reads fresh — no staleness, no memory); opt-in populates + revalidates.
fn test_cache_opt_in_default_off() {
	dir := os.join_path(os.vtmp_dir(), 'cx_serve_cache_test_${os.getpid()}')
	os.mkdir_all(dir) or {
		assert false, 'mkdir failed: ${err}'
		return
	}
	defer { os.rmdir_all(dir) or {} }
	os.write_file(os.join_path(dir, 'f.txt'), 'BODY-A') or {
		assert false, 'write failed: ${err}'
		return
	}

	// Isolate this file's key from any other test's cache state.
	key := os.join_path(dir, 'f.txt')
	mut c := serve_file_cache()
	c.lock.lock()
	c.m.delete(key)
	c.lock.unlock()

	// use_cache = false → correct body, but NOTHING cached.
	o_off := serve_file_outcome('f.txt', dir, false)
	assert o_off.status == 200
	assert o_off.body == 'BODY-A'
	c.lock.rlock()
	cached_off := key in c.m
	c.lock.runlock()
	assert !cached_off, 'cache OFF must not store an entry'

	// use_cache = true → body cached; a second call is a hit.
	o_on := serve_file_outcome('f.txt', dir, true)
	assert o_on.status == 200
	assert o_on.body == 'BODY-A'
	c.lock.rlock()
	cached_on := key in c.m
	c.lock.runlock()
	assert cached_on, 'cache ON must store an entry'
}

fn test_respects_shadowing() {
	// serve-file shadowed by a closure-valued binding → must NOT fast-path
	// (the eval path would invoke the user closure, not the builtin).
	mut bn := map[string]cx.Node{}
	bn['serve-file'] = mk_closure_sentinel('user-serve-file')
	if _ := static_serve_file_spec(sf_call([]cx.ProgramNode{}), map[string]Closure{}, bn) {
		assert false, 'closure-shadowed serve-file must not be fast-pathed'
	}
}
