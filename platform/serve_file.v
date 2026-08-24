@[has_globals]
module platform
import code {
	MatchEnv,
	path_separator,
	scalar_string,
}

import cx
import os
import sync

// ── static-file cache (concurrency-safe) ─────────────────────────────
//
// The picoev multi-reactor runs handlers on N worker threads in
// parallel, so serving a file per request used to do os.is_dir +
// os.is_file + os.read_bytes + bytestr() copy on EVERY request — heavy
// syscalls + allocation that throttle scaling under load. This caches
// the materialized body + content-type keyed by resolved fs-path,
// validated by mtime (one stat per hit vs a full read + copy). Reads
// take the shared rlock (concurrent across workers); a miss takes the
// exclusive lock to fill. Stored bodies are V strings (immutable,
// shared by header) so a cache hit copies no bytes.

struct CachedFile {
	body  string
	ct    string
	mtime i64
}

struct ServeFileCache {
mut:
	lock &sync.RwMutex = unsafe { nil }
	m    map[string]CachedFile
}

__global (
	g_serve_file_cache voidptr
)

// serve_file_cache_init eagerly creates the cache before worker threads
// spawn (avoids a lazy-init race). Idempotent.
fn serve_file_cache_init() {
	if g_serve_file_cache == unsafe { nil } {
		c := &ServeFileCache{
			lock: sync.new_rwmutex()
		}
		g_serve_file_cache = voidptr(c)
	}
}

fn serve_file_cache() &ServeFileCache {
	serve_file_cache_init()
	return unsafe { &ServeFileCache(g_serve_file_cache) }
}

// serve_file_cache_get returns the cached entry for `fs_path` iff present
// AND its mtime still matches (one stat). Otherwise none.
fn serve_file_cache_get(fs_path string) ?CachedFile {
	mut c := serve_file_cache()
	c.lock.rlock()
	entry := c.m[fs_path] or {
		c.lock.runlock()
		return none
	}
	c.lock.runlock()
	if os.file_last_mod_unix(fs_path) != entry.mtime {
		return none
	}
	return entry
}

// serve_file_cache_put stores a materialized file body + content-type.
fn serve_file_cache_put(fs_path string, body string, ct string, mtime i64) {
	mut c := serve_file_cache()
	c.lock.lock()
	c.m[fs_path] = CachedFile{
		body:  body
		ct:    ct
		mtime: mtime
	}
	c.lock.unlock()
}

// serve_file.v — [$serve-file] zero-arg static-file builtin.
//
// Resolves $request/path (or the optional positional path arg) under
// the service root stashed in dyn_context as cx-service-root, returns
// a [response status=… [headers Content-Type=…] [body BYTES]] element.
//
// Path-traversal guard: any `..` segment in the request path → 400.
// Missing file → 404. Success → 200 with MIME type from mime.v.
//
// Dispatched from eval.v's dispatch_call_l via try_eval_serve_file
// before the stdlib_builtin fallback.

// dyn_service_root_key — the dyn_context key under which the active
// service root is stashed at handler-entry time. Used by
// [$serve-file] to resolve a request path to a filesystem path.
const dyn_service_root_key = 'cx-service-root'

// try_eval_serve_file dispatches the [$serve-file] builtin. Returns
// none when `name` is not the serve-file builtin so the regular
// dispatch chain continues. The signature matches dispatch_call_l's
// env-bearing form so [$serve-file] can read $request from env.
fn try_eval_serve_file(name string, args []cx.Node, mut env MatchEnv) ?cx.Node {
	if name != 'serve-file' { return none }

	// Determine the request path. Optional arg 0 overrides; otherwise
	// read from $request/path.
	mut req_path := ''
	if args.len >= 1 {
		req_path = scalar_string(args[0]) or { return mk_serve_response(400, '', 'bad path') }
	} else {
		req_path = serve_file_read_request_path(mut env) or {
			return mk_serve_response(400, '', 'bad request')
		}
	}

	// Resolve under service root from dyn_context.
	root := serve_file_lookup_root(env) or {
		return mk_serve_response(500, '', 'no service root in scope')
	}

	o := serve_file_outcome(req_path, root, serve_file_lookup_cache(env))
	return mk_serve_response(o.status, o.ct, o.body)
}

// ServeOutcome is the (status, content-type, body) result of resolving a
// request path under a service root. `body` for a non-200 outcome is the
// plain error message (mk_serve_response maps an empty `ct` to text/plain).
struct ServeOutcome {
	status int
	ct     string
	body   string
}

// serve_file_outcome resolves `req_path` under `root` to a ServeOutcome via
// the mtime-validated static-file cache. This is the SINGLE source of truth
// for path resolution + caching, shared by the `[$serve-file]` builtin
// (try_eval_serve_file) and the listener's static-file fast path
// (serve_file_fast_wire) so the two can never diverge on resolution or cache
// semantics. Pure w.r.t. cx.Node (no env, no Element construction).
fn serve_file_outcome(req_path string, root string, use_cache bool) ServeOutcome {
	// Path-traversal guard.
	for seg in req_path.split('/') {
		if seg == '..' { return ServeOutcome{ status: 400, body: 'bad path' } }
	}
	// Trim leading `/` so os.join_path doesn't anchor to fs-root.
	mut rel := req_path
	if rel.starts_with('/') { rel = rel[1..] }
	mut fs_path := os.join_path(root, rel)
	if os.is_dir(fs_path) {
		// Directory request — try index.html.
		fs_path = os.join_path(fs_path, 'index.html')
	}
	// Cache hit (mtime-validated) — skip is_file + read + bytestr copy.
	// Only consulted when the service opted in via [cache true]; default
	// off reads the file fresh every request (always current).
	if use_cache {
		if cf := serve_file_cache_get(fs_path) {
			return ServeOutcome{ status: 200, ct: cf.ct, body: cf.body }
		}
	}
	if !os.is_file(fs_path) {
		return ServeOutcome{ status: 404, body: 'not found: ${req_path}' }
	}
	// SECURITY: confine the RESOLVED path under the resolved root. The literal
	// `..`-segment check above does NOT stop a symlink inside the webroot that
	// points outside it (e.g. webroot/link -> /etc/hosts). os.real_path
	// canonicalizes symlinks + `..`; reject anything that escapes root. Checked
	// AFTER the is_file/404 gate on purpose: os.real_path does not resolve a
	// non-existent path, so a missing file under a symlinked webroot (e.g. macOS
	// /tmp → /private/tmp) would otherwise false-positive as 403 instead of 404.
	real_root := os.real_path(root)
	real_target := os.real_path(fs_path)
	if real_target != real_root && !real_target.starts_with(real_root + os.path_separator) {
		return ServeOutcome{ status: 403, body: 'forbidden' }
	}
	bytes := os.read_bytes(fs_path) or {
		return ServeOutcome{ status: 500, body: 'read error: ${err.msg()}' }
	}
	ct := content_type_for(fs_path)
	body_str := bytes.bytestr()
	if use_cache {
		serve_file_cache_put(fs_path, body_str, ct, os.file_last_mod_unix(fs_path))
	}
	return ServeOutcome{ status: 200, ct: ct, body: body_str }
}

// serve_file_read_request_path pulls $request/path from env bindings.
// $request is the request envelope built by build_request_node; its
// `path` field is an attribute on the [request …] element.
fn serve_file_read_request_path(mut env MatchEnv) ?string {
	req := env.bindings['request'] or { return none }
	if req !is cx.Element { return none }
	el := req as cx.Element
	// `path` is an attribute on the request envelope.
	p := el.attr('path')
	if p != '' { return p }
	// Legacy fallback: a child `[path "…"]` element.
	for c in el.items {
		if c is cx.Element && (c as cx.Element).name == 'path' {
			pe := c as cx.Element
			if pe.items.len >= 1 {
				return scalar_string(pe.items[0])
			}
		}
	}
	return none
}

// serve_file_lookup_root walks env.dyn_context for the cx-service-root
// entry. Returns none when no listener has stashed a root.
fn serve_file_lookup_root(env MatchEnv) ?string {
	for e in env.dyn_context {
		if e is cx.Element && (e as cx.Element).name == dyn_service_root_key {
			el := e as cx.Element
			if el.items.len >= 1 {
				return scalar_string(el.items[0])
			}
		}
	}
	return none
}

// serve_file_lookup_cache returns the service's static-file cache opt-in,
// carried as the `cache` attribute on the cx-service-root dyn entry the
// listener stashes at handler entry. Default false (no service in scope, or
// [cache true] absent) — direct [$serve-file] eval outside a service never
// caches.
fn serve_file_lookup_cache(env MatchEnv) bool {
	for e in env.dyn_context {
		if e is cx.Element && (e as cx.Element).name == dyn_service_root_key {
			el := e as cx.Element
			if a := el.attr_val('cache') {
				if a is bool {
					return a
				}
			}
			return false
		}
	}
	return false
}

// mk_serve_response builds a [response status=N [headers Content-Type=…]
// [body STR]] element. Empty content_type → text/plain default for the
// error path; otherwise the resolved MIME type. Wire emitter (in the
// real-socket listener) consumes this envelope shape.
fn mk_serve_response(status int, content_type string, body_str string) cx.Node {
	mut r_attrs := []cx.Attribute{}
	mut r_items := []cx.Node{}
	r_attrs << cx.new_attribute('status', cx.ScalarValue(i64(status)), cx.AttributeMeta{
		data_type: ?string('int') })
	ct := if content_type == '' { 'text/plain; charset=utf-8' } else { content_type }
	hdr := cx.Element{
		name: 'headers'
		items: [cx.Node(cx.Element{
			name: 'header'
			attrs: [
				cx.new_attribute('name',  cx.ScalarValue('Content-Type'), cx.AttributeMeta{
					data_type: ?string(none) }),
				cx.new_attribute('value', cx.ScalarValue(ct), cx.AttributeMeta{
					data_type: ?string(none) }),
			]
		})]
	}
	r_items << hdr
	r_items << cx.Element{
		name: 'body'
		items: [cx.Node(cx.ScalarNode{
			value: cx.ScalarValue(body_str), data_type: cx.ScalarType.string_type
		})]
	}
	return cx.Element{
		name:  'response'
		attrs: r_attrs
		items: r_items
	}
}
