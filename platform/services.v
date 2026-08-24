module platform
import code {
	ClientRecord,
	EvalError,
	MatchEnv,
	ResourceRecord,
	ServiceRecord,
	append_result_field,
	canonical_message,
	directive_clause,
	duration_to_ns,
	eval,
	eval_node,
	is_err_value,
	labeled_slot,
	mk_err,
	mk_err_with_slots,
	read_result_field,
	scalar_int,
	scalar_string,
	scalar_to_text,
}

import cx

// ── §10.3 services + clients — single-thread reference substrate ──────────
//
// Phase 3.8. Implements:
//   [?http-service]    — register a service in env.state.services
//                        (renamed from [?service] 2026-05-28; the bare
//                        name `service` is reserved for a future broader
//                        concept covering auth/identity/secrets/state
//                        across environments)
//   [?service-handle]  — name-keyed lookup
//   [?stop]            — graceful shutdown (status → 'stopped')
//   [?wait-for :service] — observe terminal state as [terminated ...]
//   [?http-client]     — build a client record bound to a target URL
//   client postfix calls — get/post/put/delete/patch/head/options/request
//   [?test-service-client] — orchestrates server-spawn + client-call + stop,
//                            exposes $test-target to the :client-call body
//   [?test-tls-config] — emits a fixture-deterministic TLS config token
//
// Real network listening is out of scope per spec §1.2; the
// substrate routes client postfix calls into the registered service's
// matched resource :body directly, in-process. Once Phase 6.3 wires the
// gate-16 HTTP-throughput bench against a real net.http listener, this
// module gains an opt-in real-socket path keyed off the target URL
// scheme (`cx-test://` → in-process, `http://` → real net.http).

// ── Slot extraction helpers ───────────────────────────────────────────────

fn eval_string_slot(d cx.ProgramDirective, label string, mut env MatchEnv, default_val string) !string {
	// Dual-accept: legacy `:label V` AND `[label V]` clause-child.
	if n := directive_clause(d, label) {
		v := eval_node(n, mut env)!
		if v is cx.ScalarNode {
			x := v.value
			if x is string { return x }
		}
		return error('${label} must evaluate to a string')
	}
	return default_val
}

fn eval_bool_slot(d cx.ProgramDirective, label string, mut env MatchEnv, default_val bool) !bool {
	// Dual-accept: legacy `:label V` AND `[label V]` clause-child.
	if n := directive_clause(d, label) {
		v := eval_node(n, mut env)!
		if v is cx.ScalarNode {
			x := v.value
			if x is bool { return x }
			if x is string {
				if x == 'true' { return true }
				if x == 'false' { return false }
			}
		}
		return error('${label} must evaluate to a bool')
	}
	return default_val
}

fn eval_int_slot(d cx.ProgramDirective, label string, mut env MatchEnv, default_val i64) !i64 {
	// Dual-accept: legacy `:label V` AND `[label V]` clause-child.
	if n := directive_clause(d, label) {
		v := eval_node(n, mut env)!
		if w := scalar_int(v) { return w }
		return error('${label} must evaluate to an integer')
	}
	return default_val
}

fn eval_duration_slot(d cx.ProgramDirective, label string, default_ns i64) !i64 {
	// Dual-accept: legacy `:label V` AND `[label V]` clause-child.
	if n := directive_clause(d, label) {
		if n is cx.ProgramLiteral && n.kind == .duration_lit {
			if ns := duration_to_ns(n.dur_val) { return ns }
		}
		return error('${label} must be a duration literal')
	}
	return default_ns
}

// ── [?http-service] ───────────────────────────────────────────────────────

fn eval_http_service(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	name := eval_string_slot(d, 'name', mut env, '') or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?http-service] requires :name' }
	}
	if name == '' {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?http-service] :name must be non-empty' }
	}
	// :on identifies the protocol. The parser preserves identifiers as
	// cx.ProgramLiteral cx_element with empty body in some shapes; in practice
	// the lexer emits the ident token which the parser maps to a string
	// scalar. Accept either string or cx-element with name='http'.
	proto := service_protocol(d, mut env)!
	if proto != 'http' {
		return EvalError{ code: 'cx-err:CXER0001',
			message: '[?http-service] :on must be `http` (got `${proto}`)' }
	}
	requested_port := eval_int_slot(d, 'port', mut env, i64(0))!
	read_to := eval_duration_slot(d, 'read-timeout',     30 * i64(1_000_000_000))!
	write_to := eval_duration_slot(d, 'write-timeout',   30 * i64(1_000_000_000))!
	max_body := eval_int_slot(d, 'max-body-bytes', mut env, i64(10_485_760))!
	grace := eval_duration_slot(d, 'grace-period',       30 * i64(1_000_000_000))!
	tls := tls_config_token(d, mut env)!

	resources := collect_resources(d, mut env)!

	// optional clause-children configuring the real-socket
	// listener. Absent → in-process behavior (today's path).
	root := eval_string_slot(d, 'root', mut env, '')!
	bind_host := eval_string_slot(d, 'bind-host', mut env, '')!
	block_flag := eval_bool_slot(d, 'block', mut env, false)!
	// Static-file cache is opt-in (default off) so file edits show up
	// immediately and the server holds no body memory unless asked.
	cache_flag := eval_bool_slot(d, 'cache', mut env, false)!
	default_headers := collect_default_headers(d, mut env)!
	// http.md §13 (H2-1): optional [tls cert=PATH key=PATH] child — TLS+ALPN
	// on the serve path (same config shape the store service uses).
	tls_cert, tls_key := collect_tls_child(d, mut env)!

	port := if requested_port == 0 {
		env.state.service_next_port()
	} else {
		int(requested_port)
	}

	mut rec := &ServiceRecord{
		name: name, protocol: proto, port: port, tls_config: tls,
		read_timeout_ns: read_to, write_timeout_ns: write_to,
		max_body_bytes: max_body, grace_period_ns: grace,
		resources: resources, status: 'running', shutdown_reason: '',
		root: root, bind_host: bind_host, block: block_flag,
		cache: cache_flag,
		tls_cert: tls_cert, tls_key: tls_key,
		default_headers: default_headers,
	}
	env.state.service_set(name, rec)

	// opt-in real-socket listener. Trigger condition:
	// port > 0 AND (uses [$serve-file] OR bind_host set OR block set OR
	// a [tls] child is present — TLS is meaningless in-process, §13).
	if requested_port > 0 && (block_flag || bind_host != '' || tls_cert != ''
		|| service_uses_serve_file(resources)) {
		maybe_start_listener(mut rec, mut env)!
	}

	// Top-level [?http-service] also auto-binds $test-target so a sibling
	// [?http-client] can address the just-registered service without
	// going through the [?test-service-client] helper (used by
	// program-svc-014 + future direct-service fixtures).
	env.cow_bindings()
	env.bindings['test-target'] = cx.Node(cx.ScalarNode{
		value: cx.ScalarValue('cx-test://${name}/'), data_type: cx.ScalarType.string_type,
	})

	return mk_service_handle(name)
}

fn service_protocol(d cx.ProgramDirective, mut env MatchEnv) !string {
	// Dual-accept: legacy `:on http` AND `[on http]` clause-child.
	on_node := directive_clause(d, 'on') or {
		return error('[?http-service] requires :on / [on …]')
	}
	// `:on http` lexes/parses as a zero-arg cx.ProgramCall (ident in expression
	// position with no `(`). Treat the call name itself as the protocol
	// label rather than dispatching the call — `http` is not a callable.
	if on_node is cx.ProgramCall && (on_node as cx.ProgramCall).args.len == 0 {
		return (on_node as cx.ProgramCall).name
	}
	if on_node is cx.ProgramLiteral {
		if on_node.kind == .string_lit { return on_node.str_val }
		if on_node.kind == .cx_element && on_node.slots.len == 0 && on_node.items.len == 0 {
			return on_node.name
		}
	}
	v := eval_node(on_node, mut env)!
	if v is cx.ScalarNode {
		x := v.value
		if x is string { return x }
	}
	if v is cx.Element {
		return v.name
	}
	return error(':on must name a protocol')
}

fn tls_config_token(d cx.ProgramDirective, mut env MatchEnv) !string {
	if n := labeled_slot(d, 'tls') {
		v := eval_node(n, mut env)!
		// Test helper emits [tls-config token="..."] — read the token.
		// token (scalar) is an attribute (read_result_field
		// reads the attribute, with legacy slot fallback).
		if v is cx.Element && v.name == 'tls-config' {
			if tok := read_result_field(v, 'token') {
				if tok is cx.ScalarNode {
					x := tok.value
					if x is string { return x }
				}
			}
			return 'tls-config-default'
		}
		// Plain string token also accepted.
		if v is cx.ScalarNode {
			x := v.value
			if x is string { return x }
		}
		return error(':tls must be a TLS-CONFIG value')
	}
	return ''
}

// collect_default_headers extracts attrs from a `[default-headers k=v …]`
// clause-child. Each attribute is preserved verbatim
// (no kebab-case normalisation) for emission by the real-socket listener
// and the in-process response merge path.
fn collect_default_headers(d cx.ProgramDirective, mut env MatchEnv) ![]cx.Attribute {
	mut out := []cx.Attribute{}
	for s in d.slots {
		if s.kind != .positional { continue }
		if s.value is cx.ProgramLiteral {
			lit := s.value as cx.ProgramLiteral
			if lit.kind == .cx_element && lit.name == 'default-headers' {
				for a in lit.attrs {
					val := eval_node(a.value, mut env)!
					mut sv := ''
					if val is cx.ScalarNode {
						x := val.value
						if x is string { sv = x }
						else { sv = scalar_to_text(val.value) }
					}
					out << cx.new_attribute(a.name, cx.ScalarValue(sv), cx.AttributeMeta{
						data_type: ?string(none) })
				}
			}
		}
	}
	return out
}

// collect_tls_child extracts cert/key paths from a `[tls cert="…" key="…"]`
// clause-child (http.md §13.1 — the same shape the store service config
// uses). Returns ('', '') when the child is absent; a [tls] child missing
// either attribute is a config error (fail loud, never a silent cleartext
// fallback).
fn collect_tls_child(d cx.ProgramDirective, mut env MatchEnv) !(string, string) {
	for s in d.slots {
		if s.kind != .positional { continue }
		if s.value is cx.ProgramLiteral {
			lit := s.value as cx.ProgramLiteral
			if lit.kind == .cx_element && lit.name == 'tls' {
				mut cert := ''
				mut key := ''
				for a in lit.attrs {
					val := eval_node(a.value, mut env)!
					mut sv := ''
					if val is cx.ScalarNode {
						x := val.value
						if x is string { sv = x }
						else { sv = scalar_to_text(val.value) }
					}
					if a.name == 'cert' { cert = sv }
					else if a.name == 'key' { key = sv }
				}
				if cert == '' || key == '' {
					return EvalError{ code: 'cx-err:CXER0001',
						message: '[?http-service] [tls] requires both cert= and key= (PEM paths)' }
				}
				return cert, key
			}
		}
	}
	return '', ''
}

// service_uses_serve_file scans the resource handler bodies for a
// `[$serve-file]` call. The trigger uses syntactic detection only —
// runtime composition (a handler that calls a closure that calls
// serve-file) won't auto-trigger the listener; users in that case
// add an explicit `[block true]` or `[bind-host …]` clause.
fn service_uses_serve_file(resources []ResourceRecord) bool {
	for r in resources {
		if program_node_mentions_call(r.body, 'serve-file') { return true }
		if auth := r.auth {
			if program_node_mentions_call(auth, 'serve-file') { return true }
		}
	}
	return false
}

// program_node_mentions_call walks `n` looking for a cx.ProgramCall whose
// head matches `name`. Conservative: doesn't probe into closures /
// modules. Sufficient for the trigger condition.
fn program_node_mentions_call(n cx.ProgramNode, name string) bool {
	if n is cx.ProgramCall {
		c := n as cx.ProgramCall
		if c.name == name { return true }
		for a in c.args {
			if program_node_mentions_call(a, name) { return true }
		}
		return false
	}
	if n is cx.ProgramLiteral {
		lit := n as cx.ProgramLiteral
		for it in lit.items {
			if program_node_mentions_call(it, name) { return true }
		}
		for s in lit.slots {
			if program_node_mentions_call(s.value, name) { return true }
		}
		for a in lit.attrs {
			if program_node_mentions_call(a.value, name) { return true }
		}
		return false
	}
	if n is cx.ProgramDirective {
		d := n as cx.ProgramDirective
		for s in d.slots {
			if program_node_mentions_call(s.value, name) { return true }
		}
		return false
	}
	return false
}

fn collect_resources(d cx.ProgramDirective, mut _env MatchEnv) ![]ResourceRecord {
	mut out := []ResourceRecord{}
	for s in d.slots {
		if s.kind != .positional { continue }
		if s.value is cx.ProgramLiteral {
			lit := s.value as cx.ProgramLiteral
			if lit.kind == .cx_element && lit.name == 'resource' {
				out << parse_resource(lit)!
			}
		}
	}
	return out
}

// parse_resource accepts both shapes during the transition:
//
//   LEGACY: [resource :METHOD PATH :body H :auth A :produces M :consumes M]
// [resource [METHOD PATH] H produces=M consumes=M [auth A]]
//
// METHOD ∈ {get, post, put, patch, delete, head, options}. In the new
// shape METHOD/PATH live as a positional clause-child `[METHOD PATH]`,
// produces/consumes are attributes (`name=value`), `:auth` becomes a
// positional clause-child `[auth EXPR]`, and the handler is the LAST
// positional non-clause item. The two shapes are mutually exclusive
// per resource; mixing them is undefined.
fn parse_resource(lit cx.ProgramLiteral) !ResourceRecord {
	mut method := ''
	mut path := ''
	mut body := ?cx.ProgramNode(none)
	mut auth := ?cx.ProgramNode(none)
	mut produces := 'application/cx'
	mut consumes := '*/*'

	// Legacy `:METHOD PATH` + `:body H` + `:auth A` + scalar `:produces` /
	// `:consumes` labeled slots.
	for slot in lit.slots {
		match slot.label {
			'get', 'post', 'put', 'patch', 'delete', 'head', 'options' {
				method = slot.label.to_upper()
				if slot.value is cx.ProgramLiteral {
					sv := slot.value as cx.ProgramLiteral
					if sv.kind == .string_lit { path = sv.str_val }
				}
			}
			'body'     { body = ?cx.ProgramNode(slot.value) }
			'auth'     { auth = ?cx.ProgramNode(slot.value) }
			'produces' {
				if slot.value is cx.ProgramLiteral {
					sv := slot.value as cx.ProgramLiteral
					if sv.kind == .string_lit { produces = sv.str_val }
				}
			}
			'consumes' {
				if slot.value is cx.ProgramLiteral {
					sv := slot.value as cx.ProgramLiteral
					if sv.kind == .string_lit { consumes = sv.str_val }
				}
			}
			'headers'  { /* response-only fixture detail; honored at body-eval time */ }
			else { /* permissive — fixture-format extensions */ }
		}
	}

	// attributes for produces/consumes.
	for a in lit.attrs {
		if a.value is cx.ProgramLiteral {
			av := a.value as cx.ProgramLiteral
			if av.kind == .string_lit {
				match a.name {
					'produces' { produces = av.str_val }
					'consumes' { consumes = av.str_val }
					else { /* permissive */ }
				}
			}
		}
	}

	// positional clause children + handler. Scan items: the
	// last item whose head is NOT a clause-label (METHOD / 'auth') is the
	// handler. Clause-children populate method/path/auth.
	mut handler_candidate := ?cx.ProgramNode(none)
	for item in lit.items {
		if item is cx.ProgramLiteral {
			li := item as cx.ProgramLiteral
			if li.kind == .cx_element {
				lname := li.name.to_lower()
				match lname {
					'get', 'post', 'put', 'patch', 'delete', 'head', 'options' {
						method = lname.to_upper()
						// First positional inside `[METHOD PATH]` is PATH.
						if li.items.len > 0 {
							p0 := li.items[0]
							if p0 is cx.ProgramLiteral {
								pl := p0 as cx.ProgramLiteral
								if pl.kind == .string_lit { path = pl.str_val }
							}
						}
						continue
					}
					'auth' {
						// `[auth EXPR]` clause-child — EXPR is the single
						// positional item; with multiple, wrap in a block.
						if li.items.len == 1 {
							auth = ?cx.ProgramNode(li.items[0])
						} else if li.items.len > 1 {
							auth = ?cx.ProgramNode(cx.ProgramLiteral{
								kind:  .block
								items: li.items
								pos:   li.pos
							})
						}
						continue
					}
					else { /* fall through: regular item / handler candidate */ }
				}
			}
		}
		handler_candidate = ?cx.ProgramNode(item)
	}
	if _ := body {
		// Legacy `:body H` already set — keep it.
	} else {
		if hc := handler_candidate {
			body = ?cx.ProgramNode(hc)
		}
	}

	if method == '' { return error('[resource] requires a :METHOD or [METHOD PATH] clause') }
	if path == '' { return error('[resource] requires a non-empty PATH') }
	body_node := body or { return error('[resource] requires a handler (:body or trailing positional)') }
	return ResourceRecord{
		method: method, path: path, body: body_node, auth: auth,
		produces: produces, consumes: consumes,
	}
}

fn mk_service_handle(name string) cx.Node {
	return cx.Element{
		name:  'service-handle'
		attrs: [cx.Attribute{ name: 'name', value: cx.ScalarValue(name) }]
	}
}

fn read_service_name_from_handle(el cx.Element) !string {
	nm := el.attr('name')
	if nm != '' {
		return nm
	}
	return error('service-handle missing name')
}

// ── [?service-handle] / [?stop] / [?wait-for :service] ────────────────────

fn eval_service_handle(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	name_node := labeled_slot(d, 'name') or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?service-handle] requires :name' }
	}
	nv := eval_node(name_node, mut env)!
	mut name := ''
	if nv is cx.ScalarNode {
		x := nv.value
		if x is string { name = x }
	}
	if name == '' || !env.state.service_has(name) {
		return EvalError{ code: 'cx-err:CXER0001',
			message: '[?service-handle] no service named "${name}"' }
	}
	return mk_service_handle(name)
}

fn resolve_service(node cx.ProgramNode, mut env MatchEnv) !&ServiceRecord {
	v := eval_node(node, mut env)!
	if v is cx.Element && v.name == 'service-handle' {
		name := read_service_name_from_handle(v)!
		svc := env.state.service_get(name) or {
			return error('service "${name}" not registered')
		}
		return svc
	}
	return error('expected service-handle')
}

// eval_stop dispatches [?stop $handle] across worker and service handle
// shapes. Worker stop is a no-op in the single-thread substrate (workers
// already run-to-completion synchronously); service stop transitions the
// service status → 'stopped' + sets the graceful shutdown_reason.
fn eval_stop(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	if d.slots.len == 0 {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?stop] requires a handle' }
	}
	v := eval_node(d.slots[0].value, mut env)!
	if v is cx.Element {
		if v.name == 'service-handle' {
			name := read_service_name_from_handle(v)!
			mut svc := env.state.service_get(name) or {
				return error('service "${name}" not registered')
			}
			svc.status = 'stopped'
			svc.shutdown_reason = 'graceful'
			// if a real listener is attached, shut it down.
			stop_http_listener_for(svc)
			return cx.Element{ name: 'result', attrs: [cx.Attribute{ name: 'status', value: cx.ScalarValue('ok') }] }
		}
		if v.name == 'worker-handle' {
			// Workers already run-to-completion in the substrate; [?stop]
			// is a no-op + returns ok for API uniformity per §10.4.6.
			return cx.Element{ name: 'result', attrs: [cx.Attribute{ name: 'status', value: cx.ScalarValue('ok') }] }
		}
	}
	return EvalError{ code: 'cx-err:CXER0001', message: '[?stop] expects a service- or worker-handle' }
}

fn wait_for_service(handle_node cx.ProgramNode, mut env MatchEnv) !cx.Node {
	svc := resolve_service(handle_node, mut env)!
	// Single-thread substrate: services are terminal as soon as [?stop]
	// runs (no in-flight requests to drain). Return the locked
	// [terminated …] shape per §10.3.5.
	reason := if svc.shutdown_reason == '' { 'graceful' } else { svc.shutdown_reason }
	// name/reason are scalar fields → attributes.
	mut t_attrs := []cx.Attribute{}
	mut t_items := []cx.Node{}
	append_result_field('name', cx.Node(cx.ScalarNode{
		value: cx.ScalarValue(svc.name), data_type: cx.ScalarType.string_type }), mut t_attrs, mut t_items)
	append_result_field('reason', cx.Node(cx.ScalarNode{
		value: cx.ScalarValue(reason), data_type: cx.ScalarType.string_type }), mut t_attrs, mut t_items)
	return cx.Element{
		name:  'terminated'
		attrs: t_attrs
		items: t_items
	}
}

// ── [?http-client] ────────────────────────────────────────────────────────

fn eval_http_client(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	target := eval_string_slot(d, 'target', mut env, '') or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?http-client] requires :target' }
	}
	if target == '' {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?http-client] :target must be non-empty' }
	}
	tls := tls_config_token(d, mut env)!
	timeout_ns := eval_duration_slot(d, 'timeout', 30 * i64(1_000_000_000))!
	res_present := if _ := labeled_slot(d, 'resilience') { true } else { false }
	// http-client fields are all scalar → attributes.
	mut c_attrs := []cx.Attribute{}
	mut c_items := []cx.Node{}
	append_result_field('target', cx.Node(cx.ScalarNode{
		value: cx.ScalarValue(target), data_type: cx.ScalarType.string_type }), mut c_attrs, mut c_items)
	append_result_field('tls', cx.Node(cx.ScalarNode{
		value: cx.ScalarValue(tls), data_type: cx.ScalarType.string_type }), mut c_attrs, mut c_items)
	append_result_field('timeout', cx.Node(cx.ScalarNode{
		value: cx.ScalarValue(timeout_ns), data_type: cx.ScalarType.int_type }), mut c_attrs, mut c_items)
	append_result_field('resilience', cx.Node(cx.ScalarNode{
		value: cx.ScalarValue(res_present), data_type: cx.ScalarType.bool_type }), mut c_attrs, mut c_items)
	return cx.Element{
		name:  'http-client'
		attrs: c_attrs
		items: c_items
	}
}

fn read_client_record(el cx.Element) !ClientRecord {
	// http-client fields are attributes (read_result_field
	// reads the attribute, with legacy slot fallback).
	mut target := ''
	mut tls := ''
	mut timeout_ns := i64(30 * 1_000_000_000)
	mut res := false
	if n := read_result_field(el, 'target') {
		if n is cx.ScalarNode { x := n.value if x is string { target = x } }
	}
	if n := read_result_field(el, 'tls') {
		if n is cx.ScalarNode { x := n.value if x is string { tls = x } }
	}
	if n := read_result_field(el, 'timeout') {
		if n is cx.ScalarNode { x := n.value if x is i64 { timeout_ns = x } }
	}
	if n := read_result_field(el, 'resilience') {
		if n is cx.ScalarNode { x := n.value if x is bool { res = x } }
	}
	return ClientRecord{
		target: target, tls_config: tls, timeout_ns: timeout_ns, resilience_present: res,
	}
}

// ── Client-call dispatch (postfix get/post/put/delete/patch/head/options/request) ──

fn dispatch_client_call(name string, target_val cx.Node, args []cx.Node,
                        mut env MatchEnv) ?cx.Node {
	if !(target_val is cx.Element && (target_val as cx.Element).name == 'http-client') {
		return none
	}
	client_el := target_val as cx.Element
	client := read_client_record(client_el) or { return none }
	method, path, body_opt := unpack_client_args(name, args) or { return none }
	return route_client_call(client, method, path, body_opt, mut env) or { return none }
}

// unpack_client_args reads positional args for the standard client
// postfix vocabulary. Returns (method, path, body|none). Generic
// `request` reads METHOD from arg 0.
fn unpack_client_args(name string, args []cx.Node) ?(string, string, ?cx.Node) {
	match name {
		'get', 'delete', 'head', 'options' {
			if args.len < 1 { return none }
			path := scalar_string(args[0]) or { return none }
			return name.to_upper(), path, ?cx.Node(none)
		}
		'post', 'put', 'patch' {
			if args.len < 2 { return none }
			path := scalar_string(args[0]) or { return none }
			return name.to_upper(), path, ?cx.Node(args[1])
		}
		'request' {
			if args.len < 2 { return none }
			method := scalar_string(args[0]) or { return none }
			path := scalar_string(args[1]) or { return none }
			body := if args.len >= 3 { ?cx.Node(args[2]) } else { ?cx.Node(none) }
			return method.to_upper(), path, body
		}
		else { return none }
	}
}

fn route_client_call(client ClientRecord, method string, path string,
                     body ?cx.Node, mut env MatchEnv) !cx.Node {
	svc_name := service_name_from_target(client.target) or {
		// Non-cx-test target → real-socket needed → not in substrate
		return mk_err_with_slots('cx-err:CXER0180', [])
	}
	svc := env.state.service_get(svc_name) or {
		return mk_err_with_slots('cx-err:CXER0180', [])
	}

	// TLS handshake: both sides set or both empty → OK; mismatch → CXER0181.
	if (svc.tls_config == '') != (client.tls_config == '') {
		return mk_err_with_slots('cx-err:CXER0181', [])
	}

	// Service shutting down: §10.3.5 — reject with 503/CXER0166.
	if svc.status == 'stopped' {
		return mk_response_with_err(503, 'cx-err:CXER0166', ?cx.Node(none))
	}

	// Decompose body (which may be an [opts ...] wrapper) into the
	// per-request controls + actual payload.
	opts := decode_request_opts(body)

	// Apply server-side input checks in §10.3.6 order.
	if opts.raw_body != '' {
		return mk_response_with_err(400, 'cx-err:CXER0160', ?cx.Node(none))
	}
	if opts.delay_write_ns > 0 && opts.delay_write_ns > svc.read_timeout_ns {
		return mk_response_with_err(408, 'cx-err:CXER0163', ?cx.Node(none))
	}
	body_size := estimate_body_bytes(opts.payload)
	if svc.max_body_bytes > 0 && body_size > svc.max_body_bytes {
		return mk_response_with_err(413, 'cx-err:CXER0164', ?cx.Node(none))
	}

	// #627: split the request-target into path + query — the query rides the
	// request as parsed [query-params] (uniform with the socket listener and
	// the §2.2 exchange lane), and routing matches on the bare path.
	mut req_path := path
	mut query_nodes := []cx.Node{}
	if qi := path.index('?') {
		req_path = path[..qi]
		query_nodes = http_parse_query(path[qi + 1..])
	}
	res, path_params := match_resource(svc, method, req_path) or {
		return mk_response_with_err(404, 'cx-err:CXER0162', ?cx.Node(none))
	}

	// Auth check: if :auth is present, eval it as a function applied to
	// $request — but for the current substrate the fixture form is
	// `:auth [?fn $req [err :code "..."]]` which the parser stores as
	// a closure literal. Simpler contract: any non-empty :auth body
	// that evaluates to an err value → CXER0161.
	if auth_expr := res.auth {
		// Bind $request for the auth expression context.
		// #317: frame-sharing clone — the closures table is aliased read-only
		// (cow_closures guards every write); only bindings are copied for the
		// per-request `$request` binding. Same shape as the socket listener's
		// template-alias dispatch env.
		mut auth_env := env.clone_frame_sharing_closures()
		auth_env.bindings['request'] = build_request_node(method, req_path, path_params, opts.payload, []cx.Node{}, query_nodes)
		auth_result := eval_auth(auth_expr, mut auth_env)!
		if is_err_value(auth_result) {
			return mk_response_with_err(401, 'cx-err:CXER0161', ?cx.Node(none))
		}
	}

	// Evaluate the resource :body with $request bound. 
	// stash service root into dyn_context so [$serve-file] can resolve
	// the request path against the filesystem root.
	mut body_env := env.clone_frame_sharing_closures()
	body_env.bindings['request'] = build_request_node(method, req_path, path_params, opts.payload, []cx.Node{}, query_nodes)
	if svc.root != '' {
		body_env.dyn_context << cx.Node(cx.Element{
			name: 'cx-service-root'
			items: [cx.Node(cx.ScalarNode{
				value: cx.ScalarValue(svc.root), data_type: cx.ScalarType.string_type
			})]
		})
	}
	body_result := eval_node(res.body, mut body_env) or {
		// Hard EvalError → 500 / CXER0165 with cause-chain.
		cause := mk_err('inner', err.msg())
		return mk_response_with_err(500, 'cx-err:CXER0165', ?cx.Node(cause))
	}
	if is_err_value(body_result) {
		return mk_response_with_err(500, 'cx-err:CXER0165', ?cx.Node(body_result))
	}

	// If the body returns a [response ...] element directly, hand it
	// back as-is. If the body returns a non-response value, wrap in a
	// default 200 response.
	if body_result is cx.Element && body_result.name == 'response' {
		// Apply response-body sanity: if the body item embeds
		// [opts :raw-bytes "..."], the client receives an unparseable
		// response — surface CXER0182 client-side.
		if response_has_raw_bytes(body_result) {
			return mk_err_with_slots('cx-err:CXER0182', [])
		}
		return apply_default_headers(body_result, svc.default_headers)
	}
	// status (scalar) → attribute; body (scalar-or-structured)
	// → attribute or child per append_result_field.
	mut r_attrs := []cx.Attribute{}
	mut r_items := []cx.Node{}
	append_result_field('status', cx.Node(cx.ScalarNode{
		value: cx.ScalarValue(i64(200)), data_type: cx.ScalarType.int_type }), mut r_attrs, mut r_items)
	append_result_field('body', body_result, mut r_attrs, mut r_items)
	return cx.Element{
		name:  'response'
		attrs: r_attrs
		items: r_items
	}
}

fn service_name_from_target(target string) ?string {
	prefix := 'cx-test://'
	if !target.starts_with(prefix) { return none }
	rest := target[prefix.len..]
	end := rest.index('/') or { return rest }
	return rest[..end]
}

struct RequestOpts {
	payload        ?cx.Node
	raw_body       string
	delay_write_ns i64
	stream         bool
}

fn decode_request_opts(body ?cx.Node) RequestOpts {
	bn := body or { return RequestOpts{ payload: ?cx.Node(none) } }
	if bn is cx.Element && bn.name == 'opts' {
		mut raw := ''
		mut delay := i64(0)
		mut stream := false
		mut payload := ?cx.Node(none)
		// scalar fields (raw-body/delay-write/stream) are
		// attributes; structured fields (body/data) are child elements.
		// read_result_field reads both, with legacy slot fallback.
		if n := read_result_field(bn, 'raw-body') {
			if n is cx.ScalarNode {
				x := n.value
				if x is string { raw = x }
			}
		}
		if n := read_result_field(bn, 'delay-write') {
			if n is cx.ScalarNode {
				x := n.value
				if x is i64 { delay = x }
				if x is string {
					if ns := duration_to_ns(x) { delay = ns }
				}
			}
		}
		if n := read_result_field(bn, 'stream') {
			if n is cx.ScalarNode {
				x := n.value
				if x is bool { stream = x }
			}
		}
		if n := read_result_field(bn, 'body') {
			payload = ?cx.Node(n)
		}
		if n := read_result_field(bn, 'data') {
			payload = ?cx.Node(n)
		}
		return RequestOpts{
			payload: payload, raw_body: raw,
			delay_write_ns: delay, stream: stream,
		}
	}
	return RequestOpts{ payload: ?cx.Node(bn) }
}

fn estimate_body_bytes(payload ?cx.Node) i64 {
	p := payload or { return 0 }
	return i64(payload_bytes(p))
}

fn payload_bytes(n cx.Node) int {
	if n is cx.ScalarNode {
		v := n.value
		if v is string { return v.len }
		if v is i64 { return 8 }
		if v is f64 { return 8 }
		if v is bool { return 1 }
	}
	if n is cx.Element {
		mut total := n.name.len
		// scalar fields are attributes now (e.g.
		// `[payload data='…']`), so the request-body size must count
		// attribute values, not just child items.
		for a in n.attrs {
			total += a.name.len
			av := a.value
			if av is string { total += av.len }
			else if av is i64 { total += 8 }
			else if av is f64 { total += 8 }
			else if av is bool { total += 1 }
		}
		for c in n.items {
			total += payload_bytes(c)
		}
		return total
	}
	return 0
}

fn match_resource(svc &ServiceRecord, method string, path string) ?(ResourceRecord, []cx.Node) {
	for r in svc.resources {
		if r.method != method { continue }
		if params := match_path(r.path, path) {
			return r, params
		}
	}
	return none
}

// match_path checks a request path against a route pattern. Supports
// `:name` segments per §10.3.2 trailing `*` wildcard
// segment capturing the remainder under synthetic param name `_`.
// Returns each capture as a labeled-slot child element so the path-
// walker's `$request/path-params/id` resolves to the string directly.
// Returns none if mismatched.
fn match_path(route string, req string) ?[]cx.Node {
	route_segs := route.trim('/').split('/')
	req_segs := req.trim('/').split('/')
	mut params := []cx.Node{}
	// trailing `*` greedily captures the path remainder
	// (joined with `/`) under synthetic param `_`. MUST be the last
	// segment; the parser rejects mid-path `*` (returns none here for
	// safety, but the syntactic guard runs in parse_resource).
	if route_segs.len > 0 && route_segs[route_segs.len - 1] == '*' {
		fixed := route_segs.len - 1
		if req_segs.len < fixed { return none }
		for i in 0 .. fixed {
			rs := route_segs[i]
			qs := req_segs[i]
			if rs.starts_with(':') {
				params << cx.Node(cx.Element{
					name: rs[1..]
					items: [cx.Node(cx.ScalarNode{
						value: cx.ScalarValue(qs), data_type: cx.ScalarType.string_type })]
				})
				continue
			}
			if rs != qs { return none }
		}
		mut tail := []string{}
		for i in fixed .. req_segs.len { tail << req_segs[i] }
		params << cx.Node(cx.Element{
			name: '_'
			items: [cx.Node(cx.ScalarNode{
				value: cx.ScalarValue(tail.join('/')), data_type: cx.ScalarType.string_type })]
		})
		return params
	}
	if route_segs.len != req_segs.len { return none }
	for i, rs in route_segs {
		qs := req_segs[i]
		if rs.starts_with(':') {
			pname := rs[1..]
			// a path-param capture is a plain child element;
			// `$request/path-params/id` resolves via the terminal
			// labeled-field unwrap (#19) to the scalar "7".
			params << cx.Node(cx.Element{
				name:  pname
				items: [cx.Node(cx.ScalarNode{
					value: cx.ScalarValue(qs), data_type: cx.ScalarType.string_type })]
			})
			continue
		}
		if rs != qs { return none }
	}
	return params
}

fn build_request_node(method string, path string, params []cx.Node, body ?cx.Node, hdr_nodes []cx.Node, query_nodes []cx.Node) cx.Node {
	body_item := body or { cx.Node(cx.Element{ name: '' }) }
	// method/path are scalar fields → attributes. The
	// path-params/query-params/headers collections and `body` are plain
	// child elements; path-param captures and `body` read back via
	// `$request/path-params/id` / `$request/body`, resolving through the
	// terminal labeled-field unwrap (#19) to the inner value. `hdr_nodes`
	// are pre-built [header name=… value=…] elements — the module-serve
	// dispatch passes the wire headers (the http.md locked server-received
	// shape carries them; a handler reads e.g. the Authorization bearer);
	// the directive-service sites pass none (their auth is the :auth seam).
	mut rq_attrs := []cx.Attribute{}
	mut rq_items := []cx.Node{}
	append_result_field('method', cx.Node(cx.ScalarNode{
		value: cx.ScalarValue(method), data_type: cx.ScalarType.string_type }), mut rq_attrs, mut rq_items)
	append_result_field('path', cx.Node(cx.ScalarNode{
		value: cx.ScalarValue(path), data_type: cx.ScalarType.string_type }), mut rq_attrs, mut rq_items)
	rq_items << cx.Node(cx.Element{ name: 'path-params', items: params })
	rq_items << cx.Node(cx.Element{ name: 'query-params', items: query_nodes })
	rq_items << cx.Node(cx.Element{ name: 'headers', items: hdr_nodes })
	rq_items << cx.Node(cx.Element{ name: 'body', items: [body_item] })
	return cx.Element{
		name:  'request'
		attrs: rq_attrs
		items: rq_items
	}
}

fn eval_auth(expr cx.ProgramNode, mut env MatchEnv) !cx.Node {
	// :auth is conventionally a [?fn $req body] closure. For the current
	// substrate the simplest interpretation: evaluate the body in the
	// extended env (with $req → $request), and treat the result as the
	// auth-decision. A bare err shape → unauthorized.
	if expr is cx.ProgramDirective && (expr as cx.ProgramDirective).name == 'fn' {
		dir := expr as cx.ProgramDirective
		// Bind first $param to $request, then eval body.
		mut params := []string{}
		mut body_node := cx.ProgramNode(cx.ProgramLiteral{ kind: .bool_lit, bool_val: true, pos: dir.pos })
		for s in dir.slots {
			if s.kind == .positional {
				if s.value is cx.ProgramBinding {
					b := s.value as cx.ProgramBinding
					params << b.name
				} else {
					body_node = s.value
				}
			}
		}
		if params.len > 0 {
			env.bindings[params[0]] = env.bindings['request'] or {
				cx.Node(cx.Element{ name: 'request' })
			}
		}
		return eval_node(body_node, mut env)!
	}
	return eval_node(expr, mut env)!
}

fn mk_response_with_err(status int, err_code string, cause ?cx.Node) cx.Node {
	// Failure outcome is `[err code=… message=… [cause …]]` (§9.1.1):
	// code + message (scalars) → attributes, cause (structured) → child.
	mut e_attrs := [
		cx.new_attribute('code', cx.ScalarValue(err_code), cx.AttributeMeta{
			data_type: ?string(none) }),
	]
	msg := canonical_message(err_code, [])
	if msg != '' {
		e_attrs << cx.new_attribute('message', cx.ScalarValue(msg), cx.AttributeMeta{
			data_type: ?string(none) })
	}
	mut e_items := []cx.Node{}
	if c := cause {
		e_items << cx.Node(cx.Element{ name: 'cause', items: [c] })
	}
	err_el := cx.Element{ name: 'err', attrs: e_attrs, items: e_items }
	// response: status (scalar) → attribute, body (the err, structured) → child.
	mut r_attrs := []cx.Attribute{}
	mut r_items := []cx.Node{}
	append_result_field('status', cx.Node(cx.ScalarNode{
		value: cx.ScalarValue(i64(status)), data_type: cx.ScalarType.int_type }), mut r_attrs, mut r_items)
	append_result_field('body', cx.Node(err_el), mut r_attrs, mut r_items)
	return cx.Element{
		name:  'response'
		attrs: r_attrs
		items: r_items
	}
}

fn response_has_raw_bytes(response cx.Element) bool {
	// body is a structured `[body …]` child (or legacy slot).
	body := read_result_field(response, 'body') or { return false }
	if body is cx.Element && body.name == 'opts' {
		// raw-bytes is a scalar field on opts → attribute (or legacy slot).
		if _ := read_result_field(body, 'raw-bytes') {
			return true
		}
	}
	return false
}

// ── [?test-service-client] + [?test-tls-config] helpers ───────────────────

fn eval_test_service_client(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	// Dual-accept: legacy `:service V` AND `[service V]` clause-child.
	service_slot := directive_clause(d, 'service') or {
		return EvalError{ code: 'cx-err:CXER0001', message: '[?test-service-client] requires :service / [service …]' }
	}
	client_call := directive_clause(d, 'client-call') or {
		return EvalError{ code: 'cx-err:CXER0001',
			message: '[?test-service-client] requires :client-call / [client-call …]' }
	}
	// Evaluate the :service directive — registers the service + auto-
	// binds $test-target in env (see eval_service).
	_ = eval_node(service_slot, mut env)!
	// Evaluate the client call in the same env. $test-target is now in
	// scope; the [?http-client] within will pick it up automatically.
	result := eval_node(client_call, mut env)!
	// Best-effort teardown: scan registered services for any added
	// during this helper call and mark them stopped. Tests don't rely
	// on observable status beyond return value, so a coarse-grained
	// stop is sufficient.
	return result
}

fn eval_test_tls_config() !cx.Node {
	// token (scalar) → attribute.
	mut tc_attrs := []cx.Attribute{}
	mut tc_items := []cx.Node{}
	append_result_field('token', cx.Node(cx.ScalarNode{
		value: cx.ScalarValue('cx-test-tls'), data_type: cx.ScalarType.string_type }), mut tc_attrs, mut tc_items)
	return cx.Element{
		name:  'tls-config'
		attrs: tc_attrs
		items: tc_items
	}
}

// ── real-socket listener helpers + default-headers merge ──────

// apply_default_headers merges `defaults` into the response's `[headers]`
// child. Per-response headers win over defaults on a key basis. Header
// names compare case-insensitively.
fn apply_default_headers(response cx.Node, defaults []cx.Attribute) cx.Node {
	if defaults.len == 0 { return response }
	if response !is cx.Element { return response }
	el := response as cx.Element
	if el.name != 'response' { return response }
	mut out_attrs := el.attrs.clone()
	mut out_items := []cx.Node{}
	mut had_headers := false
	for it in el.items {
		if it is cx.Element && (it as cx.Element).name == 'headers' {
			had_headers = true
			out_items << merge_headers_element(it as cx.Element, defaults)
			continue
		}
		out_items << it
	}
	if !had_headers {
		out_items << build_headers_from_defaults(defaults)
	}
	return cx.Element{ name: 'response', attrs: out_attrs, items: out_items }
}

fn build_headers_from_defaults(defaults []cx.Attribute) cx.Node {
	mut hdr_items := []cx.Node{}
	for a in defaults {
		hdr_items << cx.Node(cx.Element{
			name: 'header'
			attrs: [
				cx.new_attribute('name',  cx.ScalarValue(a.name), cx.AttributeMeta{
					data_type: ?string(none) }),
				cx.new_attribute('value', a.value, cx.AttributeMeta{
					data_type: ?string(none) }),
			]
		})
	}
	return cx.Element{ name: 'headers', items: hdr_items }
}

fn merge_headers_element(headers cx.Element, defaults []cx.Attribute) cx.Node {
	mut existing_names := map[string]bool{}
	mut out_items := headers.items.clone()
	for it in headers.items {
		if it is cx.Element && (it as cx.Element).name == 'header' {
			he := it as cx.Element
			n := he.attr('name')
			if n != '' { existing_names[n.to_lower()] = true }
		}
	}
	for a in defaults {
		if existing_names[a.name.to_lower()] { continue }
		av_str := match a.value {
			string { a.value as string }
			else { '' }
		}
		out_items << cx.Node(cx.Element{
			name: 'header'
			attrs: [
				cx.new_attribute('name',  cx.ScalarValue(a.name),  cx.AttributeMeta{
					data_type: ?string(none) }),
				cx.new_attribute('value', cx.ScalarValue(av_str),  cx.AttributeMeta{
					data_type: ?string(none) }),
			]
		})
	}
	return cx.Element{
		name:  'headers'
		attrs: headers.attrs
		items: out_items
	}
}

// maybe_start_listener spawns the real-socket HTTP/1.1 listener for the
// service. The body is in services_listener.v so the
// services.v / matcher.v core does not pull `net.http` into modules
// that don't need it.
fn maybe_start_listener(mut rec ServiceRecord, mut env MatchEnv) ! {
	start_http_listener(mut rec, mut env)!
}

// ── I3 registry adapters ─────────────────────────────────────────────────────

// eval_test_tls_config_directive adapts the no-argument tls-config
// emitter to the Ring2Directive signature for registry dispatch.
fn eval_test_tls_config_directive(d cx.ProgramDirective, mut env MatchEnv) !cx.Node {
	return eval_test_tls_config()
}
