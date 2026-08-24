module platform
import code {
	EvalError,
	ForLimitState,
	MatchEnv,
	StreamCtx,
	YieldSpec,
	gen_emit_item,
	gen_emit_item_streamed,
	is_err_value,
	net_mut_handle,
	net_read_exact_buf,
	net_read_line_buf,
}

import cx

// iter_walks_net_http.v — the Ring-2 iterator-source walkers (I3 seam
// D/E; moved from eval.v). Each walks a live net/http source inside
// a [?for]: net accept, http accept(+exchange), net lines, net chunks —
// buffered + streamed variants. They are REGISTERED into the Ring-1
// iterator registry keyed by cx.IteratorSourceKind (ring2_register.v);
// the [?for] engine probes the registry after its own Ring-1 kinds
// (.iter_iterate / .iter_unfold stay direct). The SSE-client walkers
// (.iter_sse_events) moved back to stdlib_http.v at seam H — the SSE
// client is part of the Ring-1 http-client pack, so its read loop is
// Ring 1 and dispatches directly. The evaluator plumbing walked here
// (gen_emit_item(_streamed), YieldSpec, ForLimitState, StreamCtx) is
// the Ring-1 yield pipeline — a Ring-2 → Ring-1 dependency, legal
// under the §3 contracts.

// iter_net_accept_walk — buffered twin of iter_net_accept_walk_streamed for the
// top-level `[?for [in $conn [$net:accept-iter $l]] …]` form (net.md §3.3). Each
// pull blocks on accept() and emits the accepted socket through the downstream
// yield pipeline. A server accept loop is unbounded — it runs until the listener
// closes / accept faults (terminates the loop) or a [?take]/[?while] bound is hit.
// No force budget: a server is meant to run until its listener is torn down. The
// per-iteration yield typically reduces to a closed handle, so `out` does not
// accumulate live sockets.
fn iter_net_accept_walk(source_val cx.IteratorNode, c cx.ProgramForClause,
	clauses []cx.ProgramForClause, idx int, spec YieldSpec, mut env MatchEnv,
	mut out []cx.Node, mut limit_state ForLimitState) ! {
	if source_val.source_args.len != 1 {
		return
	}
	listener := source_val.source_args[0]
	for {
		if limit_state.remaining == 0 {
			return
		}
		mut h := net_mut_handle(listener) or { return }
		conn := net_accept_real(mut h)
		if is_err_value(conn) {
			return // listener closed / fatal accept error → terminate the loop
		}
		gen_emit_item(c, conn, clauses, idx, spec, mut env, mut out, mut limit_state)!
	}
}

// iter_http_accept_walk / _streamed — the http.md §3.5 twin of the net accept
// walkers for `[?for [in $ex [$http:accept-iter $srv]] …]`. Each pull blocks on
// the net listener's accept(), wraps the accepted connection as an [exchange]
// (http_exchange_from_conn), and emits it. Same unbounded-server lifecycle as
// iter_net_accept_walk; terminates on listener close / accept fault / bound.
fn iter_http_accept_walk(source_val cx.IteratorNode, c cx.ProgramForClause,
	clauses []cx.ProgramForClause, idx int, spec YieldSpec, mut env MatchEnv,
	mut out []cx.Node, mut limit_state ForLimitState) ! {
	if source_val.source_args.len != 1 {
		return
	}
	server := source_val.source_args[0]
	for {
		if limit_state.remaining == 0 {
			return
		}
		mut h := net_mut_handle(server) or { return }
		conn := net_accept_real(mut h)
		if is_err_value(conn) {
			return
		}
		ex := http_exchange_from_conn(conn)
		gen_emit_item(c, ex, clauses, idx, spec, mut env, mut out, mut limit_state)!
		// #23: surface a handler that returned without responding (and close
		// the dangling connection) instead of silently hanging the client.
		http_finalize_unresponded_exchange(ex)
	}
}

fn iter_http_accept_walk_streamed(source_val cx.IteratorNode, c cx.ProgramForClause,
	clauses []cx.ProgramForClause, idx int, spec YieldSpec, mut env MatchEnv,
	mut ctx StreamCtx, mut limit_state ForLimitState) ! {
	if source_val.source_args.len != 1 {
		return
	}
	server := source_val.source_args[0]
	for {
		if limit_state.remaining == 0 {
			return
		}
		mut h := net_mut_handle(server) or { return }
		conn := net_accept_real(mut h)
		if is_err_value(conn) {
			return
		}
		ex := http_exchange_from_conn(conn)
		gen_emit_item_streamed(c, ex, clauses, idx, spec, mut env, mut ctx, mut limit_state)!
		// #23: surface a handler that returned without responding (and close
		// the dangling connection) instead of silently hanging the client.
		http_finalize_unresponded_exchange(ex)
	}
}

// iter_net_line_walk / _streamed — [$net:line-iter sock] (net.md §3.4): yield one
// CRLF/LF-stripped line off the socket per iteration until clean EOF.
fn iter_net_line_walk(source_val cx.IteratorNode, c cx.ProgramForClause,
	clauses []cx.ProgramForClause, idx int, spec YieldSpec, mut env MatchEnv,
	mut out []cx.Node, mut limit_state ForLimitState) ! {
	if source_val.source_args.len < 1 {
		return
	}
	sock := source_val.source_args[0]
	for {
		if limit_state.remaining == 0 {
			return
		}
		mut h := net_mut_handle(sock) or { return }
		line := net_read_line_buf(mut h) or {
			// none → clean EOF, UNLESS a configured read deadline lapsed first
			// (#56): then surface CXER4507 rather than silently ending the stream.
			if h.timed_out {
				return EvalError{
					code:    code.net_err_timeout
					message: 'E_NET_TIMEOUT: line-iter exceeded the ${h.read_deadline_ms}ms read deadline'
				}
			}
			return
		}
		gen_emit_item(c, net_str(line), clauses, idx, spec, mut env, mut out, mut limit_state)!
	}
}

fn iter_net_line_walk_streamed(source_val cx.IteratorNode, c cx.ProgramForClause,
	clauses []cx.ProgramForClause, idx int, spec YieldSpec, mut env MatchEnv,
	mut ctx StreamCtx, mut limit_state ForLimitState) ! {
	if source_val.source_args.len < 1 {
		return
	}
	sock := source_val.source_args[0]
	for {
		if limit_state.remaining == 0 {
			return
		}
		mut h := net_mut_handle(sock) or { return }
		line := net_read_line_buf(mut h) or {
			if h.timed_out {
				return EvalError{
					code:    code.net_err_timeout
					message: 'E_NET_TIMEOUT: line-iter exceeded the ${h.read_deadline_ms}ms read deadline'
				}
			}
			return
		}
		gen_emit_item_streamed(c, net_str(line), clauses, idx, spec, mut env, mut ctx, mut limit_state)!
	}
}

// iter_net_chunk_walk / _streamed — [$net:chunk-iter sock n] (net.md §3.4): yield
// one up-to-n-byte chunk off the socket per iteration until clean EOF.
fn iter_net_chunk_walk(source_val cx.IteratorNode, c cx.ProgramForClause,
	clauses []cx.ProgramForClause, idx int, spec YieldSpec, mut env MatchEnv,
	mut out []cx.Node, mut limit_state ForLimitState) ! {
	if source_val.source_args.len < 2 {
		return
	}
	sock := source_val.source_args[0]
	n := net_arg_int(source_val.source_args[1]) or { return }
	for {
		if limit_state.remaining == 0 {
			return
		}
		mut h := net_mut_handle(sock) or { return }
		chunk := net_read_exact_buf(mut h, int(n))
		if chunk.len == 0 {
			return // EOF
		}
		gen_emit_item(c, net_bytes(chunk), clauses, idx, spec, mut env, mut out, mut limit_state)!
	}
}

fn iter_net_chunk_walk_streamed(source_val cx.IteratorNode, c cx.ProgramForClause,
	clauses []cx.ProgramForClause, idx int, spec YieldSpec, mut env MatchEnv,
	mut ctx StreamCtx, mut limit_state ForLimitState) ! {
	if source_val.source_args.len < 2 {
		return
	}
	sock := source_val.source_args[0]
	n := net_arg_int(source_val.source_args[1]) or { return }
	for {
		if limit_state.remaining == 0 {
			return
		}
		mut h := net_mut_handle(sock) or { return }
		chunk := net_read_exact_buf(mut h, int(n))
		if chunk.len == 0 {
			return
		}
		gen_emit_item_streamed(c, net_bytes(chunk), clauses, idx, spec, mut env, mut ctx, mut limit_state)!
	}
}

// iter_net_accept_walk_streamed — incremental walker for [$net:accept-iter L]
// inside a [?for]: each pull blocks on accept() and yields the accepted socket
// (net.md §3.3). Unbounded (a server accept loop); terminates when the listener
// closes / accept faults, or a [?take]/[?while] bound is reached. No force
// budget — a server runs until its listener is closed.
fn iter_net_accept_walk_streamed(source_val cx.IteratorNode, c cx.ProgramForClause,
	clauses []cx.ProgramForClause, idx int, spec YieldSpec, mut env MatchEnv,
	mut ctx StreamCtx, mut limit_state ForLimitState) ! {
	if source_val.source_args.len != 1 {
		return
	}
	listener := source_val.source_args[0]
	for {
		if limit_state.remaining == 0 {
			return
		}
		mut h := net_mut_handle(listener) or { return }
		conn := net_accept_real(mut h)
		if is_err_value(conn) {
			return // listener closed / fatal accept error → terminate the loop
		}
		gen_emit_item_streamed(c, conn, clauses, idx, spec, mut env, mut ctx, mut limit_state)!
	}
}
