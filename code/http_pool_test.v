module code

import net
import sync.stdatomic
import time

// http_pool_test.v — #234 client connection pool (§5.2 keep-alive reuse) over a
// live loopback server that COUNTS accepted connections. Proves: (1) two
// sequential requests to a keep-alive origin ride ONE connection; (2) a
// `Connection: close` response is never pooled; (3) a parked conn the server
// closed is dropped and redialed ONCE (no error, no request replay after
// bytes); (4) idle conns are evicted after http_pool_idle_ms.

@[heap]
struct PoolSrv {
mut:
	listener          &net.TcpListener
	port              int
	accepts           u64 // stdatomic
	conn_close_header bool // respond `Connection: close` + close after one exchange
	close_after_first bool // keep-alive response, then close the conn (stale-park)
}

fn pool_srv_start(conn_close_header bool, close_after_first bool) &PoolSrv {
	mut listener := net.listen_tcp(.ip, '127.0.0.1:0') or { panic('listen: ${err.msg()}') }
	addr := listener.addr() or { panic('addr: ${err.msg()}') }
	mut s := &PoolSrv{
		listener:          listener
		port:              addr.port() or { panic('port') }
		conn_close_header: conn_close_header
		close_after_first: close_after_first
	}
	spawn pool_srv_loop(mut s)
	return s
}

fn pool_srv_loop(mut s PoolSrv) {
	for {
		mut conn := s.listener.accept() or { return }
		stdatomic.add_u64(&s.accepts, 1)
		spawn pool_srv_conn(mut s, mut conn)
	}
}

fn pool_srv_conn(mut s PoolSrv, mut conn net.TcpConn) {
	for {
		mut req := []u8{}
		for {
			mut tmp := []u8{len: 4096}
			n := conn.read(mut tmp) or {
				conn.close() or {}
				return
			}
			if n <= 0 {
				conn.close() or {}
				return
			}
			req << tmp[..n]
			if req.bytestr().contains('\r\n\r\n') {
				break
			}
		}
		if s.conn_close_header {
			conn.write_string('HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello') or {}
			conn.close() or {}
			return
		}
		conn.write_string('HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nhello') or {}
		if s.close_after_first {
			// let the client finish reading + park the conn before the FIN lands
			time.sleep(100 * time.millisecond)
			conn.close() or {}
			return
		}
	}
}

struct PoolGetResult {
	status int
	ok     bool
}

fn pool_get(port int) PoolGetResult {
	r := http_do_single('GET', 'http://127.0.0.1:${port}/x', [][]string{}, []u8{}, HttpReqOpts{})
	st := http_response_status(r)
	return PoolGetResult{
		status: st
		ok:     st == 200
	}
}

fn test_pool_reuses_keepalive_connection() {
	caps_set_all()
	mut s := pool_srv_start(false, false)
	r1 := pool_get(s.port)
	assert r1.ok, 'first request must succeed (status ${r1.status})'
	r2 := pool_get(s.port)
	assert r2.ok, 'second request must succeed (status ${r2.status})'
	accepts := stdatomic.load_u64(&s.accepts)
	assert accepts == 1, 'two keep-alive requests must ride ONE connection (server accepted ${accepts})'
	s.listener.close() or {}
}

fn test_pool_never_pools_connection_close() {
	caps_set_all()
	mut s := pool_srv_start(true, false)
	r1 := pool_get(s.port)
	assert r1.ok
	r2 := pool_get(s.port)
	assert r2.ok
	accepts := stdatomic.load_u64(&s.accepts)
	assert accepts == 2, 'Connection: close responses must not be pooled (server accepted ${accepts})'
	s.listener.close() or {}
}

fn test_pool_stale_conn_redials_once() {
	caps_set_all()
	mut s := pool_srv_start(false, true)
	r1 := pool_get(s.port)
	assert r1.ok, 'first request must succeed'
	// server closes the parked conn after ~100ms; wait for the FIN to land
	time.sleep(300 * time.millisecond)
	r2 := pool_get(s.port)
	assert r2.ok, 'request over a stale parked conn must transparently redial (status ${r2.status})'
	accepts := stdatomic.load_u64(&s.accepts)
	assert accepts == 2, 'stale conn must be dropped and redialed once (server accepted ${accepts})'
	s.listener.close() or {}
}

fn test_pool_idle_eviction() {
	caps_set_all()
	mut s := pool_srv_start(false, false)
	r1 := pool_get(s.port)
	assert r1.ok
	key := http_pool_key('http', '127.0.0.1', s.port, true, '')
	// the conn is parked; take it, back-date it past the idle window, re-park it
	// directly (http_pool_put would reset the clock), then take again → evicted.
	mut pc := http_pool_take(key) or { panic('conn must be parked after a keep-alive exchange') }
	pc.last_ms = time.ticks() - http_pool_idle_ms - 1000
	g_http_pool_mu.lock()
	g_http_pool[key] = [pc]
	g_http_pool_total++
	g_http_pool_mu.unlock()
	if _ := http_pool_take(key) {
		panic('an idle-expired conn must be evicted, not handed out')
	}
	s.listener.close() or {}
}
