module main

import os
import time
import net

// http_reactor_rss_bound_test.v — BEHAVIORAL guard for cx-private #57.
//
// Root cause (CX side): the `[?for]` comprehension walker built each
// per-generator-item frame with `MatchEnv.clone()`, which DEEP-COPIES the whole
// `closures` table. In a `[?lib]`-loaded `$http:serve` handler that table holds
// the entire imported stdlib closure set, so an N-item `[?for]` copied it N
// times PER REQUEST. Under the shipped `-gc e` collector that transient
// high-water is held, so a handler that runs a modest comprehension grows to
// hundreds of MB on the first request (measured: a 200-item `[?for]` → ~660 MB,
// a 2000-item one → ~1.6 GB) and sustained traffic exhausts the heap →
// `V panic: memory allocation failure` (the reported OOM).
//
// Fix: the walker now uses `clone_frame_sharing_closures()`, which ALIASES the
// closures table (the same B17 optimization the closure-call path uses) instead
// of copying it. The same 200-item handler now holds at ~60 MB. This test drives
// a real loopback `$http:serve` whose handler runs a per-request comprehension,
// hammers it, and asserts (a) the process survives and (b) RSS stays well under
// a ceiling that cleanly separates the fixed path (~60 MB) from the pre-fix
// blow-up (660 MB+). It MUST run against the shipped `-gc e` build to be
// meaningful.

fn cx_bin() string {
	abs := os.real_path('vcx/target/cx')
	if !os.is_file(abs) {
		panic('vcx/target/cx not found at ${abs} — run `make build-vcx` first')
	}
	return abs
}

fn rss_port() int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100
	return 26600 + int(salt)
}

fn write_tmp_file(name string, content string) string {
	p := os.join_path(os.temp_dir(), name)
	os.write_file(p, content) or { panic('write ${p}: ${err}') }
	return p
}

// rss_kb reads the resident set size (KB) of `pid` via ps. Returns 0 when
// unmeasurable so the test can SKIP rather than fail spuriously.
fn rss_kb(pid int) u64 {
	r := os.execute('ps -o rss= -p ${pid}')
	if r.exit_code != 0 {
		return 0
	}
	return r.output.trim_space().u64()
}

// A handler that does real per-request transient allocation: a 200-item `[?for]`
// building short strings (mirrors the issue's "concat + [?for]" response build).
// Pre-fix this alone drove the per-request high-water to ~660 MB.
fn rss_server_prog(port int) string {
	return "[?lib 'cx-stdlib/http' :as http]\n" +
		'[?def h impure (\$req)\n' +
		'  [?let [= \$rows [?for [in \$i [\$range 1 200]]\n' +
		'                    [yield [\$concat "row-" [\$text \$i] "=" [\$text [* \$i \$i]] ";"]]]]\n' +
		'    [response status=200 [body [\$concat "ok " [\$text [\$count \$rows]]]]]]]\n' +
		'[\$http:serve "tcp://127.0.0.1:${port}" \$h {block: true}]\n'
}

// one_get fires a single GET and returns true once the full response (status
// line + Content-Length body) has been read. It must NOT wait for socket EOF —
// the reactor defers the connection close to its idle path, so reading to EOF
// would block the full read timeout on every request. Instead it parses
// Content-Length and returns as soon as the advertised body has arrived.
fn one_get(port int) bool {
	mut c := net.dial_tcp('127.0.0.1:${port}') or { return false }
	defer {
		c.close() or {}
	}
	c.write_string('GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n') or { return false }
	c.set_read_timeout(4 * time.second)
	mut raw := []u8{}
	mut buf := []u8{len: 4096}
	mut head_end := -1
	mut want := -1
	for {
		n := c.read(mut buf) or { break }
		if n <= 0 {
			break
		}
		raw << buf[..n]
		s := raw.bytestr()
		if head_end < 0 {
			head_end = s.index('\r\n\r\n') or { -1 }
			if head_end >= 0 {
				for line in s[..head_end].split('\r\n') {
					if line.to_lower().starts_with('content-length:') {
						want = line.all_after(':').trim_space().int()
					}
				}
			}
		}
		if head_end >= 0 {
			body_have := raw.len - (head_end + 4)
			if want < 0 || body_have >= want {
				break // full response in hand; don't wait for the deferred close
			}
		}
		if raw.len > 65536 {
			break
		}
	}
	return raw.bytestr().contains('200')
}

fn test_reactor_rss_bounded_under_sustained_for_comprehension() {
	port := rss_port()
	prog := write_tmp_file('cx_rss_srv.cx', rss_server_prog(port))
	pid_s := os.execute('${cx_bin()} --allow-all ${prog} >/tmp/cx_rss_srv.log 2>&1 & echo \$!')
	pid := pid_s.output.trim_space().int()
	if pid <= 0 {
		eprintln('SKIP: could not spawn cx reactor server')
		return
	}
	defer {
		os.execute('kill -9 ${pid} 2>/dev/null')
	}

	// Wait for the listener to bind (first successful GET).
	mut up := false
	for _ in 0 .. 50 {
		if one_get(port) {
			up = true
			break
		}
		time.sleep(100 * time.millisecond)
	}
	if !up {
		log := os.read_file('/tmp/cx_rss_srv.log') or { '' }
		eprintln('SKIP: cx reactor never bound on ${port}; log: ${log}')
		return
	}

	// Drive a sustained run. Pre-fix the heap blew past the ceiling within a
	// handful of requests and eventually OOM-panicked; post-fix RSS plateaus.
	mut ok := 0
	for _ in 0 .. 500 {
		if one_get(port) {
			ok++
		}
	}

	// The server must still be alive (no OOM panic) ...
	alive := os.execute('kill -0 ${pid} 2>/dev/null').exit_code == 0
	log := os.read_file('/tmp/cx_rss_srv.log') or { '' }
	assert alive, 'reactor died under sustained polling (likely the #57 OOM panic); served ${ok}/500; log: ${log}'
	assert ok >= 450, 'reactor dropped too many requests: ${ok}/500 ok; log: ${log}'

	// ... and its RSS must stay far below the pre-fix blow-up. Fixed path holds
	// ~60 MB; pre-fix exceeded 660 MB after only ~30 requests. 300 MB cleanly
	// separates the two with generous platform headroom.
	rkb := rss_kb(pid)
	if rkb == 0 {
		eprintln('NOTE: RSS unmeasurable on this platform; survival assertions still hold')
		return
	}
	assert rkb < 300 * 1024, 'reactor RSS ${rkb} KB after 500 requests exceeds the 300 MB ceiling — the per-request closures-table copy regressed (#57); pre-fix this was 660 MB+'
}
