module main

import os
import testenv
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
	return testenv.cx_bin()
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

// A heavier per-request value-building handler (1000-item [?for] → concat join),
// the cx-private #131 (xap-marine OOM) shape: large transient body building, a
// small steady live set. vgc's OLD fixed-floor pacer never fired on this pattern,
// so committed pages — and RSS — climbed monotonically (measured: ~571 MB and
// rising). The reactor churn gate (gc_collect_if_churned) held it flat as a
// host-side crutch; since cx #71 the vgc ADAPTIVE pacer bounds it by
// construction and the gate defaults OFF — so this test now guards the pacer
// itself (no CX_HTTP_GC_* env is set).
fn rss_heavy_server_prog(port int) string {
	return "[?lib 'cx-stdlib/http' :as http]\n" +
		'[?def h impure (\$req)\n' +
		'  [?let [= \$rows [?for [in \$i [\$range 1 1000]]\n' +
		'                    [yield [\$concat "row-" [\$text \$i] "=" [\$text [* \$i \$i]] ";"]]]]\n' +
		'    [response status=200 [body [\$concat "ok " [\$text [\$count \$rows]]]]]]]\n' +
		'[\$http:serve "tcp://127.0.0.1:${port}" \$h {block: true}]\n'
}

fn test_reactor_rss_bounded_under_heavy_value_building() {
	port := rss_port() + 1
	prog := write_tmp_file('cx_rss_heavy.cx', rss_heavy_server_prog(port))
	// Single reactor (CX_HTTP_N=1): RSS bounding is the concern here. Frequent
	// collection trips the known residual multi-reactor GC race (a SEPARATE
	// axis), so pin one reactor to keep this gate measuring RSS, not the race.
	pid_s := os.execute('CX_HTTP_N=1 ${cx_bin()} --allow-all ${prog} >/tmp/cx_rss_heavy.log 2>&1 & echo \$!')
	pid := pid_s.output.trim_space().int()
	if pid <= 0 {
		eprintln('SKIP: could not spawn heavy reactor server')
		return
	}
	defer {
		os.execute('kill -9 ${pid} 2>/dev/null')
	}

	mut up := false
	for _ in 0 .. 50 {
		if one_get(port) {
			up = true
			break
		}
		time.sleep(100 * time.millisecond)
	}
	if !up {
		log := os.read_file('/tmp/cx_rss_heavy.log') or { '' }
		eprintln('SKIP: heavy reactor never bound on ${port}; log: ${log}')
		return
	}

	// Sustained heavy load, measured as CONVERGENCE: drive identical 1000-req
	// windows until one grows RSS by <10% over the previous window's end (the
	// pacer's steady state), bounded by a window budget and a hard absolute
	// backstop. The honest #71 contract is "plateaus by construction" — the
	// absolute equilibrium (and how fast it is reached) legitimately varies
	// with build opt-level AND with CPU contention from parallel test jobs
	// (both inflate GC pauses, so the adaptive headroom settles higher), which
	// a fixed ceiling or a fixed-split plateau conflates with a leak. The
	// pre-fix failure cannot pass: its climb is ~linear per request (~140 MB
	// per window), so it crosses the 520 MB backstop long before consecutive
	// window ratios flatten under 1.10, and eventually OOM-panics.
	mut ok := 0
	mut total := 0
	mut prev_kb := u64(0)
	mut converged := false
	mut last_kb := u64(0)
	for _ in 0 .. 7 {
		for _ in 0 .. 1000 {
			if one_get(port) {
				ok++
			}
		}
		total += 1000
		last_kb = rss_kb(pid)
		if last_kb == 0 {
			break // RSS unmeasurable; survival assertions below still hold
		}
		assert last_kb < 520 * 1024, 'heavy reactor RSS ${last_kb} KB after ${total} requests exceeds the 520 MB runaway backstop (#131/#71); the pre-adaptive-pacer repro reaches ~571 MB by 4000 requests and keeps climbing'
		if prev_kb > 0 && f64(last_kb) / f64(prev_kb) < 1.10 {
			converged = true
			break
		}
		prev_kb = last_kb
	}

	alive := os.execute('kill -0 ${pid} 2>/dev/null').exit_code == 0
	log := os.read_file('/tmp/cx_rss_heavy.log') or { '' }
	assert alive, 'heavy reactor died under ${total}-req load (likely the #131 OOM panic); served ${ok}/${total}; log: ${log}'
	assert ok * 100 >= total * 95, 'heavy reactor dropped too many requests: ${ok}/${total} ok; log: ${log}'
	if last_kb == 0 {
		eprintln('NOTE: RSS unmeasurable on this platform; survival assertions still hold')
		return
	}
	assert converged, 'heavy reactor RSS never plateaued: ${last_kb} KB after ${total} requests, still growing >=10% per 1000-req window — transients are not being reclaimed by construction (#131/#71)'
}

// The churn-gate OPT-IN must keep working (it is the ops escape hatch for a
// host-chosen collection pace, and builtin.gc_collect_if_churned needs a live
// consumer): the same heavy shape with CX_HTTP_GC_MB=1 pinned must stay bounded
// and serve traffic exactly like the default path.
fn test_reactor_rss_bounded_with_churn_gate_pinned() {
	port := rss_port() + 2
	prog := write_tmp_file('cx_rss_gate.cx', rss_heavy_server_prog(port))
	pid_s := os.execute('CX_HTTP_N=1 CX_HTTP_GC_MB=1 ${cx_bin()} --allow-all ${prog} >/tmp/cx_rss_gate.log 2>&1 & echo \$!')
	pid := pid_s.output.trim_space().int()
	if pid <= 0 {
		eprintln('SKIP: could not spawn gate-pinned reactor server')
		return
	}
	defer {
		os.execute('kill -9 ${pid} 2>/dev/null')
	}

	mut up := false
	for _ in 0 .. 50 {
		if one_get(port) {
			up = true
			break
		}
		time.sleep(100 * time.millisecond)
	}
	if !up {
		log := os.read_file('/tmp/cx_rss_gate.log') or { '' }
		eprintln('SKIP: gate-pinned reactor never bound on ${port}; log: ${log}')
		return
	}

	mut ok := 0
	for _ in 0 .. 1000 {
		if one_get(port) {
			ok++
		}
	}

	alive := os.execute('kill -0 ${pid} 2>/dev/null').exit_code == 0
	log := os.read_file('/tmp/cx_rss_gate.log') or { '' }
	assert alive, 'gate-pinned reactor died under load; served ${ok}/1000; log: ${log}'
	assert ok >= 950, 'gate-pinned reactor dropped too many requests: ${ok}/1000 ok; log: ${log}'

	rkb := rss_kb(pid)
	if rkb == 0 {
		eprintln('NOTE: RSS unmeasurable on this platform; survival assertions still hold')
		return
	}
	assert rkb < 280 * 1024, 'gate-pinned reactor RSS ${rkb} KB exceeds the 280 MB ceiling — the CX_HTTP_GC_MB opt-in regressed'
}
