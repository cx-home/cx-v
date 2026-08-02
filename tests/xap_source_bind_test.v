module main

import os
import testenv
import time
import net.http

// xap_source_bind_test.v — BEHAVIORAL proof of the §3.1.2 event-source
// binding (#583): `[$xap:run {sources: […]}]` makes the RUNTIME own the
// fabric subscription (group offsets, batched pull, ack **after** fold);
// each received entry enters the cascade as the mapped verb, so panels stay
// folds-of-events; combined with the §3.1.1 journal binding the ingested
// commits are durable acts and a restart re-folds them; a served runtime
// pushes the re-rendered surface to /events on every ingested commit AND on
// every in-process emit (not only web intents).

const sb_host_did = 'did:key:z6MkiaMbhXHNA4eJVCCj8dbzKzTgYDKf6crKgHVHid1F1WCT' // RFC 8032 TEST 2
const sb_host_seed_hex = '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb'
const sb_client_did = 'did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw' // RFC 8032 TEST 1
const sb_client_seed_hex = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'

// Disjoint port band (27600-27699), after xap-journal-bind (27500-27599).
fn sb_port() int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 80
	return 27600 + int(salt)
}

fn sb_write(dir string, name string, content string) string {
	p := os.join_path(dir, name)
	os.write_file(p, content) or { panic('write ${p}: ${err}') }
	return p
}

fn sb_run(args string, prog string) string {
	res := os.execute('${testenv.cx_bin()} ${args} ${prog}')
	return res.output.trim_space()
}

fn sb_curl(args string) string {
	r := os.execute('curl -s --max-time 3 ${args}')
	return r.output
}

// The ingesting component: entries enter the cascade as :evidence intents,
// so the /evidence slice is the fold and the view renders each record's id.
const sb_component = '[?lib \'cx-xap\' :as xap]
[\$xap:component evid
  {bind: "/evidence"
   emits: ([do :evidence [e :element]])
   view: [?fn (\$rs) [panel [list [?for [in \$r \$rs] [yield [item \$r/evidence/id]]]]]]
   working-panel: :none}]
'

fn test_xap_source_bind_embedded_ingest_ack_and_refold() {
	tmp := os.join_path(os.temp_dir(), 'cx-xap-sbind-${os.getpid()}')
	os.rmdir_all(tmp) or {}
	os.mkdir_all(tmp) or { panic(err) }
	defer {
		os.rmdir_all(tmp) or {}
	}
	evid := 'file://${tmp}/evidence-journal'
	acts := 'file://${tmp}/acts-journal'
	src := '{fabric: "${evid}", stream: "evidence", group: "g1", verb: :evidence, actor: "ingest"}'
	jbind := '{url: "${acts}", stream: "acts"}'

	// seed the evidence stream from a plain fabric publisher (no xap).
	pub1 := sb_write(tmp, 'publish.cx', "[?lib 'cx-fabric' :as fabric]\n" +
		"[?lib 'cx-stdlib/journal' :as journal]\n" +
		'[?let [= \$j [\$journal:open "${evid}" "demo"]]\n' +
		'      [= \$f [\$fabric:open \$j]]\n' +
		'      [= \$a [\$fabric:publish \$f "evidence" [evidence [id "e1"] [kind "cro"]] {actor: "src" authority: "sim"}]]\n' +
		'      [= \$b [\$fabric:publish \$f "evidence" [evidence [id "e2"] [kind "cro"]] {actor: "src" authority: "sim"}]]\n' +
		'  [out \$b]]\n')
	pout := sb_run('--allow-read --allow-write', pub1)
	assert pout.contains('seq=2'), 'publisher did not seed two events: ${pout}'

	// worker 1: the runtime owns the subscription — after the pump drains,
	// the fold holds both records, entered as :evidence intents.
	w1 := sb_write(tmp, 'worker1.cx', sb_component +
		'[?let [= \$rt [\$xap:run {tenant: "demo" journal: ${jbind} sources: [${src}]}]]\n' +
		'      [= \$w [?sleep 2500ms]]\n' +
		'  [out [\$count [\$xap:state \$rt "/evidence"]]]]\n')
	out1 := sb_run('--allow-read --allow-write', w1)
	assert out1.contains('[out 2]'), 'runtime-owned source did not ingest+fold two entries: ${out1}'

	// worker 2 (RESTART, same group + same journal binding): the group's
	// offset is committed (ack-after-fold — nothing redelivers), and the
	// §3.1.1 acts stream re-folds BOTH ingested commits at boot. Together
	// the journal is the only hand-off in both directions.
	out2 := sb_run('--allow-read --allow-write', w1)
	assert out2.contains('[out 2]'), 'restart did not re-fold the ingested acts (or the group redelivered): ${out2}'

	// denial lane: an agent actor with no authority chain is denied by the
	// PEP — the entry is SKIPPED but ACKNOWLEDGED (deny-by-default must not
	// wedge the group), so a follow-up admissible worker on the SAME group
	// sees nothing redelivered.
	evid2 := 'file://${tmp}/evidence2-journal'
	acts2 := 'file://${tmp}/acts2-journal'
	pub2 := sb_write(tmp, 'publish2.cx', "[?lib 'cx-fabric' :as fabric]\n" +
		"[?lib 'cx-stdlib/journal' :as journal]\n" +
		'[?let [= \$j [\$journal:open "${evid2}" "demo"]]\n' +
		'      [= \$f [\$fabric:open \$j]]\n' +
		'      [= \$a [\$fabric:publish \$f "evidence" [evidence [id "e9"] [kind "cro"]] {actor: "src" authority: "sim"}]]\n' +
		'  [out \$a]]\n')
	pout2 := sb_run('--allow-read --allow-write', pub2)
	assert pout2.contains('seq=1'), 'publisher 2 did not seed: ${pout2}'
	denied_src := '{fabric: "${evid2}", stream: "evidence", group: "g2", verb: :evidence, actor: "agent:ghost"}'
	w3 := sb_write(tmp, 'worker3.cx', sb_component +
		'[?let [= \$rt [\$xap:run {tenant: "demo" journal: {url: "${acts2}", stream: "acts"} sources: [${denied_src}]}]]\n' +
		'      [= \$w [?sleep 2500ms]]\n' +
		'  [out [\$count [\$xap:state \$rt "/evidence"]]]]\n')
	out3 := sb_run('--allow-read --allow-write', w3)
	assert out3.contains('[out 0]'), 'denied ingest must fold nothing: ${out3}'
	ok_src := '{fabric: "${evid2}", stream: "evidence", group: "g2", verb: :evidence, actor: "ingest"}'
	w4 := sb_write(tmp, 'worker4.cx', sb_component +
		'[?let [= \$rt [\$xap:run {tenant: "demo" journal: {url: "${acts2}", stream: "acts"} sources: [${ok_src}]}]]\n' +
		'      [= \$w [?sleep 2000ms]]\n' +
		'  [out [\$count [\$xap:state \$rt "/evidence"]]]]\n')
	out4 := sb_run('--allow-read --allow-write', w4)
	assert out4.contains('[out 0]'), 'a denied entry must be acked past, never redelivered: ${out4}'
}

fn test_xap_source_bind_remote_live_ingest_and_sse_push() {
	if os.execute('which curl').exit_code != 0 {
		eprintln('SKIP: curl not available')
		return
	}
	cxbin := testenv.cx_bin()
	port := sb_port()
	hport := port + 100
	wport := port + 200
	tmp := os.join_path(os.temp_dir(), 'cx-xap-sbind-xsp-${os.getpid()}')
	os.rmdir_all(tmp) or {}
	os.mkdir_all(tmp) or { panic(err) }
	cfg := '[fabric-service
  [bind addr="127.0.0.1:${port}"]
  [health addr="127.0.0.1:${hport}"]
  [identity did="${sb_host_did}" seed-env="CX_FABRIC_SEED"]
  [policy mode="mutual"]
  [limits pending-window=16 liveness-ms=15000 request-timeout-ms=5000]
  [fabrics [fabric name="main" store="file://${tmp}/store" tenant="acme"]]
  [principals
    [principal did="${sb_client_did}"
      [grant action="publish" scope="*"]
      [grant action="consume" scope="*"]
      [grant action="observe" scope="*"]]]]'
	cfg_path := sb_write(tmp, 'fabric.service.cx', cfg)
	os.setenv('CX_FABRIC_SEED', sb_host_seed_hex, true)
	mut proc := os.new_process('/bin/sh')
	proc.set_args(['-c',
		'exec "${cxbin}" fabric-serve --config "${cfg_path}" --allow-read --allow-write --allow-net=127.0.0.1:${port} --allow-net=127.0.0.1:${hport} --allow-env >"${tmp}/daemon.log" 2>&1'])
	proc.run()
	defer {
		proc.signal_kill()
		os.unsetenv('CX_FABRIC_SEED')
		os.rmdir_all(tmp) or {}
	}
	mut up := false
	for _ in 0 .. 100 {
		time.sleep(100 * time.millisecond)
		r := http.get('http://127.0.0.1:${hport}/ready') or { continue }
		if r.status_code == 200 && r.body.contains('[accepting true]') {
			up = true
			break
		}
	}
	if !up {
		out := os.read_file(os.join_path(tmp, 'daemon.log')) or { '' }
		panic('fabric-serve never came up: ${out}')
	}

	client_open := '[\$fabric:open "xsp://127.0.0.1:${port}" {tenant: "acme" did: "${sb_client_did}" seed: [\$bytes:from-hex "${sb_client_seed_hex}"]}]'
	// seed one evidence event before the worker boots.
	pub1 := sb_write(tmp, 'publish1.cx', "[?lib 'cx-fabric' :as fabric]\n[?lib 'cx-stdlib/bytes' :as bytes]\n" +
		'[?let [= \$f ${client_open}]\n' +
		'  [\$fabric:publish \$f "evidence" [evidence [id "e1"] [kind "cro"]] {}]]\n')
	pout1 := sb_run('--allow-net=127.0.0.1:${port}', pub1)
	assert pout1.contains('seq=1'), 'remote publish 1 failed: ${pout1}'

	// the served worker: runtime-owned remote source + web serve.
	src := '{fabric: "xsp://127.0.0.1:${port}", stream: "evidence", group: "gw", verb: :evidence, actor: "ingest", tenant: "acme", did: "${sb_client_did}", seed: [\$bytes:from-hex "${sb_client_seed_hex}"]}'
	wsrv := sb_write(tmp, 'worker-serve.cx', "[?lib 'cx-stdlib/bytes' :as bytes]\n" + sb_component +
		'[?let [= \$rt [\$xap:run {tenant: "acme" sources: [${src}]}]]\n' +
		'  [\$xap:serve "http://127.0.0.1:${wport}" {runtime: \$rt}]]\n')
	pid_s := os.execute('${cxbin} --allow-net=127.0.0.1:${port} --allow-net=127.0.0.1:${wport} ${wsrv} >${tmp}/worker.log 2>&1 & echo \$!')
	wpid := pid_s.output.trim_space().int()
	defer {
		os.execute('kill ${wpid} 2>/dev/null')
	}

	// the pre-boot event lands on the surface (ingest → cascade → fold → view).
	mut got1 := false
	for _ in 0 .. 60 {
		s := sb_curl('http://127.0.0.1:${wport}/surface')
		if s.contains("[item 'e1']") {
			got1 = true
			break
		}
		time.sleep(200 * time.millisecond)
	}
	wlog := os.read_file(os.join_path(tmp, 'worker.log')) or { '' }
	assert got1, 'pre-boot evidence never reached the served surface (worker log: ${wlog})'

	// live: hold an SSE reader open, publish a SECOND event from a separate
	// process — the runtime's pump must fold it AND push the re-rendered
	// surface to the held reader (§3.1.2: live media follow ingest).
	cap_file := os.join_path(tmp, 'sse.cap')
	os.execute('curl -sN --max-time 6 http://127.0.0.1:${wport}/events >${cap_file} 2>&1 & echo \$!')
	time.sleep(500 * time.millisecond)
	pub2 := sb_write(tmp, 'publish2.cx', "[?lib 'cx-fabric' :as fabric]\n[?lib 'cx-stdlib/bytes' :as bytes]\n" +
		'[?let [= \$f ${client_open}]\n' +
		'  [\$fabric:publish \$f "evidence" [evidence [id "e2"] [kind "cro"]] {}]]\n')
	pout2 := sb_run('--allow-net=127.0.0.1:${port}', pub2)
	assert pout2.contains('seq=2'), 'remote publish 2 failed: ${pout2}'
	mut got2 := false
	for _ in 0 .. 30 {
		cap := os.read_file(cap_file) or { '' }
		if cap.contains("[item 'e2']") {
			got2 = true
			break
		}
		time.sleep(200 * time.millisecond)
	}
	cap := os.read_file(cap_file) or { '' }
	assert got2, 'ingested commit was not pushed to the held /events reader; got: ${cap}'
}

// §3.1.2 rider: an IN-PROCESS emit after boot refreshes /events subscribers
// too — push-on-commit is the cascade's, not the web bridge's.
fn test_xap_inprocess_emit_pushes_sse() {
	if os.execute('which curl').exit_code != 0 {
		eprintln('SKIP: curl not available')
		return
	}
	port := sb_port() + 90
	tmp := os.join_path(os.temp_dir(), 'cx-xap-emit-sse-${os.getpid()}')
	os.rmdir_all(tmp) or {}
	os.mkdir_all(tmp) or { panic(err) }
	defer {
		os.rmdir_all(tmp) or {}
	}
	srv := sb_write(tmp, 'emit-server.cx', '[?lib \'cx-xap\' :as xap]\n' +
		'[\$xap:component guestbook\n' +
		'  {bind: "/guestbook"\n' +
		'   emits: ([do :sign [name :string]])\n' +
		'   view: [?fn (\$gs) [panel [list [?for [in \$g \$gs] [yield [item \$g/name]]]]]]\n' +
		'   working-panel: :none}]\n' +
		'[?let [= \$rt [\$xap:run {tenant: "demo"}]]\n' +
		'      [= \$srv [\$xap:serve "http://127.0.0.1:${port}" {runtime: \$rt block: false}]]\n' +
		'      [= \$w1 [?sleep 1500ms]]\n' +
		'      [= \$e [\$xap:emit \$rt [do :sign [name "Iris"]]]]\n' +
		'      [= \$w2 [?sleep 8s]]\n' +
		'  [out \$e]]\n')
	pid_s := os.execute('${testenv.cx_bin()} --allow-net ${srv} >${tmp}/server.log 2>&1 & echo \$!')
	pid := pid_s.output.trim_space().int()
	defer {
		os.execute('kill ${pid} 2>/dev/null')
	}
	mut up := false
	for _ in 0 .. 30 {
		if sb_curl('-o /dev/null -w "%{http_code}" http://127.0.0.1:${port}/surface') == '200' {
			up = true
			break
		}
		time.sleep(100 * time.millisecond)
	}
	assert up, 'xap serve never bound on ${port}'

	cap_file := os.join_path(tmp, 'sse.cap')
	os.execute('curl -sN --max-time 5 http://127.0.0.1:${port}/events >${cap_file} 2>&1 & echo \$!')
	// the in-process emit fires ~1.5s after boot; the held reader must get
	// the post-emit surface without any web intent in the loop.
	mut got := false
	for _ in 0 .. 30 {
		cap := os.read_file(cap_file) or { '' }
		if cap.contains("[item 'Iris']") {
			got = true
			break
		}
		time.sleep(200 * time.millisecond)
	}
	cap := os.read_file(cap_file) or { '' }
	assert got, 'in-process emit did not push to the held /events reader; got: ${cap}'
}

// #593: on a runtime with BOTH a remote source and a remote §3.1.1 journal
// binding, a received batch commits through ONE pipelined append turn —
// every entry lands on the acts stream in order and folds. Pins the batch
// lane end-to-end: 6 pre-published evidence events → 6 ingested commits →
// 6 ordered acts observable by an independent client.
fn test_xap_source_batch_pipelined_appends() {
	cxbin := testenv.cx_bin()
	port := sb_port() + 45
	hport := port + 100
	tmp := os.join_path(os.temp_dir(), 'cx-xap-sbatch-${os.getpid()}')
	os.rmdir_all(tmp) or {}
	os.mkdir_all(tmp) or { panic(err) }
	cfg := '[fabric-service
  [bind addr="127.0.0.1:${port}"]
  [health addr="127.0.0.1:${hport}"]
  [identity did="${sb_host_did}" seed-env="CX_FABRIC_SEED"]
  [policy mode="mutual"]
  [limits pending-window=64 liveness-ms=15000 request-timeout-ms=5000]
  [fabrics [fabric name="main" store="file://${tmp}/store" tenant="acme"]]
  [principals
    [principal did="${sb_client_did}"
      [grant action="publish" scope="*"]
      [grant action="consume" scope="*"]
      [grant action="observe" scope="*"]]]]'
	cfg_path := sb_write(tmp, 'fabric.service.cx', cfg)
	os.setenv('CX_FABRIC_SEED', sb_host_seed_hex, true)
	mut proc := os.new_process('/bin/sh')
	proc.set_args(['-c',
		'exec "${cxbin}" fabric-serve --config "${cfg_path}" --allow-read --allow-write --allow-net=127.0.0.1:${port} --allow-net=127.0.0.1:${hport} --allow-env >"${tmp}/daemon.log" 2>&1'])
	proc.run()
	defer {
		proc.signal_kill()
		os.unsetenv('CX_FABRIC_SEED')
		os.rmdir_all(tmp) or {}
	}
	mut up := false
	for _ in 0 .. 100 {
		time.sleep(100 * time.millisecond)
		r := http.get('http://127.0.0.1:${hport}/ready') or { continue }
		if r.status_code == 200 && r.body.contains('[accepting true]') {
			up = true
			break
		}
	}
	if !up {
		out := os.read_file(os.join_path(tmp, 'daemon.log')) or { '' }
		panic('fabric-serve never came up: ${out}')
	}

	client_open := '[\$fabric:open "xsp://127.0.0.1:${port}" {tenant: "acme" did: "${sb_client_did}" seed: [\$bytes:from-hex "${sb_client_seed_hex}"]}]'
	pub6 := sb_write(tmp, 'publish6.cx', "[?lib 'cx-fabric' :as fabric]\n[?lib 'cx-stdlib/bytes' :as bytes]\n" +
		'[?let [= \$f ${client_open}]\n' +
		'      [= \$a [\$fabric:publish \$f "evidence" [evidence [id "e1"]] {}]]\n' +
		'      [= \$b [\$fabric:publish \$f "evidence" [evidence [id "e2"]] {}]]\n' +
		'      [= \$c [\$fabric:publish \$f "evidence" [evidence [id "e3"]] {}]]\n' +
		'      [= \$d [\$fabric:publish \$f "evidence" [evidence [id "e4"]] {}]]\n' +
		'      [= \$e [\$fabric:publish \$f "evidence" [evidence [id "e5"]] {}]]\n' +
		'  [out [\$fabric:publish \$f "evidence" [evidence [id "e6"]] {}]]]\n')
	pout := sb_run('--allow-net=127.0.0.1:${port}', pub6)
	assert pout.contains('seq=6'), 'seed publishes failed: ${pout}'

	jbind := '{url: "xsp://127.0.0.1:${port}", stream: "acts", tenant: "acme", did: "${sb_client_did}", seed: [\$bytes:from-hex "${sb_client_seed_hex}"]}'
	src := '{fabric: "xsp://127.0.0.1:${port}", stream: "evidence", group: "gb", verb: :evidence, actor: "ingest", tenant: "acme", did: "${sb_client_did}", seed: [\$bytes:from-hex "${sb_client_seed_hex}"]}'
	w := sb_write(tmp, 'worker.cx', "[?lib 'cx-stdlib/bytes' :as bytes]\n" + sb_component +
		'[?let [= \$rt [\$xap:run {tenant: "acme" journal: ${jbind} sources: [${src}]}]]\n' +
		'      [= \$w [?sleep 4s]]\n' +
		'  [out [\$count [\$xap:state \$rt "/evidence"]]]]\n')
	wout := sb_run('--allow-net=127.0.0.1:${port}', w)
	assert wout.contains('[out 6]'), 'batched ingest did not fold all six entries: ${wout}'

	// the pipelined appends landed IN ORDER on the acts stream.
	obs := sb_write(tmp, 'observe.cx', "[?lib 'cx-fabric' :as fabric]\n[?lib 'cx-stdlib/bytes' :as bytes]\n" +
		"[?lib 'cx-stdlib/format' :as format]\n" +
		'[?let [= \$f ${client_open}]\n' +
		'      [= \$s [\$fabric:observe \$f "acts" "event"]]\n' +
		'      [= \$es [\$fabric:receive \$s {max: 16, deadline: 2000}]]\n' +
		'  [out [?str \'{[\$count \$es]}|{[\$format:canonical [\$nth \$es 1]]}|{[\$format:canonical [\$nth \$es 6]]}\']]]\n')
	oout := sb_run('--allow-net=127.0.0.1:${port}', obs)
	assert oout.contains('6|'), 'acts stream must carry all six pipelined appends: ${oout}'
	assert oout.contains('e1') && oout.contains('e6'), 'append order lost: ${oout}'
}
