module main

import os
import testenv
import time
import net.http

// xap_journal_bind_test.v — BEHAVIORAL proof of the §3.1.1 durable journal
// binding (#582): with `[$xap:run {journal: …}]` the cascade's commit IS the
// durable append (uniform [event …] envelope), an external process observes
// committed acts on the bound stream, and a fresh runtime re-folds the
// stream at boot (restart = re-fold). Absent the binding, behavior is the
// prior in-process demo mode (pinned by the existing xap tests).
//
// Lane 1 (embedded, file:// journal): commit → reopen in a NEW process →
// state re-folded; a third process observes the [event] entries directly
// off the journal through the fabric surface.
// Lane 2 (remote, xsp:// daemon): the same contract over the served tier —
// commits publish to the daemon's stream (attribution = the proven session
// principal, the PEP actor rides in the envelope), an independent client
// observes them, and a restarted runtime re-folds from the daemon.

const jb_host_did = 'did:key:z6MkiaMbhXHNA4eJVCCj8dbzKzTgYDKf6crKgHVHid1F1WCT' // RFC 8032 TEST 2
const jb_host_seed_hex = '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb'
const jb_client_did = 'did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw' // RFC 8032 TEST 1
const jb_client_seed_hex = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'

// Disjoint port band (27500-27599) from fabric-serve (27100-27299) and the
// fabric adapter lanes (27300-27499).
fn jb_port() int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 80
	return 27500 + int(salt)
}

fn jb_write(dir string, name string, content string) string {
	p := os.join_path(dir, name)
	os.write_file(p, content) or { panic('write ${p}: ${err}') }
	return p
}

fn jb_run(args string, prog string) string {
	res := os.execute('${testenv.cx_bin()} ${args} ${prog}')
	return res.output.trim_space()
}

const jb_component = '[?lib \'cx-xap\' :as xap]
[\$xap:component guestbook
  {bind: "/guestbook"
   emits: ([do :sign [name :string]])
   view: [?fn (\$gs) [panel [list [?for [in \$g \$gs] [yield [item \$g/name]]]]]]
   working-panel: :none}]
'

fn test_xap_journal_bind_embedded_commit_and_refold() {
	tmp := os.join_path(os.temp_dir(), 'cx-xap-jbind-${os.getpid()}')
	os.rmdir_all(tmp) or {}
	os.mkdir_all(tmp) or { panic(err) }
	defer {
		os.rmdir_all(tmp) or {}
	}
	store := 'file://${tmp}/journal'
	bind := '{url: "${store}", stream: "acts"}'

	// process 1: bound runtime, two attributed commits, state = the live fold.
	p1 := jb_write(tmp, 'commit.cx', jb_component +
		'[?let [= \$rt [\$xap:run {tenant: "demo" journal: ${bind}}]]\n' +
		'[?let [= \$a [\$xap:emit \$rt [do :sign [name "Ada"]] {actor: "u1"}]]\n' +
		'[?let [= \$b [\$xap:emit \$rt [do :sign [name "Lin"]] {actor: "u1"}]]\n' +
		'  [out [\$count [\$xap:state \$rt "/guestbook"]]]]]]\n')
	out1 := jb_run('--allow-read --allow-write', p1)
	assert out1.contains('2'), 'bound runtime did not fold two commits: ${out1}'

	// process 1b: an ANONYMOUS emit on a bound runtime refuses (the
	// journal's no-anonymous-appends invariant propagates as-is, N-IMPL-1)
	// and folds nothing — the re-folded count stays 2.
	// (the refused commit folds/appends nothing — process 2's re-fold below
	// still counting exactly 2 is the proof.)
	p1b := jb_write(tmp, 'ghost.cx', jb_component +
		'[?let [= \$rt [\$xap:run {tenant: "demo" journal: ${bind}}]]\n' +
		'      [= \$g [\$xap:emit \$rt [do :sign [name "Ghost"]]]]\n' +
		'  [out \$g]]\n')
	out1b := jb_run('--allow-read --allow-write', p1b)
	assert out1b.contains('E_JOURNAL_ATTRIBUTION_INVALID'), 'anonymous emit on a bound runtime must refuse: ${out1b}'

	// process 2 (RESTART): a fresh runtime over the same binding re-folds
	// the stream at boot — no re-emit, the journal is the hand-off.
	p2 := jb_write(tmp, 'refold.cx', jb_component +
		'[?let [= \$rt [\$xap:run {tenant: "demo" journal: ${bind}}]]\n' +
		'  [out [\$count [\$xap:state \$rt "/guestbook"]]]]\n')
	out2 := jb_run('--allow-read --allow-write', p2)
	assert out2.contains('2'), 'restart did not re-fold the bound stream: ${out2}'

	// process 3 (EXTERNAL OBSERVER): the committed acts are ordinary journal
	// entries on the bound stream — readable outside any xap runtime, as the
	// uniform [event …] envelope.
	p3 := jb_write(tmp, 'observe.cx', "[?lib 'cx-fabric' :as fabric]\n" +
		"[?lib 'cx-stdlib/journal' :as journal]\n" +
		"[?lib 'cx-stdlib/format' :as format]\n" +
		'[?let [= \$j [\$journal:open "${store}" "demo"]]\n' +
		'  [= \$f [\$fabric:open \$j]]\n' +
		'  [= \$s [\$fabric:observe \$f "acts" "event"]]\n' +
		'  [= \$es [\$fabric:receive \$s {max: 8}]]\n' +
		'  [out [?str \'{[\$count \$es]}|{[\$format:canonical [\$nth \$es 1]]}\']]]\n')
	out3 := jb_run('--allow-read --allow-write', p3)
	assert out3.contains('2|'), 'external observer did not read two committed acts: ${out3}'
	assert out3.contains('[event') && out3.contains(':sign') && out3.contains('Ada'), 'committed envelope wrong: ${out3}'
	assert out3.contains('actor=u1') || out3.contains("actor='u1'"), 'envelope must carry the PEP actor: ${out3}'

	// process 4: a broken binding refuses at run, not at first commit.
	p4 := jb_write(tmp, 'badbind.cx', jb_component +
		'[out [\$xap:run {tenant: "demo" journal: {stream: "acts"}}]]\n')
	out4 := jb_run('--allow-read --allow-write', p4)
	assert out4.contains('err') && out4.contains('url'), 'binding without url must refuse at run: ${out4}'
}

fn test_xap_journal_bind_remote_xsp() {
	cxbin := testenv.cx_bin()
	port := jb_port()
	hport := port + 100
	tmp := os.join_path(os.temp_dir(), 'cx-xap-jbind-xsp-${os.getpid()}')
	os.rmdir_all(tmp) or {}
	os.mkdir_all(tmp) or { panic(err) }
	cfg := '[fabric-service
  [bind addr="127.0.0.1:${port}"]
  [health addr="127.0.0.1:${hport}"]
  [identity did="${jb_host_did}" seed-env="CX_FABRIC_SEED"]
  [policy mode="mutual"]
  [limits pending-window=16 liveness-ms=15000 request-timeout-ms=5000]
  [fabrics [fabric name="main" store="file://${tmp}/store" tenant="acme"]]
  [principals
    [principal did="${jb_client_did}"
      [grant action="publish" scope="*"]
      [grant action="consume" scope="*"]
      [grant action="observe" scope="*"]]]]'
	cfg_path := jb_write(tmp, 'fabric.service.cx', cfg)
	os.setenv('CX_FABRIC_SEED', jb_host_seed_hex, true)
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

	bind := '{url: "xsp://127.0.0.1:${port}", stream: "acts", tenant: "acme",
      did: "${jb_client_did}",
      seed: [\$bytes:from-hex "${jb_client_seed_hex}"]}'
	prelude := "[?lib 'cx-stdlib/bytes' :as bytes]\n"

	// process 1: bound runtime commits over the wire.
	p1 := jb_write(tmp, 'commit.cx', prelude + jb_component +
		'[?let [= \$rt [\$xap:run {tenant: "acme" journal: ${bind}}]]\n' +
		'[?let [= \$a [\$xap:emit \$rt [do :sign [name "Ada"]] {actor: "u1"}]]\n' +
		'  [out [\$count [\$xap:state \$rt "/guestbook"]]]]]\n')
	out1 := jb_run('--allow-net=127.0.0.1:${port}', p1)
	assert out1.contains('1'), 'remote-bound runtime did not commit/fold: ${out1}'

	// process 2 (independent observer): the act is on the daemon's stream.
	p2 := jb_write(tmp, 'observe.cx', "[?lib 'cx-fabric' :as fabric]\n" + prelude +
		"[?lib 'cx-stdlib/format' :as format]\n" +
		'[?let [= \$f [\$fabric:open "xsp://127.0.0.1:${port}" {tenant: "acme" did: "${jb_client_did}" seed: [\$bytes:from-hex "${jb_client_seed_hex}"]}]]\n' +
		'  [= \$s [\$fabric:observe \$f "acts" "event"]]\n' +
		'  [= \$es [\$fabric:receive \$s {max: 8, deadline: 2000}]]\n' +
		'  [out [?str \'{[\$count \$es]}|{[\$format:canonical [\$nth \$es 1]]}\']]]\n')
	out2 := jb_run('--allow-net=127.0.0.1:${port}', p2)
	assert out2.contains('1|'), 'observer did not read the committed act: ${out2}'
	assert out2.contains(':sign') && out2.contains('Ada'), 'observed envelope wrong: ${out2}'

	// process 3 (RESTART): a fresh runtime re-folds from the daemon.
	p3 := jb_write(tmp, 'refold.cx', prelude + jb_component +
		'[?let [= \$rt [\$xap:run {tenant: "acme" journal: ${bind}}]]\n' +
		'  [out [\$count [\$xap:state \$rt "/guestbook"]]]]\n')
	out3 := jb_run('--allow-net=127.0.0.1:${port}', p3)
	assert out3.contains('1'), 'remote restart did not re-fold: ${out3}'
}

// §3.1.1 fold checkpoints (#595): with checkpoint:/checkpoint-every: in the
// binding, the fold persists as a derived [checkpoint …] doc and boot seeds
// from it + replays only the suffix. A checkpoint is derived state, never
// authority: a doctored checkpoint proves seed+suffix (the doctored state
// shows through), and a garbage checkpoint falls back to full replay.
fn test_xap_journal_checkpoint_suffix_replay_and_fail_open() {
	tmp := os.join_path(os.temp_dir(), 'cx-xap-ckpt-${os.getpid()}')
	os.rmdir_all(tmp) or {}
	os.mkdir_all(tmp) or { panic(err) }
	defer {
		os.rmdir_all(tmp) or {}
	}
	store := 'file://${tmp}/journal'
	ckpt := 'file://${tmp}/ckpt'
	bind := '{url: "${store}", stream: "acts", checkpoint: "${ckpt}", checkpoint-every: 2}'

	// three commits: the every-2 cadence persists a checkpoint at seq 2.
	// The persist is ASYNC (#604) — the short sleep keeps this short-lived
	// process alive long enough for the off-thread write to land (a real
	// daemon never exits mid-persist; an exit that races it just leaves
	// the previous checkpoint standing, by design).
	p1 := jb_write(tmp, 'commit.cx', jb_component +
		'[?let [= \$rt [\$xap:run {tenant: "demo" journal: ${bind}}]]\n' +
		'[?let [= \$a [\$xap:emit \$rt [do :sign [name "Ada"]] {actor: "u1"}]]\n' +
		'[?let [= \$b [\$xap:emit \$rt [do :sign [name "Lin"]] {actor: "u1"}]]\n' +
		'[?let [= \$c [\$xap:emit \$rt [do :sign [name "Cyd"]] {actor: "u1"}]]\n' +
		'[?let [= \$w [?sleep 1s]]\n' +
		'  [out [\$count [\$xap:state \$rt "/guestbook"]]]]]]]]\n')
	out1 := jb_run('--allow-read --allow-write', p1)
	assert out1.contains('[out 3]'), 'checkpointed runtime did not fold three commits: ${out1}'

	// the derived doc is alias-addressed in the checkpoint store at seq 2.
	pchk := jb_write(tmp, 'readckpt.cx', "[?lib 'cx-stdlib/store' :as store]\n" +
		'[?let [= \$s [\$store:open "${ckpt}"]]\n' +
		'      [= \$h [\$store:get-alias \$s "xap-checkpoint-demo-acts"]]\n' +
		'  [out [\$store:get-doc \$s \$h]]]\n')
	outc := jb_run('--allow-read --allow-write', pchk)
	assert outc.contains('[checkpoint') && outc.contains('acts'), 'checkpoint doc missing: ${outc}'
	assert outc.contains("seq='2'") || outc.contains('seq=2'), 'checkpoint must cover seq 2: ${outc}'
	assert outc.contains('Ada') && outc.contains('Lin') && !outc.contains('Cyd'), 'checkpoint slice wrong: ${outc}'

	// restart: checkpoint seed + suffix replay reconstructs all three.
	p2 := jb_write(tmp, 'refold.cx', jb_component +
		'[?let [= \$rt [\$xap:run {tenant: "demo" journal: ${bind}}]]\n' +
		'  [out [\$count [\$xap:state \$rt "/guestbook"]]]]\n')
	out2 := jb_run('--allow-read --allow-write', p2)
	assert out2.contains('[out 3]'), 'checkpoint restart did not reconstruct the fold: ${out2}'

	// doctor the checkpoint (one fake record at seq 2): the restart shows
	// the DOCTORED state + only the suffix — proof boot seeded from the
	// checkpoint and replayed from seq+1, not from the head.
	pdoc := jb_write(tmp, 'doctor.cx', "[?lib 'cx-stdlib/store' :as store]\n" +
		'[?let [= \$s [\$store:open "${ckpt}"]]\n' +
		'      [= \$h [\$store:put-doc \$s "[checkpoint stream=acts seq=\'2\' [slice bind=\'/guestbook\' {actor: \'u1\', name: \'Zed\'}]]"]]\n' +
		'      [= \$a [\$store:set-alias \$s "xap-checkpoint-demo-acts" \$h]]\n' +
		'  [out \$a]]\n')
	outd := jb_run('--allow-read --allow-write', pdoc)
	assert !outd.contains('err'), 'doctoring the checkpoint failed: ${outd}'
	p3 := jb_write(tmp, 'doctored.cx', jb_component +
		"[?lib 'cx-stdlib/format' :as format]\n" +
		'[?let [= \$rt [\$xap:run {tenant: "demo" journal: ${bind}}]]\n' +
		'  [out [?str \'{[\$count [\$xap:state \$rt "/guestbook"]]}|{[\$format:canonical [\$xap:state \$rt "/guestbook"]]}\']]]\n')
	out3 := jb_run('--allow-read --allow-write', p3)
	assert out3.contains('2|'), 'doctored checkpoint must seed 1 + replay 1 suffix (got: ${out3})'
	assert out3.contains('Zed') && out3.contains('Cyd') && !out3.contains('Ada'), 'suffix replay must start after the checkpoint seq: ${out3}'

	// fail-open: a garbage checkpoint falls back to FULL replay.
	pbad := jb_write(tmp, 'garbage.cx', "[?lib 'cx-stdlib/store' :as store]\n" +
		'[?let [= \$s [\$store:open "${ckpt}"]]\n' +
		'      [= \$h [\$store:put-doc \$s "[not-a-checkpoint]"]]\n' +
		'      [= \$a [\$store:set-alias \$s "xap-checkpoint-demo-acts" \$h]]\n' +
		'  [out \$a]]\n')
	jb_run('--allow-read --allow-write', pbad)
	out4 := jb_run('--allow-read --allow-write', p2)
	assert out4.contains('[out 3]'), 'garbage checkpoint must fall back to full replay: ${out4}'
}
