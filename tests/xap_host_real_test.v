module main

import os
import testenv
import time
import net.http

// xap_host_real_test.v — BEHAVIORAL proof of the distribution spec's §6.3
// deployment host (§11.18): a toy XAP — a deployment doc + two published
// feature packages, with ZERO XAP-specific server code — boots through
// [$xap:host] alone and serves the standard surface.
//
//   door  — carries its §1.2 contract module (readout + apply), a
//           non-observe verb (unlock, act) granted to=resident, exports
//           declared (the contract gate runs at the host's verify).
//   porch — spec-only (no code entry): composes, surfaces an empty readout.
//
// Checks over a real loopback socket:
//   GET  /grammar             → the composed projection (bare-terms table)
//   GET  /features            → both pins
//   GET  /surface/door        → the contract readout ran (its marker shows)
//   POST /intent unlock@resident → ack ok=true + apply ran (readout mutates)
//   POST /intent unlock@guest    → ack ok=false (the PEP denied — no dial)
//   POST /intent frobnicate      → ack ok=false reason=unknown-verb
//   GET  /whoami (adapter route) → the OPTS routes closure answered
//
// Black-box like module_pkg_loader_test.v: publish + host are cx programs
// run by the real binary; the registry binding is CX_REGISTRY.

fn xh_cx_binary() string {
	return testenv.cx_bin()
}

// Disjoint port band (26800-26899) from http (26400) / csrp (26600) / wire (26700).
fn xh_pick_port() int {
	salt := (u64(os.getpid()) * u64(2654435761) + u64(time.now().unix_nano())) % 100
	return 26800 + int(salt)
}

fn xh_write(dir string, name string, content string) string {
	p := os.join_path(dir, name)
	os.write_file(p, content) or { panic('write ${p}: ${err}') }
	return p
}

const xh_door_spec = "[feature name=door version=1.0.0
 [nouns [noun name=door singular=true [field name=locked type=int]]]
 [verbs
  [verb name=read-door effect=observe scope=local consequence=none [intent [do :read-door]] [reads door]]
  [verb name=unlock effect=act scope=shared consequence=reversible [intent [do :unlock]] [writes door]]]
 [governance [grant verb=read-door to=any] [grant verb=unlock to=resident]]
 [requirements
  [requirement kind=functional as=resident traces=read-door [want 'to see the door'] [so 'I know its state']]
  [requirement kind=functional as=resident traces=unlock [want 'to unlock the door'] [so 'guests can enter']]]]"

const xh_porch_spec = "[feature name=porch version=1.0.0
 [nouns [noun name=porch singular=true [field name=lit type=int]]]
 [verbs [verb name=read-porch effect=observe scope=local consequence=none [intent [do :read-porch]] [reads porch]]]
 [governance [grant verb=read-porch to=any]]
 [requirements [requirement kind=functional as=resident traces=read-porch [want 'to see the porch'] [so 'arrival is visible']]]]"

// the door contract module: readout reflects an unlock counter kept in the
// working store (alias door-count); apply bumps it. Both scope=public.
const xh_door_code = "[?lib 'cx-stdlib/store' :as store]
[?lib 'cx-stdlib/strings' :as s]
[?def readout scope=public impure (\$store \$t)
  [?let [= \$h [\$store:get-alias \$store 'door-count']]
   [= \$n [?else [\$store:get-doc \$store \$h] '0']]
   [?element 'readout' [?attr 'feature' 'door'] [?attr 'unlocks' [\$concat '' \$n]]]]]
[?def apply scope=public impure (\$verb \$intent \$store)
  [?let [= \$jam [\$s:join [?for [in \$i \$intent//intent] [yield [?else \$i/@jam '']]] '']]
  [?if [= \$jam 'true']
   [then [?element 'err' [?attr 'code' 'cx-err:CXER0100'] [?attr 'message' 'E_DOOR_JAMMED']]]
   [else
  [?let [= \$stuck [\$s:join [?for [in \$i \$intent//intent] [yield [?else \$i/@stuck '']]] '']]
   [?if [= \$stuck 'true']
    [then [?element 'refused' [?attr 'reason' 'door-stuck']]]
    [else
     [?let [= \$h [?else [\$store:get-alias \$store 'door-count'] '']]
      [= \$n [?if [= \$h ''] [then 0] [else [\$cast [\$concat '' [\$store:get-doc \$store \$h]] 'int']]]]
      [= \$nh [\$store:put-doc \$store [\$concat '' [+ \$n 1]]]]
      [= \$a [\$store:set-alias \$store 'door-count' \$nh]]
      \$verb]]]]]]]]"

fn xh_publish_prog(reg_dir string) string {
	return "[?lib 'cx-xap' :as xap]\n[?lib 'cx-stdlib/store' :as store]\n" +
		"[?lib 'cx-stdlib/crypto' :as crypto]\n[?lib 'cx-stdlib/did' :as did]\n" +
		"[?lib 'cx-stdlib/io' :as io]\n" +
		'[?let [= \$s [\$store:open "file://${reg_dir}"]]\n' +
		'[?let [= \$kp [\$crypto:ed25519-keypair]]\n' +
		'[?let [= \$pub [\$did:key-create \$kp@public]]\n' +
		'[?let [= \$dspec [\$io:read-file "${reg_dir}/../door.feature.cxd"]]\n' +
		'[?let [= \$dcode [\$io:read-file "${reg_dir}/../door.cx"]]\n' +
		'[?let [= \$pspec [\$io:read-file "${reg_dir}/../porch.feature.cxd"]]\n' +
		'[?let [= \$t1 [\$xap:pkg-tree ([?element "entry" [?attr "path" "door.feature.cxd"] \$dspec], [?element "entry" [?attr "path" "door.cx"] \$dcode])]]\n' +
		'[?let [= \$d1 [?element "package" [?attr "name" "door"] [?attr "version" "1.0.0"] [?attr "kind" "feature"]\n' +
		'               [?element "publisher" [?attr "did" \$pub]]\n' +
		'               [?element "exports" [?element "def" [?attr "name" "door/readout"]] [?element "def" [?attr "name" "door/apply"]]]]]\n' +
		'[?let [= \$s1 [\$xap:pkg-seal \$s \$t1 \$d1]]\n' +
		'[?let [= \$m1 [\$store:put-doc \$s [\$xap:pkg-sign [\$store:get-doc \$s \$s1@manifest] \$kp@private]]]\n' +
		'[?let [= \$p1 [\$xap:pkg-publish \$s "door" "1.0.0" \$m1]]\n' +
		'[?let [= \$t2 [\$xap:pkg-tree ([?element "entry" [?attr "path" "porch.feature.cxd"] \$pspec])]]\n' +
		'[?let [= \$d2 [?element "package" [?attr "name" "porch"] [?attr "version" "1.0.0"] [?attr "kind" "feature"]\n' +
		'               [?element "publisher" [?attr "did" \$pub]]]]\n' +
		'[?let [= \$s2 [\$xap:pkg-seal \$s \$t2 \$d2]]\n' +
		'[?let [= \$m2 [\$store:put-doc \$s [\$xap:pkg-sign [\$store:get-doc \$s \$s2@manifest] \$kp@private]]]\n' +
		'[?let [= \$p2 [\$xap:pkg-publish \$s "porch" "1.0.0" \$m2]]\n' +
		'[\$concat \$m1 " " \$s1@hash " " \$m2 " " \$s2@hash]]]]]]]]]]]]]]]]]\n'
}

fn xh_host_prog(port int, xap_path string) string {
	// the toy deployment: ZERO XAP-specific server code — the doc, the host
	// call, one adapter route (the deployment-specific bit, an OPTS closure).
	return "[?lib 'cx-xap' :as xap]\n[?lib 'cx-stdlib/store' :as store]\n" +
		"[?lib 'cx-stdlib/io' :as io]\n" +
		'[?let [= \$xdoc [\$cx:parse [\$io:read-file "${xap_path}"]]]\n' +
		'[?let [= \$x [\$first [?for [in \$e \$xdoc//xap] [yield \$e]]]]\n' +
		'[?let [= \$ws [\$store:open "mem://"]]\n' +
		'[\$xap:host \$x {url: "http://127.0.0.1:${port}" store: \$ws\n' +
		'  routes: {whoami: [?fn (\$req) [response status=200 [headers [header name="content-type" value="text/plain"]] [body "toy-xap"]]]\n' +
		'           "echo/": [?fn (\$req) [?let [= \$p [\$concat "" \$req/@path]] [response status=200 [headers [header name="content-type" value="text/plain"]] [body \$p]]]]\n' +
		'           features: [?fn (\$req) [response status=200 [headers [header name="content-type" value="application/cx"]] [body "[features [feature name=door title=\\"The Door\\"] [feature name=porch title=\\"The Porch\\"]]"]]]}}]]]]\n'
}

fn xh_get(port int, path string) string {
	resp := http.get('http://127.0.0.1:${port}${path}') or { return 'GET-FAILED: ${err}' }
	return resp.body
}

fn xh_post_intent(port int, intent string) string {
	resp := http.post('http://127.0.0.1:${port}/intent', intent) or {
		return 'POST-FAILED: ${err}'
	}
	return resp.body
}

fn test_xap_host_boots_a_toy_xap_from_packages() {
	cxbin := xh_cx_binary()
	port := xh_pick_port()
	tmp := os.join_path(os.temp_dir(), 'cx-xap-host-test-${os.getpid()}')
	os.rmdir_all(tmp) or {}
	os.mkdir_all(tmp) or { panic('mkdir ${tmp}: ${err}') }
	defer {
		os.rmdir_all(tmp) or {}
	}
	reg := os.join_path(tmp, 'registry')
	os.mkdir_all(reg) or { panic('mkdir ${reg}: ${err}') }
	xh_write(tmp, 'door.feature.cxd', xh_door_spec)
	xh_write(tmp, 'door.cx', xh_door_code)
	xh_write(tmp, 'porch.feature.cxd', xh_porch_spec)

	// publish both features.
	pub_prog := xh_write(tmp, 'publish.cx', xh_publish_prog(reg))
	pres := os.execute('${cxbin} --allow-read --allow-write --allow-random ${pub_prog}')
	if pres.exit_code != 0 {
		panic('publish failed (${pres.exit_code}): ${pres.output}')
	}
	parts := pres.output.trim_space().trim("'").split(' ')
	if parts.len != 4 {
		panic('unexpected publish output: ${pres.output}')
	}
	door_m, door_t, porch_m, porch_t := parts[0], parts[1], parts[2], parts[3]

	// the deployment doc: fully pinned rows + the roles ladder.
	xap_doc := '[xap name=toy
  [roles [role name=resident rank=1] [role name=guest rank=0]]
  [features
    [feature name=door version=1.0.0 manifest=${door_m} hash=${door_t}]
    [feature name=porch version=1.0.0 manifest=${porch_m} hash=${porch_t}]]]'
	xap_path := xh_write(tmp, 'toy.xap.cxd', xap_doc)

	// boot the host as a real subprocess (CX_REGISTRY bound; loopback only).
	host_prog := xh_write(tmp, 'host.cx', xh_host_prog(port, xap_path))
	os.setenv('CX_REGISTRY', 'file://${reg}', true)
	mut proc := os.new_process(cxbin)
	proc.set_args(['--allow-read', '--allow-write', '--allow-net=127.0.0.1:${port}',
		'--allow-env', host_prog])
	proc.set_redirect_stdio()
	proc.run()
	defer {
		proc.signal_kill()
		os.unsetenv('CX_REGISTRY')
	}
	// wait for the listener.
	mut up := false
	for _ in 0 .. 100 {
		time.sleep(100 * time.millisecond)
		g := xh_get(port, '/grammar')
		if g.contains('bare-terms') {
			up = true
			break
		}
	}
	if !up {
		out := proc.stdout_slurp() + proc.stderr_slurp()
		panic('host never came up: ${out}')
	}

	// standard surface.
	gram := xh_get(port, '/grammar')
	assert gram.contains('door/unlock'), 'grammar missing qualified verb: ${gram}'
	// /features is OVERRIDDEN by the deployment's adapter route (adapter
	// routes are consulted before the standard surface — §6.3 extend).
	feats := xh_get(port, '/features')
	assert feats.contains('name=door') && feats.contains('The Door'), 'features (adapter-enriched): ${feats}'
	ro0 := xh_get(port, '/surface/door')
	assert ro0.contains('unlocks'), 'door readout did not run: ${ro0}'
	assert ro0.contains("'0'") || ro0.contains('unlocks=0'), 'door readout initial: ${ro0}'
	rop := xh_get(port, '/surface/porch')
	assert rop.contains('readout'), 'porch (spec-only) surface: ${rop}'

	// admitted act: resident unlocks — ack ok + the contract apply mutates state.
	a1 := xh_post_intent(port, '[intent verb="unlock" author="dana" role="resident"]')
	assert a1.contains('ok=true'), 'resident unlock refused: ${a1}'
	assert a1.contains('door/unlock'), 'ack not qualified: ${a1}'
	ro1 := xh_get(port, '/surface/door')
	assert ro1.contains("'1'") || ro1.contains('unlocks=1'), 'apply did not run: ${ro1}'

	// denied act: guest holds no unlock dial — the PEP refuses.
	a2 := xh_post_intent(port, '[intent verb="unlock" author="gus" role="guest"]')
	assert a2.contains('ok=false'), 'guest unlock admitted: ${a2}'
	ro2 := xh_get(port, '/surface/door')
	assert ro2.contains("'1'") || ro2.contains('unlocks=1'), 'denied act mutated state: ${ro2}'

	// unknown verb: rho refuses by name.
	a3 := xh_post_intent(port, '[intent verb="frobnicate" author="dana" role="resident"]')
	assert a3.contains('ok=false') && a3.contains('unknown-verb'), 'unknown verb: ${a3}'

	// apply-refusal: the PEP admits the verb, the feature refuses the VALUES —
	// ok=false with the feature's reason, and no state change.
	a4 := xh_post_intent(port, '[intent verb="unlock" author="dana" role="resident" stuck="true"]')
	assert a4.contains('ok=false') && a4.contains('door-stuck'), 'apply refusal: ${a4}'

	// an err VALUE returned by apply must fail the ack (error-as-value: the
	// or {} on invoke_closure catches raises only) — and mutate nothing.
	a5 := xh_post_intent(port, '[intent verb="unlock" author="dana" role="resident" jam="true"]')
	assert a5.contains('ok=false') && a5.contains('apply-error'), 'apply err value swallowed: ${a5}'
	assert a5.contains('E_DOOR_JAMMED'), 'apply err detail missing: ${a5}'
	ro4 := xh_get(port, '/surface/door')
	assert ro4.contains("'1'") || ro4.contains('unlocks=1'), 'errored apply mutated state: ${ro4}'
	ro3 := xh_get(port, '/surface/door')
	assert ro3.contains("'1'") || ro3.contains('unlocks=1'), 'refused apply mutated state: ${ro3}'

	// adapter route: the deployment's OPTS closure answers.
	who := xh_get(port, '/whoami')
	assert who.contains('toy-xap'), 'adapter route: ${who}'

	// prefix adapter route ('echo/' key): matches /echo/<anything>.
	ec := xh_get(port, '/echo/abc')
	assert ec.contains('/echo/abc'), 'prefix adapter route: ${ec}'
}
