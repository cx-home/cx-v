module platform
import code {
	caps_set_all,
	render_canonical,
}

import cx
import os

// store_concurrent_writer_test.v — #217/#220 concurrent-writer durability gate.
//
// N spawned threads drive puts through svc_profile_route — the surviving
// daemon data-op core (svc_dispatch_data_op → svc_profile_data_op) — against
// ONE opened store handle, the daemon worker-pool shape. It serializes on the
// handle's op_lock; a backend whose CONSTRUCTOR fails to set op_lock lets puts
// race the flush:
//   - cxpack (#217): manifest D-records referencing objects whose pack segment
//     was never written → cold reopen fails CXER1120, acknowledged docs lost;
//   - sqlite (#220): simultaneous cross-thread use of the shared libsqlite3
//     connection → SIGSEGV/SIGABRT + physical B-tree corruption.
// Exit criterion (W1): no crash, reopen intact, all N docs present.
//
// mem and file-document (flat index) run as controls — their constructors set
// op_lock and always survived the same stress.

const conc_writers = 32

fn conc_doc(i int) string {
	return '[doc [n ${i}] [customer [name "acct-${i}"] [addr [city "NYC"] [zip "1000${i}"]]] [payload "payload-body-${i}-lorem-ipsum-dolor-sit-amet-consectetur"]]'
}

// conc_put stores one doc through the daemon dispatch path; true on a
// [put-result …] response.
fn conc_put(local cx.Node, i int) bool {
	doc := cx.parse(conc_doc(i)) or { return false }
	c := render_canonical(doc.elements[0])
	resp := svc_profile_route(grpc_synth_req('put', '', c, map[string]string{}, '', ''),
		local)
	return svc_response_body(resp).contains('put-result')
}

// conc_run fires conc_writers concurrent puts at one handle; returns the count
// of acknowledged (200 put-result) writes.
fn conc_run(local cx.Node) int {
	mut threads := []thread bool{}
	for i in 0 .. conc_writers {
		threads << spawn conc_put(local, i)
	}
	mut ok := 0
	for t in threads {
		if t.wait() {
			ok++
		}
	}
	return ok
}

// conc_list_count lists docs over the same dispatch path.
fn conc_list_count(local cx.Node) int {
	resp := svc_profile_route(grpc_synth_req('list', '', '', map[string]string{}, '', ''),
		local)
	return svc_response_body(resp).count('[hash ')
}

fn conc_err_of(n cx.Node) string {
	if n is cx.Element {
		if n.name == 'err' {
			for a in n.attrs {
				if a.name == 'message' {
					return cx.scalar_value_str_public(a.value)
				}
			}
			return 'err'
		}
	}
	return ''
}

// conc_stress opens `url` fresh, fires the concurrent burst, then cold-reopens
// and asserts every acknowledged doc is present and intact.
fn conc_stress(url string, tag string) {
	caps_set_all()
	local := store_open_impl(url, '', '', false, true, map[string]string{})
	oe := conc_err_of(local)
	if oe != '' {
		panic('${tag}: open failed: ${oe}')
	}
	acked := conc_run(local)
	assert acked == conc_writers, '${tag}: ${acked}/${conc_writers} puts acknowledged'
	// live view on the same handle
	live := conc_list_count(local)
	assert live == conc_writers, '${tag}: live list sees ${live}/${conc_writers} docs'
	if !url.starts_with('mem://') {
		// cold reopen: a second handle replays the on-disk state from scratch —
		// the #217 corruption signature is a CXER1120 here (or missing docs).
		reopened := store_open_impl(url, '', '', false, true, map[string]string{})
		re := conc_err_of(reopened)
		assert re == '', '${tag}: cold reopen failed: ${re}'
		n := conc_list_count(reopened)
		assert n == conc_writers, '${tag}: cold reopen holds ${n}/${conc_writers} docs (acknowledged writes lost)'
		// every doc reconstructs to its content address (integrity, not just count)
		for i in 0 .. conc_writers {
			doc := cx.parse(conc_doc(i)) or { panic('parse') }
			c := render_canonical(doc.elements[0])
			h := cx.cx_text_hash(c) or { panic('hash') }
			gr := svc_profile_route(grpc_synth_req('get', '', '', {
				'hash': h
			}, '', ''), reopened)
			gb := svc_response_body(gr)
			assert gb.contains('acct-${i}'), '${tag}: doc ${i} (${h}) unreadable after reopen'
		}
	}
}

fn test_concurrent_writers_mem_control() {
	conc_stress('mem://conc-${os.getpid()}', 'mem')
}

fn test_concurrent_writers_file_document_control() {
	root := os.join_path(os.temp_dir(), 'cxstore_conc_doc_${os.getpid()}')
	os.rmdir_all(root) or {}
	defer {
		os.rmdir_all(root) or {}
	}
	conc_stress('document+file://${root}', 'file-document')
}

fn test_concurrent_writers_cxpack() {
	root := os.join_path(os.temp_dir(), 'cxstore_conc_pack_${os.getpid()}')
	os.rmdir_all(root) or {}
	defer {
		os.rmdir_all(root) or {}
	}
	conc_stress('file://${root}', 'cxpack')
}

// ── #218: conditional refs-set (CAS) — racing advance, exactly one winner ─────

// conc_resp_status extracts the HTTP status from a sw_resp node.
fn conc_resp_status(n cx.Node) int {
	if n is cx.Element {
		for a in n.attrs {
			if a.name == 'status' {
				return cx.scalar_value_str_public(a.value).int()
			}
		}
	}
	return 0
}

// conc_refs_set_cas fires a conditional refs-set (expect="" ⇒ ref must not
// exist) through the daemon dispatch path; returns the HTTP status.
fn conc_refs_set_cas(local cx.Node, key string, root string) int {
	resp := svc_profile_route(grpc_synth_req('refs-set', '',
		'[refs-set [r key="${key}" root="${root}" expect=""]]', map[string]string{}, '',
		''), local)
	return conc_resp_status(resp)
}

fn test_racing_conditional_refs_set_exactly_one_wins() {
	caps_set_all()
	local := store_open_impl('mem://conc-cas-${os.getpid()}', '', '', false, true,
		map[string]string{})
	key := 'refs/heads/main'
	// two distinct 32-byte roots (hex)
	ra := 'aa'.repeat(32)
	rb := 'bb'.repeat(32)
	mut threads := []thread int{}
	threads << spawn conc_refs_set_cas(local, key, ra)
	threads << spawn conc_refs_set_cas(local, key, rb)
	mut statuses := []int{}
	for t in threads {
		statuses << t.wait()
	}
	statuses.sort()
	assert statuses == [200, 409], 'racing conditional refs-set must yield exactly one 200 and one 409, got ${statuses}'

	// the loser's retry WITH the winner's value as expect succeeds (the CAS loop)
	resp := svc_profile_route(grpc_synth_req('refs', '', '[refs [k key="${key}"]]',
		map[string]string{}, '', ''), local)
	body := svc_response_body(resp)
	cur := if body.contains(ra) { ra } else { rb }
	rc := 'cc'.repeat(32)
	retry := svc_profile_route(grpc_synth_req('refs-set', '',
		'[refs-set [r key="${key}" root="${rc}" expect="${cur}"]]', map[string]string{},
		'', ''), local)
	assert conc_resp_status(retry) == 200, 'CAS retry with the current value must succeed'

	// a stale expect is rejected without applying
	rd := 'dd'.repeat(32)
	stale := svc_profile_route(grpc_synth_req('refs-set', '',
		'[refs-set [r key="${key}" root="${rd}" expect="${cur}"]]', map[string]string{},
		'', ''), local)
	assert conc_resp_status(stale) == 409, 'stale expect must 409'
}

// #220 — gated like the backend itself; without -d cxstore_sqlite this is a
// compile-time no-op. Run via `make test-vcx-sqlite`.
fn test_concurrent_writers_sqlite() {
	$if cxstore_sqlite ? {
		path := os.join_path(os.temp_dir(), 'cxstore_conc_sqlite_${os.getpid()}.db')
		os.rm(path) or {}
		defer {
			os.rm(path) or {}
		}
		conc_stress('sqlite://${path}', 'sqlite')
	}
}
