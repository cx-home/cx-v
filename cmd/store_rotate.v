module main

import code
import cx
import os

// `cx store-rotate-kek --url <store-url> --encrypt-key-id <old> --new-key-id <new>`
// — the operator KEK-rotation verb (#287 / store.md §9.1). Opens the encrypted
// store under its CURRENT key-id, re-wraps every at-rest envelope's data key
// under the new tenant key (payloads and content addresses untouched, atomic
// per object, resumable, fail-closed), and prints the [rotation-report …].
// Both `CX_STORE_KEK_<old>` and `CX_STORE_KEK_<new>` must be set; once the
// report shows every object current under the new key, the old KEK can be
// destroyed.

fn run_store_rotate_kek(args []string) {
	mut url := ''
	mut old_id := ''
	mut new_id := ''
	mut i := 0
	for i < args.len {
		a := args[i]
		if a.starts_with('--url=') {
			url = a['--url='.len..]
			i++
			continue
		}
		if a == '--url' && i + 1 < args.len {
			url = args[i + 1]
			i += 2
			continue
		}
		if a.starts_with('--encrypt-key-id=') {
			old_id = a['--encrypt-key-id='.len..]
			i++
			continue
		}
		if a == '--encrypt-key-id' && i + 1 < args.len {
			old_id = args[i + 1]
			i += 2
			continue
		}
		if a.starts_with('--new-key-id=') {
			new_id = a['--new-key-id='.len..]
			i++
			continue
		}
		if a == '--new-key-id' && i + 1 < args.len {
			new_id = args[i + 1]
			i += 2
			continue
		}
		eprintln('cx store-rotate-kek: unknown arg "${a}"')
		eprintln('usage: cx store-rotate-kek --url <store-url> --encrypt-key-id <old> --new-key-id <new>')
		exit(2)
	}
	if url == '' || old_id == '' || new_id == '' {
		eprintln('cx store-rotate-kek: --url, --encrypt-key-id and --new-key-id are all required')
		eprintln('usage: cx store-rotate-kek --url <store-url> --encrypt-key-id <old> --new-key-id <new>')
		exit(2)
	}
	// Fail fast on the env keys BEFORE opening anything — both must be present
	// for a rotation to be able to read old envelopes and write new ones.
	for id in [old_id, new_id] {
		if os.getenv('CX_STORE_KEK_${id}') == '' {
			eprintln('cx store-rotate-kek: env CX_STORE_KEK_${id} is not set (64 hex chars = 32-byte KEK)')
			exit(1)
		}
	}
	// Capabilities — the verb's whole purpose is store mutation: read+write for
	// the local substrates, net for s3 (deny-by-default otherwise, security.md §3).
	mut caps := ['read', 'write']
	if url.starts_with('s3://') {
		caps << 'net'
	}
	code.caps_set_list(caps)
	r := code.svc_rotate_kek(url, old_id, new_id)
	if code.svc_is_err(r) {
		eprintln('cx store-rotate-kek: ${code.svc_err_text(r)}')
		exit(1)
	}
	println(code.render_canonical(r))
	if r is cx.Element {
		objs := r.attr('objects')
		rew := r.attr('rewrapped')
		eprintln('cx store-rotate-kek: ${objs} object(s) now under `${new_id}` (${rew} re-wrapped) — verify reads, then destroy the old KEK `${old_id}`.')
	}
}
