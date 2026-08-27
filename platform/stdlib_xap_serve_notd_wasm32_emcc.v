@[has_globals]
module platform
import code {
	Closure,
	MatchEnv,
	ProgramState,
	Scope,
	cap_guard,
	is_err_value,
	iterate,
	mk_err,
	render_canonical,
}

// stdlib_xap_serve_notd_wasm32_emcc.v — the cx-xap web bridge (`[$xap:serve]`).
//
// XAP opens NO socket of its own (xap.md §9): it bootstraps the surface onto
// the core picoev/picohttpparser engine that also backs cx-stdlib/http. This
// file is the `.xap` listener mode — the request is dispatched against the
// runtime entirely in V (no CX handler closure), content-negotiated to
// text/html for the web client. It compiles only on the native build (the
// `_notd_wasm32_emcc` suffix excludes it from the emscripten target, mirroring
// services_listener_notd_wasm32_emcc.v, since picoev/net are not linked there).
//
// Routes (the medium-specific shell; the surface itself is medium-agnostic):
//   GET  /                    → the document shell with every `{{surface:NAME}}`
//                               mount spliced (#567 — any declared surface, any
//                               mount tag/id; unknown surface refuses loudly).
//   GET  /surface             → the SAME surface, application/cx (agent parity).
//   GET  /events              → §24 SSE feed (held-open, event-driven push).
//   GET  /static/<f>          → a static asset from <shell>/static/.
//   GET  /<bind>              → the panel FRAGMENT of the component bound to
//                               /<bind> (RULED: ATC-2 — the answering route
//                               for the client layer's per-pane hx-get
//                               cadence); unknown bind = 404.
//   GET  /<bind>/<key>        → #578 detail route: the component bound to
//                               /<bind>, its view over the id=<key> record
//                               slice; unmatched key / unknown bind = 404.
//   GET  /surface/<bind>/<key>→ the detail view-tree, application/cx.
//   POST /intent/<verb>       → the cascade for any DECLARED verb (#570 —
//                               grammar slots from the form; undeclared = 403);
//                               answers the panel fragment (htmx swap), or the
//                               re-rendered DETAIL panel when the form carries
//                               the reserved `_detail` return context (#578).

import cx
import os
import time
import transport.picoev
import sync

// ── §24: SSE subscriber registry (held-open event feeds per runtime) ─────────
//
// GET /events promotes the connection to an SSE feed: listener_callback holds
// the fd (picoev.cx_hold_fd), then registers it here while writing the prelude —
// atomically under this lock, so the prelude/initial frame is a readiness ack
// (see xap_sse_subscribe). On a state change (POST /intent/sign), xap_sse_push
// writes a surface frame to every
// subscriber fd — event-driven push, no reactor blocked. Cleanup is synchronous:
// picoev's close_conn invokes xap_sse_on_close_fd (registered via
// cx_set_sse_on_close) under this lock BEFORE the socket closes, so a push from
// another reactor never writes to a reused fd.
//
// #303: the lock is REFERENCE-typed, initialized in the module init()
// (stdlib_codec.v) — a VALUE-typed zeroed sync.Mutex global is a silently
// non-locking pthread mutex on Darwin; see cx_sse_topic_lock for the full
// mechanism (identical defect, identical barrier).
__global (
	xap_sse_subs map[int][]int
	xap_sse_lock &sync.Mutex
	// #594 render cache: rt_id → key → rendered string, valid for exactly
	// one rt.commit_seq (xap_render_cache_seq). Cached entries are the
	// O(state) view evaluations (per-panel inner HTML, the canonical
	// surface, the self-contained fallback page); layout.html is still
	// read per request (shell hot-reload preserved), and keyed/detail
	// renders are record-scoped and not cached.
	xap_render_cache     map[int]map[string]string
	xap_render_cache_seq map[int]u64
	xap_render_lock      &sync.Mutex
	// #594 push coalescer: leading-edge push when the min interval has
	// elapsed, else ONE trailing renderer per runtime that fires at the
	// window edge over the then-current state.
	xap_push_last    map[int]i64
	xap_push_waiting map[int]bool
	xap_push_lock    &sync.Mutex
	// #609 changed-panel SSE: fds that opted into delta frames
	// (GET /events?delta=1) and each fd's high-water commit_seq. Guarded by
	// xap_sse_lock with the subscriber set.
	xap_sse_delta map[int]bool
	xap_sse_fdseq map[int]u64
	// #994 host-boot ordering: pumps whose §3.1.2 subscription is OPEN (so a
	// bad binding still refuses at run assembly) but which have not been
	// ARMED — they must not consume until the composing layer has finished
	// wiring the runtime's authority. rt_id → the held pumps; the entry is
	// removed by xap_arm_source_pumps (spawn them) or by
	// xap_abandon_source_pumps (never spawn them).
	xap_pending_pumps map[int][]XapSourcePump
	xap_pump_lock     &sync.Mutex
	// SSE-1 (xsp.md §4.1): fds that negotiated the XSP-envelope carriage
	// (GET /events?envelope=xsp, GET /stream?envelope=xsp) — each frame's
	// data: field is base64(XSP event frame) carrying byte-for-byte the text
	// the plain lane delivers. Guarded by xap_sse_lock with the subscriber set.
	xap_sse_xsp map[int]bool
)

// xap_push_min_interval_ns is the #594 coalescing window: commit bursts
// within it collapse to one leading + one trailing SSE render. Small enough
// to be invisible to a human or an agent poll loop; large enough to bound
// render work to ~40/s per runtime under any burst.
const xap_push_min_interval_ns = i64(25_000_000)

// xap_render_cached returns the cached render for (rt, key) when the cache
// still reflects rt.commit_seq.
fn xap_render_cached(rt &XapRuntime, key string) ?string {
	xap_render_lock.lock()
	defer {
		xap_render_lock.unlock()
	}
	if (xap_render_cache_seq[rt.id] or { u64(0) }) != rt.commit_seq {
		return none
	}
	if rt.id in xap_render_cache {
		if key in xap_render_cache[rt.id] {
			return xap_render_cache[rt.id][key]
		}
	}
	return none
}

// xap_render_store caches `val` for (rt, key) as of `seq` — the seq is
// captured BEFORE the render, so a commit that landed mid-render simply
// drops the store (the next request re-renders at the new seq; never a
// stale value labeled fresh).
fn xap_render_store(rt &XapRuntime, seq u64, key string, val string) {
	xap_render_lock.lock()
	defer {
		xap_render_lock.unlock()
	}
	if rt.commit_seq != seq {
		return
	}
	if (xap_render_cache_seq[rt.id] or { u64(0) }) != seq {
		xap_render_cache[rt.id] = map[string]string{}
		xap_render_cache_seq[rt.id] = seq
	}
	xap_render_cache[rt.id][key] = val
}

// xap_sse_subscribe writes the SSE prelude + initial frame (`ack`) to a held fd
// and adds the fd to `rt_id`'s subscriber set — atomically, under the registry
// lock, so the ack is a readiness barrier: a concurrent xap_sse_push either
// snapshots before this fd exists (and the client cannot yet have read its ack)
// or snapshots after (and its frame follows the fully-written prelude on the
// wire). Same barrier as cx_sse_topic_subscribe — see that fn for the full
// ordering argument.
fn xap_sse_subscribe(rt_id int, fd int, ack string, delta bool, seq u64, xsp bool) {
	xap_sse_lock.lock()
	send_all(fd, ack)
	xap_sse_subs[rt_id] << fd
	if delta {
		// #609: the initial frame (in `ack`) IS the resync; from here this
		// fd receives only changed panels past its high-water mark.
		xap_sse_delta[fd] = true
		xap_sse_fdseq[fd] = seq
	}
	if xsp {
		// SSE-1: this fd negotiated the XSP-envelope carriage.
		xap_sse_xsp[fd] = true
	}
	xap_sse_lock.unlock()
}

// xap_sse_on_close_fd drops `fd` from every runtime's subscriber set. Invoked by
// picoev's close_conn (held-fd close) and by xap_sse_push on a write failure;
// idempotent.
fn xap_sse_on_close_fd(fd int) {
	xap_sse_lock.lock()
	xap_sse_delta.delete(fd)
	xap_sse_fdseq.delete(fd)
	xap_sse_xsp.delete(fd)
	for rt_id, fds in xap_sse_subs {
		mut kept := []int{}
		for f in fds {
			if f != fd {
				kept << f
			}
		}
		xap_sse_subs[rt_id] = kept
	}
	xap_sse_lock.unlock()
}

// xap_sse_push writes one event to every subscriber of `rt_id` in each fd's
// negotiated carriage (SSE-1): `plain` to plain subscribers, `xsp` (the
// base64-XSP-envelope rendering of the SAME event) to XSP-envelope
// subscribers. A fd whose write fails (disconnected) is dropped from the set
// (picoev closes the socket itself on the disconnect read event).
fn xap_sse_push(rt_id int, plain string, xsp string) {
	xap_sse_lock.lock()
	fds := (xap_sse_subs[rt_id] or { []int{} }).clone()
	mut plain_fds := []int{}
	mut xsp_fds := []int{}
	for fd in fds {
		if xap_sse_xsp[fd] or { false } {
			xsp_fds << fd
		} else {
			plain_fds << fd
		}
	}
	xap_sse_lock.unlock()
	if plain_fds.len > 0 {
		xap_sse_write_fds(plain_fds, plain)
	}
	if xsp_fds.len > 0 && xsp != '' {
		xap_sse_write_fds(xsp_fds, xsp)
	}
}

// xap_sse_write_fds writes one frame to a set of held fds, dropping the
// disconnected.
fn xap_sse_write_fds(fds []int, frame string) {
	mut dead := []int{}
	for fd in fds {
		if !write_all_fd(fd, frame) {
			dead << fd
		}
	}
	for fd in dead {
		xap_sse_on_close_fd(fd)
	}
}

// xap_ckpt_persist_dispatch runs a checkpoint persist OFF the commit path
// (#604) — the committing emit never pays the serialize/store cost.
fn xap_ckpt_persist_dispatch(snap XapCkptSnap) {
	spawn xap_ckpt_persist_run(snap)
}

// xap_sse_has_subs reports whether any /events reader is held open for the
// runtime — the §3.1.2 push seam renders the surface only when someone is
// actually listening.
fn xap_sse_has_subs(rt_id int) bool {
	xap_sse_lock.lock()
	n := (xap_sse_subs[rt_id] or { []int{} }).len
	xap_sse_lock.unlock()
	return n > 0
}

// xap_surface_cx_cached is the cache-aware canonical surface render (#594):
// one O(state) view evaluation per commit_seq, shared by GET /surface, the
// SSE initial frame, and every push. A failing view (err surface) is never
// cached — the 500 path stays simple and re-diagnoses per request.
fn xap_surface_cx_cached(rt &XapRuntime, mut env MatchEnv) (string, bool) {
	if s := xap_render_cached(rt, 'surface-cx') {
		return s, false
	}
	seq := rt.commit_seq
	sn := xap_runtime_surface(rt, mut env)
	body := render_canonical(sn) + '\n'
	if sn is cx.Element && is_err_value(sn) {
		return body, true
	}
	xap_render_store(rt, seq, 'surface-cx', body)
	return body, false
}

// xap_push_now renders (through the cache) and pushes to every held
// /events subscriber — full surface frames to plain subscribers, and (#609)
// changed-panel [surface-delta …] frames to delta subscribers, each against
// its own high-water commit_seq.
fn xap_push_now(rt_id int, mut env MatchEnv) {
	reg := xap_reg()
	rt := reg.runtimes[rt_id] or { return }
	xap_sse_lock.lock()
	fds := (xap_sse_subs[rt_id] or { []int{} }).clone()
	mut full_fds := []int{}
	mut full_xsp_fds := []int{}
	mut delta_fds := []int{}
	mut delta_since := []u64{}
	mut delta_xsp := []bool{}
	for fd in fds {
		is_xsp := xap_sse_xsp[fd] or { false }
		if xap_sse_delta[fd] or { false } {
			delta_fds << fd
			delta_since << (xap_sse_fdseq[fd] or { u64(0) })
			delta_xsp << is_xsp
		} else if is_xsp {
			full_xsp_fds << fd
		} else {
			full_fds << fd
		}
	}
	xap_sse_lock.unlock()
	if full_fds.len > 0 || full_xsp_fds.len > 0 {
		body, _ := xap_surface_cx_cached(rt, mut env)
		if full_fds.len > 0 {
			xap_sse_write_fds(full_fds, xap_sse_frame(body))
		}
		if full_xsp_fds.len > 0 {
			// SSE-1: the SAME surface event in the negotiated XSP carriage.
			xap_sse_write_fds(full_xsp_fds, xap_sse_frame_xsp(body))
		}
	}
	now_seq := rt.commit_seq
	for i, fd in delta_fds {
		payload := xap_delta_payload(rt, delta_since[i], mut env) or {
			// nothing this fd hasn't seen — no frame, watermark unchanged.
			continue
		}
		frame := if delta_xsp[i] { xap_sse_frame_xsp(payload) } else { xap_sse_frame(payload) }
		xap_sse_write_fds([fd], frame)
		xap_sse_lock.lock()
		xap_sse_fdseq[fd] = now_seq
		xap_sse_lock.unlock()
	}
}

// xap_delta_payload composes the #609 changed-panel event PAYLOAD for one
// subscriber (the caller wraps it in the subscriber's negotiated SSE
// carriage — SSE-1): every registered component whose bind moved past
// `since` contributes its re-rendered panel (through the #594 per-seq
// cache). Returns none when nothing changed. Failing views are skipped
// here — the full-frame lanes and page requests surface E_XAP_VIEW_FAILED
// loudly (§3.5); a delta frame only ever carries render-able panels.
fn xap_delta_payload(rt &XapRuntime, since u64, mut env MatchEnv) ?string {
	reg := xap_reg()
	mut parts := ''
	mut n := 0
	for _, c in reg.components {
		if !c.has_view || c.bind == '' {
			continue
		}
		bseq := rt.bind_seq[c.bind] or { u64(0) }
		if bseq <= since {
			continue
		}
		key := 'panel-cx:${c.name}'
		body := xap_render_cached(rt, key) or {
			seq := rt.commit_seq
			p := xap_runtime_panel_named(rt, c.name, mut env) or { continue }
			if p is cx.Element && is_err_value(p) {
				continue
			}
			computed := render_canonical(p)
			xap_render_store(rt, seq, key, computed)
			computed
		}
		parts += ' [panel-frame name=${c.name} ' + body + ']'
		n++
	}
	if n == 0 {
		return none
	}
	return '[surface-delta seq=${rt.commit_seq}' + parts + ']\n'
}

// XapPushWaiter carries the listener-style env capture a trailing push
// renders under (#594) — same discipline as XapSourcePump.
struct XapPushWaiter {
	rt_id    int
	delay_ns i64
	bindings map[string]cx.Node
	closures map[string]Closure
	state    &ProgramState = unsafe { nil }
	scope    &Scope        = unsafe { nil }
}

// xap_push_trailing fires ONE render at the coalescing-window edge, over
// whatever state is current THEN — every commit that landed inside the
// window rides this single frame (full-surface frames are snapshots;
// last-write-wins is exactly SSE's contract).
fn xap_push_trailing(w XapPushWaiter) {
	time.sleep(w.delay_ns * time.nanosecond)
	mut env := MatchEnv{
		bindings:        w.bindings
		bindings_shared: true
		closures:        w.closures
		closures_shared: true
		state:           unsafe { w.state }
		scope:           w.scope
	}
	xap_push_lock.lock()
	xap_push_waiting[w.rt_id] = false
	xap_push_last[w.rt_id] = time.sys_mono_now()
	xap_push_lock.unlock()
	xap_push_now(w.rt_id, mut env)
}

// xap_push_live re-renders the runtime's surface and pushes it to every held
// /events subscriber — §3.1.2: live media follow EVERY commit lane (source
// ingest + in-process emit), not only web intents. #594: pushes coalesce —
// leading edge immediately when the min interval has elapsed, else one
// trailing renderer per runtime at the window edge; a burst of N commits
// costs at most two renders per window instead of N.
fn xap_push_live(rt_id int, mut env MatchEnv) {
	if !xap_sse_has_subs(rt_id) {
		return
	}
	now := time.sys_mono_now()
	xap_push_lock.lock()
	last := xap_push_last[rt_id] or { i64(0) }
	if now - last < xap_push_min_interval_ns {
		if xap_push_waiting[rt_id] or { false } {
			// a trailing renderer is already scheduled; it renders the
			// then-current state, which includes this commit.
			xap_push_lock.unlock()
			return
		}
		xap_push_waiting[rt_id] = true
		xap_push_lock.unlock()
		spawn xap_push_trailing(XapPushWaiter{
			rt_id:    rt_id
			delay_ns: xap_push_min_interval_ns - (now - last)
			bindings: env.bindings.clone()
			closures: env.closures.clone()
			state:    unsafe { env.state }
			scope:    env.scope
		})
		return
	}
	xap_push_last[rt_id] = now
	xap_push_lock.unlock()
	xap_push_now(rt_id, mut env)
}

// ── §3.1.2 event-source bindings (#583) ──────────────────────────────────────
//
// The runtime owns each source subscription: group offsets, batched pull
// (backpressure = the pull cadence), ack AFTER fold. Every received entry
// enters the cascade as the mapped verb through the ONE xap_emit_into path —
// PEP, the §3.1.1 durable append when bound, the fold — so panels stay
// folds-of-events with no per-app pump.

struct XapSourcePump {
mut:
	rt_id  int
	sub    cx.Node
	stream string
	verb   string
	actor  string // '' = attribute each entry's proven actor
	remote bool
	// listener-style program-env capture: the §3.1.2 SSE re-render on ingest
	// evaluates views exactly as a request env does.
	bindings map[string]cx.Node
	closures map[string]Closure
	state    &ProgramState = unsafe { nil }
	scope    &Scope        = unsafe { nil }
}

// xap_start_source_pumps resolves each §3.1.2 source-binding map and opens its
// subscription NOW (a bad binding refuses at run, never at first delivery).
// Returns the refusal err VALUE, or none when every binding opened.
//
// #994: opening is NOT consuming. The pump is HELD here and starts at
// xap_arm_source_pumps — the direct `[$xap:run]` lane arms before it returns
// (unchanged behavior), a composing caller arms once it has wired authority.
fn xap_start_source_pumps(rt_id int, sources []cx.Node, tenant string, mut env MatchEnv) ?cx.Node {
	for s in sources {
		if s !is cx.Element || (s as cx.Element).name != '__cx_map__' {
			return mk_err(xap_err_arg_invalid,
				'E_XAP: run {sources: …} takes source-binding maps (xap.md §3.1.2)')
		}
		mut verb := ''
		if vn := xap_map_get_node(s, 'verb') {
			verb = xap_verb_name(vn)
		}
		if verb == '' {
			return mk_err(xap_err_arg_invalid,
				'E_XAP: source binding needs verb: (the cascade verb entries enter as, xap.md §3.1.2)')
		}
		stream := xap_map_get_str(s, 'stream')
		if stream == '' {
			return mk_err(xap_err_arg_invalid, 'E_XAP: source binding needs stream:')
		}
		group := xap_map_get_str(s, 'group')
		if group == '' {
			return mk_err(xap_err_arg_invalid,
				'E_XAP: source binding needs group: — the runtime owns committed offsets (at-least-once, xap.md §3.1.2)')
		}
		fv := xap_map_get_node(s, 'fabric') or {
			return mk_err(xap_err_arg_invalid,
				'E_XAP: source binding needs fabric: (an xsp:// daemon, a journal url, or a [\$fabric:open] handle)')
		}
		mut fab := cx.Node(cx.Element{})
		mut remote := false
		furl := xap_arg_name(fv)
		if furl != '' {
			if furl.starts_with('xsp://') || furl.starts_with('xsps://') {
				f := fabric_stdlib_builtin('fabric-open', [cx.Node(bus_str(furl)), s]) or {
					return mk_err(xap_err_arg_invalid, 'E_XAP: source fabric-open unavailable')
				}
				if is_err_value(f) {
					return mk_err(xap_err_arg_invalid, 'E_XAP: source binding: ${xap_err_message(f)}')
				}
				fab = f
				remote = true
			} else {
				jrn := journal_stdlib_builtin('journal-open', [cx.Node(bus_str(furl)),
					cx.Node(bus_str(tenant))]) or {
					return mk_err(xap_err_arg_invalid, 'E_XAP: source journal-open unavailable')
				}
				if is_err_value(jrn) {
					return mk_err(xap_err_arg_invalid, 'E_XAP: source binding: ${xap_err_message(jrn)}')
				}
				f := fabric_stdlib_builtin('fabric-open', [jrn]) or {
					return mk_err(xap_err_arg_invalid, 'E_XAP: source fabric-open unavailable')
				}
				if is_err_value(f) {
					return mk_err(xap_err_arg_invalid, 'E_XAP: source binding: ${xap_err_message(f)}')
				}
				fab = f
			}
		} else if fv is cx.Element && (fv.name == 'fabric' || fv.name == 'fabric-remote') {
			fab = fv
			remote = fv.name == 'fabric-remote'
		} else {
			return mk_err(xap_err_arg_invalid,
				'E_XAP: source fabric: must be a url or a [\$fabric:open] handle')
		}
		// default pattern = the verb's name as a head-name pattern (the
		// published `[<verb> …]` event shape); set pattern: for anything else.
		pattern := xap_map_get_node(s, 'pattern') or { cx.Node(bus_str(verb)) }
		sub := fabric_stdlib_builtin_env('fabric-subscribe', [fab, cx.Node(bus_str(stream)),
			pattern, xap_map_node(['group'], [cx.Node(bus_str(group))])], mut env) or {
			return mk_err(xap_err_arg_invalid, 'E_XAP: source subscribe unavailable')
		}
		if is_err_value(sub) {
			return mk_err(xap_err_arg_invalid, 'E_XAP: source binding: ${xap_err_message(sub)}')
		}
		p := XapSourcePump{
			rt_id:    rt_id
			sub:      sub
			stream:   stream
			verb:     verb
			actor:    xap_map_get_str(s, 'actor')
			remote:   remote
			bindings: env.bindings.clone()
			closures: env.closures.clone()
			state:    unsafe { env.state }
			scope:    env.scope
		}
		xap_pump_lock.lock()
		// read-modify-write, not `map[k] << v`: appending through a map value
		// that contains pointers refuses under -prod's stricter check (the
		// break hid wherever a worktree without third_party/v/v silently
		// dropped PROD_FLAGS — found by #993's pinned-V build).
		mut held := xap_pending_pumps[rt_id] or { []XapSourcePump{} }
		held << p
		xap_pending_pumps[rt_id] = held
		xap_pump_lock.unlock()
	}
	return none
}

// xap_arm_source_pumps starts every pump held for this runtime (#994). The
// caller is asserting that the runtime's authority is wired: from here on a
// PEP denial on an ingested entry is a real authority decision, not a boot
// race, and §3.1.2's skip-and-ack applies to it.
//
// Idempotent: a second call finds nothing held and spawns nothing.
fn xap_arm_source_pumps(rt_id int) {
	xap_pump_lock.lock()
	held := xap_pending_pumps[rt_id] or { []XapSourcePump{} }
	xap_pending_pumps.delete(rt_id)
	xap_pump_lock.unlock()
	for p in held {
		spawn xap_source_pump_loop(p)
	}
}

// xap_abandon_source_pumps discards the pumps held for a runtime whose boot
// FAILED after run assembly (#994) — the composing layer never reached the
// point where it could honestly say the PEP was wired.
//
// The policy for the boot window is NOT skip-and-ack and NOT an in-pump retry:
// it is "never consumed, and said out loud". Nothing was received, so nothing
// was acked, so the group's committed offset is exactly where the failed boot
// found it and every entry stays redeliverable to the next boot of the same
// group — redelivery by construction, with no way to wedge a live group on a
// permanent denial. The refusal is loud because a binding a deployment
// declared and this process will not serve must never look like a quiet
// no-op (distribution spec §6.3.1).
fn xap_abandon_source_pumps(rt_id int, why string) {
	xap_pump_lock.lock()
	held := xap_pending_pumps[rt_id] or { []XapSourcePump{} }
	xap_pending_pumps.delete(rt_id)
	xap_pump_lock.unlock()
	for p in held {
		eprintln('cx-xap: source binding "${p.stream}" (verb ${p.verb}) never consumed: ${why} — the subscription opened but the runtime\'s authority was never wired, so NOTHING was received and NOTHING was acked; the group\'s entries stay redeliverable to the next boot (#994)')
	}
}

// xap_entry_seq reads an [entry]'s seq attribute as an int (-1 when absent).
fn xap_entry_seq(en cx.Element) i64 {
	s := en.attr('seq')
	if s == '' {
		return -1
	}
	return s.i64()
}

// xap_source_pump_loop is one source's pump: batched receive → each entry
// enters the cascade as the mapped verb → cumulative ack AFTER the batch
// folded → push the re-rendered surface to /events readers. A PEP denial
// (or a §3.1.1 append refusal) skips-and-acks the entry and records a
// [source-denied …] event — deny-by-default never wedges the group, never
// silently (§3.1.2).
fn xap_source_pump_loop(pp XapSourcePump) {
	mut p := pp
	// #762: the module verb is retired — the contract arm is the scan
	// (one turn per batch: max 32 within a 1000ms remote deadline).
	// #596: the embedded tier's receive never blocks, so an idle pump would
	// re-scan its cursor at a fixed cadence forever. Exponential idle
	// backoff (100ms → 1s, reset on any delivery) makes quiet workers
	// near-free; worst added first-event latency after a quiet period is
	// the current backoff (≤1s, bounded). Remote receive blocks server-side
	// up to the deadline and never backs off.
	mut idle_ms := 100
	for {
		mut env := MatchEnv{
			bindings:        p.bindings
			bindings_shared: true
			closures:        p.closures
			closures_shared: true
			state:           unsafe { p.state }
			scope:           p.scope
		}
		batch := fab_sub_contract_receive(p.sub, 32, 1000, mut env)
		if batch is cx.Element && is_err_value(batch) {
			eprintln('cx-xap: source pump "${p.stream}" receive: ${xap_err_message(batch)}')
			time.sleep(1000 * time.millisecond)
			continue
		}
		entries := xap_seq_items(batch)
		if entries.len == 0 {
			if !p.remote {
				time.sleep(idle_ms * time.millisecond)
				if idle_ms < 1000 {
					idle_ms *= 2
				}
			}
			continue
		}
		idle_ms = 100
		reg := xap_reg()
		mut rt := reg.runtimes[p.rt_id] or { return }
		mut last := i64(-1)
		mut folded := false
		// #593: collect the batch's intents FIRST, then commit them through
		// ONE xap_emit_batch_into — on a remote journal binding the durable
		// appends pipeline (~one wire round-trip per batch, not per event).
		mut b_intents := []cx.Node{}
		mut b_optss := []cx.Node{}
		mut b_seqs := []i64{}
		for en in entries {
			if en is cx.Element && en.name == 'entry' {
				seq := xap_entry_seq(en)
				if seq > last {
					last = seq
				}
				mut payload := cx.Node(cx.Element{})
				mut has_payload := false
				for it in en.items {
					if it is cx.Element && it.name == 'event' && it.items.len > 0 {
						payload = it.items[0]
						has_payload = true
						break
					}
				}
				if !has_payload {
					continue
				}
				mut actor := p.actor
				if actor == '' {
					actor = en.attr('actor')
				}
				b_intents << cx.Node(cx.Element{
					name:  'do'
					items: [bus_atom(p.verb), payload]
				})
				b_optss << xap_map_node(['actor'], [cx.Node(bus_str(actor))])
				b_seqs << seq
			}
		}
		if b_intents.len > 0 {
			results := xap_emit_batch_into(mut rt, b_intents, b_optss, mut env)
			for i, res in results {
				if res is cx.Element && is_err_value(res) {
					// #994: a pump only ever runs ARMED, so this denial is a
					// real authority decision over a wired PEP, never the
					// boot race. Skip-and-ack stays — deny-by-default must
					// not wedge the group on a permanent refusal — but it is
					// said OUT LOUD as well as journaled into rt.log: an
					// entry the runtime drops is never silent (§3.1.2).
					eprintln('cx-xap: source pump "${p.stream}" seq ${b_seqs[i]} DENIED, skipped and acked: ${xap_err_message(res)}')
					rt.log << cx.Node(xap_elem('source-denied', [
						xap_attr('stream', p.stream),
						xap_attr('seq', b_seqs[i].str()),
					], [res]))
				} else {
					folded = true
				}
			}
		}
		if last >= 0 {
			fabric_stdlib_builtin('fabric-ack', [p.sub, xap_int_node(last)]) or {
				cx.Node(cx.Element{})
			}
		}
		if folded {
			xap_push_live(p.rt_id, mut env)
		}
	}
}

// xap_sse_frame renders one SSE wire frame carrying the surface value as the
// event `data` (multi-line surface → one `data:` line per LF; the cx sse-events
// client rejoins them). Terminated by the blank-line frame boundary.
fn xap_sse_frame(surface string) string {
	mut sb := []string{}
	for line in surface.trim_right('\n').split('\n') {
		sb << 'data: ${line}'
	}
	return sb.join('\n') + '\n\n'
}

// xap_sse_frame_xsp renders one SSE wire frame in the SSE-1 XSP-envelope
// carriage: `data:` is base64(XSP `event` frame, binary=false) whose payload
// is byte-for-byte the text the plain lane's client reassembles for the same
// event (xap_sse_frame splits on LF; the sse client rejoins with LF — the
// frame carries the joined text). Base64 is a single line, so no splitting.
// The only encode refusal (payload past the frame's 2^32-1 ceiling) degrades
// to a loud SSE comment frame — never a plain frame an XSP client would fail
// to decode as base64.
fn xap_sse_frame_xsp(surface string) string {
	b64 := xsp_sse_data_b64(surface.trim_right('\n')) or {
		eprintln('cx-xap: SSE event exceeds the XSP frame payload ceiling — XSP-envelope frame skipped')
		return ': xsp-envelope-encode-failed\n\n'
	}
	return 'data: ${b64}\n\n'
}

// xap_sse_named_frame_xsp is the named-event twin (the deployment host's
// per-feature `event: <name>` frames): the SSE event NAME stays a plain
// transport-metadata line; only the data carriage changes (SSE-1).
fn xap_sse_named_frame_xsp(fname string, payload string) string {
	b64 := xsp_sse_data_b64(payload.trim_right('\n')) or {
		eprintln('cx-xap: SSE event "${fname}" exceeds the XSP frame payload ceiling — XSP-envelope frame skipped')
		return ': xsp-envelope-encode-failed\n\n'
	}
	return 'event: ${fname}\ndata: ${b64}\n\n'
}

// xap_query_param reads one query parameter from a raw request path
// ('' when absent) — the per-subscription negotiation carrier of the XAP
// feeds (SSE-1: ?envelope=xsp, mirroring §24's ?delta=1 opt-in shape).
fn xap_query_param(raw_path string, key string) string {
	q := raw_path.index('?') or { return '' }
	for pair in raw_path[q + 1..].split('&') {
		if eq := pair.index('=') {
			if xap_urldecode(pair[..eq]) == key {
				return xap_urldecode(pair[eq + 1..])
			}
		}
	}
	return ''
}

// xap_sse_envelope_of resolves a feed request's negotiated carriage:
// (wants_xsp, refusal). A present-but-unknown envelope value refuses loudly
// (400) — a silent plain fallback would hand an XSP-decoding client
// undecodable frames.
fn xap_sse_envelope_of(raw_path string) (bool, string) {
	env := xap_query_param(raw_path, 'envelope')
	if env == '' {
		return false, ''
	}
	if env == 'xsp' {
		return true, ''
	}
	return false, 'unknown feed envelope "${env}" — the v1 web binding negotiates envelope=xsp (xsp.md §4.1)\n'
}

// xap_serve bootstraps a runtime + binds the core http engine to serve it.
// `[$xap:serve url {tenant: … components: (…) surfaces: (…) shell: "<dir>"}]`.
// Blocks (the server runs until the process is signalled), matching a daemon.
// #839 R7.2: per-runtime auth for [$xap:serve {auth: [host-auth …]}] — the
// SAME XSP-AUTH object the deployment host builds, keyed off the runtime id
// (a registry, not an XapRuntime field: XapRuntime compiles on wasm32 and
// XapHostAuth deliberately does not).
__global (
	xap_serve_auths map[int]&XapHostAuth
)

fn xap_serve(args []cx.Node, mut env MatchEnv) ?cx.Node {
	if args.len < 1 {
		return mk_err(xap_err_arg_invalid, 'E_XAP: serve expects (url, opts?)')
	}
	url := xap_arg_name(args[0])
	opts := if args.len > 1 { args[1] } else { xap_elem('__cx_map__', [], []) }
	mut reg := xap_reg()
	// Reuse a pre-seeded runtime when one is handed in (`runtime: $rt`), so a
	// program can `run` + `emit` (seed the journal) and then `serve` the SAME
	// fold (continuity with D2). Otherwise wire a fresh single-tenant runtime.
	mut id := 0
	if rn := xap_map_get_node(opts, 'runtime') {
		if mut existing := xap_runtime_of(rn) {
			id = existing.id
			existing.shell_dir = xap_map_get_str(opts, 'shell')
		}
	}
	if id == 0 {
		reg.next_id = reg.next_id + 1
		id = reg.next_id
		reg.runtimes[id] = &XapRuntime{
			id:        id
			tenant:    xap_map_get_str(opts, 'tenant')
			state:     map[string][]cx.Node{}
			shell_dir: xap_map_get_str(opts, 'shell')
		}
	}
	// #839 R7.2: an `auth: [host-auth …]` opt arms the SAME session/attribution
	// path the deployment host carries — POST /attach is the XSP-AUTH M1–M4
	// handshake, every non-[public] request must carry a verifying §4.8 rule-2
	// possession proof, and the committing actor of an admitted intent is the
	// channel's session principal. Absent ⇒ the wire shape is unchanged and an
	// UNBOUND runtime keeps the documented anonymous-emit back-compat; a
	// journal-BOUND runtime becomes servable because admitted intents now
	// carry a real actor (mode=floor names even the anonymous principal).
	if an := xap_map_get_node(opts, 'auth') {
		if an is cx.Element && an.name == 'host-auth' {
			rtt := reg.runtimes[id] or { return mk_err(xap_err_arg_invalid, 'E_XAP: serve auth: unknown runtime') }
			a := xap_host_auth_build(an, rtt.tenant) or {
				return mk_err(xap_err_arg_invalid, 'E_XAP: serve auth: ${err.msg()}')
			}
			xap_serve_auths[id] = a
		} else {
			return mk_err(xap_err_arg_invalid, 'E_XAP: serve auth: expects a [host-auth …] element')
		}
	}
	// derive the bind host:port (a public http(s) URL → the tcp listener).
	host, port := xap_serve_authority(url)
	if port == 0 {
		return mk_err(xap_err_arg_invalid, 'E_XAP: serve URL needs an explicit port: ${url}')
	}
	// Gate `net` BEFORE binding the socket (§6: serve needs net via http; the
	// sibling http_serve_env guards identically). A denial surfaces the core
	// CXER0271 from the effect point — never remapped, never bypassed.
	if d := cap_guard('net', '${host}:${port}') {
		return d
	}
	// block defaults true (a daemon parks here forever). `block: false` spawns
	// the reactor threads and RETURNS the [xap-server] handle, so one program
	// can serve the web bridge AND keep running (e.g. drive an in-process TUI
	// client over the same runtime) — both share the process-global fold.
	block := xap_map_get_str(opts, 'block') != 'false'
	return start_xap_listener(id, host, port, block, mut env) or {
		return mk_err(xap_err_arg_invalid, 'E_XAP_SERVE_FAILED: ${err.msg()}')
	}
}

// xap_serve_authority extracts (host, port) from a public http(s)/tcp URL.
fn xap_serve_authority(url string) (string, int) {
	mut rest := url
	if i := rest.index('://') {
		rest = rest[i + 3..]
	}
	if sl := rest.index('/') {
		rest = rest[..sl]
	}
	if li := rest.last_index(':') {
		return rest[..li], rest[li + 1..].int()
	}
	return rest, 0
}

// start_xap_listener binds the picoev engine in `.xap` dispatch mode. Shares
// the reactor pool + wire pipeline with the http handler listener.
fn start_xap_listener(rt_id int, host string, port int, block bool, mut env MatchEnv) !cx.Node {
	mut h := &ListenerHandler{
		mode:               .xap
		service_name:       ''
		xap_rt:             rt_id
		enclosing_bindings: env.bindings.clone()
		enclosing_closures: env.closures.clone()
		enclosing_dyn:      env.dyn_context.clone()
		// The program's lexical Scope at serve time — parity with the
		// [$http:serve] start sites, so view/render evaluation resolves
		// scope-registered names exactly as a handler closure does (#585).
		enclosing_scope:    env.scope
		state:              unsafe { env.state }
	}
	// §24: drop a closing SSE fd from the subscriber set synchronously (picoev
	// invokes this just before close_socket, under the same lock pushes take).
	picoev.cx_set_sse_on_close(xap_sse_on_close_fd)
	spawn_shared_reactors(mut h, host, port)!
	bind_host := if host == '' { '0.0.0.0' } else { host }
	// A serving daemon prints nothing on stdout (the program "output" is the
	// HTTP responses); emit a one-line startup banner on stderr so the
	// blocking run is visibly alive rather than a silent hang.
	mut tenant := ''
	if rt := xap_reg().runtimes[rt_id] {
		tenant = rt.tenant
	}
	eprintln('cx-xap: serving tenant "${tenant}" on http://${bind_host}:${port}  (open it in a browser, or curl it; Ctrl-C to stop)')
	if block {
		for {
			time.sleep(time.hour)
		}
	}
	return http_server_handle('tcp://${bind_host}:${port}')
}

// ── request dispatch (text/html) ─────────────────────────────────────────────

fn xap_dispatch_http(rt_id int, method string, raw_path string, body string, xsp_hdrs XspReqHdrs, mut env MatchEnv) WireResp {
	// deployment-host mode (§6.3): a runtime booted by [$xap:host] serves the
	// standard package-driven surface instead of the component demo bridge.
	if mut h := xap_hosts[rt_id] {
		return xap_host_dispatch(mut h, method, raw_path, body, xsp_hdrs, mut env)
	}
	reg := xap_reg()
	mut rt := reg.runtimes[rt_id] or {
		return mk_wire(500, [], 'xap: unknown runtime\n')
	}
	mut path := raw_path
	if q := path.index('?') {
		path = path[..q]
	}
	// #839 R7.2: the host's auth gate, verbatim semantics. POST /attach is the
	// handshake (always open, before every route); every other non-[public]
	// request must carry a verifying possession proof, and the admitted
	// principal is the actor an intent commits under.
	mut auth_principal := ''
	if mut sa := xap_serve_auths[rt_id] {
		if method == 'POST' && path == '/attach' {
			return xap_auth_attach(mut sa, body, xsp_hdrs)
		}
		if !xap_host_auth_public(sa, path) {
			d := xap_auth_admit(mut sa, xsp_hdrs, body)
			if !d.ok {
				return d.resp
			}
			auth_principal = d.principal
		}
	}
	if method == 'GET' && path == '/' {
		page := xap_html_page(mut rt, mut env) or {
			// #567: a shell mount naming an unknown surface (or a malformed
			// placeholder) refuses the page LOUDLY — never serves the
			// placeholder text to the browser.
			return mk_wire(500, [], '${err.msg()}\n')
		}
		return xap_wire_html(200, page)
	}
	if method == 'GET' && path == '/surface' {
		// the SAME surface, content-negotiated to application/cx — what a CLI
		// or TUI client (or an agent) reads. The browser GETs '/' for text/html;
		// a terminal client GETs '/surface' for the view-tree value (§5/§13.2).
		// #585 / xap.md §3.5: a failed view IS the surface value ([err] with
		// CXER4863) — served under the transport's failure mapping (500),
		// never an empty surface.
		sbody, serr := xap_surface_cx_cached(rt, mut env)
		if serr {
			return xap_wire_cx(500, sbody)
		}
		return xap_wire_cx(200, sbody)
	}
	if method == 'GET' && path == '/events' {
		// §24 SSE feed: the SAME surface, pushed live. listener_callback holds
		// the fd open + subscribes it; the initial frame is the current surface,
		// and POST /intent/sign pushes each subsequent surface. A remote TUI/agent
		// reads it with [$http:sse-events] instead of polling /surface.
		// #585: a failing view refuses the subscribe loudly (500 + the [err])
		// instead of holding a feed open over a broken surface.
		sbody, serr := xap_surface_cx_cached(rt, mut env)
		if serr {
			return xap_wire_cx(500, sbody)
		}
		// #609: ?delta=1 opts this subscriber into changed-panel frames —
		// the initial FULL frame below is its resync baseline; subsequent
		// frames carry only panels whose binds changed past its watermark.
		wants_delta := raw_path.contains('delta=1')
		// SSE-1 (xsp.md §4.1): ?envelope=xsp negotiates the XSP-envelope
		// carriage for THIS subscription — the initial frame included.
		wants_xsp, env_refusal := xap_sse_envelope_of(raw_path)
		if env_refusal != '' {
			return mk_wire(400, [], env_refusal)
		}
		return WireResp{
			status:    200
			sse:       true
			sse_rt:    rt_id
			sse_delta: wants_delta
			sse_seq:   rt.commit_seq
			sse_xsp:   wants_xsp
			body:      if wants_xsp { xap_sse_frame_xsp(sbody) } else { xap_sse_frame(sbody) }
		}
	}
	if method == 'GET' && path.starts_with('/static/') {
		return xap_serve_static(rt, path[8..])
	}
	if method == 'POST' && path.starts_with('/intent/') {
		return xap_web_intent(rt_id, mut rt, path[8..], body, auth_principal, mut env)
	}
	// #578: parameterized detail routes. GET /<seg>/<key> renders the view
	// of the component whose bind is "/<seg>", parameterized by key — the
	// slice filtered to the record(s) whose `id` equals <key> (the xap.md §5
	// keyed-slice convention: `bind: "/orders[= @/id …]"`). The
	// application/cx twin rides GET /surface/<seg>/<key> (§2.5 agent
	// parity). The reserved firsts (/surface /events /static /intent) all
	// matched above, so nothing here can shadow them.
	if method == 'GET' && path.starts_with('/surface/') {
		segs := path[9..].split('/')
		if segs.len == 2 && segs[0] != '' && segs[1] != '' {
			return xap_web_detail(rt, xap_urldecode(segs[0]), xap_urldecode(segs[1]), true, mut env)
		}
	}
	if method == 'GET' && path.len > 1 {
		segs := path[1..].split('/')
		if segs.len == 2 && segs[0] != '' && segs[1] != '' {
			return xap_web_detail(rt, xap_urldecode(segs[0]), xap_urldecode(segs[1]), false, mut env)
		}
		// RULED: ATC-2 — GET /<seg> answers the panel FRAGMENT of the
		// component bound to /<seg>: the answering route for the client
		// layer's declared per-pane hypermedia cadence ([pane … refresh=…]
		// → hx-get polling), which previously 404'd silently. The reserved
		// firsts (/surface /events /static /intent) all matched above; an
		// unknown seg still falls through to the 404 below.
		if segs.len == 1 && segs[0] != '' {
			if c := xap_component_by_bind_seg(xap_urldecode(segs[0])) {
				frag := xap_html_fragment_named(rt, c.name, mut env) or {
					// #585: a failing view refuses loudly with its own message.
					return mk_wire(500, [], '${err.msg()}\n')
				}
				return xap_wire_html(200, frag)
			}
		}
	}
	if method == 'HEAD' && path == '/' {
		return xap_wire_html(200, '')
	}
	return mk_wire(404, [], 'not found: ${method} ${path}\n')
}

// xap_web_detail serves one #578 detail route: the component bound to
// "/<seg>", its view rendered over the id=<key> record slice. A missing
// component or an unmatched key is a 404 (the route names a record
// resource). as_cx=true is the application/cx twin (agent parity): the
// keyed view-tree wrapped as [surface name=… key=…].
fn xap_web_detail(rt &XapRuntime, seg string, key string, as_cx bool, mut env MatchEnv) WireResp {
	c := xap_component_by_bind_seg(seg) or {
		return mk_wire(404, [], 'not found: no component bound to /${seg}\n')
	}
	panel := xap_runtime_panel_keyed(rt, c, key, mut env) or {
		return mk_wire(404, [], 'not found: /${seg}/${key} matches no record\n')
	}
	// #585: a keyed view failure surfaces the view's own error (CXER4863).
	if panel is cx.Element && is_err_value(panel) {
		if as_cx {
			return xap_wire_cx(500, render_canonical(panel) + '\n')
		}
		return mk_wire(500, [], xap_err_message(panel) + '\n')
	}
	if as_cx {
		return xap_wire_cx(200, render_canonical(cx.Node(xap_elem('surface',
			[xap_attr('name', c.name), xap_attr('key', key)], [panel]))))
	}
	return xap_wire_html(200, xap_detail_page(c.name, key, panel))
}

fn xap_detail_pid(name string) string {
	return '${name}-detail'
}

fn xap_detail_page(name string, key string, panel cx.Node) string {
	pid := xap_detail_pid(name)
	title := '${name} — ${key}'
	return '<!doctype html>\n<html lang="en">\n<head><meta charset="utf-8">' +
		'<title>${xap_html_escape(title)}</title></head>\n<body>\n' +
		'<main id="${pid}">\n    ${xap_html_panel_inner_ctx(panel, name, pid, key)}\n  </main>\n</body>\n</html>\n'
}

// xap_web_intent commits one web-leg intent (#570). The route table IS the
// declared emits vocabulary (xap.md §14/§16): POST /intent/<verb> routes for
// every verb some registered component declares — the form params map onto
// the declared grammar slots — and an undeclared verb is refused as a policy
// decision (403), never a silent missing route. The commit path is
// xap_emit_into: the SAME grammar-resolution → PEP → record → journal
// cascade the in-process [$xap:emit] runs, so the web medium cannot bypass
// the cascade.
fn xap_web_intent(rt_id int, mut rt XapRuntime, verb string, body string, auth_principal string, mut env MatchEnv) WireResp {
	if verb == '' {
		return mk_wire(404, [], 'not found: POST /intent/\n')
	}
	c := xap_component_declaring(verb) or {
		return mk_wire(403, [], 'forbidden: intent verb "${verb}" is not in any registered component\'s emits vocabulary\n')
	}
	slots := xap_emit_slots(c, verb)
	mut items := [cx.Node(xap_str(verb))]
	mut filled := 0
	for slot in slots {
		v := xap_form_field(body, slot)
		if v != '' {
			items << cx.Node(xap_elem(slot, [], [xap_str(v)]))
			filled++
		}
	}
	// An empty form against a slotted grammar commits nothing (the D3 demo
	// behavior for a blank sign box, kept general): the fragment re-renders
	// the current surface and no record is appended.
	if slots.len > 0 && filled == 0 {
		blank_frag := xap_html_fragment_named(rt, c.name, mut env) or {
			return mk_wire(500, [], '${err.msg()}\n')
		}
		return xap_wire_html(200, blank_frag)
	}
	intent := cx.Node(cx.Element{
		name:  'do'
		items: items
	})
	// #839 R7.2: an authenticated request commits AS its channel's session
	// principal — opts.actor is what the cascade's attribution reads (§3.4),
	// so a journal-BOUND runtime accepts the append. Anonymous (auth off)
	// keeps the empty opts map: the documented back-compat on an unbound
	// runtime, refused by a bound journal exactly as before.
	mut eopts := xap_elem('__cx_map__', [], [])
	if auth_principal != '' {
		eopts = xap_elem('__cx_map__', [], [
			cx.Node(xap_elem('actor', [], [cx.Node(xap_str(auth_principal))])),
		])
	}
	res := xap_emit_into(mut rt, intent, cx.Node(eopts), mut env) or {
		return mk_wire(500, [], 'xap: emit failed\n')
	}
	if res is cx.Element && is_err_value(res) {
		// PEP denial / resolution failure — surface the err value with the
		// policy status, never a silent 200.
		return mk_wire(403, [], render_canonical(res) + '\n')
	}
	// §24: push the new surface to every live SSE feed on this runtime
	// (the TUI/agent clients) — the event-driven half of the §16 feed.
	// #594: through the coalescer/cache like every other commit lane.
	xap_push_live(rt_id, mut env)
	// #578: an intent committed FROM a detail page carries the page's key
	// as the reserved `_detail` field — answer with the re-rendered detail
	// panel so the htmx swap keeps the user on their drill-down. When the
	// key no longer matches a record, fall back to the list fragment.
	detail := xap_form_field(body, '_detail')
	if detail != '' {
		if p := xap_runtime_panel_keyed(rt, c, detail, mut env) {
			// #585: the keyed re-render's view failure is the wire failure.
			if p is cx.Element && is_err_value(p) {
				return mk_wire(500, [], xap_err_message(p) + '\n')
			}
			pid := xap_detail_pid(c.name)
			return xap_wire_html(200, '<main id="${pid}">\n    ${xap_html_panel_inner_ctx(p, c.name, pid, detail)}\n  </main>')
		}
	}
	frag := xap_html_fragment_named(rt, c.name, mut env) or {
		return mk_wire(500, [], '${err.msg()}\n')
	}
	return xap_wire_html(200, frag)
}

// ── HTML serialization (the web medium of the medium-agnostic surface) ───────

// xap_surface_name reads the surface's name attr (the served component's name).
fn xap_surface_name(surface cx.Node) string {
	if surface is cx.Element {
		return surface.attr('name')
	}
	return ''
}

// xap_panel_id resolves the htmx swap-target id for a surface: the mount id
// learned from the shell splice (#567) when a shell declared one, else the
// `<name>-panel` convention (the self-contained fallback page and the D3
// guestbook shape both follow it).
fn xap_panel_id(rt &XapRuntime, name string) string {
	if pid := rt.panel_ids[name] {
		return pid
	}
	if name != '' {
		return '${name}-panel'
	}
	return 'panel'
}

// xap_panel_tag resolves the mount element tag learned from the shell
// splice; 'main' when no shell declared one.
fn xap_panel_tag(rt &XapRuntime, name string) string {
	if tag := rt.panel_tags[name] {
		return tag
	}
	return 'main'
}

// xap_html_inner_of serializes the panel of ONE already-rendered surface
// value to the web medium — the default (first-component) lane used by the
// self-contained fallback page. The caller renders the surface (and checks
// the #585 view-failure err) exactly once.
fn xap_html_inner_of(surface cx.Node, rt &XapRuntime) string {
	name := xap_surface_name(surface)
	mut panel := cx.Node(xap_elem('panel', [], []))
	if surface is cx.Element && surface.items.len > 0 {
		panel = surface.items[0]
	}
	return xap_html_panel_inner(panel, name, xap_panel_id(rt, name))
}

// xap_html_panel_inner serializes ONE panel node to the web medium. Mapping
// the view vocabulary to HTML (per-medium serializer, §2.5/§13.2): list→<ul>,
// item→<li>, control→<form>. htmx target/swap are the bridge binding; the
// endpoint + field + label all come from the view-tree, so changing the view
// changes this output (no hand-built strings). `sname`/`panel_id` carry the
// surface's identity so the markup targets THIS surface's mount (#567) —
// nothing here is guestbook-shaped.
fn xap_html_panel_inner(panel cx.Node, sname string, panel_id string) string {
	return xap_html_panel_inner_ctx(panel, sname, panel_id, '')
}

// xap_html_panel_inner_ctx is the context-carrying serializer: `detail`
// ('' = none) is the #578 detail-route key — controls rendered on a detail
// page carry it back as the `_detail` form field, so the intent response
// re-renders THIS page's panel, not the list.
fn xap_html_panel_inner_ctx(panel cx.Node, sname string, panel_id string, detail string) string {
	mut parts := []string{}
	if panel is cx.Element {
		for child in panel.items {
			s := xap_html_node(child, sname, panel_id, detail)
			if s != '' {
				parts << s
			}
		}
	}
	return parts.join('\n    ')
}

// xap_html_node maps one view-tree node to its HTML materialization.
fn xap_html_node(n cx.Node, sname string, panel_id string, detail string) string {
	if n !is cx.Element {
		return ''
	}
	e := n as cx.Element
	return match e.name {
		'list' { xap_html_list(e, sname) }
		'table' { xap_html_table(e, sname) }
		'control' { xap_html_control(e, panel_id, detail) }
		'text' { xap_html_escape(xap_node_text(n)) }
		else { '' }
	}
}

// xap_html_table maps the [table …] view node (RULED: ATC-2 — the generic
// table view the --client scaffold derives from a surface's `shows`
// declarations) to an HTML table: [head [cell …]…] → <thead>/<th>,
// [row [cell …]…] → <tbody>/<td>. Row yields from a [?for] comprehension
// flatten exactly as [list …] bodies do; everything cell-shaped goes
// through the escaper. The node is medium-agnostic view-tree data — the
// application/cx leg carries it unchanged (agent parity).
fn xap_html_table(e cx.Element, sname string) string {
	mut head := ''
	mut body := ''
	for it in xap_list_item_nodes(e) {
		if it !is cx.Element {
			continue
		}
		re := it as cx.Element
		if re.name == 'head' {
			mut ths := ''
			for c in xap_table_cells(re) {
				ths += '<th>${xap_html_escape(c)}</th>'
			}
			head = '<thead><tr>${ths}</tr></thead>'
		} else if re.name == 'row' {
			mut tds := ''
			for c in xap_table_cells(re) {
				tds += '<td>${xap_html_escape(c)}</td>'
			}
			body += '<tr>${tds}</tr>'
		}
	}
	cls := if sname != '' { ' class="${sname}"' } else { '' }
	return '<table${cls}>${head}<tbody>${body}</tbody></table>'
}

// xap_table_cells reads a [head …]/[row …] element's cells as text: each
// [cell …] child by its text, and any bare scalar item directly (so a
// hand-shortened row still renders).
fn xap_table_cells(e cx.Element) []string {
	mut out := []string{}
	for it in xap_list_item_nodes(e) {
		if it is cx.Element {
			if it.name == 'cell' {
				out << xap_node_text(it)
			}
		} else {
			out << xap_node_text(it)
		}
	}
	return out
}

fn xap_html_list(e cx.Element, sname string) string {
	mut lis := ''
	for it in xap_list_item_nodes(e) {
		lis += '<li>${xap_html_escape(xap_node_text(it))}</li>'
	}
	cls := if sname != '' { ' class="${sname}"' } else { '' }
	return '<ul${cls}>${lis}</ul>'
}

// xap_list_item_nodes flattens a [list …] body: a `(…)` sequence (many items)
// or bare item(s) — mirrors the view's `[?for]` comprehension yield shape.
fn xap_list_item_nodes(e cx.Element) []cx.Node {
	mut out := []cx.Node{}
	for it in e.items {
		match it {
			cx.SequenceNode { out << it.items }
			cx.ArrayNode { out << it.items }
			cx.IteratorNode { out << iterate(it) } // materialize the [?for] comprehension
			cx.Element {
				// an empty-name element is the anonymous sequence wrapper the
				// [?for] comprehension yields (render prints it as `(…)`); the
				// marker-named envelopes are the other collection shapes.
				if it.name == '' || it.name == '__cx_seq__' || it.name == '__cx_arr__' {
					out << it.items
				} else {
					out << it
				}
			}
			else {
				out << it
			}
		}
	}
	return out
}

// xap_html_control maps [control :verb [label …] [input :field]] → the htmx form;
// the intent endpoint (/intent/<verb>), the field name, and the label are read
// from the view-tree (not hard-coded), so the control IS the capability (§17).
// The swap target is THIS surface's mount id (#567), never a fixed demo id.
// On a detail page (#578) the form additionally carries the page's key as
// the reserved `_detail` field — never a grammar slot — so xap_web_intent
// answers with the re-rendered detail panel instead of the list.
fn xap_html_control(e cx.Element, panel_id string, detail string) string {
	verb := xap_atom_name(e)
	mut label := 'Submit'
	// #839: EVERY [input :slot] child gets its own <input> — the last-one-wins
	// overwrite this replaces silently dropped all but one slot, so a verb
	// whose intent took two slots committed a record missing the first and
	// the next view render failed on the absent field. The htmx form posts
	// the full body and xap_emit_slots already maps each form field to its
	// grammar slot, so the renderer was the only narrowing.
	mut fields := []string{}
	for it in e.items {
		if it is cx.Element {
			if it.name == 'label' {
				label = xap_node_text(it)
			} else if it.name == 'input' {
				fields << xap_atom_name(it)
			}
		}
	}
	if fields.len == 0 {
		// no [input …] child — keep the historical single default field.
		fields << 'value'
	}
	ctx := if detail != '' {
		'      <input type="hidden" name="_detail" value="${xap_html_escape(detail)}">\n'
	} else {
		''
	}
	mut inputs := ''
	for f in fields {
		// name + placeholder both carry the slot name, so a multi-slot form
		// stays legible without per-slot label plumbing (the control is the
		// capability, §17 — the slot NAME is view-tree data, never hard-coded).
		inputs += '      <input name="${f}" placeholder="${xap_html_escape(f)}">\n'
	}
	return '<form hx-post="/intent/${verb}" hx-target="#${panel_id}" hx-swap="outerHTML">\n' + ctx +
		inputs + '      <button type="submit">${xap_html_escape(label)}</button>\n' +
		'    </form>'
}

// xap_node_text reads an element's first scalar item (or a scalar itself) as text.
fn xap_node_text(n cx.Node) string {
	if n is cx.Element && n.items.len > 0 {
		t := n.items[0]
		if t is cx.ScalarNode {
			v := t.value
			if v is string {
				return v
			}
		}
	}
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	return ''
}

// xap_atom_name returns the name of an element's leading atom (e.g. :sign → "sign").
fn xap_atom_name(e cx.Element) string {
	for it in e.items {
		if it is cx.ScalarNode {
			v := it.value
			if v is string {
				return v
			}
		}
	}
	return ''
}

// xap_html_fragment_named is the htmx swap target for ONE surface: the
// mount element (shell-learned tag/id, #567) wrapping the re-rendered panel.
// A render-time view failure errors with the view's own message (#585 /
// xap.md §3.5) — the caller maps it to the wire 500.
fn xap_html_fragment_named(rt &XapRuntime, name string, mut env MatchEnv) !string {
	pid := xap_panel_id(rt, name)
	tag := xap_panel_tag(rt, name)
	// #594: the same per-commit_seq panel cache the shell splice fills —
	// an intent's own re-render misses (the commit bumped the seq) and
	// re-fills for the GETs that follow.
	ckey := 'panel:${name}:${pid}'
	if cv := xap_render_cached(rt, ckey) {
		return '<${tag} id="${pid}">\n    ${cv}\n  </${tag}>'
	}
	seq := rt.commit_seq
	panel := xap_runtime_panel_named(rt, name, mut env) or { cx.Node(xap_elem('panel', [], [])) }
	if panel is cx.Element && is_err_value(panel) {
		return error(xap_err_message(panel))
	}
	inner := xap_html_panel_inner(panel, name, pid)
	xap_render_store(rt, seq, ckey, inner)
	return '<${tag} id="${pid}">\n    ${inner}\n  </${tag}>'
}

// xap_html_page splices the rendered surfaces into the document shell
// (layout.html, the swappable bridge layer). Falls back to a self-contained
// page when no shell dir is configured / readable. A shell whose mount names
// an unknown surface is an ERROR (#567) — the placeholder is never served.
fn xap_html_page(mut rt XapRuntime, mut env MatchEnv) !string {
	if rt.shell_dir != '' {
		if tpl := os.read_file('${rt.shell_dir}/layout.html') {
			return xap_shell_splice(mut rt, tpl, mut env)!
		}
	}
	// #594: the self-contained fallback page is a pure function of the fold —
	// cache the whole page per commit_seq (no shell file involved). A failed
	// view is never cached (#585 refusal re-diagnoses per request).
	if cv := xap_render_cached(rt, 'fallback-page') {
		return cv
	}
	seq := rt.commit_seq
	surface := xap_runtime_surface(rt, mut env)
	// #585 / xap.md §3.5: a failed view IS the surface value (CXER4863) —
	// the fallback page refuses with the view's error, never renders empty.
	if surface is cx.Element && is_err_value(surface) {
		return error(xap_err_message(surface))
	}
	name := xap_surface_name(surface)
	title := if name != '' { name } else { 'cx-xap' }
	pid := xap_panel_id(rt, name)
	page := '<!doctype html>\n<html lang="en">\n<head><meta charset="utf-8">' +
		'<title>${xap_html_escape(title)} — cx-xap</title></head>\n<body>\n<h1>${xap_html_escape(title)}</h1>\n' +
		'<main id="${pid}">${xap_html_inner_of(surface, rt)}</main>\n</body>\n</html>\n'
	xap_render_store(rt, seq, 'fallback-page', page)
	return page
}

// xap_shell_splice resolves every `{{surface:NAME}}` mount in the shell
// template (#567): each names a registered component whose view renders the
// panel spliced in its place. When the placeholder sits inside a mount
// element carrying an id (`<main id="review-queue-panel">{{surface:review-queue}}</main>`),
// the WHOLE mount element is replaced and its tag/id are recorded on the
// runtime, so POST fragments and control hx-targets swap against the
// shell's own geometry. A bare placeholder (no enclosing id) is replaced by
// a default `<main id="<name>-panel">` wrapper. An unknown surface name or
// an unterminated placeholder refuses the page — fail loudly, never serve
// the placeholder text.
fn xap_shell_splice(mut rt XapRuntime, tpl string, mut env MatchEnv) !string {
	mut out := tpl
	mut search_from := 0
	for {
		rel := out[search_from..].index('{{surface:') or { break }
		ph := search_from + rel
		tail := out[ph + 10..]
		ne := tail.index('}}') or {
			return error('E_XAP_SHELL_MOUNT_INVALID: unterminated {{surface:…}} placeholder in layout.html')
		}
		name := tail[..ne]
		ph_end := ph + 10 + ne + 2
		// locate the enclosing mount element (an open tag with an id, whose
		// `>` precedes the placeholder and whose close tag follows it).
		mut repl_start := ph
		mut repl_end := ph_end
		mut tag := 'main'
		mut pid := '${name}-panel'
		if lt := out[..ph].last_index('<') {
			if oe := out[lt..ph].index('>') {
				open_tag := out[lt + 1..lt + oe]
				tname := open_tag.all_before(' ')
				if tname != '' && !tname.contains('/') {
					if idv := xap_html_tag_attr(open_tag, 'id') {
						close_pat := '</${tname}>'
						if ce := out[ph_end..].index(close_pat) {
							tag = tname
							pid = idv
							repl_start = lt
							repl_end = ph_end + ce + close_pat.len
						}
					}
				}
			}
		}
		rt.panel_ids[name] = pid
		rt.panel_tags[name] = tag
		// #594: the O(state) work (view eval + HTML mapping) caches per
		// commit_seq — a cache hit skips the render entirely (a cached
		// inner implies the view succeeded at this seq). The splice itself
		// still re-reads layout.html per request (shell hot-reload
		// preserved). A failed view is never cached; every request through
		// it re-diagnoses (#585 loud-failure semantics unchanged).
		ckey := 'panel:${name}:${pid}'
		mut inner := ''
		if cv := xap_render_cached(rt, ckey) {
			inner = cv
		} else {
			seq := rt.commit_seq
			panel := xap_runtime_panel_named(rt, name, mut env) or {
				return error('E_XAP_SHELL_SURFACE_UNKNOWN: shell mount {{surface:${name}}} names no registered component with a view')
			}
			// #585 / xap.md §3.5: a view that FAILED at render refuses the
			// page with ITS OWN error (CXER4863) — never the unknown-surface
			// refusal, never a silently absent panel.
			if panel is cx.Element && is_err_value(panel) {
				return error(xap_err_message(panel))
			}
			inner = xap_html_panel_inner(panel, name, pid)
			xap_render_store(rt, seq, ckey, inner)
		}
		replacement := '<${tag} id="${pid}">\n    ${inner}\n  </${tag}>'
		out = out[..repl_start] + replacement + out[repl_end..]
		// continue AFTER the replacement: rendered user data could itself
		// contain placeholder-shaped text; it must not be re-spliced.
		search_from = repl_start + replacement.len
	}
	return out
}

// xap_html_tag_attr reads one double-quoted attribute value from an open
// tag's source text (`main id="guestbook-panel" class=…` → 'guestbook-panel').
fn xap_html_tag_attr(tag_src string, name string) ?string {
	pat := '${name}="'
	i := tag_src.index(pat) or { return none }
	rest := tag_src[i + pat.len..]
	j := rest.index('"') or { return none }
	return rest[..j]
}

// xap_serve_static reads a static asset from <shell>/static/ (app.css, …).
fn xap_serve_static(rt &XapRuntime, rel string) WireResp {
	if rt.shell_dir == '' || rel.contains('..') {
		return mk_wire(404, [], 'not found\n')
	}
	data := os.read_file('${rt.shell_dir}/static/${rel}') or {
		return mk_wire(404, [], 'not found\n')
	}
	ct := if rel.ends_with('.css') {
		'text/css; charset=utf-8'
	} else if rel.ends_with('.js') {
		'application/javascript; charset=utf-8'
	} else {
		'application/octet-stream'
	}
	return WireResp{
		status:  200
		headers: [WireHeader{ name: 'Content-Type', value: ct }]
		body:    data
	}
}

fn xap_wire_html(status int, body string) WireResp {
	return WireResp{
		status:  status
		headers: [WireHeader{ name: 'Content-Type', value: 'text/html; charset=utf-8' }]
		body:    body
	}
}

fn xap_wire_cx(status int, body string) WireResp {
	return WireResp{
		status:  status
		headers: [WireHeader{ name: 'Content-Type', value: 'application/cx; charset=utf-8' }]
		body:    body
	}
}

// ── small text utilities ─────────────────────────────────────────────────────

fn xap_html_escape(s string) string {
	return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
}

// xap_form_field reads one field from an application/x-www-form-urlencoded body.
fn xap_form_field(body string, key string) string {
	for pair in body.split('&') {
		if eq := pair.index('=') {
			if xap_urldecode(pair[..eq]) == key {
				return xap_urldecode(pair[eq + 1..])
			}
		}
	}
	return ''
}

fn xap_urldecode(s string) string {
	mut out := []u8{}
	mut i := 0
	for i < s.len {
		c := s[i]
		if c == `+` {
			out << ` `
			i++
		} else if c == `%` && i + 2 < s.len {
			hi := xap_hex_val(s[i + 1])
			lo := xap_hex_val(s[i + 2])
			if hi >= 0 && lo >= 0 {
				out << u8(hi * 16 + lo)
				i += 3
			} else {
				out << c
				i++
			}
		} else {
			out << c
			i++
		}
	}
	return out.bytestr()
}

fn xap_hex_val(c u8) int {
	if c >= `0` && c <= `9` {
		return int(c - `0`)
	}
	if c >= `a` && c <= `f` {
		return int(c - `a` + 10)
	}
	if c >= `A` && c <= `F` {
		return int(c - `A` + 10)
	}
	return -1
}
