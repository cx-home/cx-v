module platform

import cx
import code { MatchEnv, mk_err }

// coordination.v — stream 10 (#682; cross_stream_coordination.md): the
// saga/escrow vocabulary's platform home. Cross-stream atomic commit stays
// REJECTED on the §1 derivation — nothing here fabricates a fourth
// serialization point; the mechanism is choreography over the shipped
// per-stream locks.
//
// The CXER4950–4969 coordination band (governance §9.6, registered before
// first use):
//   CXER4950 E_COORD_PIN_STALE — a [requires-at] admission read failed:
//     the target stream's head is BEFORE the pinned seq, or the entry at
//     seq does not hash-match. The pin means "the fact I depend on was
//     committed at-or-before this position and had these bytes" — never a
//     live two-stream version conjunction (that conjunction is
//     unsatisfiable without a global serialization point, stated openly
//     in the spec).
//   CXER4951 E_COORD_PIN_UNEVALUATED — a pinned command invoked outside a
//     journal-bound commit (raised engine-side, vcx/code/eval.v: Ring 1
//     holds no journal, so an unadmitted invocation refuses fail-closed
//     rather than silently skipping the admission check).

const coord_err_pin_stale = 'cx-err:CXER4950'

// coord_pin_check runs the B3 ADMISSION read (§1/§2): under the writing
// stream's own commit path, read the TARGET stream — its head must be
// AT-OR-PAST the pinned seq and the entry at seq must hash-match. Both
// facts are monotone (an entry at a position never changes; heads only
// advance), so the read needs no lock coupling beyond the journal's own.
// Returns the CXER4950 refusal, or none when admitted. NEVER a fold
// input — the caller records it in the envelope for audit only.
fn coord_pin_check(journal cx.Node, stream string, seq i64, hash string) ?cx.Node {
	h := journal_stdlib_builtin('journal-head', [journal, store_str(stream)]) or {
		return mk_err(coord_err_pin_stale, 'E_COORD_PIN_STALE: [requires-at stream="${stream}" seq=${seq}] — the target stream is unreadable at the commit point (the admission basis must be checkable, never assumed)')
	}
	head_seq := if h is cx.Element { h.attr('seq').i64() } else { i64(0) }
	if head_seq < seq {
		return mk_err(coord_err_pin_stale, 'E_COORD_PIN_STALE: [requires-at stream="${stream}" seq=${seq}] — the target stream head is at ${head_seq}, BEFORE the pinned position; the fact this command depends on has not committed (cross_stream_coordination §2)')
	}
	e := journal_stdlib_builtin('journal-read', [journal, cx.Node(jrn_int(seq)),
		store_str(stream)]) or {
		return mk_err(coord_err_pin_stale, 'E_COORD_PIN_STALE: [requires-at stream="${stream}" seq=${seq}] — the pinned entry is unreadable')
	}
	got := if e is cx.Element { e.attr('hash') } else { '' }
	if got != hash {
		return mk_err(coord_err_pin_stale, 'E_COORD_PIN_STALE: [requires-at stream="${stream}" seq=${seq}] — the entry at the pinned position does not hash-match (expected ${hash}, chain holds ${got}); the dependence names different bytes than the chain records')
	}
	return none
}

// ── W2: the saga record + the Ring-2 runner (§2) ────────────────────────────
//
// A saga is an ORDINARY JOURNALED VALUE in its home stream — (saga-id,
// steps[], per-step status, authority basis) — never a coordinator stream,
// never an engine object. The runner drives command steps in order and
// journals each status transition as a NEW [saga] record; the current
// state of saga S = the LAST [saga id=S] record on the home stream (the
// erase-subject record-scan precedent). That journaled record IS the
// durable step-dedup: a step recorded :done never re-executes on resume —
// redelivery ⇒ one effect, with no new dedup machinery. The replay rule
// holds by construction: participants fold their OWN entries only; the
// saga document is an order-independent reporting JOIN.

const coord_saga_stream_default = ''

// coord_saga_last scans the home stream for the newest [saga id=…] record.
fn coord_saga_last(mut j Journal, stream string, id string) ?cx.Element {
	jrn_refresh_head(mut j, stream)
	st := j.named[stream] or { return none }
	if st.head_seq < 1 {
		return none
	}
	items := jrn_state_collect_range_of(j, stream, st, 1, st.head_seq)
	mut found := ?cx.Element(none)
	for it in items {
		if it is cx.Element {
			for ch in it.items {
				if ch is cx.Element && ch.name == 'event' && ch.items.len > 0 {
					p := ch.items[0]
					if p is cx.Element && p.name == 'saga' && p.attr('id') == id {
						found = p
					}
				}
			}
		}
	}
	return found
}

struct CoordStep {
	name   string
	pivot  bool
	fnv    cx.Node
	labels []string
	vals   []cx.Node
mut:
	status string
}

// coord_saga_record renders the saga value for journaling.
fn coord_saga_record(id string, status string, steps []CoordStep) cx.Element {
	mut items := []cx.Node{}
	for st in steps {
		mut sattrs := [
			cx.Attribute{
				name:  'name'
				value: cx.ScalarValue(st.name)
			},
			cx.new_attribute('status', cx.ScalarValue(st.status), cx.AttributeMeta{
				data_type: 'atom'
			}),
		]
		if st.pivot {
			sattrs << cx.Attribute{
				name:  'pivot'
				value: cx.ScalarValue(true)
			}
		}
		items << cx.Node(cx.Element{
			name:  'step'
			attrs: sattrs
		})
	}
	return cx.Element{
		name:  'saga'
		attrs: [
			cx.Attribute{
				name:  'id'
				value: cx.ScalarValue(id)
			},
			cx.new_attribute('status', cx.ScalarValue(status), cx.AttributeMeta{
				data_type: 'atom'
			}),
		]
		items: items
	}
}

struct CoordAppended {
	seq  i64
	hash string
}

fn coord_saga_append(jnode cx.Node, stream string, id string, status string, steps []CoordStep, actor string, authority string) !CoordAppended {
	mut m_items := [
		cx.Node(cx.Element{
			name:  'actor'
			items: [jrn_str(actor)]
		}),
		cx.Node(cx.Element{
			name:  'authority'
			items: [jrn_str(authority)]
		}),
	]
	if !jrn_is_default(stream) {
		m_items << cx.Node(cx.Element{
			name:  'stream'
			items: [jrn_str(stream)]
		})
	}
	r := jrn_append([jnode, cx.Node(coord_saga_record(id, status, steps)),
		cx.Node(cx.Element{
			name:  'map'
			items: m_items
		})]) or { return error('E_JOURNAL_OPEN_FAILED: saga record append failed') }
	if r is cx.Element && r.name == 'err' {
		return error('${r.attr('code')}: ${r.attr('message')}')
	}
	if r is cx.Element {
		return CoordAppended{
			seq:  r.attr('seq').i64()
			hash: r.attr('hash')
		}
	}
	return CoordAppended{}
}

// coord_parse_steps reads the [saga-def] element's [step …] children.
fn coord_parse_steps(def cx.Element) !([]CoordStep, string) {
	mut steps := []CoordStep{}
	mut pivot_seen := false
	for it in def.items {
		if it is cx.Element && it.name == 'step' {
			name := it.attr('name')
			if name == '' {
				return error('a [step] needs name=')
			}
			pivot := it.attr('pivot') == 'true'
			if pivot {
				if pivot_seen {
					return error('at most ONE pivot step (the single irreversible point)')
				}
				pivot_seen = true
			}
			mut fnv := cx.Node(cx.ScalarNode{})
			mut labels := []string{}
			mut vals := []cx.Node{}
			mut has_fn := false
			for ch in it.items {
				if ch is cx.Element {
					match ch.name {
						'fn' {
							if ch.items.len > 0 {
								fnv = ch.items[0]
								has_fn = true
							}
						}
						'args' {
							if ch.items.len == 1 {
								am := ch.items[0]
								if am is cx.Element && am.name == '__cx_map__' {
									for e in am.items {
										if e is cx.Element && e.items.len > 0 {
											labels << e.name
											vals << e.items[0]
										}
									}
								}
							}
						}
						else {}
					}
				}
			}
			if !has_fn {
				return error('step `${name}` needs an [fn …] child (a command value)')
			}
			steps << CoordStep{
				name:   name
				pivot:  pivot
				fnv:    fnv
				labels: labels
				vals:   vals
				status: 'pending'
			}
		}
	}
	if steps.len == 0 {
		return error('a saga needs at least one [step]')
	}
	id := def.attr('id')
	if id == '' {
		return error('a saga needs id=')
	}
	return steps, id
}

// coord_saga_run — [$journal:saga-run $j [saga-def id= [step …]…] $opts]:
// drive the steps in order, journaling each transition; resume skips
// steps the record already shows :done. W2 = the happy path + resume;
// compensation flows land at W3 (a failed step marks the saga :failed).
fn coord_saga_run(args []cx.Node, mut env MatchEnv) ?cx.Node {
	if args.len < 2 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: saga-run expects (journal, saga-def, opts?)')
	}
	mut j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	if args[1] !is cx.Element || (args[1] as cx.Element).name != 'saga-def' {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: saga-run expects a [saga-def id= [step …]…] value')
	}
	def := args[1] as cx.Element
	mut steps, id := coord_parse_steps(def) or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: ${err.msg()}')
	}
	mut stream := ''
	mut actor := ''
	mut authority := ''
	if args.len > 2 {
		if v := jrn_map_get(args[2], 'stream') {
			stream = v
		}
		if v := jrn_map_get(args[2], 'actor') {
			actor = v
		}
		if v := jrn_map_get(args[2], 'authority') {
			authority = v
		}
	}
	if actor == '' || authority == '' {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: saga-run needs opts.actor + opts.authority (the authority basis rides the record)')
	}
	// the pivot index (-1 = none declared → the saga must be FULLY
	// compensable); pre-pivot steps MUST carry a [compensates] pairing —
	// checked BEFORE anything runs (fail-closed, never a mid-saga surprise).
	mut pivot_idx := -1
	for i, st in steps {
		if st.pivot {
			pivot_idx = i
		}
	}
	for i, st in steps {
		needs_comp := if pivot_idx >= 0 { i < pivot_idx } else { true }
		if needs_comp && code.command_compensator_name(st.fnv, mut env) == '' {
			return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: step `${st.name}` precedes the pivot but its command declares no [compensates] pairing — a pre-pivot step must be compensable (cross_stream_coordination §2)')
		}
	}
	// resume: terminal states dedup; :done steps skip (the durable dedup).
	mut resumed := 0
	if last := coord_saga_last(mut j, stream, id) {
		lstatus := last.attr('status').trim_left(':')
		if lstatus in ['done', 'compensated', 'uncompensatable'] {
			return cx.Node(cx.Element{
				name:  'deduped'
				items: [cx.Node(last)]
			})
		}
		mut recorded := map[string]string{}
		for ch in last.items {
			if ch is cx.Element && ch.name == 'step' {
				recorded[ch.attr('name')] = ch.attr('status').trim_left(':')
			}
		}
		for i, st in steps {
			if (recorded[st.name] or { '' }) == 'done' {
				steps[i].status = 'done'
				resumed++
			}
		}
	}
	coord_saga_append(args[0], stream, id, 'running', steps, actor, authority) or {
		return mk_err(jrn_err_open_failed, err.msg())
	}
	// per-step :done record locators — the [compensates] link targets.
	mut done_loc := map[string]CoordAppended{}
	for i, st in steps {
		if st.status == 'done' {
			continue
		}
		// [requires-at] admission (the W1 seam — the runner is the second
		// journal-bound commit site; bracketed per step, leak-proof).
		mut pin_src := ''
		if pstream, pseq, phash := code.command_pin_of(st.fnv, mut env) {
			if refusal := coord_pin_check(args[0], pstream, pseq, phash) {
				steps[i].status = 'failed'
				coord_saga_append(args[0], stream, id, 'failed', steps, actor,
					authority) or {}
				return refusal
			}
			if sa := code.command_pin_src_addr(st.fnv, mut env) {
				pin_src = sa
				code.command_pin_admit(mut env, sa)
			}
		}
		res := code.command_invoke_labeled(st.fnv, st.labels, st.vals, mut env) or {
			// an uninvokable step IS a failed step — never silent success.
			cx.Node(cx.Element{
				name:  'err'
				attrs: [
					cx.Attribute{
						name:  'code'
						value: cx.ScalarValue('cx-err:CXER0100')
					},
					cx.Attribute{
						name:  'message'
						value: cx.ScalarValue('saga step `${st.name}`: ${err.msg()}')
					},
				]
			})
		}
		if pin_src != '' {
			code.command_pin_clear(mut env, pin_src)
		}
		if res is cx.Element && res.name == 'err' {
			steps[i].status = 'failed'
			past_pivot := pivot_idx >= 0 && i > pivot_idx
			if past_pivot {
				// POST-PIVOT: compensation is definitionally unavailable —
				// forward-only idempotent retry with the incomplete count
				// VISIBLE (resume re-attempts; the pivot either committed
				// or it did not — never a silent partial).
				mut incomplete := 0
				for k in i .. steps.len {
					if steps[k].status != 'done' {
						incomplete++
					}
				}
				coord_saga_append(args[0], stream, id, 'incomplete', steps, actor,
					authority) or { return mk_err(jrn_err_open_failed, err.msg()) }
				mut rec := coord_saga_record(id, 'incomplete', steps)
				rec.attrs << cx.Attribute{
					name:  'incomplete'
					value: cx.ScalarValue(i64(incomplete))
				}
				return cx.Node(rec)
			}
			// PRE-PIVOT: compensate the :done steps in REVERSE via the
			// [compensates] pairing — each compensation an ordinary command
			// invocation; the record carries the locator-triple link to the
			// :done transition it reverses (never a fifth relation — the
			// compensating entry is an :assertion-class new fact).
			coord_saga_append(args[0], stream, id, 'compensating', steps, actor,
				authority) or { return mk_err(jrn_err_open_failed, err.msg()) }
			for k := i - 1; k >= 0; k-- {
				if steps[k].status != 'done' {
					continue
				}
				comp_name := code.command_compensator_name(steps[k].fnv, mut env)
				cres := code.command_invoke_named(comp_name, steps[k].labels, steps[k].vals, mut
					env) or {
					// an uninvokable compensator IS uncompensatable.
					cx.Node(cx.Element{
						name:  'err'
						attrs: [
							cx.Attribute{
								name:  'code'
								value: cx.ScalarValue('cx-err:CXER0100')
							},
							cx.Attribute{
								name:  'message'
								value: cx.ScalarValue('compensator `${comp_name}`: ${err.msg()}')
							},
						]
					})
				}
				if cres is cx.Element && cres.name == 'err' {
					// a compensator that fails yields the ONE conflict value —
					// inspectable data, never an opaque failure.
					steps[k].status = 'uncompensatable'
					coord_saga_append(args[0], stream, id, 'uncompensatable', steps,
						actor, authority) or {
						return mk_err(jrn_err_open_failed, err.msg())
					}
					loc := done_loc[steps[k].name] or { CoordAppended{} }
					mut conf_items := [
						cx.Node(cx.Element{
							name:  'ours'
							items: [cx.Node(cres)]
						}),
					]
					if loc.hash != '' {
						conf_items.insert(0, cx.Node(cx.Element{
							name:  'compensates'
							attrs: [
								cx.Attribute{
									name:  'stream'
									value: cx.ScalarValue(stream)
								},
								cx.Attribute{
									name:  'seq'
									value: cx.ScalarValue(loc.seq)
								},
								cx.Attribute{
									name:  'hash'
									value: cx.ScalarValue(loc.hash)
								},
							]
						}))
					}
					return cx.Node(cx.Element{
						name:  'conflict'
						attrs: [
							cx.Attribute{
								name:  'subject'
								value: cx.ScalarValue('${id}/${steps[k].name}')
							},
							cx.new_attribute('kind', cx.ScalarValue('uncompensatable'),
								cx.AttributeMeta{
								data_type: 'atom'
							}),
							cx.new_attribute('policy', cx.ScalarValue('manual-resolution'),
								cx.AttributeMeta{
								data_type: 'atom'
							}),
						]
						items: conf_items
					})
				}
				steps[k].status = 'compensated'
				coord_saga_append(args[0], stream, id, 'compensating', steps, actor,
					authority) or { return mk_err(jrn_err_open_failed, err.msg()) }
			}
			coord_saga_append(args[0], stream, id, 'compensated', steps, actor,
				authority) or { return mk_err(jrn_err_open_failed, err.msg()) }
			return cx.Node(coord_saga_record(id, 'compensated', steps))
		}
		steps[i].status = 'done'
		loc := coord_saga_append(args[0], stream, id, 'running', steps, actor,
			authority) or { return mk_err(jrn_err_open_failed, err.msg()) }
		done_loc[st.name] = loc
	}
	coord_saga_append(args[0], stream, id, 'done', steps, actor, authority) or {
		return mk_err(jrn_err_open_failed, err.msg())
	}
	mut rec := coord_saga_record(id, 'done', steps)
	if resumed > 0 {
		rec.attrs << cx.Attribute{
			name:  'resumed'
			value: cx.ScalarValue(i64(resumed))
		}
	}
	return cx.Node(rec)
}

// coord_saga_status — [$journal:saga-status $j $id $opts?]: the last
// recorded [saga] value for id (absence when none).
fn coord_saga_status(args []cx.Node) ?cx.Node {
	if args.len < 2 {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: saga-status expects (journal, id, opts?)')
	}
	mut j, errn, ok := jrn_get_open(args[0])
	if !ok {
		return errn
	}
	id := jrn_arg_str(args[1]) or {
		return mk_err(jrn_err_arg_invalid, 'E_JOURNAL_ARG_INVALID: saga-status expects a string saga id')
	}
	mut stream := ''
	if args.len > 2 {
		if v := jrn_map_get(args[2], 'stream') {
			stream = v
		}
	}
	if last := coord_saga_last(mut j, stream, id) {
		return cx.Node(last)
	}
	return jrn_empty()
}
