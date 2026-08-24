module platform

import cx
import code { cx_mod_diff, mk_err }

// store_reconcile.v — stream 9 (#681; distributed_store.md §4/§5, rulings
// L175/L176): per-ref reconciliation of the ALIAS plane — the mutable half
// sync needs (the immutable plane is content-addressed and conflict-free by
// construction). For every branch-class alias name on either side:
//
//   fast-forward — ours never moved past the common base while theirs did:
//     the advance APPLIES (target doc copied when absent, alias advanced
//     through the one live-mutation seam, durably recorded like set-alias).
//   ahead — ours moved, theirs did not: nothing to apply, counted visibly.
//   diverged — BOTH moved past the common base: the ref applies NOTHING and
//     the report carries the ONE Ring-0 conflict value (the shape stream 10
//     co-owns): [conflict subject= kind=:diverged-advance [base position=
//     hash=] [ours position= hash= [diff …]] [theirs position= hash=
//     [diff …]] [cas code=CXER1114 expect-pos= actual-pos=]] — base/ours/
//     theirs carry navigable, PATCHABLE [diff] payloads against the base
//     (`patch(base, ours-diff) ≡ ours`, the cx module's §5 law), and the
//     CAS coordinates ride AS DATA, never a second dialect.
//
// The COMMON BASE is normative (L174): the greatest position at which both
// lineages record the same target — computed from the E3 alias lineage
// (ms.advances), newest-first from ours. Two refs with NO shared target
// ever (independent creations) conflict with the [base] child ABSENT (the
// absence channel, stated rather than invented).
//
// Two surfaces, one walk (the XAP compose/compose-report agreement-law
// precedent, stdlib_xap.v): `reconcile-report` NEVER raises — the report
// with ok= and every outcome as data; `reconcile` (the enforcing twin)
// applies the same fast-forwards and RAISES CXER5053 E_SYNC_DIVERGED
// carrying every [conflict] iff the report says ok=false — raise ⟺ ok=false,
// the agreement law. Partial success is REPORTED, never mixed silently:
// clean refs advance even when siblings diverge (per-ref independence), and
// the report names both.
//
// Scope (v1, recorded in the stream ledger): the branch-class alias plane —
// derived-cache namespaces (`computation/`, `cx-live/`) are NOT reconciled
// (caches rebuild; they are not the divergence surface); the wire-refs
// plane rides the sync-surface wave over the shipped object-wire CAS.

const sync_err_diverged = 'cx-err:CXER5053'

// ── PeerView — ONE read abstraction over the reconciliation peer ────────────
//
// (W6, the wire composition.) The walk/classification consume the peer
// through this view: a LOCAL peer reads the MemStore directly; a REMOTE
// (cx-store://) peer reads the SAME facts over the shipped wire — aliases
// via `aliases all`, the E3 lineage via the `log` op, doc text via the
// remote read arm. One examination, two transports; the local fast path
// stays allocation-light.

struct PeerView {
	handle cx.Node // the peer's handle node (remote doc reads route through it)
mut:
	ms       &MemStore = unsafe { nil }
	remote   bool
	aliases  map[string]string
	advances []StoreAdvance
}

fn store_peer_view(handle cx.Node, mut ms MemStore) ?PeerView {
	if !store_remote_active(ms) {
		return PeerView{
			handle: handle
			ms:     unsafe { &ms }
		}
	}
	mut owc := store_objwire_client(ms) or {
		return none // byte-source remote: no service to ask
	}
	mut view := PeerView{
		handle: handle
		ms:     unsafe { &ms }
		remote: true
	}
	pairs := owc.alias_list() or { return none }
	for p in pairs {
		if p.len == 2 {
			view.aliases[p[0]] = p[1]
		}
	}
	advs := owc.log_advances() or { return none }
	for a in advs {
		view.advances << StoreAdvance{
			plane: a.attr('plane')
			kind:  a.attr('kind')
			name:  if a.attr('plane') == 'aliases' { a.attr('key') } else { '' }
			hash:  a.attr('hash')
			pos:   a.attr('pos').i64()
		}
	}
	return view
}

fn (v &PeerView) peer_aliases() map[string]string {
	if v.remote {
		return v.aliases
	}
	return v.ms.aliases.clone()
}

fn (v &PeerView) peer_lineage(name string) RefLineage {
	if v.remote {
		mut positions := []i64{}
		mut targets := []string{}
		for adv in v.advances {
			if adv.plane == 'aliases' && adv.name == name && adv.kind == 'advance' {
				positions << adv.pos
				targets << adv.hash
			}
		}
		return RefLineage{
			positions: positions
			targets:   targets
		}
	}
	return store_reconcile_lineage(v.ms, name)
}

fn (v &PeerView) peer_doc_text(hash string) ?string {
	if v.remote {
		r := store_stdlib_builtin_inner('store-get-doc-text', [v.handle, store_str(hash)]) or {
			return none
		}
		if r is cx.ScalarNode {
			sv := r.value
			if sv is string {
				return sv
			}
		}
		return none
	}
	return store_doc_text(v.ms, hash) or { return none }
}

// store_reconcile_names is the deterministic examination set: the union of
// both sides' branch-class alias names, sorted.
fn store_reconcile_names(ms_d &MemStore, view &PeerView) []string {
	mut set := map[string]bool{}
	for name, _ in ms_d.aliases {
		set[name] = true
	}
	for name, _ in view.peer_aliases() {
		set[name] = true
	}
	mut names := []string{}
	for name, _ in set {
		if name.starts_with('computation/') || name.starts_with('cx-live/') {
			continue
		}
		// The journal's OWN state (entry pointers, heads, stream index,
		// replica registrations) is NEVER the branch-class divergence
		// surface: journal streams sync via ingest-stream — chain-verified,
		// byte-identical — and a blind alias fast-forward here would bypass
		// that verification entirely (found by the M5 end-to-end: the pull
		// pre-empted ingest with unverified journal pointers).
		if name.starts_with('cx-journal/') || name.starts_with('cx-replica/') {
			continue
		}
		names << name
	}
	names.sort()
	return names
}

struct RefLineage {
	positions []i64
	targets   []string
}

// store_reconcile_lineage collects one ref's alias-plane advance history
// (oldest→newest) from the live E3 feed.
fn store_reconcile_lineage(ms &MemStore, name string) RefLineage {
	mut positions := []i64{}
	mut targets := []string{}
	for adv in ms.advances {
		if adv.plane == 'aliases' && adv.name == name && adv.kind == 'advance' {
			positions << adv.pos
			targets << adv.hash
		}
	}
	return RefLineage{
		positions: positions
		targets:   targets
	}
}

struct RefBase {
	found     bool
	hash      string
	ours_pos  i64
	their_pos i64
}

// store_reconcile_base finds the greatest ours-position whose target also
// appears in theirs' lineage — the normative common base (L174).
fn store_reconcile_base(ours RefLineage, theirs RefLineage) RefBase {
	for i := ours.targets.len - 1; i >= 0; i-- {
		h := ours.targets[i]
		if h == '' {
			continue
		}
		for k := theirs.targets.len - 1; k >= 0; k-- {
			if theirs.targets[k] == h {
				return RefBase{
					found:     true
					hash:      h
					ours_pos:  ours.positions[i]
					their_pos: theirs.positions[k]
				}
			}
		}
	}
	return RefBase{}
}

// store_reconcile_diff builds the navigable [diff …] of base → side, absent
// (nil) when either doc is unreadable (the conflict still reports; the diff
// is a courtesy payload, never the identity carrier).
fn store_reconcile_diff(ms_base &MemStore, view &PeerView, base_hash string, side_hash string, theirs bool) ?cx.Node {
	if base_hash == '' || side_hash == '' {
		return none
	}
	btext := store_doc_text(ms_base, base_hash) or { return none }
	stext := if theirs {
		view.peer_doc_text(side_hash) or { return none }
	} else {
		store_doc_text(ms_base, side_hash) or { return none }
	}
	bdoc := cx.parse(btext) or { return none }
	sdoc := cx.parse(stext) or { return none }
	if bdoc.elements.len == 0 || sdoc.elements.len == 0 {
		return none
	}
	d := cx_mod_diff([cx.Node(bdoc.elements[0]), cx.Node(sdoc.elements[0])])
	if d is cx.Element && d.name == 'diff' {
		return d
	}
	return none
}

fn store_reconcile_side_node(name string, pos i64, hash string, diff ?cx.Node) cx.Node {
	mut items := []cx.Node{}
	if d := diff {
		items << d
	}
	return cx.Node(cx.Element{
		name:  name
		attrs: [
			cx.Attribute{
				name:  'position'
				value: cx.ScalarValue(pos)
			},
			cx.Attribute{
				name:  'hash'
				value: cx.ScalarValue(hash)
			},
		]
		items: items
	})
}

// store_reconcile_walk runs the examination + applies fast-forwards; the
// caller chooses the enforcing or reporting presentation of the outcome.
fn store_reconcile_walk(dst cx.Node, mut ms_d MemStore, view &PeerView, resolutions map[string]string) cx.Node {
	store_lock_enter(mut ms_d)
	defer {
		store_lock_exit(mut ms_d)
	}
	peer_aliases := view.peer_aliases()
	names := store_reconcile_names(ms_d, view)
	mut identical := 0
	mut advanced := 0
	mut ahead := 0
	mut resolved := 0
	mut children := []cx.Node{}
	mut conflicts := []cx.Node{}
	for name in names {
		ours_cur := ms_d.aliases[name] or { '' }
		theirs_cur := peer_aliases[name] or { '' }
		if ours_cur == theirs_cur {
			identical++
			continue
		}
		if theirs_cur == '' {
			// theirs never had it (or retracted): ours-only is AHEAD —
			// nothing to apply in this direction.
			ahead++
			continue
		}
		ours_lin := store_reconcile_lineage(ms_d, name)
		theirs_lin := view.peer_lineage(name)
		base := store_reconcile_base(ours_lin, theirs_lin)
		ff_create := ours_cur == '' && ours_lin.targets.len == 0
		ff_advance := base.found && ours_cur == base.hash
		if ff_create || ff_advance {
			// FAST-FORWARD: land the target doc when absent, advance through
			// the one live-mutation seam, record durably (the set-alias
			// funnel's own persistence discipline).
			if !store_doc_present(ms_d, theirs_cur) {
				ttext := view.peer_doc_text(theirs_cur) or {
					conflicts << store_reconcile_conflict(name, base, ms_d, view, ours_cur,
						theirs_cur, ours_lin, theirs_lin)
					continue
				}
				tdoc := cx.parse(ttext) or {
					conflicts << store_reconcile_conflict(name, base, ms_d, view, ours_cur,
						theirs_cur, ours_lin, theirs_lin)
					continue
				}
				if tdoc.elements.len > 0 {
					put := store_stdlib_builtin_inner('store-put-doc', [dst,
						cx.Node(tdoc.elements[0])]) or { cx.Node(cx.ScalarNode{}) }
					if put is cx.Element && put.name == 'err' {
						return put
					}
				}
			}
			store_alias_set_local(mut ms_d, name, theirs_cur)
			store_append(mut ms_d, store_alias_record(name, theirs_cur)) or {
				return store_persist_err(ms_d, err.msg())
			}
			advanced++
			children << cx.Node(cx.Element{
				name:  'advance'
				attrs: [
					cx.Attribute{
						name:  'name'
						value: cx.ScalarValue(name)
					},
					cx.Attribute{
						name:  'from'
						value: cx.ScalarValue(ours_cur)
					},
					cx.Attribute{
						name:  'to'
						value: cx.ScalarValue(theirs_cur)
					},
				]
			})
			continue
		}
		if base.found && theirs_cur == base.hash {
			ahead++
			continue
		}
		if rtarget := resolutions[name] {
			// RESOLUTION (merge-as-an-entry, L174): the join is recorded —
			// a stored [merge] record naming both tips + the base as locator
			// triples — and the lineage ADOPTS theirs before advancing to
			// the resolved target, so the next reconcile finds theirs' tip
			// as the common base (ahead, never a re-conflict; pure +
			// replayable: identical input + resolutions ⇒ identical end
			// state).
			if !store_doc_present(ms_d, rtarget) {
				if rtarget == theirs_cur {
					ttext := view.peer_doc_text(theirs_cur) or {
						return mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: resolution target ${rtarget} for ref `${name}` unreadable at the source')
					}
					tdoc := cx.parse(ttext) or {
						return mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: resolution target ${rtarget} for ref `${name}` unparsable')
					}
					if tdoc.elements.len > 0 {
						put := store_stdlib_builtin_inner('store-put-doc', [dst,
							cx.Node(tdoc.elements[0])]) or { cx.Node(cx.ScalarNode{}) }
						if put is cx.Element && put.name == 'err' {
							return put
						}
					}
				} else {
					return mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: resolution target ${rtarget} for ref `${name}` — a resolution names a doc the resolver landed locally (or one side\'s tip)')
				}
			}
			if !store_doc_present(ms_d, theirs_cur) {
				ttext := view.peer_doc_text(theirs_cur) or {
					return mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: theirs tip ${theirs_cur} for ref `${name}` unreadable at the source')
				}
				tdoc := cx.parse(ttext) or {
					return mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: theirs tip ${theirs_cur} for ref `${name}` unparsable')
				}
				if tdoc.elements.len > 0 {
					put := store_stdlib_builtin_inner('store-put-doc', [dst,
						cx.Node(tdoc.elements[0])]) or { cx.Node(cx.ScalarNode{}) }
					if put is cx.Element && put.name == 'err' {
						return put
					}
				}
			}
			skey := store_feed_stream_key('aliases', name)
			ours_pos := if ours_lin.positions.len > 0 {
				ours_lin.positions[ours_lin.positions.len - 1]
			} else {
				i64(0)
			}
			theirs_pos := if theirs_lin.positions.len > 0 {
				theirs_lin.positions[theirs_lin.positions.len - 1]
			} else {
				i64(0)
			}
			mut mrec_items := []cx.Node{}
			if base.found {
				mrec_items << store_reconcile_triple('base', skey, base.ours_pos, base.hash)
			}
			mrec_items << store_reconcile_triple('ours', skey, ours_pos, ours_cur)
			mrec_items << store_reconcile_triple('theirs', skey, theirs_pos, theirs_cur)
			mrec_items << cx.Node(cx.Element{
				name:  'target'
				attrs: [
					cx.Attribute{
						name:  'hash'
						value: cx.ScalarValue(rtarget)
					},
				]
			})
			mrec := cx.Element{
				name:  'merge'
				attrs: [
					cx.Attribute{
						name:  'ref'
						value: cx.ScalarValue(name)
					},
				]
				items: mrec_items
			}
			rput := store_stdlib_builtin_inner('store-put-doc', [dst, cx.Node(mrec)]) or {
				cx.Node(cx.ScalarNode{})
			}
			if rput is cx.Element && rput.name == 'err' {
				return rput
			}
			rec_hash := if rput is cx.ScalarNode {
				cx.scalar_value_str_public(rput.value)
			} else {
				''
			}
			// the join rides the lineage: adopt theirs, then the target.
			store_alias_set_local(mut ms_d, name, theirs_cur)
			store_append(mut ms_d, store_alias_record(name, theirs_cur)) or {
				return store_persist_err(ms_d, err.msg())
			}
			if rtarget != theirs_cur {
				store_alias_set_local(mut ms_d, name, rtarget)
				store_append(mut ms_d, store_alias_record(name, rtarget)) or {
					return store_persist_err(ms_d, err.msg())
				}
			}
			resolved++
			children << cx.Node(cx.Element{
				name:  'resolved'
				attrs: [
					cx.Attribute{
						name:  'name'
						value: cx.ScalarValue(name)
					},
					cx.Attribute{
						name:  'to'
						value: cx.ScalarValue(rtarget)
					},
					cx.Attribute{
						name:  'record'
						value: cx.ScalarValue(rec_hash)
					},
				]
			})
			continue
		}
		conflicts << store_reconcile_conflict(name, base, ms_d, view, ours_cur, theirs_cur,
			ours_lin, theirs_lin)
	}
	mut items := children.clone()
	for c in conflicts {
		items << c
	}
	mut rattrs := [
		cx.Attribute{
			name:  'ok'
			value: cx.ScalarValue(conflicts.len == 0)
		},
		cx.Attribute{
			name:  'refs'
			value: cx.ScalarValue(i64(names.len))
		},
		cx.Attribute{
			name:  'identical'
			value: cx.ScalarValue(i64(identical))
		},
		cx.Attribute{
			name:  'advanced'
			value: cx.ScalarValue(i64(advanced))
		},
		cx.Attribute{
			name:  'ahead'
			value: cx.ScalarValue(i64(ahead))
		},
		cx.Attribute{
			name:  'conflicts'
			value: cx.ScalarValue(i64(conflicts.len))
		},
	]
	// resolved= appears only when the resolution seam ENGAGED (the L119
	// present-when-non-zero posture — resolution-free reports stay
	// byte-identical to the pre-resolutions shape).
	if resolved > 0 {
		rattrs << cx.Attribute{
			name:  'resolved'
			value: cx.ScalarValue(i64(resolved))
		}
	}
	return cx.Node(cx.Element{
		name:  'reconcile-report'
		attrs: rattrs
		items: items
	})
}

// store_reconcile_triple is one locator triple of the recorded join
// (stream, position, hash — the #717 rule on the alias lineage).
fn store_reconcile_triple(name string, stream string, pos i64, hash string) cx.Node {
	return cx.Node(cx.Element{
		name:  name
		attrs: [
			cx.Attribute{
				name:  'stream'
				value: cx.ScalarValue(stream)
			},
			cx.Attribute{
				name:  'position'
				value: cx.ScalarValue(pos)
			},
			cx.Attribute{
				name:  'hash'
				value: cx.ScalarValue(hash)
			},
		]
	})
}

// store_reconcile_resolutions reads opts.resolutions — a sequence of
// [resolve ref= target=] items (the resolutions-as-an-input-table seam).
fn store_reconcile_resolutions(args []cx.Node) map[string]string {
	mut out := map[string]string{}
	if args.len < 3 {
		return out
	}
	opts := args[2]
	if opts is cx.Element {
		for it in opts.items {
			if it is cx.Element && it.name == 'resolutions' {
				for r in it.items {
					if r is cx.Element && r.name == 'resolve' {
						rf := r.attr('ref')
						tg := r.attr('target')
						if rf != '' && tg != '' {
							out[rf] = tg
						}
					}
				}
			}
		}
	}
	return out
}

fn store_reconcile_conflict(name string, base RefBase, ms_d &MemStore, view &PeerView, ours_cur string, theirs_cur string, ours_lin RefLineage, theirs_lin RefLineage) cx.Node {
	ours_pos := if ours_lin.positions.len > 0 {
		ours_lin.positions[ours_lin.positions.len - 1]
	} else {
		i64(0)
	}
	theirs_pos := if theirs_lin.positions.len > 0 {
		theirs_lin.positions[theirs_lin.positions.len - 1]
	} else {
		i64(0)
	}
	mut items := []cx.Node{}
	if base.found {
		items << cx.Node(cx.Element{
			name:  'base'
			attrs: [
				cx.Attribute{
					name:  'position'
					value: cx.ScalarValue(base.ours_pos)
				},
				cx.Attribute{
					name:  'hash'
					value: cx.ScalarValue(base.hash)
				},
			]
		})
	}
	items << store_reconcile_side_node('ours', ours_pos, ours_cur, store_reconcile_diff(ms_d,
		view, base.hash, ours_cur, false))
	items << store_reconcile_side_node('theirs', theirs_pos, theirs_cur, store_reconcile_diff(ms_d,
		view, base.hash, theirs_cur, true))
	items << cx.Node(cx.Element{
		name:  'cas'
		attrs: [
			cx.Attribute{
				name:  'code'
				value: cx.ScalarValue('CXER1114')
			},
			cx.Attribute{
				name:  'expect-pos'
				value: cx.ScalarValue(base.ours_pos)
			},
			cx.Attribute{
				name:  'actual-pos'
				value: cx.ScalarValue(ours_pos)
			},
		]
	})
	return cx.Node(cx.Element{
		name:  'conflict'
		attrs: [
			cx.Attribute{
				name:  'subject'
				value: cx.ScalarValue(name)
			},
			cx.new_attribute('kind', cx.ScalarValue('diverged-advance'), cx.AttributeMeta{
				data_type: 'atom'
			}),
		]
		items: items
	})
}

// store_reconcile_impl serves both verbs: enforcing=true raises iff the
// report says ok=false (raise ⟺ ok=false — the agreement law), carrying
// every [conflict] as err children; enforcing=false returns the report.
fn store_reconcile_impl(args []cx.Node, enforcing bool) ?cx.Node {
	if args.len < 2 {
		return mk_err('cx-err:CXER0108', 'E_ARG: reconcile expects ($store, $source, $opts?)')
	}
	mut ms_d, derr, dok := store_get_open(args[0])
	if !dok {
		return derr
	}
	mut ms_s, serr, sok := store_get_open(args[1])
	if !sok {
		return serr
	}
	if ms_d.read_only {
		return mk_err('cx-err:CXER1110', 'E_STORE_READ_ONLY: ${ms_d.url}')
	}
	if store_remote_active(ms_d) {
		return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: reconcile mutates OURS locally — the destination must be a local store (sync FROM a remote peer; the daemon reconciles its own)')
	}
	view := store_peer_view(args[1], mut ms_s) or {
		return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: the reconciliation peer must be a local store or a service-tier (cx-store://) remote — a byte source has no lineage to ask')
	}
	resolutions := store_reconcile_resolutions(args)
	report := store_reconcile_walk(args[0], mut ms_d, &view, resolutions)
	if report is cx.Element && report.name == 'err' {
		return report
	}
	if !enforcing {
		return report
	}
	mut ok := false
	mut advanced := '0'
	mut nconf := '0'
	mut conflict_children := []cx.Node{}
	if report is cx.Element {
		ok = report.attr('ok') == 'true'
		advanced = report.attr('advanced')
		nconf = report.attr('conflicts')
		for it in report.items {
			if it is cx.Element && it.name == 'conflict' {
				conflict_children << it
			}
		}
	}
	if ok {
		return report
	}
	// The enforcing raise (agreement law): the err CARRIES every conflict
	// value + the partial-success accounting — reported, never silent.
	return cx.Node(cx.Element{
		name:  'err'
		attrs: [
			cx.Attribute{
				name:  'code'
				value: cx.ScalarValue(sync_err_diverged)
			},
			cx.Attribute{
				name:  'message'
				value: cx.ScalarValue('E_SYNC_DIVERGED: ${nconf} ref(s) diverged (${advanced} fast-forward(s) applied — partial success reported); each [conflict] child carries base/ours/theirs with patchable diffs; resolve and re-sync (distributed_store §4)')
			},
		]
		items: conflict_children
	})
}

// ── W5: the dry classification — status ahead/behind vs a peer ─────────────
//
// (L177, #719 item 1's peer half.) The SAME examination the reconcile walk
// runs, with NOTHING applied: per branch-class alias ref, classify ours vs
// theirs as :identical / :ahead (ours moved past the common base, theirs
// did not) / :behind (the fast-forward case — theirs moved, ours did not,
// including theirs-only creation) / :diverged (both moved). Positions are
// each side's OWN dense E3 coordinates (never compared numerically across
// stores — a position is a local coordinate; the CLASSIFICATION is the
// cross-store fact).

struct RefClass {
	name       string
	state      string
	ours_pos   i64
	theirs_pos i64
}

fn store_reconcile_classify(ms_d &MemStore, view &PeerView) []RefClass {
	names := store_reconcile_names(ms_d, view)
	peer_aliases := view.peer_aliases()
	mut out := []RefClass{}
	for name in names {
		ours_cur := ms_d.aliases[name] or { '' }
		theirs_cur := peer_aliases[name] or { '' }
		ours_lin := store_reconcile_lineage(ms_d, name)
		theirs_lin := view.peer_lineage(name)
		ours_pos := if ours_lin.positions.len > 0 {
			ours_lin.positions[ours_lin.positions.len - 1]
		} else {
			i64(0)
		}
		theirs_pos := if theirs_lin.positions.len > 0 {
			theirs_lin.positions[theirs_lin.positions.len - 1]
		} else {
			i64(0)
		}
		mut state := 'diverged'
		if ours_cur == theirs_cur {
			state = 'identical'
		} else if theirs_cur == '' {
			state = 'ahead'
		} else if ours_cur == '' && ours_lin.targets.len == 0 {
			state = 'behind'
		} else {
			base := store_reconcile_base(ours_lin, theirs_lin)
			if base.found && ours_cur == base.hash {
				state = 'behind'
			} else if base.found && theirs_cur == base.hash {
				state = 'ahead'
			}
		}
		out << RefClass{
			name:       name
			state:      state
			ours_pos:   ours_pos
			theirs_pos: theirs_pos
		}
	}
	return out
}

// store_status_peer builds status's [peer …] block from the classification.
fn store_status_peer(ms &MemStore, view &PeerView, peer_url string) cx.Node {
	classes := store_reconcile_classify(ms, view)
	mut identical := 0
	mut ahead := 0
	mut behind := 0
	mut diverged := 0
	mut children := []cx.Node{}
	for c in classes {
		match c.state {
			'identical' { identical++ }
			'ahead' { ahead++ }
			'behind' { behind++ }
			else { diverged++ }
		}
		children << cx.Node(cx.Element{
			name:  'stream'
			attrs: [
				cx.Attribute{
					name:  'name'
					value: cx.ScalarValue('aliases/' + c.name)
				},
				cx.new_attribute('state', cx.ScalarValue(c.state), cx.AttributeMeta{
					data_type: 'atom'
				}),
				cx.Attribute{
					name:  'ours-pos'
					value: cx.ScalarValue(c.ours_pos)
				},
				cx.Attribute{
					name:  'theirs-pos'
					value: cx.ScalarValue(c.theirs_pos)
				},
			]
		})
	}
	return cx.Node(cx.Element{
		name:  'peer'
		attrs: [
			cx.Attribute{
				name:  'url'
				value: cx.ScalarValue(peer_url)
			},
			cx.Attribute{
				name:  'identical'
				value: cx.ScalarValue(i64(identical))
			},
			cx.Attribute{
				name:  'ahead'
				value: cx.ScalarValue(i64(ahead))
			},
			cx.Attribute{
				name:  'behind'
				value: cx.ScalarValue(i64(behind))
			},
			cx.Attribute{
				name:  'diverged'
				value: cx.ScalarValue(i64(diverged))
			},
		]
		items: children
	})
}
