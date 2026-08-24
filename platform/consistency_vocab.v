module platform

import cx
import code { mk_err }

// consistency_vocab.v — the ONE authority for the stream-7 declare-and-verify
// consistency vocabulary (spec/03-approved/core/consistency_vocabulary.md, letters
// L122–L125; campaign #679). Every consistency-bearing surface (journal open/
// attach floors first; store/fabric/xsp floors follow with their waves) parses
// declarations and builds refusals THROUGH this file — a second token list or
// a second refusal shape is a drift hole.
//
// The vocabulary is a CLOSED set of atoms (closure is a MUST: an unknown
// token is a typed error, never ignored) and a lattice of independent
// conjuncts, not a level ladder. Satisfy-or-reject, fail-loud, never
// approximate. `:exactly-once` and `:serializable` are in the closed set as
// PERMANENT teaching refusals — the refusal names the answer ([idempotent] /
// stream 10's coordination design) instead of leaving the caller to assume.

// ── error band CXER4990–4999 (consistency_vocabulary.md §5; governance §9.6) ─

const cst_err_unsatisfiable = 'cx-err:CXER4990' // E_CONSISTENCY_UNSATISFIABLE
const cst_err_pin_uncoverable = 'cx-err:CXER4991' // E_CONSISTENCY_PIN_UNCOVERABLE

// cst_closed_set — the L122 closed vocabulary, bare atom names (the surface
// spelling is `:name`). `snapshot-isolation`, `causal`, `eventual` are OUT
// entirely (admitting them as refusals implies roadmap); `valid-at` is a
// bitemporal query parameter, not a consistency token (the two axes never
// fuse).
const cst_closed_set = [
	'prefix-consistent',
	'at-seq-pinned',
	'at-head-set',
	'linearizable-ref',
	'read-your-writes',
	'monotonic-reads',
	'gapless',
	'at-least-once',
	'exactly-once',
	'serializable',
]

// cst_consumer_checkable — the two tokens whose checks a CONSUMER surface
// can run unconditionally against its own cursor (stream 3's live rung=
// opt accepts exactly these two alongside its adapter-ladder atoms — one
// name authority, no drift).
const cst_consumer_checkable = ['monotonic-reads', 'gapless']

// cst_atom builds an atom-typed scalar node (renders `:name`).
fn cst_atom(name string) cx.Node {
	return cx.ScalarNode{
		data_type: cx.ScalarType.atom_type
		value:     cx.ScalarValue(name)
	}
}

// cst_kv builds a one-child context element, e.g. [token :gapless].
fn cst_kv(name string, child cx.Node) cx.Node {
	return cx.Element{
		name:  name
		items: [child]
	}
}

// cst_context assembles the D-C1 structured naming children on a refusal:
// [context [stage :s] [token …] [surface '…'] [guarantees :a :b …] [answer '…']?].
// The token child is an ATOM for closed-set spellings and the offending
// VALUE verbatim for out-of-vocabulary ones (a string spelling renders
// quoted — visibly not an atom).
fn cst_context(stage string, token cx.Node, surface string, guarantees []string, answer string) cx.Node {
	mut items := []cx.Node{}
	items << cst_kv('stage', cst_atom(stage))
	items << cst_kv('token', token)
	items << cst_kv('surface', jrn_str(surface))
	if guarantees.len > 0 {
		mut g := []cx.Node{}
		for t in guarantees {
			g << cst_atom(t)
		}
		items << cx.Node(cx.Element{
			name:  'guarantees'
			items: g
		})
	}
	if answer != '' {
		items << cst_kv('answer', jrn_str(answer))
	}
	return cx.Element{
		name:  'context'
		items: items
	}
}

// cst_refusal builds the CXER4990 refusal err VALUE (declarations refuse
// loudly — §5): [err code= message= [context …]]. The message carries the
// human sentence; the context children carry the machine-checkable D-C1
// naming (failing stage + failing token + surface + the advertised set).
fn cst_refusal(stage string, token cx.Node, token_text string, surface string, guarantees []string, why string, answer string) cx.Node {
	msg := 'E_CONSISTENCY_UNSATISFIABLE: ${token_text} at ${surface} (stage ${stage}) — ${why}'
	e := mk_err(cst_err_unsatisfiable, msg)
	mut ee := e as cx.Element
	ee.items << cst_context(stage, token, surface, guarantees, answer)
	return cx.Node(ee)
}

// cst_pin_refusal builds the CXER4991 companion (a declared position no
// longer resolvable, AFTER the resolve-through-covering-snapshot rule):
// [err code= message= [context [stage :read] [token …] [surface '…']
// [requested N] [floor B] [resolve-through '…']]].
fn cst_pin_refusal(surface string, token string, requested int, floor int, resolve string) cx.Node {
	msg := 'E_CONSISTENCY_PIN_UNCOVERABLE: :${token} at ${surface} — position ${requested} needs the pruned prefix (retained floor is ${floor}); ${resolve}'
	e := mk_err(cst_err_pin_uncoverable, msg)
	mut ee := e as cx.Element
	mut items := []cx.Node{}
	items << cst_kv('stage', cst_atom('read'))
	items << cst_kv('token', cst_atom(token))
	items << cst_kv('surface', jrn_str(surface))
	items << cst_kv('requested', jrn_int(requested))
	items << cst_kv('floor', jrn_int(floor))
	items << cst_kv('resolve-through', jrn_str(resolve))
	ee.items << cx.Node(cx.Element{
		name:  'context'
		items: items
	})
	return cx.Node(ee)
}

// cst_read_declared reads the `consistency` opts key (child-element map form,
// the `{k: v}` literal): one atom or a `(…, …)` sequence of atoms. Tokens are
// TYPE-STRICT atoms — a string spelling is refused (stage `vocabulary`), so a
// quoted near-miss can never silently declare. Absent key → (empty, ok).
// Returns (tokens, refusal-err, ok).
fn cst_read_declared(opts cx.Node, surface string) ([]string, cx.Node, bool) {
	empty := jrn_empty()
	m := opts
	if m is cx.Element {
		if m.name == '__cx_map__' || m.name == 'map' {
			for it in m.items {
				if it is cx.Element && it.name == 'consistency' {
					mut toks := []string{}
					for v in m_key_values(it) {
						if v is cx.ScalarNode {
							if v.data_type == .atom_type {
								sv := v.value
								if sv is string {
									toks << sv
									continue
								}
							}
						}
						// non-atom value: refuse with the offending value verbatim
						return []string{}, cst_refusal('vocabulary', v, cst_value_text(v),
							surface, [], 'consistency tokens are atoms from the closed vocabulary — a non-atom spelling never declares silently', ''), false
					}
					return toks, empty, true
				}
			}
		}
	}
	return []string{}, empty, true
}

// m_key_values flattens a map key element's value position: a single scalar
// child, or the items of a sequence child.
fn m_key_values(key cx.Element) []cx.Node {
	mut out := []cx.Node{}
	for v in key.items {
		if v is cx.Element && (v.name == code.seq_marker_name || v.name == '') {
			for s in v.items {
				out << s
			}
		} else {
			out << v
		}
	}
	return out
}

// cst_value_text renders a token value for the refusal message (`:name` for
// atoms, the quoted image otherwise).
fn cst_value_text(v cx.Node) string {
	if v is cx.ScalarNode {
		sv := v.value
		if sv is string {
			if v.data_type == .atom_type {
				return ':${sv}'
			}
			return '"${sv}"'
		}
	}
	return 'non-atom value'
}

// cst_check_floor validates a declared token list ONCE, at declaration time,
// against the surface's advertised guarantee set (L123 — the handle/session
// floor; the CSRP pre-flight model). Order of scrutiny per token: closed-set
// membership (unknown → stage `vocabulary`), the two teaching refusals, then
// the advert. Returns the first refusal, or none when every token is
// satisfied.
fn cst_check_floor(declared []string, surface string, advert []string) ?cx.Node {
	for t in declared {
		if t !in cst_closed_set {
			return cst_refusal('vocabulary', cst_atom(t), ':${t}', surface, [],
				'unknown token — the consistency vocabulary is a closed set; unknown tokens are typed errors, never ignored', '')
		}
		if t == 'exactly-once' {
			return cst_refusal('floor', cst_atom(t), ':${t}', surface, advert,
				'permanently refused — exactly-once delivery is not a property any substrate can promise end-to-end; declare the command [idempotent] (code.md command clauses) and retry: effect-boundary dedup answers the replay',
				'[idempotent]')
		}
		if t == 'serializable' {
			// stream 10 SHIPPED (L160): the refusal retargets to the live
			// escrow/saga pattern — the intent :serializable names is
			// satisfiable as reserve-then-confirm without a global
			// serialization point.
			return cst_refusal('floor', cst_atom(t), ':${t}', surface, advert,
				'refused — no surface advertises a global serial order; the intent is the stream-10 escrow/saga pattern: reserve-then-confirm ([$authz:allocate] escrow), a [requires-at] admission pin at the commit point, and [$journal:saga-run] choreography (cross_stream_coordination)',
				'the stream-10 escrow/saga pattern (reserve-then-confirm; [requires-at]; saga-run)')
		}
		if t !in advert {
			return cst_refusal('floor', cst_atom(t), ':${t}', surface, advert,
				'the surface does not advertise this guarantee — satisfy-or-reject, never approximate', '')
		}
	}
	return none
}
