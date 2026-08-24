module code

import cx

// stdlib_diagram.v — the ONE native primitive behind cx-stdlib/diagram's
// caller-facing surface (#889, RULED DRW3-1/DRW3-3/DRW3-4 —
// ledger/rulings_2026_08_20_diagram_wave3.md).
//
// The renderer itself is CX (stdlib/diagram.cx). What CX cannot do is
// PARSE: the module's public entry points (`of-source`, `code-diagram`)
// take SOURCE TEXT and must reach the engine's parser to obtain the
// program image the emitters read. DR-7(a) rules that image
// engine-injected; DRW3-3 moves the injection point from the wave-1
// seam into this primitive so the module — not its caller — owns the
// ingress. Nothing here produces a byte of diagram text.
//
//   [$diagram-program-image SRC MODE] → program image | [err …]
//
//     MODE = "ref"  — the DRW1-1 image exactly as the wave-1/2 seam
//                     builds it (`diagram_lower`): the ast.md §4
//                     structural projection materialized as a CXDM tree.
//                     Feeds `of-source` and the reference renderer, so
//                     no wave-1/2 golden can move.
//     MODE = "code" — the same image plus the DRW3-4 `[?def]` expansion
//                     (see diagram_lower_code): the playground renderer
//                     reads def NAME + BODY as structure, never as the
//                     deferred `raw-source` text the parser hands over.
//
// A parse failure is an err VALUE, not a thrown EvalError: the CX side
// coalesces it with `[?else]` and degrades to the text-level
// classification the shipped emitter degrades to (wave-2 finding C14 —
// binding an err in a `[?let]` propagates railway-style).

//     MODE = "effects" — the "code" image plus a `<cx:lib-image>` child
//                     on every `[?lib]` (RULED: DGX-1e). Feeds the
//                     effect/capability graph, whose callee resolution
//                     needs the alias an import binds — text the parser
//                     defers exactly as it defers a `[?def]` body.
//
// The SECOND primitive (RULED: DGX-1a) hands the module the engine's
// LIVE capability tables rather than a copy:
//
//   [$diagram-effect-table] → [effect-table [cap …] [prim …] [impure …]]
//
// The prim→capability map is `security.md` §2.1's normative closed set,
// mirrored by effect_alignment.v and held to it in both directions by
// `make check-effect-alignment`. A capability diagram built on a STALE
// copy of that table can only fail one way — silently omitting a
// newly-gated effect point — and a capability diagram that quietly
// under-reports is worse than none. So the module reads it live and
// cannot drift from it by construction.

fn diagram_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	match name {
		'diagram-program-image' {
			return diagram_program_image_prim(args)
		}
		'diagram-effect-table' {
			return diagram_effect_table_prim()
		}
		else {
			return none
		}
	}
}

// diagram_effect_table_prim projects the engine's live effect
// classification as ONE data value:
//
//   [cap name=…]           — the capability roster, `capability_names()`
//                            (the same list `--allow-<name>` accepts and
//                            the CLI help is generated from), in order.
//   [prim name=… cap=…]    — every capability-gated effect point,
//                            `capability_gated_prims()`.
//   [impure name=…]        — a primitive the purity classifier calls
//                            impure that charges NO capability: the
//                            §6.5.1 closed exception table (bare
//                            `print`, the state-bearing PRNG, the mock
//                            clock, …). Rendered at the `full` rung as
//                            an UNCHARGED effect — honest about the
//                            fact that "needs no grant" is not the same
//                            as "does nothing".
//
// Rows are sorted so the value is deterministic across V map iteration
// order — the renderer's output is golden-pinned.
fn diagram_effect_table_prim() cx.Node {
	mut kids := []cx.Node{}
	for c in capability_names() {
		kids << cx.Node(cx.Element{
			name:  'cap'
			attrs: [cx.Attribute{
				name:  'name'
				value: cx.ScalarValue(c)
			}]
		})
	}
	gated := capability_gated_prims()
	mut prim_names := gated.keys()
	prim_names.sort()
	for p in prim_names {
		kids << cx.Node(cx.Element{
			name:  'prim'
			attrs: [
				cx.Attribute{
					name:  'name'
					value: cx.ScalarValue(p)
				},
				cx.Attribute{
					name:  'cap'
					value: cx.ScalarValue(gated[p])
				},
			]
		})
	}
	mut uncharged := []string{}
	for n in impure_builtin_names() {
		if n !in gated {
			uncharged << n
		}
	}
	uncharged.sort()
	for n in uncharged {
		kids << cx.Node(cx.Element{
			name:  'impure'
			attrs: [cx.Attribute{
				name:  'name'
				value: cx.ScalarValue(n)
			}]
		})
	}
	// Ring-2 pack verbs the packs declared impure. Their capability
	// charge is made INSIDE the pack (`cap_guard` at the pack's own
	// dispatch site) and is registered at runtime, so it is not in the
	// static §2.1 table and this graph cannot name it. Listing them
	// SEPARATELY is what lets the renderer say so — an opacity source
	// (DGX-1c `ring2`) rather than a silent classification as pure.
	for n in ring2_impure_names() {
		if n !in gated {
			kids << cx.Node(cx.Element{
				name:  'ring2'
				attrs: [cx.Attribute{
					name:  'name'
					value: cx.ScalarValue(n)
				}]
			})
		}
	}
	// The frozen `cx-stdlib/*` roster, by its PRIM PREFIX (the last
	// resolver segment — `cx-stdlib/io` backs the `io-*` primitives).
	// This is what lets callee resolution tell a bundled module's verb
	// from an opaque one: `[$io:read-file]` and an aliased
	// `[$fs:read-file]` both resolve to `io-read-file` and charge
	// `read`, while `[$mymod:read-file]` resolves to NOTHING and must
	// render as an unknown edge (DGX-1c `call` / `lib`) rather than be
	// silently dropped as "probably pure".
	for m in bundled_stdlib_names() {
		kids << cx.Node(cx.Element{
			name:  'module'
			attrs: [
				cx.Attribute{
					name:  'name'
					value: cx.ScalarValue(m.all_after_last('/'))
				},
				cx.Attribute{
					name:  'resolver'
					value: cx.ScalarValue(m)
				},
			]
		})
	}
	return cx.Node(cx.Element{
		name:  'effect-table'
		items: kids
	})
}

fn diagram_program_image_prim(args []cx.Node) cx.Node {
	if args.len < 1 {
		return mk_err('cx-err:CXER0100', 'diagram-program-image: expected (source[, mode])')
	}
	src := arg_string(args[0]) or {
		return mk_err('cx-err:CXER0100', 'diagram-program-image: source must be a string')
	}
	mode := if args.len > 1 {
		arg_string(args[1]) or { 'ref' }
	} else {
		'ref'
	}
	prog := cx.parse_program(src) or {
		// RULED: D910-1 (#910) — the ingress applies the run surface's
		// guarded DATA fallback (the eval_code contract, same guards):
		// a document the PROGRAM reading refuses but the DATA reading
		// accepts lifts as data, so the data language's own documents
		// (prose bodies, bare URLs/paths — the shipped examples/config.cx)
		// are diagrammable. Unambiguous program intent stays fail-loud:
		// unknown/retired directives, program-committed syntax errors,
		// and any source whose data reading carries a registered
		// [?directive].
		no_data_fallback := if err is cx.ParseError {
			err.unknown_directive || err.program_committed
		} else {
			false
		}
		if !no_data_fallback && !data_reading_has_program_directive(src) {
			if doc := cx.parse(src) {
				if img := diagram_data_image(doc) {
					return img
				}
			}
		}
		return mk_err('cx-err:CXER0100', 'diagram-program-image: parse: ${err.msg()}')
	}
	if mode == 'code' {
		return diagram_lower_code(cx.ProgramNode(prog.body))
	}
	if mode == 'effects' {
		return diagram_lower_effects(cx.ProgramNode(prog.body))
	}
	return diagram_lower(cx.ProgramNode(prog.body))
}
