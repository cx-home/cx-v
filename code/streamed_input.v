@[has_globals]
module code

import cx

// ── The [?for] streamed-input fast path (§11.6 gate-15; stream 17 W5,
// L91 — the parser_streaming disposition) ────────────────────────────
//
// When the streaming program body is the canonical
// `[?for [in $u $doc/user] [yield $u]]` shape, the input document is
// never materialized: cx.open_top_level_children pulls top-level
// children one at a time, each match is namespace/lang-resolved under
// the root's context (identical to a whole-document resolve — both
// scopes are lexical and downward), and the ordinary streamed clause
// runner executes per match. Peak input working set is ONE child
// subtree instead of the whole document AST.
//
// TRANSPARENCY POSTURE — the fast path engages only when its answer
// is provably the materializing path's answer, and it COMMITS (emits)
// only once equivalence is decided:
//
//  * Program side (streamed_input_plan): the first clause's source
//    must be `$doc`/`$input` with 1–2 plain child steps (no
//    predicates); the SOURCE TEXT may spell `$doc`/`$input` exactly
//    once (that source) — a conservative byte scan, so a reference
//    anywhere else (yield body, later clauses, strings that would
//    interpolate) declines; `..` anywhere declines (the parent
//    axis's $doc-scan fallback needs the whole document); a rooted
//    path spelling (`/x`, `//x`, `/@a`, `/*` at expression position)
//    anywhere declines — rooted paths read $doc, which the fast path
//    never binds (#806).
//  * Input side (streamed_input_safe): `&` anywhere, a `#id`
//    declaration candidate, or a `@name` reference candidate declines
//    — resolve_ids is document-global (anchors, #id declarations and
//    @ references cross children). The name predicate is the PARSER's
//    ([L10a] full Unicode), not the ASCII subset (#806). In-string
//    false positives only lose the fast path, never correctness.
//  * DEFERRED COMMIT: matches buffer until the SECOND arrives. A walk
//    that ends with 0 or 1 total matches DECLINES — nothing was
//    emitted, and the caller re-runs the materializing path, which
//    owns every low-cardinality subtlety verbatim (the single-match
//    field-read shape, the #21 lone-collection unwrap, the
//    `__cx_slot:` fallback that fires only when NO bare-named child
//    matched). Multi-match walks are plain node-set iteration on both
//    paths, so streaming them is exact.
//  * The head + tail are validated by the reader (the head via a real
//    cx.parse of its slice; the tail must be empty), and every child
//    goes through the real parser.
//  * ONE WALK (#804 leg 3, ruled 1a). There used to be a full
//    validation pass before the evaluation pass, so that an input the
//    materializing path would refuse ALWAYS declined pre-emission. It
//    was removed because it was measurably the binding constraint on
//    §11.4.4: the two-pass ceiling is 201.7 MB/s against a 200 MB/s
//    floor, so a perfect evaluation pass still could not pass the gate.
//    Input errors now behave as EVAL-time errors already did — partial
//    chunks may precede the failure, which is the streaming mode's
//    stated contract. Deferred commit still covers everything up to the
//    second match, so an input whose error precedes its second match
//    declines with nothing emitted and falls back verbatim, exactly as
//    before. The accepted-input set is unchanged; only the moment a
//    late refusal is discovered has moved.

__global (
	// The #804 leg-2 runtime kill switch — see lazy_records_disabled.
	g_lazy_records_off bool
	// Commit counter — the live witness that the fast path ENGAGED
	// (not silently fell back), asserted by the parity fixtures so
	// the seam can never go quietly dead again.
	g_streamed_input_commits u64
)

// streamed_input_commits reports how many times the streamed-input
// fast path has COMMITTED (emitted from a streamed walk) in this
// process. Test/diagnostic surface.
pub fn streamed_input_commits() u64 {
	return g_streamed_input_commits
}

// lazy_records_disabled reports whether the #804 leg-2 mechanism is withdrawn.
//
// TWO switches, and they exist for different reasons.
//
// `-d cx_no_lazy_record` is the BUILD switch: with it, `cx.LazyRecord` is
// never constructed anywhere, so a build can be shipped that cannot contain
// the variant at all.
//
// `g_lazy_records_off` is the RUNTIME switch, and it is what makes ruling
// 1a's differential a real gate rather than a release ritual. Because it is
// runtime, ONE test binary can evaluate the same program both ways and
// compare the bytes — so the differential runs on every suite run instead of
// only when someone remembers to build twice. That matters: the forcing
// discipline is verified rather than guaranteed (1,323 of the tree's
// `is Element` sites are silent `if`-form tests, so the compiler cannot
// help), and a verification that runs rarely is most of the way back to no
// verification at all.
@[inline]
fn lazy_records_disabled() bool {
	$if cx_no_lazy_record ? {
		return true
	}
	return g_lazy_records_off
}

// set_lazy_records_off toggles the runtime switch. Test/diagnostic surface —
// the differential harness uses it to run both arms in one process.
pub fn set_lazy_records_off(off bool) {
	g_lazy_records_off = off
}

// lazy_records_active reports whether a lazy record could be built right now.
// Lets the differential assert it is actually exercising the lazy arm rather
// than comparing the strict path against itself — the vacuous-pass shape this
// project keeps meeting.
pub fn lazy_records_active() bool {
	return !lazy_records_disabled()
}

// StreamedInputPlan is the verified program-side shape: the generator
// clause and its 1–2 child steps.
struct StreamedInputPlan {
	steps  []cx.ProgramPathStep
	clause cx.ProgramForClause
	// needs_position — see YieldSpec.needs_position (#804 leg 6). Computed
	// here because this is where the program SOURCE is in scope.
	needs_position bool
}

// streamed_source_steps verifies the SOURCE-EXPRESSION side of the fast path:
// the source must be `$doc`/`$input` navigated by 1–2 plain child steps (no
// predicates). Returns the step list, or none to decline.
//
// Factored out of streamed_input_plan for #845 so the `[?map]` lane asks the
// SAME question of its source slot that the `[?for]` lane asks of its first
// generator clause — `[?map $doc/user [using …]]` is the same access shape as
// `[?for [in $u $doc/user] …]`, and a second copy of this test would be free
// to drift from it.
fn streamed_source_steps(src cx.ProgramNode) ?[]cx.ProgramPathStep {
	if src !is cx.ProgramBinding {
		return none
	}
	b := src as cx.ProgramBinding
	if b.name != 'doc' && b.name != 'input' {
		return none
	}
	if b.path.len < 1 || b.path.len > 2 {
		return none
	}
	for st in b.path {
		if st.kind != .child || st.predicates.len > 0 {
			return none
		}
	}
	return b.path
}

// streamed_source_scans_ok is the conservative PROGRAM-TEXT side, shared by
// both lanes (#845): exactly ONE `$doc`/`$input` spelling in the whole program
// (the verified source), no parent axis, and no rooted-path spelling — rooted
// paths read $doc, which the fast path never binds (#806). Over-matching (e.g.
// inside a string) only declines the fast path, never changes an answer.
fn streamed_source_scans_ok(program_src string) bool {
	if count_binding_spelling(program_src, 'doc') + count_binding_spelling(program_src, 'input') != 1 {
		return false
	}
	if program_src.contains('..') {
		return false
	}
	if has_rooted_path_spelling(program_src) {
		return false
	}
	return true
}

// streamed_input_plan verifies the program side of the fast path.
fn streamed_input_plan(f cx.ProgramForComp, program_src string) ?StreamedInputPlan {
	if f.clauses.len == 0 {
		return none
	}
	c0 := f.clauses[0]
	if c0.kind != .generator {
		return none
	}
	src := c0.source or { return none }
	steps := streamed_source_steps(src) or { return none }
	if !streamed_source_scans_ok(program_src) {
		return none
	}
	return StreamedInputPlan{
		steps:  steps
		clause: c0
		// Conservative, like the scans above: if the spelling appears
		// anywhere in the program text we bind `$_position`. An over-match
		// costs one allocation per item; it can never change an answer.
		needs_position: program_src.contains('\$_position')
	}
}

// count_binding_spelling counts occurrences of `$<name>` NOT followed
// by a further name character (so `$doc2` never counts as `$doc`).
fn count_binding_spelling(src string, name string) int {
	pat := '$' + name
	mut n := 0
	mut from := 0
	for {
		idx := src.index_after(pat, from) or { break }
		after := idx + pat.len
		if after >= src.len || !cx.is_name_char_b(src[after]) {
			n++
		}
		from = idx + 1
	}
	return n
}

// has_rooted_path_spelling detects document-rooted path candidates
// (`/name`, `//name`, `/@attr`, `/*`) at expression position — after
// whitespace or `[`, or at the very start. Rooted paths read $doc,
// which the fast path never binds; declining them keeps
// success/refusal parity (#806). The `/` operator head (`[/ $x 2]`,
// space-followed) is NOT a candidate. In-string false positives only
// lose the fast path, never correctness.
fn has_rooted_path_spelling(src string) bool {
	for i in 0 .. src.len {
		if src[i] != `/` {
			continue
		}
		at_expr_pos := i == 0 || src[i - 1] in [u8(` `), `\t`, `\n`, `\r`, `[`]
		if !at_expr_pos || i + 1 >= src.len {
			continue
		}
		f := src[i + 1]
		if f == `/` || f == `@` || f == `*` || name_start_at(src, i + 1) {
			return true
		}
	}
	return false
}

// name_start_at reports whether the character starting at src[i] is a
// name-start character — the PARSER's predicate ([L10a] full-Unicode
// names), not the ASCII subset: the byte arm for ASCII, a real
// codepoint decode for multi-byte sequences (#806). Invalid UTF-8
// counts as a candidate (conservative: only declines the fast path;
// the parse entries refuse such input on both paths anyway).
fn name_start_at(src string, i int) bool {
	b := src[i]
	if b < 0x80 {
		return cx.is_name_start_b(b)
	}
	mut win := []u8{cap: 4}
	for j := i; j < src.len && win.len < 4; j++ {
		win << src[j]
	}
	cp, sz := cx.utf8_cp_at(win, 0)
	if sz == 0 {
		return true
	}
	return cx.is_name_start_cp(cp)
}

// streamed_input_safe is the input-side byte gate: no anchors (`&`),
// no `#id` declaration candidates, no `@name` reference candidates —
// resolve_ids is document-global and cannot run per child (#806
// pinned `@` at both attribute and [ref @name] body position).
fn streamed_input_safe(input string) bool {
	for i in 0 .. input.len {
		ch := input[i]
		if ch == `&` {
			return false
		}
		if (ch == `#` || ch == `@`) && i + 1 < input.len && name_start_at(input, i + 1) {
			return false
		}
	}
	return true
}

// streamed_input_resolve runs the whole-document-equivalent resolution
// for one streamed child: wrap it under a synthetic root carrying the
// REAL root's name + attrs, run resolve_namespaces (namespace +
// cx:lang scopes) + validate_reserved_ns_bindings, and unwrap.
fn streamed_input_resolve(top cx.CXTopLevel, child cx.Node) !cx.Node {
	mut sdoc := cx.Document{
		elements: [
			cx.Node(cx.Element{
				name:  top.name
				attrs: top.attrs
				items: [child]
			}),
		]
	}
	cx.resolve_namespaces(mut sdoc)
	cx.validate_reserved_ns_bindings(sdoc)!
	wrapped := sdoc.elements[0]
	if wrapped is cx.Element && wrapped.items.len == 1 {
		return wrapped.items[0]
	}
	return error('streamed-input: per-child resolution lost the child')
}

// streamed_input_emit runs the remaining clauses for one source item —
// the generator arm's per-item body verbatim (bind or pattern-match,
// then recurse into clauses[1..]).
fn streamed_input_emit(m cx.Node, clause cx.ProgramForClause, clauses []cx.ProgramForClause,
	spec YieldSpec, mut frame MatchEnv, mut ctx StreamCtx, mut limit_state ForLimitState) ! {
	// #804 leg 7 — the per-item frame's bindings map is BORROWED from the
	// #36 per-thread frame pool, not freshly allocated.
	//
	// Profiling the for-shape after leg 6 put this one allocation at ~19% of
	// samples: `clone_frame_sharing_closures` inclusive, almost entirely
	// `vgc_malloc_typed_opts` building an empty map, plus the GC that map
	// then feeds. Worth naming how that was missed twice — sorted by TOP OF
	// STACK the clone reads as 14 samples, because the cost lands in the
	// allocator's frames, not the caller's. Only the CALL TREE attributes it.
	//
	// The mechanism is not new and that is the point. #36 built exactly this
	// free-list for closure call frames on exactly this soundness argument:
	// every path that retains a frame's bindings beyond its extent COPIES
	// them. Re-audited for this site rather than inherited on faith — the
	// routes are `[?fn]` (snapshot_bindings, a fresh map), `[?def]` (captures
	// NOTHING by #341), error hooks (env.clone()), the buffered for-frames
	// (clone_frame_sharing_closures), and worker spawn (bindings.clone()).
	// No struct in the tree stores a `&MatchEnv`, so there is no route by
	// which a live alias of this frame outlives the iteration.
	//
	// And it inherits #36's ESCAPE DETECTOR: under `-d cx_frame_poison`
	// return_frame_map clears without pooling, so any alias that DID escape
	// reads as an empty frame and breaks the suite by its missing bindings.
	// That build is this leg's soundness evidence — an audit that agrees with
	// itself is not evidence, and this one is checkable.
	mut borrowed := borrow_frame_map(frame.frame_pool)
	defer {
		return_frame_map(frame.frame_pool, mut borrowed)
	}
	mut next := frame.clone_frame_into(borrowed)
	if expr_pat := clause.expr {
		if expr_pat is cx.ProgramPattern {
			// A pattern destructures structure by its nature, so a lazy
			// record forces before matching (#804 leg 2). Binding without a
			// pattern does NOT force — the value is carried, not inspected,
			// and that is where the win lives.
			mut subject := m
			if m is cx.LazyRecord {
				subject = cx.Node(m.force()!)
			}
			matched := match_pattern(expr_pat, subject) or { return }
			for k, v in matched.bindings {
				next.bindings[k] = v
			}
		}
	} else {
		next.bindings[clause.bind] = m
	}
	run_for_clauses_streamed(clauses, 1, spec, mut next, mut ctx, mut limit_state)!
}

// eval_for_comp_streamed_input attempts the streamed-input walk.
// Returns true when it COMPLETED the comprehension from the stream;
// false when the fast path declined BEFORE any emission (the caller
// MUST then fall back to the materializing path). Errors after commit
// propagate on the same channel as eval_for_comp_streamed.
fn eval_for_comp_streamed_input(f cx.ProgramForComp, plan StreamedInputPlan,
	input string, mut env MatchEnv, mut ctx StreamCtx) !bool {
	// ONE WALK (#804 leg 3, ruled 1a). The separate validation pass is gone.
	//
	// It used to run first: verify every child and the tail, retain nothing,
	// and only then evaluate — so an input the materializing path would
	// refuse ALWAYS declined pre-emission and the caller reproduced that
	// exact refusal. That property cost an entire traversal of the input,
	// and after leg 2 it was the binding constraint on the whole
	// architecture: measured, the two-pass ceiling is 201.7 MB/s against a
	// 200 MB/s floor, which is to say a PERFECT evaluation pass still could
	// not pass §11.4.4. One walk raises the ceiling to ~306 and leaves room
	// for the evaluator (`make bench-lazy-ceiling` reports both).
	//
	// WHAT THE RULING TRADED, stated precisely because it is a real change:
	// an input error is now discovered where it occurs rather than before
	// anything is emitted. After commit it propagates on the error channel
	// with output already streamed, exactly as an EVAL-time error does —
	// "partial chunks may precede the failure" is the streaming mode's
	// contract, and input errors now join eval errors there instead of
	// being the one class that got a stronger guarantee.
	//
	// WHAT IS UNCHANGED, and it is more than it first looks. Deferred commit
	// still buffers until the SECOND match, so an error reached before that
	// point declines with nothing emitted and the materializing path
	// produces its verbatim refusal. Every input whose error precedes its
	// second match therefore behaves exactly as before. What changed is
	// confined to inputs that are well-formed enough to emit twice and then
	// malformed later.
	//
	// Validation itself did not weaken: the surviving walk verifies each
	// child through the same `next_lazy` gate (span scan, else the real
	// parser) and reaches the root body's verified end the same way. No
	// input is accepted that was refused before; the difference is only
	// WHEN a late refusal is discovered, and what has already been written
	// when it is.
	mut stream := cx.open_top_level_children(input) or { return false }
	mut frame := env.clone_frame_sharing_closures()
	// #804 leg 7 — carry the per-thread frame pool onto the walk's base frame.
	// clone_frame_sharing_closures deliberately does NOT propagate it (#36
	// scoped pooling to a closure call chain), so the streamed-input walk opts
	// in explicitly at the one site whose per-item frame it wants to pool.
	// Thread-local and single-threaded here, exactly as #36 requires; nested
	// clauses clone normally and keep today's behaviour.
	frame.frame_pool = env.frame_pool
	mut limit_state := build_for_limit_state(f.clauses, mut frame)!
	spec := YieldSpec{
		expr:       f.yield
		value_expr: f.yield_value
		form:       f.yield_form
		// #804 leg 6 — skip the per-item `$_position` ScalarNode + map
		// insert when the program cannot observe it. Same conservative
		// whole-source scan the plan already uses for `$doc`/`$input`:
		// over-matching (a mention inside a string) costs one allocation
		// per item and never an answer, which is the safe direction.
		needs_position: plan.needs_position
	}
	// #804 leg 2 — the lazy-record gate, and the differential's other half.
	//
	// `lazy_ok` carries the same namespace precondition PASS 1's scan does:
	// a certified child may stand in for a resolved one only when the ROOT
	// contributes no namespace or language binding downward.
	//
	// `-d cx_no_lazy_record` forces it false, so the streamed walk
	// materialises every child at creation and `cx.LazyRecord` never exists
	// at runtime. That is not a debug convenience — it is the soundness
	// instrument ruling 1a chose. The forcing discipline is VERIFIED rather
	// than guaranteed (1,323 of the tree's `is Element` sites are silent
	// `if`-form tests, so the compiler cannot help), and the way it is
	// verified is that the whole corpus must render byte-identically with
	// this flag and without it. See `cx/lazy_record.v` and
	// `tests/lazy_record_differential_test.v`.
	lazy_ok := stream.top.top_is_namespace_free() && !lazy_records_disabled()
	step1 := plan.steps[0]
	mut committed := false
	mut pending := []cx.Node{} // at most one buffered match pre-commit
	// The per-child match set, hoisted and REUSED (#804 leg 4). Building it
	// inside the loop cost one array allocation per record, and profiling
	// the gate workload put allocation at ~50% of samples — far above the
	// evaluator costs that looked like the obvious targets. A one-step plan
	// pushes exactly one node into it, so the steady state is zero
	// allocations here rather than one per record.
	mut matches := []cx.Node{cap: 8}
	for {
		if committed && limit_state.remaining == 0 {
			// Limit exhausted — the comprehension is complete without
			// draining the remaining input.
			return true
		}
		// #804 leg 2: certified children come back as LAZY RECORDS —
		// scanned, not parsed. A record that is only ever yielded is never
		// materialised at all; one that is navigated, pattern-matched or
		// stepped into forces at that point and costs what it always did.
		// `-d cx_no_lazy_record` withdraws the whole mechanism.
		v := stream.next_lazy(lazy_ok) or {
			if committed {
				// Output already streamed; surface the failure on the
				// same channel the materializing path would use.
				if err is EvalError {
					return err
				}
				return EvalError{
					code:    'cx-err:CXER0100'
					message: 'parse input: ${err.msg()}'
				}
			}
			return false // declined before any emission — caller falls back
		}
		if !v.has {
			break // verified end of the root body
		}
		child := v.node
		// The name compare is the FIRST structural question asked of every
		// child, and a lazy record answers it from the scan's own walk —
		// which is why a non-matching child now costs a scan rather than a
		// parse. A materialised child answers it as before.
		// #804 leg 11 — the name compare allocates NOTHING for a lazy record.
		// It used to read a `name string` built at construction (one heap
		// string per record); the record now carries the name's OFFSETS and
		// `name_eq` compares bytes against the buffer it already holds. The
		// materialised arm is unchanged.
		mut name_matches := false
		if child is cx.LazyRecord {
			name_matches = child.name_eq(step1.name)
		} else if child is cx.Element {
			name_matches = child.name == step1.name
		} else {
			continue // non-element children are not candidates
		}
		if !name_matches {
			// A `__cx_slot:` sibling matters only when NO bare-named
			// child matches anywhere — a walk that ends uncommitted
			// declines to the materializing path, which owns the slot
			// fallback. Nothing to do here.
			continue
		}
		// A certified child's per-child resolve is a PROVABLE no-op — that is
		// what `top_is_namespace_free` + the scan's exclusion of QNames and
		// xmlns buys, and it is pinned separately by the leg-1 instrument's
		// `resolve_is_noop` property (813 spans, 0 movements). So a lazy
		// record skips the resolve rather than forcing for it; anything the
		// parser produced still goes through it verbatim.
		mut resolved := child
		if child !is cx.LazyRecord {
			resolved = streamed_input_resolve(stream.top, child) or {
				if committed {
					if err is EvalError {
						return err
					}
					return EvalError{
						code:    'cx-err:CXER0100'
						message: 'parse input: ${err.msg()}'
					}
				}
				return false
			}
		}
		// The match set this child contributes: the child itself
		// (1-step form) or its second-step matches through the REAL
		// step walker (per-focus slot fallback included).
		matches.clear()
		if plan.steps.len == 1 {
			matches << resolved
		} else {
			// A two-step plan STEPS INTO the child, which is a structural
			// read — so a lazy record forces here, and the resolve it
			// skipped above must be paid now that a real node exists.
			mut stepped := resolved
			if resolved is cx.LazyRecord {
				forced := cx.Node(resolved.force() or { return false })
				stepped = streamed_input_resolve(stream.top, forced) or {
					if committed {
						if err is EvalError {
							return err
						}
						return EvalError{
							code:    'cx-err:CXER0100'
							message: 'parse input: ${err.msg()}'
						}
					}
					return false
				}
			}
			foci := apply_binding_step([FocusedNode{
				node:      stepped
				ancestors: []cx.Node{}
			}], plan.steps[1], false)!
			for fc in foci {
				matches << fc.node
			}
		}
		for m in matches {
			if !committed {
				if pending.len == 0 {
					pending << m
					continue
				}
				committed = true
				g_streamed_input_commits++
				first := pending[0]
				pending.clear()
				streamed_input_emit(first, plan.clause, f.clauses, spec, mut frame, mut ctx, mut
					limit_state)!
			}
			if limit_state.remaining == 0 {
				return true
			}
			streamed_input_emit(m, plan.clause, f.clauses, spec, mut frame, mut ctx, mut
				limit_state)!
		}
	}
	if !committed {
		// 0 or 1 total matches (or slot-only shapes): the
		// materializing path owns the low-cardinality semantics
		// (field-read shape, #21 unwrap, slot fallback). Nothing was
		// emitted — fall back losslessly.
		return false
	}
	return true
}

// ── The [?map] streamed-input fast path (#845) ────────────────────────────
//
// `[?map $doc/user [using …]]` had a streamed OUTPUT path and no streamed
// INPUT path, so the source expression materialized the whole document while
// the results streamed. That is a growing live set, and it measured like one:
// the gate-15 map shape decayed 2.0 → 0.8 MB/s MONOTONICALLY WITHIN ONE
// PROCESS at 64 MiB and failed the §11.4.4 jitter clamp at 61.5% against an
// 80% floor — a second red criterion with a different cause from #804's
// throughput one.
//
// The access shape is the same as the `[?for]` lane's, so the preconditions
// are the SAME FUNCTIONS (streamed_source_steps + streamed_source_scans_ok),
// not a parallel copy of them.
//
// REFUSAL PARITY IS REPRODUCED, NOT DECLINED — and that is the load-bearing
// choice here, because it decides whether the ACCEPTED-INPUT SET moves. The
// deferred commit below buffers until the SECOND match exactly as the `[?for]`
// walk does, so a walk ending with 0 or 1 matches declines with nothing
// emitted and the materializing path produces its verbatim answer. That
// matters more for `[?map]` than it does for `[?for]`: the map lane's source
// goes through `iterate(eval_node(...))`, whose low-cardinality behaviour is
// precisely the container-vs-contents question that has cost this repo time
// (a single-match node-set, a field read that atomizes, the #21 lone-collection
// unwrap). Rather than re-derive those cases on the fast path, the fast path
// refuses to be the one that answers them. Consequence, stated: this change
// moves NO input from accepted to refused or refused to accepted; it changes
// only how much of the document is resident while a multi-match map runs.
//
// `[par]` DECLINES. par_map_streamed fans out over a bounded pool and
// reassembles by source index, which needs the item list up front; streaming
// input into it is a separate piece of work, not a rider on this one.
struct MapStreamPlan {
	steps []cx.ProgramPathStep
}

// streamed_map_plan verifies the program side for the [?map] lane. Reads the
// directive's shape through parse_map_slots — the same authority the evaluator
// uses — so the two cannot disagree about what the program says.
fn streamed_map_plan(d cx.ProgramDirective, program_src string, mut env MatchEnv) ?MapStreamPlan {
	// SHAPE WHITELIST FIRST, before anything is evaluated. The fast path
	// supports exactly `source + using`; every other slot declines.
	//
	// Written as a whitelist rather than a `[par]` blacklist for two reasons.
	// It is fail-closed — a slot added to `[?map]` later declines here instead
	// of being silently mishandled by a walk that never heard of it. And it
	// keeps parse_map_slots off the decline path: that function EVALUATES a
	// `[par N]` width expression, so testing `sl.par` after calling it would
	// evaluate the width once here and again on the materializing path.
	// Nothing is evaluated until the shape is known to be one this lane can
	// actually complete.
	mut positional := 0
	for slot in d.slots {
		if slot.kind == .labeled {
			if slot.label != 'using' {
				return none
			}
			continue
		}
		v := slot.value
		if v is cx.ProgramLiteral && v.kind == .cx_element {
			if v.name == 'using' {
				continue
			}
			// [par]/[ordered]/anything else in element spelling.
			return none
		}
		positional++
	}
	if positional != 1 {
		return none
	}
	sl := parse_map_slots(d, mut env) or { return none }
	if sl.par {
		return none
	}
	steps := streamed_source_steps(sl.source) or { return none }
	if !streamed_source_scans_ok(program_src) {
		return none
	}
	return MapStreamPlan{
		steps: steps
	}
}

// eval_map_directive_streamed_input attempts the streamed-input walk for a
// `[?map]`. Returns true when it COMPLETED the map from the stream; false when
// it declined BEFORE any emission (the caller MUST then fall back to the
// materializing path). Errors after commit propagate on the same channel
// eval_map_directive_streamed uses.
fn eval_map_directive_streamed_input(d cx.ProgramDirective, plan MapStreamPlan,
	input string, mut env MatchEnv, mut ctx StreamCtx) !bool {
	sl := parse_map_slots(d, mut env)!
	// The `using` closure is resolved ONCE, before the walk, and it cannot
	// mention `$doc`: streamed_source_scans_ok already required the whole
	// program to spell `$doc`/`$input` exactly once, and that one spelling is
	// the source. So evaluating it with no document bound is sound rather
	// than lucky.
	using_val := eval_node(sl.using_slot, mut env)!
	closure := resolve_closure(using_val, env) or {
		return EvalError{
			code:    'cx-err:CXER0106'
			message: '[?map] :using must evaluate to a closure (E_USING_NOT_CLOSURE)'
		}
	}
	mut stream := cx.open_top_level_children(input) or { return false }
	// Same lazy-record gate as the [?for] lane: a certified child may stand in
	// for a resolved one only when the ROOT contributes no namespace or
	// language binding downward. `-d cx_no_lazy_record` withdraws it, and the
	// differential test is what verifies the forcing discipline.
	lazy_ok := stream.top.top_is_namespace_free() && !lazy_records_disabled()
	step1 := plan.steps[0]
	mut committed := false
	mut pending := []cx.Node{} // at most one buffered match pre-commit
	mut matches := []cx.Node{cap: 8} // hoisted + reused (#804 leg 4)
	for {
		v := stream.next_lazy(lazy_ok) or {
			if committed {
				if err is EvalError {
					return err
				}
				return EvalError{
					code:    'cx-err:CXER0100'
					message: 'parse input: ${err.msg()}'
				}
			}
			return false // declined before any emission — caller falls back
		}
		if !v.has {
			break // verified end of the root body
		}
		child := v.node
		mut name_matches := false
		if child is cx.LazyRecord {
			name_matches = child.name_eq(step1.name)
		} else if child is cx.Element {
			name_matches = child.name == step1.name
		} else {
			continue // non-element children are not candidates
		}
		if !name_matches {
			continue
		}
		mut resolved := child
		if child !is cx.LazyRecord {
			resolved = streamed_input_resolve(stream.top, child) or {
				if committed {
					if err is EvalError {
						return err
					}
					return EvalError{
						code:    'cx-err:CXER0100'
						message: 'parse input: ${err.msg()}'
					}
				}
				return false
			}
		}
		matches.clear()
		if plan.steps.len == 1 {
			matches << resolved
		} else {
			// A two-step plan STEPS INTO the child — a structural read, so a
			// lazy record forces here and pays the resolve it skipped above.
			mut stepped := resolved
			if resolved is cx.LazyRecord {
				forced := cx.Node(resolved.force() or { return false })
				stepped = streamed_input_resolve(stream.top, forced) or {
					if committed {
						if err is EvalError {
							return err
						}
						return EvalError{
							code:    'cx-err:CXER0100'
							message: 'parse input: ${err.msg()}'
						}
					}
					return false
				}
			}
			foci := apply_binding_step([FocusedNode{
				node:      stepped
				ancestors: []cx.Node{}
			}], plan.steps[1], false)!
			for fc in foci {
				matches << fc.node
			}
		}
		for m in matches {
			if !committed {
				if pending.len == 0 {
					pending << m
					continue
				}
				committed = true
				g_streamed_input_commits++
				first := pending[0]
				pending.clear()
				mapped_first := invoke_closure(closure, [first], mut env)!
				ctx.emit_node(mapped_first)!
			}
			mapped := invoke_closure(closure, [m], mut env)!
			ctx.emit_node(mapped)!
		}
	}
	if !committed {
		// 0 or 1 total matches: the materializing path owns the
		// low-cardinality semantics. Nothing was emitted — fall back
		// losslessly.
		return false
	}
	return true
}
