// cx-stdlib/similar — the UNIFORM-matrix verb surface (similar.md §3/§5).
//
// The graded predicate plugs into constructs by being HANDED to them —
// never via a parallel $similar:* namespace (§3.1 "no parallel
// namespace"). The verbs here are core collection verbs served on the
// bare-name dispatch chain:
//
//   [$join left right {"on" … "selection" … "type" …}]   §5.1
//   [$distinct xs {"by" $pred "policy" :…}]              §5.2 (graded arm;
//        the 1-ary exact form stays in invoke_builtin)
//   [$group-by xs {"by" $pred "policy" :…}]              §5.2 clustering
//   [$contains seq x] / [$contains seq x $pred]          membership
//   [$sort xs {"by" … "dir" :…}]                         ranking
//   [$validate v vocab] / [$validate v vocab {"by" $pred}]
//
// plus the module's own constructors ([$similar:predicate …],
// [$similar:similarity-to …]) whose prim names are similar-*.
//
// Because a similarity predicate is DATA (stdlib_similar.v), every verb
// here is env-free; only [$sort {"by" <closure>}] needs the env-aware
// hook (similar_stdlib_builtin_env) to apply a user key function.
module code

import cx

const similar_selection_modes = ['greedy-best', 'top-k', 'all-above', 'optimal']
const similar_cluster_policies = ['transitive-closure', 'complete-linkage', 'singletons']
const similar_join_types = ['inner', 'left', 'right', 'full']

// ── options-map access ───────────────────────────────────────────────

fn similar_opt_get(opts cx.Node, key string) ?cx.Node {
	if opts is cx.MapNode {
		for e in opts.entries {
			if cx.scalar_value_str_public(e.key_value) == key {
				return e.value
			}
		}
		return none
	}
	if opts is cx.Element {
		if opts.name == map_marker_name || opts.name == 'map' {
			for it in opts.items {
				if it is cx.Element && it.name == key && it.items.len > 0 {
					return it.items[0]
				}
			}
			for a in opts.attrs {
				if a.name == key {
					return similar_attr_node(a.value)
				}
			}
		}
	}
	return none
}

fn similar_opt_is_empty_map(opts cx.Node) bool {
	if opts is cx.MapNode {
		return opts.entries.len == 0
	}
	if opts is cx.Element {
		return (opts.name == map_marker_name || opts.name == 'map') && opts.items.len == 0
			&& opts.attrs.len == 0
	}
	return false
}

fn similar_opt_is_map(opts cx.Node) bool {
	if opts is cx.MapNode {
		return true
	}
	if opts is cx.Element {
		return opts.name == map_marker_name || opts.name == 'map'
	}
	return false
}

fn similar_opt_atom(opts cx.Node, key string, def string) string {
	n := similar_opt_get(opts, key) or { return def }
	if n is cx.ScalarNode {
		return cx.scalar_value_str_public(n.value)
	}
	return def
}

fn similar_opt_int(opts cx.Node, key string, def int) int {
	n := similar_opt_get(opts, key) or { return def }
	if n is cx.ScalarNode {
		v := n.value
		if v is i64 {
			return int(v)
		}
		if v is f64 {
			return int(v)
		}
	}
	return def
}

fn similar_opts_err(verb string, msg string) cx.Node {
	return mk_err('cx-err:CXER4901', 'E_SIMILAR_${verb.to_upper().replace('-', '_')}: ${msg}')
}

// similar_verb_pred resolves an option value that must be a similarity
// predicate ("on" / "by"). An absent option yields the default predicate.
fn similar_verb_pred(n cx.Node) !SimilarPredicate {
	return similar_pred_of(n)!
}

// similar_row_field reads a named field off a row for the EXACT verb
// forms — map key, element attribute, or single-valued child element.
fn similar_row_field(row cx.Node, name string) ?cx.Node {
	if row is cx.MapNode {
		for e in row.entries {
			if cx.scalar_value_str_public(e.key_value) == name {
				return e.value
			}
		}
		return none
	}
	if row is cx.Element {
		if row.name == map_marker_name || row.name == 'map' {
			keys, vals := similar_map_pairs(cx.Node(row))
			for i, k in keys {
				if k == name {
					return vals[i]
				}
			}
			return none
		}
		for a in row.attrs {
			if a.name == name {
				return similar_attr_node(a.value)
			}
		}
		for it in row.items {
			if it is cx.Element && it.name == name {
				if it.items.len == 1 && it.attrs.len == 0 {
					return it.items[0]
				}
				return it
			}
		}
	}
	return none
}

// ── §5.1 join — labeled linkage + routing presets ────────────────────

struct SimilarJoinPair {
	li    int
	ri    int
	score f64
	band  string
}

fn similar_join(args []cx.Node) cx.Node {
	if args.len != 3 {
		return similar_opts_err('join', 'expected [\$join left right {…opts}]')
	}
	left := iterate(args[0])
	right := iterate(args[1])
	opts := args[2]
	if !similar_opt_is_map(opts) {
		return similar_opts_err('join', 'third argument must be an options map')
	}
	jtype := similar_opt_atom(opts, 'type', 'inner')
	if jtype !in similar_join_types {
		return similar_opts_err('join', 'unknown join type :${jtype} (inner|left|right|full)')
	}
	selection := similar_opt_atom(opts, 'selection', 'greedy-best')
	if selection !in similar_selection_modes {
		return similar_opts_err('join',
			'unknown selection :${selection} (greedy-best|top-k|all-above|optimal)')
	}
	k := similar_opt_int(opts, 'k', 1)
	if selection == 'top-k' && k < 1 {
		return similar_opts_err('join', 'selection :top-k needs k >= 1')
	}
	on := similar_opt_get(opts, 'on') or {
		return similar_opts_err('join',
			'missing "on" — a field name (exact) or a similarity predicate (graded)')
	}
	mut pairs := []SimilarJoinPair{}
	if on is cx.ScalarNode && on.data_type == cx.ScalarType.string_type {
		// exact equality join on a named field — every equal pair links;
		// selection/banding are the GRADED join's knobs (§5.1).
		field := cx.scalar_value_str_public(on.value)
		for li, lrow in left {
			for ri, rrow in right {
				lv := similar_row_field(lrow, field) or { continue }
				rv := similar_row_field(rrow, field) or { continue }
				if nodes_equal(lv, rv) {
					pairs << SimilarJoinPair{
						li:    li
						ri:    ri
						score: 1.0
						band:  'match'
					}
				}
			}
		}
	} else {
		mut p := similar_verb_pred(on) or { return similar_opts_err('join', err.msg()) }
		// banding is an explicit join knob — "decide" overrides the
		// predicate's cuts (a predicate without decide gets the default).
		if dec := similar_opt_get(opts, 'decide') {
			dk, dv := similar_map_pairs(dec)
			p.has_decide = true
			for i, key in dk {
				cut := (similar_scalar_f64(dv[i]) or { continue })
				if key == 'match' {
					p.match_cut = cut
				} else if key == 'review' {
					p.review_cut = cut
				}
			}
		} else if !p.has_decide {
			p.has_decide = true
			p.match_cut = similar_default_match_cut
			p.review_cut = similar_default_review_cut
		}
		// score matrix; below-review-cut pairs are 0 (not linkable).
		mut score := [][]f64{len: left.len, init: []f64{len: right.len}}
		for li, lrow in left {
			for ri, rrow in right {
				scored := similar_score_pair(lrow, rrow, p, '', 0)
				if scored.comparable && scored.score >= p.review_cut {
					score[li][ri] = scored.score
				}
			}
		}
		match selection {
			'all-above' {
				for li in 0 .. left.len {
					for ri in 0 .. right.len {
						if score[li][ri] > 0 {
							pairs << SimilarJoinPair{
								li:    li
								ri:    ri
								score: score[li][ri]
								band:  similar_band(score[li][ri], p)
							}
						}
					}
				}
			}
			'top-k', 'greedy-best' {
				limit := if selection == 'greedy-best' { 1 } else { k }
				for li in 0 .. left.len {
					mut order := []int{}
					for ri in 0 .. right.len {
						if score[li][ri] > 0 {
							order << ri
						}
					}
					// stable best-first: higher score wins, ties keep
					// input (column) order.
					order.sort_with_compare(fn [score, li] (a &int, b &int) int {
						if score[li][*a] > score[li][*b] {
							return -1
						}
						if score[li][*a] < score[li][*b] {
							return 1
						}
						return *a - *b
					})
					n := if order.len < limit { order.len } else { limit }
					for x in 0 .. n {
						ri := order[x]
						pairs << SimilarJoinPair{
							li:    li
							ri:    ri
							score: score[li][ri]
							band:  similar_band(score[li][ri], p)
						}
					}
				}
			}
			else {
				// :optimal — globally optimal 1:1 assignment (Hungarian)
				// over the above-cut score matrix (ruling Q3).
				assign := similar_optimal_assignment(score)
				for li, ri in assign {
					if ri >= 0 {
						pairs << SimilarJoinPair{
							li:    li
							ri:    ri
							score: score[li][ri]
							band:  similar_band(score[li][ri], p)
						}
					}
				}
			}
		}
	}
	// label + filter (§5.1: the join TYPE is a filter over one labeled
	// result, not a separate operation).
	mut matched_left := []bool{len: left.len}
	mut matched_right := []bool{len: right.len}
	mut any_left := []bool{len: left.len}
	mut any_right := []bool{len: right.len}
	for pr in pairs {
		any_left[pr.li] = true
		any_right[pr.ri] = true
		if pr.band == 'match' {
			matched_left[pr.li] = true
			matched_right[pr.ri] = true
		}
	}
	mut items := []cx.Node{}
	for pr in pairs {
		if jtype != 'full' && pr.band != 'match' {
			continue
		}
		items << cx.Node(cx.Element{
			name:  'pair'
			attrs: [
				cx.Attribute{
					name:  'score'
					value: cx.ScalarValue(pr.score)
				},
				similar_atom_attr('band', pr.band),
			]
			items: [
				cx.Node(cx.Element{
					name:  'left'
					items: [left[pr.li]]
				}),
				cx.Node(cx.Element{
					name:  'right'
					items: [right[pr.ri]]
				}),
			]
		})
	}
	if jtype == 'left' || jtype == 'full' {
		for li, lrow in left {
			unmatched := if jtype == 'full' { !any_left[li] } else { !matched_left[li] }
			if unmatched {
				items << cx.Node(cx.Element{
					name:  'left-only'
					items: [lrow]
				})
			}
		}
	}
	if jtype == 'right' || jtype == 'full' {
		for ri, rrow in right {
			unmatched := if jtype == 'full' { !any_right[ri] } else { !matched_right[ri] }
			if unmatched {
				items << cx.Node(cx.Element{
					name:  'right-only'
					items: [rrow]
				})
			}
		}
	}
	return cx.Element{
		name:  'join-result'
		attrs: [similar_atom_attr('type', jtype)]
		items: items
	}
}

// ── §5.2 clustering (distinct / group-by) ────────────────────────────

struct SimilarClusters {
	clusters [][]int // member input-indices, first = representative
	cohesion []f64   // mean pairwise score within the cluster
}

fn similar_cluster(items []cx.Node, p SimilarPredicate, policy string) SimilarClusters {
	n := items.len
	// pairwise score matrix (upper triangle).
	mut score := [][]f64{len: n, init: []f64{len: n}}
	for i in 0 .. n {
		score[i][i] = 1.0
		for j in i + 1 .. n {
			s := if policy == 'singletons' {
				if nodes_equal(items[i], items[j]) { 1.0 } else { 0.0 }
			} else {
				scored := similar_score_pair(items[i], items[j], p, '', 0)
				if scored.comparable {
					scored.score
				} else {
					0.0
				}
			}
			score[i][j] = s
			score[j][i] = s
		}
	}
	cut := if policy == 'singletons' { 1.0 } else { p.match_cut }
	mut assign := []int{len: n, init: -1}
	mut clusters := [][]int{}
	match policy {
		'complete-linkage' {
			// agglomerative: repeatedly merge the two clusters whose
			// COMPLETE linkage (min pairwise score) is highest and above
			// the cut; ties break on the smaller first-member index —
			// deterministic for a fixed input sequence.
			for i in 0 .. n {
				clusters << [i]
			}
			for {
				mut best_a := -1
				mut best_b := -1
				mut best_link := -1.0
				for a in 0 .. clusters.len {
					for b in a + 1 .. clusters.len {
						mut link := 2.0
						for i in clusters[a] {
							for j in clusters[b] {
								if score[i][j] < link {
									link = score[i][j]
								}
							}
						}
						if link >= cut && link > best_link {
							best_link = link
							best_a = a
							best_b = b
						}
					}
				}
				if best_a < 0 {
					break
				}
				merged := clusters[best_b]
				clusters[best_a] << merged
				clusters.delete(best_b)
			}
			for mut c in clusters {
				c.sort()
			}
		}
		'singletons' {
			// only exact duplicates collapse.
			for i in 0 .. n {
				if assign[i] >= 0 {
					continue
				}
				mut c := [i]
				assign[i] = clusters.len
				for j in i + 1 .. n {
					if assign[j] < 0 && score[i][j] >= 1.0 {
						assign[j] = clusters.len
						c << j
					}
				}
				clusters << c
			}
		}
		else {
			// :transitive-closure (default) — connected components over
			// match-band pairs; order-independent by construction.
			mut parent := []int{len: n, init: index}
			for i in 0 .. n {
				for j in i + 1 .. n {
					if score[i][j] >= cut {
						mut ri := i
						for parent[ri] != ri {
							ri = parent[ri]
						}
						mut rj := j
						for parent[rj] != rj {
							rj = parent[rj]
						}
						if ri != rj {
							if ri < rj {
								parent[rj] = ri
							} else {
								parent[ri] = rj
							}
						}
					}
				}
			}
			mut root_cluster := map[int]int{}
			for i in 0 .. n {
				mut r := i
				for parent[r] != r {
					r = parent[r]
				}
				if r !in root_cluster {
					root_cluster[r] = clusters.len
					clusters << []int{}
				}
				clusters[root_cluster[r]] << i
			}
		}
	}

	// order clusters by first (lowest) member index; compute cohesion.
	clusters.sort_with_compare(fn (a &[]int, b &[]int) int {
		return (*a)[0] - (*b)[0]
	})
	mut cohesion := []f64{}
	for c in clusters {
		if c.len < 2 {
			cohesion << 1.0
			continue
		}
		mut sum := 0.0
		mut cnt := 0
		for x in 0 .. c.len {
			for y in x + 1 .. c.len {
				sum += score[c[x]][c[y]]
				cnt++
			}
		}
		cohesion << sum / f64(cnt)
	}
	return SimilarClusters{
		clusters: clusters
		cohesion: cohesion
	}
}

fn similar_cluster_args(verb string, args []cx.Node) !(cx.Node, SimilarPredicate, string) {
	if args.len != 2 {
		return error('expected [\$${verb} xs {"by" \$pred "policy" :…}]')
	}
	opts := args[1]
	if !similar_opt_is_map(opts) {
		return error('second argument must be an options map')
	}
	by := similar_opt_get(opts, 'by') or { return error('missing "by" similarity predicate') }
	mut p := similar_verb_pred(by)!
	if !p.has_decide {
		p.has_decide = true
		p.match_cut = similar_default_match_cut
		p.review_cut = similar_default_review_cut
	}
	policy := similar_opt_atom(opts, 'policy', 'transitive-closure')
	if policy !in similar_cluster_policies {
		return error('unknown policy :${policy} (transitive-closure|complete-linkage|singletons)')
	}
	return args[0], p, policy
}

// similar_distinct_graded — clustering, then one representative per
// cluster (the first member in input order).
fn similar_distinct_graded(args []cx.Node) cx.Node {
	xs, p, policy := similar_cluster_args('distinct', args) or {
		return similar_opts_err('distinct', err.msg())
	}
	items := iterate(xs)
	cl := similar_cluster(items, p, policy)
	mut out := []cx.Node{}
	for c in cl.clusters {
		out << items[c[0]]
	}
	return cx.Element{
		name:  seq_marker_name
		items: out
	}
}

// similar_group_by_graded — the clusters themselves, each with its
// cohesion (mean pairwise score).
fn similar_group_by_graded(args []cx.Node) cx.Node {
	xs, p, policy := similar_cluster_args('group-by', args) or {
		return similar_opts_err('group-by', err.msg())
	}
	items := iterate(xs)
	cl := similar_cluster(items, p, policy)
	mut out := []cx.Node{}
	for ci, c in cl.clusters {
		mut members := []cx.Node{}
		for i in c {
			members << items[i]
		}
		out << cx.Node(cx.Element{
			name:  'cluster'
			attrs: [
				cx.Attribute{
					name:  'cohesion'
					value: cx.ScalarValue(cl.cohesion[ci])
				},
			]
			items: members
		})
	}
	return cx.Element{
		name:  seq_marker_name
		items: out
	}
}

// ── membership ───────────────────────────────────────────────────────

// similar_contains handles the SEQUENCE membership forms of `contains`
// (the string/string form stays in invoke_builtin):
//   [$contains seq x]        → bool (structural equality)
//   [$contains seq x $pred]  → best-match [similar … [best <member>]]
fn similar_contains(args []cx.Node) ?cx.Node {
	if args.len != 2 && args.len != 3 {
		return none
	}
	items := if args[0] is cx.Element || args[0] is cx.SequenceNode || args[0] is cx.ArrayNode {
		iterate(args[0])
	} else {
		return none
	}
	if args.len == 2 {
		mut found := false
		for it in items {
			if nodes_equal(it, args[1]) {
				found = true
				break
			}
		}
		return cx.Node(cx.ScalarNode{
			value:     cx.ScalarValue(found)
			data_type: cx.ScalarType.bool_type
		})
	}
	mut p := similar_verb_pred(args[2]) or {
		return mk_err('cx-err:CXER4901', 'E_SIMILAR_CONTAINS: ${err.msg()}')
	}
	if !p.has_decide {
		p.has_decide = true
		p.match_cut = similar_default_match_cut
		p.review_cut = similar_default_review_cut
	}
	mut best := -1
	mut best_score := -1.0
	for i, it in items {
		scored := similar_score_pair(it, args[1], p, '', 0)
		if scored.comparable && scored.score > best_score {
			best_score = scored.score
			best = i
		}
	}
	if best < 0 {
		return similar_report(0.0, p, none)
	}
	rep := similar_report(best_score, p, none)
	if rep is cx.Element {
		mut e := rep
		e.items << cx.Node(cx.Element{
			name:  'best'
			items: [items[best]]
		})
		return cx.Node(e)
	}
	return rep
}

// ── ranking (sort) ───────────────────────────────────────────────────

struct SimilarSortKey {
	idx    int
	num    f64
	str    string
	is_num bool
	absent bool
}

fn similar_sort_key_of(n cx.Node, idx int) SimilarSortKey {
	if is_absence_node(n) {
		return SimilarSortKey{
			idx:    idx
			absent: true
		}
	}
	if num := similar_scalar_f64(n) {
		if n is cx.ScalarNode
			&& n.data_type in [cx.ScalarType.int_type, cx.ScalarType.float_type, cx.ScalarType.decimal_type, cx.ScalarType.bigint_type] {
			return SimilarSortKey{
				idx:    idx
				num:    num
				is_num: true
			}
		}
	}
	return SimilarSortKey{
		idx: idx
		str: similar_node_string(n)
	}
}

fn similar_sort_keys(keys []SimilarSortKey, desc bool) []int {
	mut order := keys.clone()
	order.sort_with_compare(fn [desc] (a &SimilarSortKey, b &SimilarSortKey) int {
		// absent keys sort LAST regardless of direction (stable).
		if a.absent != b.absent {
			return if a.absent { 1 } else { -1 }
		}
		mut c := 0
		if !a.absent {
			if a.is_num && b.is_num {
				if a.num < b.num {
					c = -1
				} else if a.num > b.num {
					c = 1
				}
			} else {
				ka := if a.is_num { a.num.str() } else { a.str }
				kb := if b.is_num { b.num.str() } else { b.str }
				c = ka.compare(kb)
			}
			if desc {
				c = -c
			}
		}
		if c != 0 {
			return c
		}
		return a.idx - b.idx // stable — ties keep input order
	})
	mut out := []int{cap: order.len}
	for k in order {
		out << k.idx
	}
	return out
}

// similar_sort_data handles the env-free `sort` forms: no options,
// "by" a field name, or "by" a [similarity-to …] key spec (ranking by
// nearness to a reference — §3.1 sort row; footnote 4 pins that sort
// WITHOUT a reference is meaningless). Closure "by" is handled by the
// env-aware hook.
fn similar_sort_data(args []cx.Node) ?cx.Node {
	if args.len != 1 && args.len != 2 {
		return none
	}
	items := iterate(args[0])
	if args.len == 1 {
		mut keys := []SimilarSortKey{cap: items.len}
		for i, it in items {
			keys << similar_sort_key_of(it, i)
		}
		order := similar_sort_keys(keys, false)
		return cx.Node(cx.Element{
			name:  seq_marker_name
			items: order.map(items[it])
		})
	}
	opts := args[1]
	if !similar_opt_is_map(opts) {
		return mk_err('cx-err:CXER4901', 'E_SIMILAR_SORT: second argument must be an options map')
	}
	by := similar_opt_get(opts, 'by') or {
		dir0 := similar_opt_atom(opts, 'dir', 'asc')
		mut keys := []SimilarSortKey{cap: items.len}
		for i, it in items {
			keys << similar_sort_key_of(it, i)
		}
		order := similar_sort_keys(keys, dir0 == 'desc')
		return cx.Node(cx.Element{
			name:  seq_marker_name
			items: order.map(items[it])
		})
	}
	if by is cx.Element && by.name == 'similarity-to' {
		reference := similar_child(by, 'reference') or {
			return mk_err('cx-err:CXER4901',
				'E_SIMILAR_SORT: [similarity-to …] key spec is missing its [reference …]')
		}
		if reference.items.len != 1 {
			return mk_err('cx-err:CXER4901',
				'E_SIMILAR_SORT: [similarity-to …] reference must hold exactly one value')
		}
		mut pred_node := cx.Node(cx.Element{
			name: ''
		})
		if pe := similar_child(by, 'predicate') {
			if pe.items.len == 1 {
				pred_node = pe.items[0]
			}
		}
		p := similar_verb_pred(pred_node) or {
			return mk_err('cx-err:CXER4901', 'E_SIMILAR_SORT: ${err.msg()}')
		}
		// nearest first: similarity ranking defaults to DESCENDING.
		desc := similar_opt_atom(opts, 'dir', 'desc') == 'desc'
		mut keys := []SimilarSortKey{cap: items.len}
		for i, it in items {
			scored := similar_score_pair(it, reference.items[0], p, '', 0)
			keys << SimilarSortKey{
				idx:    i
				num:    if scored.comparable { scored.score } else { -1.0 }
				is_num: true
			}
		}
		order := similar_sort_keys(keys, desc)
		return cx.Node(cx.Element{
			name:  seq_marker_name
			items: order.map(items[it])
		})
	}
	if by is cx.ScalarNode && by.data_type == cx.ScalarType.string_type {
		field := cx.scalar_value_str_public(by.value)
		desc := similar_opt_atom(opts, 'dir', 'asc') == 'desc'
		mut keys := []SimilarSortKey{cap: items.len}
		for i, it in items {
			fv := similar_row_field(it, field) or {
				keys << SimilarSortKey{
					idx:    i
					absent: true
				}
				continue
			}
			keys << similar_sort_key_of(fv, i)
		}
		order := similar_sort_keys(keys, desc)
		return cx.Node(cx.Element{
			name:  seq_marker_name
			items: order.map(items[it])
		})
	}
	// a closure "by" is served by the env-aware hook; anything else is
	// an options error.
	if by is cx.Element && by.name == closure_sentinel_name {
		return none
	}
	return mk_err('cx-err:CXER4901',
		'E_SIMILAR_SORT: "by" must be a field name, a [similarity-to …] key spec, or a function')
}

// similar_sort_env applies a user key FUNCTION per item (the closure
// "by" form) — the one similarity verb that needs the environment.
fn similar_sort_env(args []cx.Node, mut env MatchEnv) ?cx.Node {
	if args.len != 2 {
		return none
	}
	opts := args[1]
	if !similar_opt_is_map(opts) {
		return none
	}
	by := similar_opt_get(opts, 'by') or { return none }
	if !(by is cx.Element && by.name == closure_sentinel_name) {
		return none
	}
	items := iterate(args[0])
	desc := similar_opt_atom(opts, 'dir', 'asc') == 'desc'
	mut keys := []SimilarSortKey{cap: items.len}
	for i, it in items {
		kv := apply_fn_value(by, [it], mut env) or {
			return mk_err('cx-err:CXER4901', 'E_SIMILAR_SORT: key function failed on item ${i}')
		}
		if kv is cx.Element && kv.name == 'err' {
			return kv
		}
		// a [similar …] report as key ranks by its score.
		if kv is cx.Element && kv.name == similar_report_name {
			keys << SimilarSortKey{
				idx:    i
				num:    similar_report_score(kv)
				is_num: true
			}
			continue
		}
		keys << similar_sort_key_of(kv, i)
	}
	order := similar_sort_keys(keys, desc)
	return cx.Node(cx.Element{
		name:  seq_marker_name
		items: order.map(items[it])
	})
}

// ── validate against a controlled vocabulary ─────────────────────────

// [$validate v vocab] → [ok v] | [invalid [violation …]]
// [$validate v vocab {"by" $pred}] → [similar … [nearest <allowed>]]
fn similar_validate(args []cx.Node) ?cx.Node {
	if args.len != 2 && args.len != 3 {
		return none
	}
	vocab := iterate(args[1])
	if args.len == 2 {
		for m in vocab {
			if nodes_equal(m, args[0]) {
				return cx.Node(cx.Element{
					name:  'ok'
					items: [args[0]]
				})
			}
		}
		return cx.Node(cx.Element{
			name:  'invalid'
			items: [
				cx.Node(cx.Element{
					name:  'violation'
					attrs: [
						cx.Attribute{
							name:  'code'
							value: cx.ScalarValue('not-in-vocabulary')
						},
						cx.Attribute{
							name:  'got'
							value: cx.ScalarValue(similar_node_string(args[0]))
						},
						cx.Attribute{
							name:  'message'
							value: cx.ScalarValue('value is not one of the ${vocab.len} allowed values')
						},
					]
				}),
			]
		})
	}
	opts := args[2]
	if !similar_opt_is_map(opts) {
		return mk_err('cx-err:CXER4901',
			'E_SIMILAR_VALIDATE: third argument must be an options map')
	}
	by := similar_opt_get(opts, 'by') or {
		return mk_err('cx-err:CXER4901', 'E_SIMILAR_VALIDATE: missing "by" similarity predicate')
	}
	mut p := similar_verb_pred(by) or {
		return mk_err('cx-err:CXER4901', 'E_SIMILAR_VALIDATE: ${err.msg()}')
	}
	if !p.has_decide {
		p.has_decide = true
		p.match_cut = similar_default_match_cut
		p.review_cut = similar_default_review_cut
	}
	mut best := -1
	mut best_score := -1.0
	for i, m in vocab {
		scored := similar_score_pair(args[0], m, p, '', 0)
		if scored.comparable && scored.score > best_score {
			best_score = scored.score
			best = i
		}
	}
	if best < 0 {
		return similar_report(0.0, p, none)
	}
	rep := similar_report(best_score, p, none)
	if rep is cx.Element {
		mut e := rep
		e.items << cx.Node(cx.Element{
			name:  'nearest'
			items: [vocab[best]]
		})
		return cx.Node(e)
	}
	return rep
}

// ── constructors (the module's own surface) ──────────────────────────

// similar_predicate_ctor builds the canonical [similar-predicate …]
// element from an options map, then VALIDATES it through the same
// parser every consumer uses — an unbuildable predicate is a
// CXER4900 err value at construction time, not at first use.
fn similar_predicate_ctor(opts cx.Node) cx.Node {
	if !similar_opt_is_map(opts) && !is_absence_node(opts) {
		return mk_err('cx-err:CXER4900', 'E_SIMILAR_PREDICATE: expected an options map')
	}
	mut attrs := []cx.Attribute{}
	mut children := []cx.Node{}
	if sc := similar_opt_get(opts, 'score') {
		attrs << similar_atom_attr('score', similar_node_string(sc))
	}
	if tol := similar_opt_get(opts, 'tolerance') {
		if tol is cx.ScalarNode && tol.data_type == cx.ScalarType.duration_type {
			s := cx.scalar_value_str_public(tol.value)
			ns := duration_to_ns(s) or {
				return mk_err('cx-err:CXER4900',
					'E_SIMILAR_PREDICATE: unreadable duration tolerance "${s}"')
			}
			attrs << cx.Attribute{
				name:  'tolerance-ns'
				value: cx.ScalarValue(ns)
			}
		} else if num := similar_scalar_f64(tol) {
			attrs << cx.Attribute{
				name:  'tolerance'
				value: cx.ScalarValue(num)
			}
		} else {
			return mk_err('cx-err:CXER4900',
				'E_SIMILAR_PREDICATE: tolerance must be a number or duration')
		}
	}
	if ord := similar_opt_get(opts, 'ordered') {
		attrs << cx.Attribute{
			name:  'ordered'
			value: cx.ScalarValue(similar_node_string(ord) == 'true')
		}
	}
	if dec := similar_opt_get(opts, 'decide') {
		keys, vals := similar_map_pairs(dec)
		mut dattrs := []cx.Attribute{}
		for i, key in keys {
			if key !in ['match', 'review'] {
				return mk_err('cx-err:CXER4900',
					'E_SIMILAR_PREDICATE: decide cuts are {match: …, review: …}, got "${key}"')
			}
			num := similar_scalar_f64(vals[i]) or {
				return mk_err('cx-err:CXER4900',
					'E_SIMILAR_PREDICATE: decide cut "${key}" must be a number')
			}
			dattrs << cx.Attribute{
				name:  key
				value: cx.ScalarValue(num)
			}
		}
		children << cx.Node(cx.Element{
			name:  'decide'
			attrs: dattrs
		})
	}
	if nrm := similar_opt_get(opts, 'normalize') {
		keys, vals := similar_map_pairs(nrm)
		mut nattrs := []cx.Attribute{}
		for i, key in keys {
			if key !in ['fold-case', 'trim', 'stem', 'stopwords'] {
				return mk_err('cx-err:CXER4900',
					'E_SIMILAR_PREDICATE: unknown normalizer "${key}" (fold-case|trim|stem|stopwords)')
			}
			nattrs << cx.Attribute{
				name:  key
				value: cx.ScalarValue(similar_node_string(vals[i]) == 'true')
			}
		}
		children << cx.Node(cx.Element{
			name:  'normalize'
			attrs: nattrs
		})
	}
	if wts := similar_opt_get(opts, 'weights') {
		keys, vals := similar_map_pairs(wts)
		mut fields := []cx.Node{}
		for i, key in keys {
			mut fattrs := []cx.Attribute{}
			fattrs << cx.Attribute{
				name:  'name'
				value: cx.ScalarValue(key)
			}
			if num := similar_scalar_f64(vals[i]) {
				fattrs << cx.Attribute{
					name:  'weight'
					value: cx.ScalarValue(num)
				}
			} else if similar_opt_is_map(vals[i]) {
				if w := similar_opt_get(vals[i], 'weight') {
					wn := similar_scalar_f64(w) or {
						return mk_err('cx-err:CXER4900',
							'E_SIMILAR_PREDICATE: field "${key}" weight must be a number')
					}
					fattrs << cx.Attribute{
						name:  'weight'
						value: cx.ScalarValue(wn)
					}
				}
				if fsc := similar_opt_get(vals[i], 'score') {
					fattrs << similar_atom_attr('score', similar_node_string(fsc))
				}
			} else {
				return mk_err('cx-err:CXER4900',
					'E_SIMILAR_PREDICATE: field "${key}" config must be a weight or a {weight, score} map')
			}
			fields << cx.Node(cx.Element{
				name:  'field'
				attrs: fattrs
			})
		}
		children << cx.Node(cx.Element{
			name:  'weights'
			items: fields
		})
	}
	if res := similar_opt_get(opts, 'resolutions') {
		mut rs := []cx.Node{}
		for it in iterate(res) {
			if it is cx.Element && it.name == 'resolution' {
				rs << cx.Node(it)
			} else {
				return mk_err('cx-err:CXER4900',
					'E_SIMILAR_PREDICATE: resolutions must be [resolution verdict=… [left …] [right …]] elements')
			}
		}
		children << cx.Node(cx.Element{
			name:  'resolutions'
			items: rs
		})
	}
	pred := cx.Element{
		name:  similar_pred_element_name
		attrs: attrs
		items: children
	}
	similar_pred_of(pred) or { return mk_err('cx-err:CXER4900', err.msg()) }
	return pred
}

// similar_similarity_to builds the [similarity-to …] key spec consumed
// by [$sort {"by" …}] (§3.1 sort row).
fn similar_similarity_to(args []cx.Node) cx.Node {
	if args.len != 1 && args.len != 2 {
		return similar_opts_err('similarity-to',
			'expected [\$similar:similarity-to x] or [\$similar:similarity-to x \$pred]')
	}
	mut items := []cx.Node{}
	items << cx.Node(cx.Element{
		name:  'reference'
		items: [args[0]]
	})
	// an absent / empty-map / absence predicate means the default one
	// (the bundle def's optional-param default is `{}`).
	if args.len == 2 && !is_absence_node(args[1]) && !similar_opt_is_empty_map(args[1]) {
		// validate eagerly — a bad predicate fails at construction.
		similar_pred_of(args[1]) or { return mk_err('cx-err:CXER4900', err.msg()) }
		items << cx.Node(cx.Element{
			name:  'predicate'
			items: [args[1]]
		})
	}
	return cx.Element{
		name:  'similarity-to'
		items: items
	}
}

// ── dispatch ─────────────────────────────────────────────────────────

fn similar_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	match name {
		'similar-predicate' {
			if args.len == 0 {
				return similar_predicate_ctor(cx.Element{ name: map_marker_name })
			}
			if args.len != 1 {
				return similar_opts_err('predicate', 'expected [\$similar:predicate {…opts}]')
			}
			return similar_predicate_ctor(args[0])
		}
		'similar-similarity-to' {
			return similar_similarity_to(args)
		}
		'similar-band-of' {
			// band as a true atom (:match / :review / :no-match); a
			// band-less report (no decide policy) → absence.
			if args.len != 1 {
				return similar_opts_err('band-of', 'expected [\$similar:band-of report]')
			}
			r := args[0]
			if r is cx.Element && r.name == similar_report_name {
				band := similar_report_band(r)
				if band == '' {
					return similar_absence()
				}
				return cx.Node(cx.ScalarNode{
					value:     cx.ScalarValue(band)
					data_type: cx.ScalarType.atom_type
				})
			}
			return similar_opts_err('band-of', 'expected a [similar …] report')
		}
		'similar-score' {
			// direct scorer access — raw score, no banding (§4.2).
			if args.len != 3 {
				return similar_opts_err('score', 'expected [\$similar:score :scorer a b]')
			}
			scorer := similar_node_string(args[0])
			if scorer !in similar_scorer_names {
				return mk_err('cx-err:CXER4900', 'E_SIMILAR_PREDICATE: unknown scorer :${scorer}')
			}
			mut p := similar_pred_default()
			p.has_decide = false
			p.scorer = scorer
			scored := similar_score_pair(args[1], args[2], p, '', 0)
			if !scored.comparable {
				return similar_absence()
			}
			return ft_float(scored.score)
		}
		'join' {
			return similar_join(args)
		}
		'distinct' {
			// 2-ary graded form only — the exact 1-ary form is the core
			// builtin and never reaches this chain.
			if args.len == 2 && similar_opt_is_map(args[1]) {
				return similar_distinct_graded(args)
			}
			return none
		}
		'group-by' {
			if args.len == 2 && similar_opt_is_map(args[1]) {
				return similar_group_by_graded(args)
			}
			return none
		}
		'contains' {
			return similar_contains(args)
		}
		'sort' {
			return similar_sort_data(args)
		}
		'validate' {
			return similar_validate(args)
		}
		else {
			return none
		}
	}
}

fn similar_stdlib_builtin_env(name string, args []cx.Node, mut env MatchEnv) ?cx.Node {
	if name == 'sort' {
		return similar_sort_env(args, mut env)
	}
	return none
}
