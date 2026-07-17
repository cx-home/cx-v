// cx-stdlib/similar — graded similarity & approximate matching
// (spec/std-lib/similar.md). Backs the core `~` operator (the graded
// cognate of `=`): scoring is defined ONCE here; every construct that
// goes graded (cxpath predicates, join, distinct, contains?, sort,
// validate, [?match] :when arms) applies this comparison in a position.
//
// A similarity predicate is a pure DATA value — a [similar-predicate …]
// element built by [$similar:predicate {…}] carrying scorer, normalizer,
// per-field weights, decision cuts, tolerance/scale, and the
// known-verdicts resolutions tier (§5.4). Because the predicate is data
// (never a closure), scoring is env-free and every verb can run on the
// env-free dispatch chain.
//
// The comparison result is a [similar score=… band=… evidence=…]
// element (§2.1); node_ebv reads it truthy iff band=:match. The
// tokenization/stemming pipeline is DELEGATED to ft (§4.3) — similar
// does not reimplement segmentation, stopwords, or Porter2.
module code

import cx
import math

// ── predicate model ──────────────────────────────────────────────────

const similar_pred_element_name = 'similar-predicate'
const similar_report_name = 'similar'
const similar_default_match_cut = 0.95
const similar_default_review_cut = 0.85
const similar_scorer_names = ['jaro-winkler', 'levenshtein', 'damerau', 'token-set', 'token-sort',
	'jaccard', 'cosine', 'metaphone', 'numeric', 'temporal']

struct SimilarFieldCfg {
mut:
	weight     f64 = 1.0
	scorer     string // '' → inherit the predicate default
	has_weight bool
}

struct SimilarResolution {
mut:
	left       cx.Node
	right      cx.Node
	verdict    string // 'match' | 'review' | 'no-match'
	decided_by string
}

struct SimilarPredicate {
mut:
	has_decide bool
	match_cut  f64    = similar_default_match_cut
	review_cut f64    = similar_default_review_cut
	scorer     string = 'jaro-winkler'
	// numeric/temporal grading is OPT-IN (§2.1.1 rule 3 / ruling Q6):
	// exact 0/1 unless the caller supplies a tolerance/scale.
	has_tol    bool
	tolerance  f64
	tol_ns     i64
	has_tol_ns bool
	// sequence/array comparison: positional alignment (ordered, the
	// default — CX sequences are ordered values) vs set similarity.
	ordered bool = true
	// normalizers (§4.3) — fold-case/trim apply to character scorers;
	// stem/stopwords apply only to token/term scorers (coupling note).
	fold_case   bool = true
	trim        bool = true
	stem        bool
	stopwords   bool
	fields      map[string]SimilarFieldCfg
	resolutions []SimilarResolution
}

fn similar_pred_default() SimilarPredicate {
	return SimilarPredicate{
		has_decide: true
	}
}

// similar_attr_value returns the raw ScalarValue of a named attribute.
fn similar_attr_value(e cx.Element, name string) ?cx.ScalarValue {
	for a in e.attrs {
		if a.name == name {
			return a.value
		}
	}
	return none
}

fn similar_attr_str(e cx.Element, name string) string {
	v := similar_attr_value(e, name) or { return '' }
	return cx.scalar_value_str_public(v)
}

fn similar_attr_f64(e cx.Element, name string) ?f64 {
	v := similar_attr_value(e, name) or { return none }
	match v {
		f64 { return v }
		i64 { return f64(v) }
		string { return v.f64() }
		else { return none }
	}
}

fn similar_child(e cx.Element, name string) ?cx.Element {
	for it in e.items {
		if it is cx.Element && it.name == name {
			return it
		}
	}
	return none
}

// similar_pred_of resolves the predicate operand of `~` (and of the
// graded verbs). Accepted forms:
//   - absence / empty element → the DEFAULT predicate (bare [~ a b]);
//   - a [similar-predicate …] element (built by [$similar:predicate …]);
//   - a numeric scalar → default predicate + that tolerance/scale
//     (the `[~ 100 105 $tol]` shorthand, §2.1.1);
//   - a duration scalar → default predicate + temporal tolerance.
// Anything else is a CXER4900 err value.
fn similar_pred_of(n cx.Node) !SimilarPredicate {
	if is_absence_node(n) {
		return similar_pred_default()
	}
	if n is cx.ScalarNode {
		v := n.value
		if n.data_type == cx.ScalarType.duration_type {
			s := cx.scalar_value_str_public(v)
			ns := duration_to_ns(s) or {
				return error('E_SIMILAR_PREDICATE: unreadable duration tolerance "${s}"')
			}
			mut p := similar_pred_default()
			p.has_tol_ns = true
			p.tol_ns = ns
			return p
		}
		match v {
			f64 {
				mut p := similar_pred_default()
				p.has_tol = true
				p.tolerance = v
				if p.tolerance <= 0 {
					return error('E_SIMILAR_PREDICATE: tolerance must be > 0')
				}
				return p
			}
			i64 {
				mut p := similar_pred_default()
				p.has_tol = true
				p.tolerance = f64(v)
				if p.tolerance <= 0 {
					return error('E_SIMILAR_PREDICATE: tolerance must be > 0')
				}
				return p
			}
			else {}
		}

		return error('E_SIMILAR_PREDICATE: third operand must be a [similar-predicate …] element or a numeric/duration tolerance')
	}
	if n is cx.Element {
		if n.name == '' && n.items.len == 1 {
			return similar_pred_of(n.items[0])
		}
		if n.name != similar_pred_element_name {
			return error('E_SIMILAR_PREDICATE: expected a [similar-predicate …] element, got [${n.name}]')
		}
		mut p := SimilarPredicate{}
		sc := similar_attr_str(n, 'score')
		if sc != '' {
			if sc !in similar_scorer_names {
				return error('E_SIMILAR_PREDICATE: unknown scorer :${sc}')
			}
			p.scorer = sc
		}
		if tol := similar_attr_f64(n, 'tolerance') {
			if tol <= 0 {
				return error('E_SIMILAR_PREDICATE: tolerance must be > 0')
			}
			p.has_tol = true
			p.tolerance = tol
		}
		tns := similar_attr_str(n, 'tolerance-ns')
		if tns != '' {
			p.has_tol_ns = true
			p.tol_ns = tns.i64()
		}
		ord := similar_attr_str(n, 'ordered')
		if ord != '' {
			p.ordered = ord == 'true'
		}
		if dec := similar_child(n, 'decide') {
			p.has_decide = true
			if m := similar_attr_f64(dec, 'match') {
				p.match_cut = m
			}
			if r := similar_attr_f64(dec, 'review') {
				p.review_cut = r
			}
			if p.review_cut > p.match_cut {
				return error('E_SIMILAR_PREDICATE: decide cuts must satisfy review <= match')
			}
		}
		if nrm := similar_child(n, 'normalize') {
			fc := similar_attr_str(nrm, 'fold-case')
			if fc != '' {
				p.fold_case = fc == 'true'
			}
			tr := similar_attr_str(nrm, 'trim')
			if tr != '' {
				p.trim = tr == 'true'
			}
			p.stem = similar_attr_str(nrm, 'stem') == 'true'
			p.stopwords = similar_attr_str(nrm, 'stopwords') == 'true'
			// coupling note (§4.3): stemming affects only token/term
			// scorers; pairing stem with a character scorer degrades
			// silently — surface it as an [invalid …]-grade config error.
			if p.stem && p.scorer in ['jaro-winkler', 'levenshtein', 'damerau', 'metaphone'] {
				return error('E_SIMILAR_PREDICATE: stem normalizer is inert for character/phonetic scorer :${p.scorer} — use a token scorer (token-set, token-sort, jaccard, cosine)')
			}
		}
		if wts := similar_child(n, 'weights') {
			for it in wts.items {
				if it is cx.Element && it.name == 'field' {
					fname := similar_attr_str(it, 'name')
					if fname == '' {
						continue
					}
					mut cfg := SimilarFieldCfg{}
					if w := similar_attr_f64(it, 'weight') {
						cfg.weight = w
						cfg.has_weight = true
					}
					fsc := similar_attr_str(it, 'score')
					if fsc != '' {
						if fsc !in similar_scorer_names {
							return error('E_SIMILAR_PREDICATE: unknown scorer :${fsc} for field ${fname}')
						}
						cfg.scorer = fsc
					}
					p.fields[fname] = cfg
				}
			}
		}
		if res := similar_child(n, 'resolutions') {
			for it in res.items {
				if it is cx.Element && it.name == 'resolution' {
					verdict := similar_attr_str(it, 'verdict')
					if verdict !in ['match', 'review', 'no-match'] {
						return error('E_SIMILAR_PREDICATE: resolution verdict must be :match, :review, or :no-match')
					}
					left := similar_child(it, 'left') or { continue }
					right := similar_child(it, 'right') or { continue }
					if left.items.len != 1 || right.items.len != 1 {
						continue
					}
					p.resolutions << SimilarResolution{
						left:       left.items[0]
						right:      right.items[0]
						verdict:    verdict
						decided_by: similar_attr_str(it, 'decided-by')
					}
				}
			}
		}
		return p
	}
	return error('E_SIMILAR_PREDICATE: expected a [similar-predicate …] element')
}

// ── value-kind classification (§2.3) ─────────────────────────────────

// similar_kind_of maps a runtime node to the comparand kind axis of the
// §3.2 matrix. Kinds in the same FAMILY are comparable; disjoint
// families are a kind-mismatch (score 0.0, no coercion — rule 5).
fn similar_kind_of(n cx.Node) string {
	if is_absence_node(n) {
		return 'absence'
	}
	match n {
		cx.ScalarNode {
			match n.data_type {
				.string_type { return 'string' }
				.int_type, .float_type, .decimal_type, .bigint_type { return 'number' }
				.bool_type { return 'bool' }
				.atom_type { return 'atom' }
				.null_type { return 'null' }
				.date_type { return 'date' }
				.datetime_type { return 'datetime' }
				.duration_type { return 'duration' }
				.period_type { return 'period' }
				.bytes_type { return 'bytes' }
			}
		}
		cx.TextNode {
			return 'string'
		}
		cx.MapNode {
			return 'map'
		}
		cx.Element {
			if n.name == closure_sentinel_name {
				return 'function'
			}
			if n.name == map_marker_name || n.name == 'map' {
				return 'map'
			}
			if n.name == arr_marker_name {
				return 'array'
			}
			if n.name == seq_marker_name || n.name == '' {
				return 'sequence'
			}
			return 'element'
		}
		else {}
	}

	return 'other'
}

// similar_kind_family groups compatible kinds: number scalars compare
// across int/float; date and datetime compare via a shared timeline.
fn similar_kind_family(kind string) string {
	match kind {
		'date', 'datetime' { return 'temporal' }
		else { return kind }
	}
}

fn similar_is_null(n cx.Node) bool {
	if n is cx.ScalarNode {
		if n.value is cx.NullValue {
			return true
		}
		if n.data_type == cx.ScalarType.null_type {
			return true
		}
	}
	return false
}

// ── string scorers (§4.2) ────────────────────────────────────────────

// similar_jaro computes the Jaro similarity over runes.
fn similar_jaro(a []rune, b []rune) f64 {
	if a.len == 0 && b.len == 0 {
		return 1.0
	}
	if a.len == 0 || b.len == 0 {
		return 0.0
	}
	window := if math.max(a.len, b.len) / 2 - 1 > 0 { math.max(a.len, b.len) / 2 - 1 } else { 0 }
	mut a_matched := []bool{len: a.len}
	mut b_matched := []bool{len: b.len}
	mut matches := 0
	for i in 0 .. a.len {
		lo := if i > window { i - window } else { 0 }
		hi := if i + window + 1 < b.len { i + window + 1 } else { b.len }
		for j := lo; j < hi; j++ {
			if b_matched[j] || a[i] != b[j] {
				continue
			}
			a_matched[i] = true
			b_matched[j] = true
			matches++
			break
		}
	}
	if matches == 0 {
		return 0.0
	}
	mut transpositions := 0
	mut k := 0
	for i in 0 .. a.len {
		if !a_matched[i] {
			continue
		}
		for !b_matched[k] {
			k++
		}
		if a[i] != b[k] {
			transpositions++
		}
		k++
	}
	m := f64(matches)
	t := f64(transpositions) / 2.0
	return (m / f64(a.len) + m / f64(b.len) + (m - t) / m) / 3.0
}

// similar_jaro_winkler applies the Winkler common-prefix boost (p=0.1,
// max prefix 4) above the conventional 0.7 threshold.
fn similar_jaro_winkler(sa string, sb string) f64 {
	a := sa.runes()
	b := sb.runes()
	j := similar_jaro(a, b)
	if j <= 0.7 {
		return j
	}
	mut l := 0
	for l < a.len && l < b.len && l < 4 && a[l] == b[l] {
		l++
	}
	return j + f64(l) * 0.1 * (1.0 - j)
}

// similar_levenshtein_dist is the classic two-row edit distance.
fn similar_levenshtein_dist(a []rune, b []rune) int {
	if a.len == 0 {
		return b.len
	}
	if b.len == 0 {
		return a.len
	}
	mut prev := []int{len: b.len + 1, init: index}
	mut cur := []int{len: b.len + 1}
	for i in 1 .. a.len + 1 {
		cur[0] = i
		for j in 1 .. b.len + 1 {
			cost := if a[i - 1] == b[j - 1] { 0 } else { 1 }
			mut best := prev[j] + 1 // deletion
			if cur[j - 1] + 1 < best { // insertion
				best = cur[j - 1] + 1
			}
			if prev[j - 1] + cost < best { // substitution
				best = prev[j - 1] + cost
			}
			cur[j] = best
		}
		for j in 0 .. b.len + 1 {
			prev[j] = cur[j]
		}
	}
	return prev[b.len]
}

// similar_damerau_dist is the TRUE Damerau-Levenshtein distance
// (adjacent transposition as a first-class edit, alphabet-tracked),
// not the restricted OSA variant.
fn similar_damerau_dist(a []rune, b []rune) int {
	if a.len == 0 {
		return b.len
	}
	if b.len == 0 {
		return a.len
	}
	maxdist := a.len + b.len
	mut da := map[rune]int{}
	// (a.len+2) x (b.len+2) matrix with the -1/0 sentinel rows.
	mut d := [][]int{len: a.len + 2, init: []int{len: b.len + 2}}
	d[0][0] = maxdist
	for i in 0 .. a.len + 1 {
		d[i + 1][0] = maxdist
		d[i + 1][1] = i
	}
	for j in 0 .. b.len + 1 {
		d[0][j + 1] = maxdist
		d[1][j + 1] = j
	}
	for i in 1 .. a.len + 1 {
		mut db := 0
		for j in 1 .. b.len + 1 {
			k := da[b[j - 1]]
			l := db
			mut cost := 1
			if a[i - 1] == b[j - 1] {
				cost = 0
				db = j
			}
			mut best := d[i][j] + cost // substitution
			if d[i + 1][j] + 1 < best { // insertion
				best = d[i + 1][j] + 1
			}
			if d[i][j + 1] + 1 < best { // deletion
				best = d[i][j + 1] + 1
			}
			trans := d[k][l] + (i - k - 1) + 1 + (j - l - 1)
			if trans < best {
				best = trans
			}
			d[i + 1][j + 1] = best
		}
		da[a[i - 1]] = i
	}
	return d[a.len + 1][b.len + 1]
}

fn similar_edit_score(dist int, alen int, blen int) f64 {
	longest := if alen > blen { alen } else { blen }
	if longest == 0 {
		return 1.0
	}
	return 1.0 - f64(dist) / f64(longest)
}

// ── token scorers — tokenization delegated to ft (§4.3) ──────────────

fn similar_tokens(s string, p SimilarPredicate) []string {
	pipe := FtPipeline{
		language:       'en'
		case_sensitive: !p.fold_case
		stem_lang:      if p.stem { 'en' } else { 'none' }
		stopwords_mode: if p.stopwords { 'default' } else { 'none' }
		min_token_len:  1
	}
	return ft_run_pipeline(ft_segment(s), pipe)
}

fn similar_token_set(toks []string) []string {
	mut seen := map[string]bool{}
	mut out := []string{}
	for t in toks {
		if t in seen {
			continue
		}
		seen[t] = true
		out << t
	}
	out.sort()
	return out
}

fn similar_jaccard_score(ta []string, tb []string) f64 {
	sa := similar_token_set(ta)
	sb := similar_token_set(tb)
	if sa.len == 0 && sb.len == 0 {
		return 1.0
	}
	mut inb := map[string]bool{}
	for t in sb {
		inb[t] = true
	}
	mut inter := 0
	for t in sa {
		if t in inb {
			inter++
		}
	}
	union_n := sa.len + sb.len - inter
	if union_n == 0 {
		return 1.0
	}
	return f64(inter) / f64(union_n)
}

fn similar_cosine_score(ta []string, tb []string) f64 {
	if ta.len == 0 && tb.len == 0 {
		return 1.0
	}
	if ta.len == 0 || tb.len == 0 {
		return 0.0
	}
	mut fa := map[string]int{}
	mut fb := map[string]int{}
	for t in ta {
		fa[t]++
	}
	for t in tb {
		fb[t]++
	}
	mut dot := 0.0
	for t, ca in fa {
		if t in fb {
			dot += f64(ca) * f64(fb[t])
		}
	}
	mut na := 0.0
	for _, ca in fa {
		na += f64(ca) * f64(ca)
	}
	mut nb := 0.0
	for _, cb in fb {
		nb += f64(cb) * f64(cb)
	}
	if na == 0 || nb == 0 {
		return 0.0
	}
	c := dot / (math.sqrt(na) * math.sqrt(nb))
	// float dot-product overshoot can exceed 1.0 by an ulp on identical
	// multisets — clamp to the §4.2 closed [0,1] contract (and rule 1's
	// "1.0 reserved for equal-under-normalizers" from above).
	if c > 1.0 {
		return 1.0
	}
	return c
}

// similar_token_sort_score: levenshtein similarity over the
// space-joined SORTED token lists (word-order-insensitive edit view).
fn similar_token_sort_score(ta []string, tb []string) f64 {
	mut sa := ta.clone()
	mut sb := tb.clone()
	sa.sort()
	sb.sort()
	ja := sa.join(' ')
	jb := sb.join(' ')
	ra := ja.runes()
	rb := jb.runes()
	return similar_edit_score(similar_levenshtein_dist(ra, rb), ra.len, rb.len)
}

// similar_token_set_score: the fuzzywuzzy token_set construction — the
// best edit similarity among (common, common+rest_a, common+rest_b),
// which reads 1.0 when one token set contains the other.
fn similar_token_set_score(ta []string, tb []string) f64 {
	sa := similar_token_set(ta)
	sb := similar_token_set(tb)
	if sa.len == 0 && sb.len == 0 {
		return 1.0
	}
	mut inb := map[string]bool{}
	for t in sb {
		inb[t] = true
	}
	mut common := []string{}
	mut rest_a := []string{}
	for t in sa {
		if t in inb {
			common << t
		} else {
			rest_a << t
		}
	}
	mut ina := map[string]bool{}
	for t in sa {
		ina[t] = true
	}
	mut rest_b := []string{}
	for t in sb {
		if t !in ina {
			rest_b << t
		}
	}
	mut with_a := common.clone()
	with_a << rest_a
	mut with_b := common.clone()
	with_b << rest_b
	c := common.join(' ')
	ca := with_a.join(' ')
	cb := with_b.join(' ')
	mut best := 0.0
	pairs := [[c, ca], [c, cb], [ca, cb]]
	for pr in pairs {
		ra := pr[0].runes()
		rb := pr[1].runes()
		s := similar_edit_score(similar_levenshtein_dist(ra, rb), ra.len, rb.len)
		if s > best {
			best = s
		}
	}
	return best
}

// ── scalar comparison ────────────────────────────────────────────────

fn similar_normalize_string(s string, p SimilarPredicate) string {
	mut out := s
	if p.trim {
		out = out.trim_space()
	}
	if p.fold_case {
		out = out.to_lower()
	}
	return out
}

fn similar_string_score(a string, b string, scorer string, p SimilarPredicate) f64 {
	match scorer {
		'token-set', 'token-sort', 'jaccard', 'cosine' {
			ta := similar_tokens(a, p)
			tb := similar_tokens(b, p)
			return match scorer {
				'token-set' { similar_token_set_score(ta, tb) }
				'token-sort' { similar_token_sort_score(ta, tb) }
				'jaccard' { similar_jaccard_score(ta, tb) }
				else { similar_cosine_score(ta, tb) }
			}
		}
		'metaphone' {
			na := similar_normalize_string(a, p)
			nb := similar_normalize_string(b, p)
			return similar_metaphone_score(na, nb)
		}
		'levenshtein', 'damerau' {
			na := similar_normalize_string(a, p).runes()
			nb := similar_normalize_string(b, p).runes()
			dist := if scorer == 'damerau' {
				similar_damerau_dist(na, nb)
			} else {
				similar_levenshtein_dist(na, nb)
			}
			return similar_edit_score(dist, na.len, nb.len)
		}
		else {
			// jaro-winkler — the default string scorer (§2.1.1 rule 2).
			na := similar_normalize_string(a, p)
			nb := similar_normalize_string(b, p)
			return similar_jaro_winkler(na, nb)
		}
	}
}

fn similar_scalar_f64(n cx.Node) ?f64 {
	if n is cx.ScalarNode {
		v := n.value
		match v {
			f64 { return v }
			i64 { return f64(v) }
			string { return v.f64() } // decimal/bigint carry verbatim strings
			else { return none }
		}
	}
	return none
}

fn similar_numeric_score(a f64, b f64, p SimilarPredicate) f64 {
	if a == b {
		return 1.0
	}
	if !p.has_tol {
		// exact by default — unbounded numerics have no canonical
		// metric (ruling Q6).
		return 0.0
	}
	diff := math.abs(a - b)
	s := 1.0 - diff / p.tolerance
	return if s > 0 { s } else { 0.0 }
}

// similar_temporal_ns parses a date/datetime scalar to epoch ns.
fn similar_temporal_ns(n cx.Node) ?i64 {
	if n is cx.ScalarNode {
		s := cx.scalar_value_str_public(n.value)
		return similar_parse_temporal_ns(s)
	}
	return none
}

// similar_parse_temporal_ns handles YYYY-MM-DD and
// YYYY-MM-DDThh:mm:ss[.fff][Z|±hh:mm] without external deps —
// days-from-civil epoch math (proleptic Gregorian).
fn similar_parse_temporal_ns(s0 string) ?i64 {
	s := s0.trim_space()
	if s.len < 10 {
		return none
	}
	y := s[0..4].int()
	mo := s[5..7].int()
	d := s[8..10].int()
	if mo < 1 || mo > 12 || d < 1 || d > 31 {
		return none
	}
	// days_from_civil (Howard Hinnant's algorithm).
	yy := if mo <= 2 { y - 1 } else { y }
	era := (if yy >= 0 { yy } else { yy - 399 }) / 400
	yoe := yy - era * 400
	doy := (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + d - 1
	doe := yoe * 365 + yoe / 4 - yoe / 100 + doy
	days := i64(era) * 146097 + i64(doe) - 719468
	mut ns := days * 86400_000_000_000
	if s.len > 10 && (s[10] == `T` || s[10] == ` `) && s.len >= 19 {
		hh := s[11..13].int()
		mm := s[14..16].int()
		ss := s[17..19].int()
		ns += (i64(hh) * 3600 + i64(mm) * 60 + i64(ss)) * 1_000_000_000
		mut rest := s[19..]
		if rest.starts_with('.') {
			mut i := 1
			mut frac := i64(0)
			mut scale := i64(100_000_000)
			for i < rest.len && rest[i] >= `0` && rest[i] <= `9` {
				frac += i64(rest[i] - `0`) * scale
				scale /= 10
				i++
			}
			ns += frac
			rest = rest[i..]
		}
		if rest.starts_with('+') || rest.starts_with('-') {
			if rest.len >= 6 {
				off := (i64(rest[1..3].int()) * 3600 + i64(rest[4..6].int()) * 60) * 1_000_000_000
				if rest[0] == `+` {
					ns -= off
				} else {
					ns += off
				}
			}
		}
	}
	return ns
}

fn similar_temporal_score(a i64, b i64, p SimilarPredicate) f64 {
	if a == b {
		return 1.0
	}
	mut tol := i64(0)
	if p.has_tol_ns {
		tol = p.tol_ns
	} else if p.has_tol {
		// a bare numeric tolerance on temporal comparands reads as DAYS
		// (the natural date grain; sub-day scales use a duration).
		tol = i64(p.tolerance * 86400.0 * 1_000_000_000.0)
	} else {
		return 0.0
	}
	if tol <= 0 {
		return 0.0
	}
	diff := if a > b { a - b } else { b - a }
	s := 1.0 - f64(diff) / f64(tol)
	return if s > 0 { s } else { 0.0 }
}

// ── report construction (§2.1) ───────────────────────────────────────

fn similar_atom_attr(name string, v string) cx.Attribute {
	return cx.new_attribute(name, cx.ScalarValue(v), cx.AttributeMeta{
		data_type: ?string('atom')
	})
}

// similar_band applies the decision policy (cuts) to a score.
fn similar_band(score f64, p SimilarPredicate) string {
	if score >= p.match_cut {
		return 'match'
	}
	if score >= p.review_cut {
		return 'review'
	}
	return 'no-match'
}

// similar_report builds the [similar score=… band=… [evidence …]]
// result. A predicate with no decide policy yields score+evidence only
// (§2.1). Evidence is a CHILD element (not an attribute): CXDM
// attribute values are scalars, and evidence is inspectable data that
// must render and round-trip.
fn similar_report(score f64, p SimilarPredicate, evidence ?cx.Node) cx.Node {
	mut attrs := []cx.Attribute{}
	attrs << cx.Attribute{
		name:  'score'
		value: cx.ScalarValue(score)
	}
	if p.has_decide {
		attrs << similar_atom_attr('band', similar_band(score, p))
	}
	mut items := []cx.Node{}
	if ev := evidence {
		items << cx.Node(cx.Element{
			name:  'evidence'
			items: [ev]
		})
	}
	return cx.Element{
		name:  similar_report_name
		attrs: attrs
		items: items
	}
}

// similar_report_band reads the band attribute off a [similar …] report
// ('' when absent). This is the node_ebv truthiness hook.
fn similar_report_band(e cx.Element) string {
	for a in e.attrs {
		if a.name == 'band' {
			return cx.scalar_value_str_public(a.value)
		}
	}
	return ''
}

fn similar_report_score(n cx.Node) f64 {
	if n is cx.Element {
		for a in n.attrs {
			if a.name == 'score' {
				v := a.value
				match v {
					f64 { return v }
					i64 { return f64(v) }
					else { return cx.scalar_value_str_public(v).f64() }
				}
			}
		}
	}
	return 0.0
}

fn similar_absence() cx.Node {
	return cx.Element{
		name: seq_marker_name
	}
}

// ── recursive comparison core (§2.3) ─────────────────────────────────

// SimilarScored is one recursive comparison outcome. comparable=false
// marks the null/absence channel: the pair contributes NOTHING to a
// composite combine (skipped, not penalized) and resolves to absence
// at top level.
struct SimilarScored {
	score      f64
	evidence   cx.Node
	comparable bool = true
	absent     bool
}

fn similar_scored_absent() SimilarScored {
	return SimilarScored{
		comparable: false
		absent:     true
		evidence:   cx.Node(cx.Element{
			name: 'absent'
		})
	}
}

fn similar_ev(name string, attrs []cx.Attribute, items []cx.Node) cx.Node {
	return cx.Element{
		name:  name
		attrs: attrs
		items: items
	}
}

fn similar_ev_scorer(scorer string) cx.Node {
	return similar_ev('scorer', [], [
		cx.Node(cx.ScalarNode{
			value:     cx.ScalarValue(scorer)
			data_type: cx.ScalarType.atom_type
		}),
	])
}

fn similar_ev_kind_mismatch(ka string, kb string) cx.Node {
	return similar_ev('kind-mismatch', [], [
		cx.Node(cx.ScalarNode{
			value:     cx.ScalarValue(ka)
			data_type: cx.ScalarType.string_type
		}),
		cx.Node(cx.ScalarNode{
			value:     cx.ScalarValue(kb)
			data_type: cx.ScalarType.string_type
		}),
	])
}

// similar_score_pair is the recursive scoring core. `field` names the
// position (per-field scorer/weight lookup); '' at the root.
fn similar_score_pair(a_in cx.Node, b_in cx.Node, p SimilarPredicate, field string, depth int) SimilarScored {
	if depth > 64 {
		return SimilarScored{
			score:    0.0
			evidence: similar_ev('depth-limit', [], [])
		}
	}
	a := meta_unwrap(a_in)
	b := meta_unwrap(b_in)
	// null / absence — the absence channel (rule 6): unknown, not
	// different. Never 0.
	if is_absence_node(a) || is_absence_node(b) || similar_is_null(a) || similar_is_null(b) {
		return similar_scored_absent()
	}
	// known-verdicts resolver tier (§5.4) — the highest-priority tier: a
	// resolved pair short-circuits before any scorer runs.
	for r in p.resolutions {
		if (nodes_equal(r.left, a) && nodes_equal(r.right, b))
			|| (nodes_equal(r.left, b) && nodes_equal(r.right, a)) {
			score := match r.verdict {
				'match' { 1.0 }
				'no-match' { 0.0 }
				else { 0.5 }
			}

			mut ev_attrs := []cx.Attribute{}
			if r.decided_by != '' {
				ev_attrs << cx.Attribute{
					name:  'decided-by'
					value: cx.ScalarValue(r.decided_by)
				}
			}
			return SimilarScored{
				score:    score
				evidence: similar_ev('resolved', ev_attrs, [
					cx.Node(cx.ScalarNode{
						value:     cx.ScalarValue(r.verdict)
						data_type: cx.ScalarType.atom_type
					}),
				])
			}
		}
	}
	ka := similar_kind_of(a)
	kb := similar_kind_of(b)
	if similar_kind_family(ka) != similar_kind_family(kb) {
		return SimilarScored{
			score:    0.0
			evidence: similar_ev_kind_mismatch(ka, kb)
		}
	}
	scorer := if field != '' && field in p.fields && p.fields[field].scorer != '' {
		p.fields[field].scorer
	} else {
		p.scorer
	}
	match similar_kind_family(ka) {
		'string' {
			sa := similar_node_string(a)
			sb := similar_node_string(b)
			return SimilarScored{
				score:    similar_string_score(sa, sb, scorer, p)
				evidence: similar_ev_scorer(scorer)
			}
		}
		'number' {
			na := similar_scalar_f64(a) or { return similar_scored_absent() }
			nb := similar_scalar_f64(b) or { return similar_scored_absent() }
			return SimilarScored{
				score:    similar_numeric_score(na, nb, p)
				evidence: similar_ev_scorer('numeric')
			}
		}
		'temporal' {
			ta := similar_temporal_ns(a) or { return similar_scored_absent() }
			tb := similar_temporal_ns(b) or { return similar_scored_absent() }
			return SimilarScored{
				score:    similar_temporal_score(ta, tb, p)
				evidence: similar_ev_scorer('temporal')
			}
		}
		'duration' {
			da := duration_to_ns(similar_node_string(a)) or { return similar_scored_absent() }
			db := duration_to_ns(similar_node_string(b)) or { return similar_scored_absent() }
			return SimilarScored{
				score:    similar_temporal_score_dur(da, db, p)
				evidence: similar_ev_scorer('temporal')
			}
		}
		'atom', 'bool', 'bytes', 'period', 'function', 'other' {
			// nominal / degenerate: `~` reduces to `=` — score ∈ {0,1}
			// (§3.2 footnote 1). No graded middle.
			eq := nodes_equal(a, b)
			return SimilarScored{
				score:    if eq { 1.0 } else { 0.0 }
				evidence: similar_ev_scorer('exact')
			}
		}
		'map' {
			return similar_score_map(a, b, p, depth)
		}
		'element' {
			return similar_score_element(a, b, p, depth)
		}
		'sequence', 'array' {
			return similar_score_seq(a, b, p, depth)
		}
		else {
			return SimilarScored{
				score:    0.0
				evidence: similar_ev_kind_mismatch(ka, kb)
			}
		}
	}
}

fn similar_temporal_score_dur(a i64, b i64, p SimilarPredicate) f64 {
	if a == b {
		return 1.0
	}
	mut tol := i64(0)
	if p.has_tol_ns {
		tol = p.tol_ns
	} else if p.has_tol {
		tol = i64(p.tolerance * 1_000_000_000.0) // bare numeric = seconds for durations
	} else {
		return 0.0
	}
	if tol <= 0 {
		return 0.0
	}
	diff := if a > b { a - b } else { b - a }
	s := 1.0 - f64(diff) / f64(tol)
	return if s > 0 { s } else { 0.0 }
}

fn similar_node_string(n cx.Node) string {
	if n is cx.ScalarNode {
		return cx.scalar_value_str_public(n.value)
	}
	if n is cx.TextNode {
		return n.value
	}
	return ''
}

// similar_map_pairs extracts (keys, values) from either map shape
// (MapNode or the __cx_map__ marker element).
fn similar_map_pairs(n cx.Node) ([]string, []cx.Node) {
	if n is cx.MapNode {
		mut keys := []string{}
		mut vals := []cx.Node{}
		for e in n.entries {
			keys << cx.scalar_value_str_public(e.key_value)
			vals << e.value
		}
		return keys, vals
	}
	keys, vals, ok := ft_map_entries(n)
	if ok {
		return keys, vals
	}
	return []string{}, []cx.Node{}
}

// SimilarContribution is one weighted component of a composite combine.
struct SimilarContribution {
	name   string
	weight f64
	scored SimilarScored
}

// similar_combine folds per-field contributions into a null-aware
// weighted mean. Skipped (absent) fields contribute nothing; when NO
// field was comparable the whole comparison is the absence channel.
fn similar_combine(contribs []SimilarContribution, skipped []string, kind_label string) SimilarScored {
	mut wsum := 0.0
	mut ssum := 0.0
	mut ev_items := []cx.Node{}
	mut any := false
	for c in contribs {
		if !c.scored.comparable {
			ev_items << similar_ev('skipped', [
				cx.Attribute{ name: 'name', value: cx.ScalarValue(c.name) },
			], [])
			continue
		}
		any = true
		wsum += c.weight
		ssum += c.scored.score * c.weight
		mut fattrs := []cx.Attribute{}
		fattrs << cx.Attribute{
			name:  'name'
			value: cx.ScalarValue(c.name)
		}
		fattrs << cx.Attribute{
			name:  'score'
			value: cx.ScalarValue(c.scored.score)
		}
		if c.weight != 1.0 {
			fattrs << cx.Attribute{
				name:  'weight'
				value: cx.ScalarValue(c.weight)
			}
		}
		ev_items << similar_ev('field', fattrs, [])
	}
	for s in skipped {
		ev_items << similar_ev('skipped', [
			cx.Attribute{ name: 'name', value: cx.ScalarValue(s) },
		], [])
	}
	if !any {
		return similar_scored_absent()
	}
	return SimilarScored{
		score:    ssum / wsum
		evidence: similar_ev(kind_label, [], ev_items)
	}
}

fn similar_field_weight(p SimilarPredicate, name string) f64 {
	if name in p.fields {
		return p.fields[name].weight
	}
	return 1.0
}

// similar_score_map — null-aware weighted combine over named fields
// (§2.3 row 2). Fields present on only one side are skipped, not
// penalized (configurably strict combining is a predicate concern for
// a later revision — v1 pins the default).
fn similar_score_map(a cx.Node, b cx.Node, p SimilarPredicate, depth int) SimilarScored {
	ka, va := similar_map_pairs(a)
	kb, vb := similar_map_pairs(b)
	mut b_idx := map[string]int{}
	for i, k in kb {
		b_idx[k] = i
	}
	mut contribs := []SimilarContribution{}
	mut skipped := []string{}
	mut seen := map[string]bool{}
	for i, k in ka {
		seen[k] = true
		if k in b_idx {
			scored := similar_score_pair(va[i], vb[b_idx[k]], p, k, depth + 1)
			contribs << SimilarContribution{
				name:   k
				weight: similar_field_weight(p, k)
				scored: scored
			}
		} else {
			skipped << k
		}
	}
	for k in kb {
		if k !in seen {
			skipped << k
		}
	}
	return similar_combine(contribs, skipped, 'fields')
}

// similar_score_element — children aligned BY NAME and recursed;
// attributes compared as cognate to children; the element name itself
// is an exact component (§2.3 row 3 / §3.2 footnote 2). Scalar/text
// content items align positionally.
fn similar_score_element(a_n cx.Node, b_n cx.Node, p SimilarPredicate, depth int) SimilarScored {
	a := a_n as cx.Element
	b := b_n as cx.Element
	mut contribs := []SimilarContribution{}
	mut skipped := []string{}
	// component 1: the element name (exact).
	contribs << SimilarContribution{
		name:   '#name'
		weight: 1.0
		scored: SimilarScored{
			score:    if a.name == b.name { 1.0 } else { 0.0 }
			evidence: similar_ev_scorer('exact')
		}
	}
	// component 2: attributes, as named fields.
	mut b_attrs := map[string]cx.ScalarValue{}
	mut b_attr_seen := map[string]bool{}
	for at in b.attrs {
		b_attrs[at.name] = at.value
	}
	for at in a.attrs {
		if at.name in b_attrs {
			b_attr_seen[at.name] = true
			bv := b_attrs[at.name] or { continue }
			scored := similar_score_pair(similar_attr_node(at.value), similar_attr_node(bv), p,
				at.name, depth + 1)
			contribs << SimilarContribution{
				name:   at.name
				weight: similar_field_weight(p, at.name)
				scored: scored
			}
		} else {
			skipped << at.name
		}
	}
	for at in b.attrs {
		if at.name !in b_attr_seen {
			skipped << at.name
		}
	}
	// component 3: child ELEMENTS aligned by name (k-th occurrence to
	// k-th occurrence); child scalars/text aligned positionally.
	mut a_kids := map[string][]cx.Node{}
	mut b_kids := map[string][]cx.Node{}
	mut a_scalars := []cx.Node{}
	mut b_scalars := []cx.Node{}
	mut a_kid_order := []string{}
	for it in a.items {
		if it is cx.Element && it.name != '' {
			if it.name !in a_kids {
				a_kid_order << it.name
			}
			a_kids[it.name] << it
		} else {
			a_scalars << it
		}
	}
	for it in b.items {
		if it is cx.Element && it.name != '' {
			b_kids[it.name] << it
		} else {
			b_scalars << it
		}
	}
	for name in a_kid_order {
		if name in b_kids {
			la := a_kids[name]
			lb := b_kids[name]
			n := if la.len < lb.len { la.len } else { lb.len }
			for i in 0 .. n {
				scored := similar_score_pair(la[i], lb[i], p, name, depth + 1)
				contribs << SimilarContribution{
					name:   name
					weight: similar_field_weight(p, name)
					scored: scored
				}
			}
			if la.len != lb.len {
				skipped << name
			}
		} else {
			skipped << name
		}
	}
	for name, _ in b_kids {
		if name !in a_kids {
			skipped << name
		}
	}
	nsc := if a_scalars.len < b_scalars.len { a_scalars.len } else { b_scalars.len }
	for i in 0 .. nsc {
		scored := similar_score_pair(a_scalars[i], b_scalars[i], p, '#text', depth + 1)
		contribs << SimilarContribution{
			name:   '#text'
			weight: 1.0
			scored: scored
		}
	}
	if a_scalars.len != b_scalars.len {
		skipped << '#text'
	}
	return similar_combine(contribs, skipped, 'element')
}

fn similar_attr_node(v cx.ScalarValue) cx.Node {
	match v {
		i64 {
			return cx.ScalarNode{
				value:     v
				data_type: cx.ScalarType.int_type
			}
		}
		f64 {
			return cx.ScalarNode{
				value:     v
				data_type: cx.ScalarType.float_type
			}
		}
		bool {
			return cx.ScalarNode{
				value:     v
				data_type: cx.ScalarType.bool_type
			}
		}
		cx.NullValue {
			return cx.ScalarNode{
				value:     v
				data_type: cx.ScalarType.null_type
			}
		}
		string {
			return cx.ScalarNode{
				value:     v
				data_type: cx.ScalarType.string_type
			}
		}
	}
}

// similar_score_seq — positional alignment normalized by the LONGER
// side when ordered (the default; unpaired members count against the
// score, unlike null-aware fields — position is identity here), set
// similarity (exact-membership Jaccard) when the predicate says
// ordered=false (§2.3 row 4).
fn similar_score_seq(a cx.Node, b cx.Node, p SimilarPredicate, depth int) SimilarScored {
	ia := if a is cx.Element { a.items } else { []cx.Node{} }
	ib := if b is cx.Element { b.items } else { []cx.Node{} }
	if !p.ordered {
		// exact-membership Jaccard over the deduplicated member sets.
		mut da := []cx.Node{}
		for it in ia {
			mut dup := false
			for d in da {
				if nodes_equal(it, d) {
					dup = true
					break
				}
			}
			if !dup {
				da << it
			}
		}
		mut db := []cx.Node{}
		for it in ib {
			mut dup := false
			for d in db {
				if nodes_equal(it, d) {
					dup = true
					break
				}
			}
			if !dup {
				db << it
			}
		}
		mut inter := 0
		for it in da {
			for it2 in db {
				if nodes_equal(it, it2) {
					inter++
					break
				}
			}
		}
		u := da.len + db.len - inter
		score := if u == 0 { 1.0 } else { f64(inter) / f64(u) }
		return SimilarScored{
			score:    score
			evidence: similar_ev_scorer('jaccard')
		}
	}
	longest := if ia.len > ib.len { ia.len } else { ib.len }
	if longest == 0 {
		return SimilarScored{
			score:    1.0
			evidence: similar_ev_scorer('alignment')
		}
	}
	shortest := if ia.len < ib.len { ia.len } else { ib.len }
	mut ssum := 0.0
	mut ev_items := []cx.Node{}
	for i in 0 .. shortest {
		scored := similar_score_pair(ia[i], ib[i], p, '', depth + 1)
		contrib := if scored.comparable { scored.score } else { 0.0 }
		ssum += contrib
		ev_items << similar_ev('member', [
			cx.Attribute{ name: 'index', value: cx.ScalarValue(i64(i)) },
			cx.Attribute{ name: 'score', value: cx.ScalarValue(contrib) },
		], [])
	}
	return SimilarScored{
		score:    ssum / f64(longest)
		evidence: similar_ev('alignment', [], ev_items)
	}
}

// ── the operator entry point ─────────────────────────────────────────

// similar_compare backs the `~` operator (eval_operator_element).
// pred_n is the third operand or an empty element for the 2-ary form.
fn similar_compare(a cx.Node, b cx.Node, pred_n cx.Node) cx.Node {
	p := similar_pred_of(pred_n) or { return mk_err('cx-err:CXER4900', err.msg()) }
	scored := similar_score_pair(a, b, p, '', 0)
	if !scored.comparable {
		// null / absence flows inertly (rule 6) — the absence channel.
		return similar_absence()
	}
	return similar_report(scored.score, p, scored.evidence)
}

// ── bundled module source ────────────────────────────────────────────

const stdlib_src_similar = $embed_file('../stdlib/similar.cx').to_string()
