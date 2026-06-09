@[has_globals]
module code

import cx
import math

// stdlib_ft.v — native primitives backing the `cx-stdlib/ft` fulltext
// search module (spec/std-lib/ft.md). A naive in-memory inverted index is
// built per call; tokenization (UAX-#29-ish segmentation → case-fold →
// stopword-removal → Porter2 stem), TF-IDF / BM25 scoring, phrase /
// boolean / field query evaluation, and snippet extraction all run in
// native V (none of it is expressible in pure CX). The bundle `[?def]`
// bodies (stdlib_src_ft) forward to the `ft-`-prefixed prims dispatched
// here via stdlib_dispatch.v.
//
// An Index is an OPAQUE in-memory value (§1) — a heap FtIndex registered
// in a process-global registry, referenced by an integer handle carried
// on the returned `[ft-index handle=N]` element (the same handle idiom as
// cx-stdlib/store). Errors are VALUES (mk_err), not exceptions.
//
// Custom tokenizers (§3.1) are CX closures and must be applied with the
// evaluator env in scope; that one path runs through the env-aware
// `ft_stdlib_builtin_env` hook called from dispatch_call_l. Everything
// else is env-free and routes through `ft_stdlib_builtin`.

// ── registry / index state ───────────────────────────────────────────

// FtDoc is one indexed document: its surface id, the flat token stream
// (for default-field search), per-field token streams (for field
// restriction), and the token count (document length, for scoring).
struct FtDoc {
mut:
	id           string
	tokens       []string
	positions    map[string][]int // token → positions in `tokens`
	field_tokens map[string][]string
	length       int
}

// FtIndex is the opaque in-memory inverted index.
@[heap]
struct FtIndex {
mut:
	docs           []FtDoc
	df             map[string]int // document frequency per term
	term_count     int            // distinct terms
	total_len      int            // sum of doc lengths (for avg_dl)
	fields         []string       // indexed field names (field restriction)
	// build options carried so `search` can tokenize the query the same way
	language       string = 'en'
	case_sensitive bool
	stemmer        string = 'en'
	stopwords_mode string = 'default' // "default" | "none" | "custom"
	stopwords_set  map[string]bool
	min_token_len  int = 2
}

@[heap]
struct FtRegistry {
mut:
	indexes map[int]&FtIndex
	next_id int
}

__global (
	g_ft_reg voidptr
)

fn ft_reg() &FtRegistry {
	if g_ft_reg == unsafe { nil } {
		r := &FtRegistry{
			indexes: map[int]&FtIndex{}
		}
		g_ft_reg = voidptr(r)
	}
	return unsafe { &FtRegistry(g_ft_reg) }
}

fn ft_register(idx &FtIndex) int {
	mut reg := ft_reg()
	reg.next_id++
	id := reg.next_id
	reg.indexes[id] = idx
	return id
}

fn ft_lookup(id int) ?&FtIndex {
	reg := ft_reg()
	return reg.indexes[id] or { return none }
}

fn ft_index_of(n cx.Node) ?&FtIndex {
	if n is cx.Element && n.name == 'ft-index' {
		for a in n.attrs {
			if a.name == 'handle' {
				id := cx.scalar_value_str_public(a.value).int()
				return ft_lookup(id)
			}
		}
	}
	return none
}

fn ft_index_element(id int) cx.Node {
	return cx.Element{
		name:  'ft-index'
		attrs: [cx.Attribute{
			name:  'handle'
			value: cx.ScalarValue(i64(id))
		}]
	}
}

// ── value builders ───────────────────────────────────────────────────

fn ft_str(s string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.string_type
	}
}

fn ft_int(v i64) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(v)
		data_type: cx.ScalarType.int_type
	}
}

fn ft_float(v f64) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(v)
		data_type: cx.ScalarType.float_type
	}
}

fn ft_seq(items []cx.Node) cx.Node {
	return cx.Element{
		name:  '__cx_seq__'
		items: items
	}
}

fn ft_map(keys []string, vals []cx.Node) cx.Node {
	mut entries := []cx.Node{}
	for i, k in keys {
		entries << cx.Element{
			name:  k
			items: [vals[i]]
		}
	}
	return cx.Element{
		name:  '__cx_map__'
		items: entries
	}
}

fn ft_arg_str(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	if n is cx.TextNode {
		return n.value
	}
	return none
}

// ft_node_text returns the textual value of any scalar/text node.
fn ft_node_text(n cx.Node) ?string {
	match n {
		cx.ScalarNode {
			v := n.value
			match v {
				string { return v }
				i64 { return v.str() }
				f64 { return cx.scalar_value_str_public(v) }
				bool { return if v { 'true' } else { 'false' } }
				cx.NullValue { return '' }
			}
		}
		cx.TextNode {
			return n.value
		}
		else {
			return none
		}
	}
}

fn ft_seq_items(n cx.Node) ?[]cx.Node {
	if n is cx.Element {
		if n.name == '__cx_seq__' || n.name == '__cx_arr__' || n.name == ''
			|| n.name == 'sequence' || n.name == 'array' {
			return n.items
		}
	}
	return none
}

fn ft_map_entries(n cx.Node) ([]string, []cx.Node, bool) {
	mut keys := []string{}
	mut vals := []cx.Node{}
	if n is cx.Element {
		if n.name == '__cx_map__' || n.name == 'map' {
			for it in n.items {
				if it is cx.Element {
					keys << it.name
					if it.items.len > 0 {
						vals << it.items[0]
					} else {
						vals << ft_str('')
					}
				}
			}
			// element-with-attrs map shape: `{k: v}` may parse as a map
			// element whose entries live in attrs.
			for a in n.attrs {
				keys << a.name
				vals << ft_str(cx.scalar_value_str_public(a.value))
			}
			return keys, vals, true
		}
	}
	return keys, vals, false
}

fn ft_map_get(n cx.Node, key string) ?cx.Node {
	keys, vals, ok := ft_map_entries(n)
	if !ok {
		return none
	}
	for i, k in keys {
		if k == key {
			return vals[i]
		}
	}
	return none
}

// ── stopwords ─────────────────────────────────────────────────────────

const ft_stopwords_en = 'a an and are as at be by for from has have he in is it its of on or that the to was were will with you your this these those they them their there here when where why how what which who whom whose'

// ft_languages_known is the set of language tags the tokenizer accepts
// (§2.1 table + bundled stopword languages). Anything else → CXER1201.
const ft_languages_known = ['en', 'es', 'fr', 'de', 'pt', 'it', 'ru', 'nl', 'ja', 'zh', 'th',
	'ko', 'ar', 'hi']

fn ft_language_known(tag string) bool {
	return tag in ft_languages_known
}

fn ft_stopwords_for(language string) map[string]bool {
	mut set := map[string]bool{}
	if language == 'en' {
		for w in ft_stopwords_en.split(' ') {
			set[w] = true
		}
	}
	// other bundled languages have lists in the spec table; only `en` is
	// exercised by the fixtures and is the only bundled list materialized
	// here. Non-`en` languages drop no stopwords (matches §2.1 "other
	// languages default to no stemming/stopwords until v0.8.x" intent and
	// ft-018: a non-bundled language keeps "the").
	return set
}

// ── tokenization pipeline ─────────────────────────────────────────────

// ft_segment splits text into raw word tokens (UAX-#29-ish): runs of
// letters / digits, with apostrophes kept inside a word (contractions)
// and `.`/`,` kept between digits (numbers like 1,234.56). Punctuation
// otherwise drops.
fn ft_segment(text string) []string {
	mut out := []string{}
	runes := text.runes()
	mut cur := []rune{}
	for i, r in runes {
		if ft_is_word_rune(r) {
			cur << r
		} else if r == `'` && cur.len > 0 && i + 1 < runes.len && ft_is_word_rune(runes[i + 1]) {
			// intra-word apostrophe (don't).
			cur << r
		} else if (r == `.` || r == `,`) && cur.len > 0 && i + 1 < runes.len
			&& ft_is_digit_rune(runes[i + 1]) && ft_is_digit_rune(cur[cur.len - 1]) {
			// numeric separator (1,234.56).
			cur << r
		} else {
			if cur.len > 0 {
				out << cur.string()
				cur = []rune{}
			}
		}
	}
	if cur.len > 0 {
		out << cur.string()
	}
	return out
}

fn ft_is_word_rune(r rune) bool {
	return (r >= `a` && r <= `z`) || (r >= `A` && r <= `Z`) || (r >= `0` && r <= `9`)
		|| r > 127
}

fn ft_is_digit_rune(r rune) bool {
	return r >= `0` && r <= `9`
}

struct FtPipeline {
	language       string
	case_sensitive bool
	stem_lang      string // "en" | "none"
	stopwords_mode string // "default" | "none" | "custom"
	stopwords_set  map[string]bool
	min_token_len  int
}

// ft_run_pipeline runs case-fold → stopword-removal → stem over a list of
// already-segmented raw tokens, dropping tokens below min length.
fn ft_run_pipeline(raw []string, p FtPipeline) []string {
	mut out := []string{}
	stop := if p.stopwords_mode == 'default' {
		ft_stopwords_for(p.language)
	} else if p.stopwords_mode == 'custom' {
		p.stopwords_set
	} else {
		map[string]bool{}
	}
	for tok0 in raw {
		mut tok := tok0
		if !p.case_sensitive {
			tok = tok.to_lower()
		}
		if p.stopwords_mode != 'none' && tok in stop {
			continue
		}
		if p.stem_lang == 'en' {
			tok = ft_porter2(tok)
		}
		if tok.len == 0 {
			continue
		}
		// min-token-length is measured in runes; stopwords already removed.
		if tok.runes().len < p.min_token_len {
			continue
		}
		out << tok
	}
	return out
}

// ft_tokenize_full = segment + pipeline (the §3.5 tokenize surface).
fn ft_tokenize_full(text string, p FtPipeline) []string {
	return ft_run_pipeline(ft_segment(text), p)
}

// ── Porter2 (English Snowball) stemmer ────────────────────────────────
// A faithful implementation of the Snowball English (Porter2) algorithm,
// sufficient for the conformance family-collapse fixtures and general use.

fn ft_is_vowel(s string, i int) bool {
	if i < 0 || i >= s.len {
		return false
	}
	c := s[i]
	if c == `a` || c == `e` || c == `i` || c == `o` || c == `u` {
		return true
	}
	if c == `y` {
		// y is a vowel unless preceded by a vowel.
		if i == 0 {
			return false
		}
		return !ft_is_vowel(s, i - 1)
	}
	return false
}

fn ft_porter2(word0 string) string {
	if word0.len <= 2 {
		return word0
	}
	mut w := word0
	// step 0a: leading apostrophe removal handled by segmenter; strip
	// trailing 's apostrophe forms.
	if w.starts_with("'") {
		w = w[1..]
	}
	// replace initial y or y-after-vowel with Y (treated as consonant)
	mut bytes := w.bytes()
	if bytes.len > 0 && bytes[0] == `y` {
		bytes[0] = `Y`
	}
	for i := 1; i < bytes.len; i++ {
		if bytes[i] == `y` && ft_byte_is_vowel(bytes[i - 1]) {
			bytes[i] = `Y`
		}
	}
	w = bytes.bytestr()

	r1, _ := ft_compute_r1r2(w)

	// step 0: possessive suffixes
	if w.ends_with("'s'") {
		w = w[..w.len - 3]
	} else if w.ends_with("'s") {
		w = w[..w.len - 2]
	} else if w.ends_with("'") {
		w = w[..w.len - 1]
	}

	// step 1a
	if w.ends_with('sses') {
		w = w[..w.len - 4] + 'ss'
	} else if w.ends_with('ied') || w.ends_with('ies') {
		stem := w[..w.len - 3]
		if stem.len > 1 {
			w = stem + 'i'
		} else {
			w = stem + 'ie'
		}
	} else if w.ends_with('ss') || w.ends_with('us') {
		// keep
	} else if w.ends_with('s') {
		// delete s if the preceding word part contains a vowel not
		// immediately before the s.
		mut has_vowel := false
		for i in 0 .. w.len - 2 {
			if ft_byte_is_vowel_y(w, i) {
				has_vowel = true
				break
			}
		}
		if has_vowel {
			w = w[..w.len - 1]
		}
	}

	// step 1b
	w = ft_porter2_step1b(w, r1)

	// step 1c: replace y/Y by i if preceded by a consonant and not the
	// first letter.
	if w.len > 2 {
		last := w[w.len - 1]
		if (last == `y` || last == `Y`) && !ft_byte_is_vowel(w[w.len - 2]) {
			w = w[..w.len - 1] + 'i'
		}
	}

	// recompute regions after 1a/1b edits
	r1b, _ := ft_compute_r1r2(w)

	// step 2
	w = ft_porter2_step2(w, r1b)
	r1c, r2c := ft_compute_r1r2(w)

	// step 3
	w = ft_porter2_step3(w, r1c, r2c)
	_, r2d := ft_compute_r1r2(w)

	// step 4
	w = ft_porter2_step4(w, r2d)

	// step 5
	w = ft_porter2_step5(w)

	// turn Y back to y
	w = w.replace('Y', 'y')
	return w
}

fn ft_byte_is_vowel(c u8) bool {
	return c == `a` || c == `e` || c == `i` || c == `o` || c == `u`
}

fn ft_byte_is_vowel_y(s string, i int) bool {
	c := s[i]
	if ft_byte_is_vowel(c) {
		return true
	}
	if c == `y` || c == `Y` {
		if i == 0 {
			return true
		}
		return !ft_byte_is_vowel_y(s, i - 1)
	}
	return false
}

// ft_compute_r1r2 returns the byte offsets where R1 and R2 begin.
fn ft_compute_r1r2(w string) (int, int) {
	// special exceptions for R1
	mut r1 := w.len
	mut start := 0
	for pfx in ['gener', 'commun', 'arsen'] {
		if w.starts_with(pfx) {
			r1 = pfx.len
			start = pfx.len
			break
		}
	}
	if start == 0 {
		r1 = ft_region_after(w, 0)
	}
	r2 := ft_region_after(w, r1)
	return r1, r2
}

// ft_region_after returns the offset of the region after a vowel→consonant
// boundary starting the search at `from`.
fn ft_region_after(w string, from int) int {
	mut i := from
	// find first vowel
	for i < w.len && !ft_byte_is_vowel_y(w, i) {
		i++
	}
	// then first non-vowel after it
	for i < w.len && ft_byte_is_vowel_y(w, i) {
		i++
	}
	if i < w.len {
		return i + 1
	}
	return w.len
}

fn ft_ends_short_syllable(w string) bool {
	// (a) consonant-vowel-consonant where final is not w/x/Y, or
	// (b) at the start: vowel-consonant.
	n := w.len
	if n >= 3 {
		c1 := w[n - 1]
		if !ft_byte_is_vowel(c1) && c1 != `w` && c1 != `x` && c1 != `Y`
			&& ft_byte_is_vowel_y(w, n - 2) && !ft_byte_is_vowel_y(w, n - 3) {
			return true
		}
	}
	if n == 2 {
		return ft_byte_is_vowel_y(w, 0) && !ft_byte_is_vowel_y(w, 1)
	}
	return false
}

fn ft_is_short(w string, r1 int) bool {
	return r1 >= w.len && ft_ends_short_syllable(w)
}

fn ft_porter2_step1b(w0 string, r1 int) string {
	mut w := w0
	if w.ends_with('eed') || w.ends_with('eedly') {
		suf := if w.ends_with('eedly') { 'eedly' } else { 'eed' }
		pos := w.len - suf.len
		if pos >= r1 {
			w = w[..w.len - suf.len] + 'ee'
		}
		return w
	}
	mut matched := false
	mut stem := w
	for suf in ['ingly', 'edly', 'ing', 'ed'] {
		if w.ends_with(suf) {
			cand := w[..w.len - suf.len]
			// test contains a vowel
			mut has_vowel := false
			for i in 0 .. cand.len {
				if ft_byte_is_vowel_y(cand, i) {
					has_vowel = true
					break
				}
			}
			if has_vowel {
				stem = cand
				matched = true
			}
			break
		}
	}
	if !matched {
		return w
	}
	w = stem
	if w.ends_with('at') || w.ends_with('bl') || w.ends_with('iz') {
		return w + 'e'
	}
	if ft_ends_double(w) {
		return w[..w.len - 1]
	}
	r1n := ft_region_after(w, 0)
	if ft_is_short(w, r1n) {
		return w + 'e'
	}
	return w
}

fn ft_ends_double(w string) bool {
	n := w.len
	if n < 2 {
		return false
	}
	a := w[n - 1]
	b := w[n - 2]
	if a != b {
		return false
	}
	return a == `b` || a == `d` || a == `f` || a == `g` || a == `m` || a == `n` || a == `p`
		|| a == `r` || a == `t`
}

fn ft_porter2_step2(w0 string, r1 int) string {
	mut w := w0
	pairs := [
		['ational', 'ate'],
		['tional', 'tion'],
		['enci', 'ence'],
		['anci', 'ance'],
		['abli', 'able'],
		['entli', 'ent'],
		['izer', 'ize'],
		['ization', 'ize'],
		['ation', 'ate'],
		['ator', 'ate'],
		['alism', 'al'],
		['aliti', 'al'],
		['alli', 'al'],
		['fulness', 'ful'],
		['ousli', 'ous'],
		['ousness', 'ous'],
		['iveness', 'ive'],
		['iviti', 'ive'],
		['biliti', 'ble'],
		['bli', 'ble'],
		['fulli', 'ful'],
		['lessli', 'less'],
		['ogi', 'og'],
		['li', ''],
	]
	for pr in pairs {
		suf := pr[0]
		rep := pr[1]
		if w.ends_with(suf) {
			pos := w.len - suf.len
			if pos < r1 {
				return w
			}
			if suf == 'ogi' {
				if pos > 0 && w[pos - 1] == `l` {
					return w[..pos] + rep
				}
				return w
			}
			if suf == 'li' {
				// delete li only when preceded by a valid li-ending.
				if pos > 0 && ft_is_li_ending(w[pos - 1]) {
					return w[..pos]
				}
				return w
			}
			return w[..pos] + rep
		}
	}
	return w
}

fn ft_is_li_ending(c u8) bool {
	return c == `c` || c == `d` || c == `e` || c == `g` || c == `h` || c == `k` || c == `m`
		|| c == `n` || c == `r` || c == `t`
}

fn ft_porter2_step3(w0 string, r1 int, r2 int) string {
	mut w := w0
	pairs := [
		['ational', 'ate'],
		['tional', 'tion'],
		['alize', 'al'],
		['icate', 'ic'],
		['iciti', 'ic'],
		['ical', 'ic'],
		['ful', ''],
		['ness', ''],
	]
	for pr in pairs {
		suf := pr[0]
		rep := pr[1]
		if w.ends_with(suf) {
			pos := w.len - suf.len
			if pos < r1 {
				return w
			}
			return w[..pos] + rep
		}
	}
	if w.ends_with('ative') {
		pos := w.len - 'ative'.len
		if pos >= r2 {
			return w[..pos]
		}
	}
	return w
}

fn ft_porter2_step4(w0 string, r2 int) string {
	mut w := w0
	sufs := ['ement', 'ance', 'ence', 'able', 'ible', 'ment', 'ant', 'ent', 'ism', 'ate',
		'iti', 'ous', 'ive', 'ize', 'al', 'er', 'ic']
	for suf in sufs {
		if w.ends_with(suf) {
			pos := w.len - suf.len
			if pos >= r2 {
				return w[..pos]
			}
			return w
		}
	}
	// special: ion preceded by s or t
	if w.ends_with('ion') {
		pos := w.len - 3
		if pos >= r2 && pos > 0 && (w[pos - 1] == `s` || w[pos - 1] == `t`) {
			return w[..pos]
		}
	}
	return w
}

fn ft_porter2_step5(w0 string) string {
	mut w := w0
	r1, r2 := ft_compute_r1r2(w)
	if w.ends_with('e') {
		pos := w.len - 1
		if pos >= r2 {
			return w[..pos]
		}
		if pos >= r1 && !ft_ends_short_syllable(w[..pos]) {
			return w[..pos]
		}
		return w
	}
	if w.ends_with('l') {
		pos := w.len - 1
		if pos >= r2 && pos > 0 && w[pos - 1] == `l` {
			return w[..pos]
		}
	}
	return w
}

// ── doc parsing / indexing ────────────────────────────────────────────

// ft_doc_id reads the `id` attr of a doc element, else generates a
// positional id `d<n>` (1-based).
fn ft_doc_id(doc cx.Node, ordinal int) string {
	if doc is cx.Element {
		for a in doc.attrs {
			if a.name == 'id' {
				return cx.scalar_value_str_public(a.value)
			}
		}
	}
	return 'd${ordinal}'
}

// ft_doc_field_texts returns the per-field text of a doc element. A doc
// with child elements exposes each child-element name as a field whose
// text is the concatenation of that child's textual descendants. The
// "default" field collects ALL textual content (used when no field
// restriction is given).
fn ft_doc_field_texts(doc cx.Node) (string, map[string]string) {
	mut default_text := []string{}
	mut fields := map[string]string{}
	if doc is cx.Element {
		// direct text children
		mut has_field_children := false
		for it in doc.items {
			if it is cx.Element {
				has_field_children = true
				break
			}
		}
		if has_field_children {
			for it in doc.items {
				if it is cx.Element {
					ftext := ft_collect_text(it)
					if it.name in fields {
						fields[it.name] = fields[it.name] + ' ' + ftext
					} else {
						fields[it.name] = ftext
					}
					default_text << ftext
				} else if s := ft_node_text(it) {
					default_text << s
				}
			}
		} else {
			for it in doc.items {
				if s := ft_node_text(it) {
					default_text << s
				}
			}
		}
	} else if s := ft_node_text(doc) {
		default_text << s
	}
	return default_text.join(' '), fields
}

// ft_collect_text concatenates all text/scalar descendants of a node.
fn ft_collect_text(n cx.Node) string {
	mut parts := []string{}
	match n {
		cx.Element {
			for it in n.items {
				parts << ft_collect_text(it)
			}
		}
		else {
			if s := ft_node_text(n) {
				parts << s
			}
		}
	}
	return parts.join(' ')
}

// FtBuildOpts carries the resolved index-with-opts configuration.
struct FtBuildOpts {
mut:
	language        string = 'en'
	case_sensitive  bool
	stemmer         string = 'en'
	stopwords_mode  string = 'default'
	stopwords_set   map[string]bool
	min_token_len   int = 2
	fields          []string
	fields_auto     bool = true
	pre_tokenized   bool             // a custom tokenizer already produced per-doc token streams
	doc_tokens      [][]string       // pre-tokenized doc token streams (parallel to docs)
}

fn (o FtBuildOpts) pipeline() FtPipeline {
	return FtPipeline{
		language:       o.language
		case_sensitive: o.case_sensitive
		stem_lang:      o.stemmer
		stopwords_mode: o.stopwords_mode
		stopwords_set:  o.stopwords_set
		min_token_len:  o.min_token_len
	}
}

// ft_build_index constructs an FtIndex from the doc sequence + opts.
fn ft_build_index(docs []cx.Node, opts FtBuildOpts) cx.Node {
	mut idx := &FtIndex{
		df:             map[string]int{}
		language:       opts.language
		case_sensitive: opts.case_sensitive
		stemmer:        opts.stemmer
		stopwords_mode: opts.stopwords_mode
		stopwords_set:  opts.stopwords_set.clone()
		min_token_len:  opts.min_token_len
		fields:         opts.fields.clone()
	}
	p := opts.pipeline()
	mut all_field_names := map[string]bool{}
	for fname in opts.fields {
		all_field_names[fname] = true
	}
	for di, doc in docs {
		mut fdoc := FtDoc{
			id:           ft_doc_id(doc, di + 1)
			positions:    map[string][]int{}
			field_tokens: map[string][]string{}
		}
		if opts.pre_tokenized {
			// custom tokenizer output already run through downstream stages
			// by the env hook; tokens are the doc's full token stream.
			fdoc.tokens = if di < opts.doc_tokens.len {
				opts.doc_tokens[di].clone()
			} else {
				[]string{}
			}
		} else {
			default_text, field_texts := ft_doc_field_texts(doc)
			fdoc.tokens = ft_tokenize_full(default_text, p)
			for fname, ftext in field_texts {
				if opts.fields_auto || fname in all_field_names {
					fdoc.field_tokens[fname] = ft_tokenize_full(ftext, p)
					if opts.fields_auto && fname !in all_field_names {
						all_field_names[fname] = true
						idx.fields << fname
					}
				}
			}
		}
		// positions + per-doc term set
		mut seen := map[string]bool{}
		for pos, t in fdoc.tokens {
			fdoc.positions[t] << pos
			seen[t] = true
		}
		for t, _ in seen {
			idx.df[t]++
		}
		fdoc.length = fdoc.tokens.len
		idx.total_len += fdoc.length
		idx.docs << fdoc
	}
	idx.term_count = idx.df.len
	id := ft_register(idx)
	return ft_index_element(id)
}

// ── query parsing ─────────────────────────────────────────────────────

enum FtQueryKind {
	keyword
	phrase
	field
	group
	negation
	and_op
	or_op
}

struct FtQueryNode {
mut:
	kind     FtQueryKind
	text     string        // keyword / field-name
	terms    []string      // phrase tokens (raw, pre-pipeline)
	field    string        // field name for field restriction
	children []FtQueryNode // for groups / field sub-term / negation
}

struct FtParser {
mut:
	src string
	pos int
}

// ft_parse_query parses the §2.2 query grammar. Returns the parsed clause
// list (implicitly AND-joined) or an error message on a malformed query.
fn ft_parse_query(q string) ([]FtQueryNode, string) {
	mut p := FtParser{
		src: q
	}
	nodes, err := p.parse_sequence(false)
	if err != '' {
		return []FtQueryNode{}, err
	}
	return nodes, ''
}

fn (mut p FtParser) skip_ws() {
	for p.pos < p.src.len && (p.src[p.pos] == ` ` || p.src[p.pos] == `\t`) {
		p.pos++
	}
}

fn (mut p FtParser) parse_sequence(in_group bool) ([]FtQueryNode, string) {
	mut nodes := []FtQueryNode{}
	for {
		p.skip_ws()
		if p.pos >= p.src.len {
			break
		}
		c := p.src[p.pos]
		if c == `)` {
			if in_group {
				break
			}
			return []FtQueryNode{}, 'unexpected )'
		}
		// connective?
		word := p.peek_word()
		if word == 'AND' || word == 'OR' {
			p.pos += word.len
			nodes << FtQueryNode{
				kind: if word == 'AND' { FtQueryKind.and_op } else { FtQueryKind.or_op }
			}
			continue
		}
		term, err := p.parse_term()
		if err != '' {
			return []FtQueryNode{}, err
		}
		nodes << term
	}
	return nodes, ''
}

fn (mut p FtParser) peek_word() string {
	mut i := p.pos
	for i < p.src.len {
		c := p.src[i]
		if c == ` ` || c == `\t` || c == `(` || c == `)` || c == `"` {
			break
		}
		i++
	}
	return p.src[p.pos..i]
}

fn (mut p FtParser) parse_term() (FtQueryNode, string) {
	p.skip_ws()
	if p.pos >= p.src.len {
		return FtQueryNode{}, 'unexpected end of query'
	}
	c := p.src[p.pos]
	// negation
	if c == `-` {
		p.pos++
		inner, err := p.parse_term()
		if err != '' {
			return FtQueryNode{}, err
		}
		return FtQueryNode{
			kind:     FtQueryKind.negation
			children: [inner]
		}, ''
	}
	if c == `(` {
		p.pos++
		inner, err := p.parse_sequence(true)
		if err != '' {
			return FtQueryNode{}, err
		}
		if p.pos >= p.src.len || p.src[p.pos] != `)` {
			return FtQueryNode{}, 'unterminated group'
		}
		p.pos++
		return FtQueryNode{
			kind:     FtQueryKind.group
			children: inner
		}, ''
	}
	if c == `"` {
		return p.parse_phrase()
	}
	// keyword or NOT or field
	word := p.peek_word()
	if word == 'NOT' {
		p.pos += word.len
		inner, err := p.parse_term()
		if err != '' {
			return FtQueryNode{}, err
		}
		return FtQueryNode{
			kind:     FtQueryKind.negation
			children: [inner]
		}, ''
	}
	// field restriction: name:term
	if ci := word.index(':') {
		fname := word[..ci]
		if ci > 0 && ft_is_field_name(fname) {
			// consume up to and including the colon, then parse the term.
			p.pos += ci + 1
			inner, err := p.parse_term()
			if err != '' {
				return FtQueryNode{}, err
			}
			return FtQueryNode{
				kind:     FtQueryKind.field
				field:    fname
				children: [inner]
			}, ''
		}
	}
	// plain keyword
	p.pos += word.len
	if word == '' {
		return FtQueryNode{}, 'empty term'
	}
	return FtQueryNode{
		kind: FtQueryKind.keyword
		text: word
	}, ''
}

fn ft_is_field_name(s string) bool {
	if s.len == 0 {
		return false
	}
	c0 := s[0]
	if !((c0 >= `a` && c0 <= `z`) || (c0 >= `A` && c0 <= `Z`)) {
		return false
	}
	for c in s {
		if !((c >= `a` && c <= `z`) || (c >= `A` && c <= `Z`) || (c >= `0` && c <= `9`)
			|| c == `_` || c == `-`) {
			return false
		}
	}
	return true
}

fn (mut p FtParser) parse_phrase() (FtQueryNode, string) {
	// opening quote
	p.pos++
	mut buf := []u8{}
	mut closed := false
	for p.pos < p.src.len {
		c := p.src[p.pos]
		if c == `"` {
			closed = true
			p.pos++
			break
		}
		buf << c
		p.pos++
	}
	if !closed {
		return FtQueryNode{}, 'unterminated phrase'
	}
	return FtQueryNode{
		kind: FtQueryKind.phrase
		text: buf.bytestr()
	}, ''
}

// ── query evaluation ──────────────────────────────────────────────────

// FtMatch records a matching doc with its score + match count.
struct FtMatch {
mut:
	doc_idx int
	score   f64
	matches int
}

// ft_doc_field_set returns the token stream of a doc to search against: a
// field-restricted set uses the field's tokens, else the full stream.
fn ft_doc_tokens_for(idx &FtIndex, di int, field string) []string {
	if field == '' {
		return idx.docs[di].tokens
	}
	return idx.docs[di].field_tokens[field] or { []string{} }
}

// ft_query_terms_for tokenizes a keyword/phrase using the search pipeline.
fn ft_pipeline_for_search(idx &FtIndex) FtPipeline {
	return FtPipeline{
		language:       idx.language
		case_sensitive: idx.case_sensitive
		stem_lang:      idx.stemmer
		stopwords_mode: idx.stopwords_mode
		stopwords_set:  idx.stopwords_set
		min_token_len:  idx.min_token_len
	}
}

// ft_doc_matches_node evaluates whether a single doc satisfies the query
// node, and returns (matched, hit_count). Scoring terms are accumulated
// separately by the caller.
fn ft_eval_node(idx &FtIndex, di int, node FtQueryNode, p FtPipeline, field string, fields_avail map[string]bool) (bool, int, string) {
	match node.kind {
		.keyword {
			terms := ft_run_pipeline([node.text], p)
			if terms.len == 0 {
				return false, 0, ''
			}
			toks := ft_doc_tokens_for(idx, di, field)
			mut hits := 0
			for t in terms {
				for tok in toks {
					if tok == t {
						hits++
					}
				}
			}
			return hits > 0, hits, ''
		}
		.phrase {
			raw := ft_segment(node.text)
			terms := ft_run_pipeline(raw, p)
			if terms.len == 0 {
				return false, 0, ''
			}
			toks := ft_doc_tokens_for(idx, di, field)
			hits := ft_phrase_hits(toks, terms)
			return hits > 0, hits, ''
		}
		.field {
			fname := node.field
			if fname !in fields_avail {
				return false, 0, fname
			}
			return ft_eval_node(idx, di, node.children[0], p, fname, fields_avail)
		}
		.negation {
			m, _, ferr := ft_eval_node(idx, di, node.children[0], p, field, fields_avail)
			if ferr != '' {
				return false, 0, ferr
			}
			return !m, 0, ''
		}
		.group {
			return ft_eval_clause_list(idx, di, node.children, p, field, fields_avail)
		}
		else {
			return false, 0, ''
		}
	}
}

// ft_phrase_hits counts contiguous occurrences of `terms` in `toks`.
fn ft_phrase_hits(toks []string, terms []string) int {
	if terms.len == 0 || toks.len < terms.len {
		return 0
	}
	mut hits := 0
	for i in 0 .. toks.len - terms.len + 1 {
		mut ok := true
		for j, t in terms {
			if toks[i + j] != t {
				ok = false
				break
			}
		}
		if ok {
			hits++
		}
	}
	return hits
}

// ft_eval_clause_list evaluates an AND/OR-connected clause sequence with
// default-AND semantics + negation. Returns (matched, total_hits, ferr).
fn ft_eval_clause_list(idx &FtIndex, di int, clauses []FtQueryNode, p FtPipeline, field string, fields_avail map[string]bool) (bool, int, string) {
	if clauses.len == 0 {
		return false, 0, ''
	}
	mut result := true
	mut have_result := false
	mut pending_or := false
	mut total_hits := 0
	for node in clauses {
		if node.kind == .and_op {
			pending_or = false
			continue
		}
		if node.kind == .or_op {
			pending_or = true
			continue
		}
		m, hits, ferr := ft_eval_node(idx, di, node, p, field, fields_avail)
		if ferr != '' {
			return false, 0, ferr
		}
		total_hits += hits
		if !have_result {
			result = m
			have_result = true
		} else if pending_or {
			result = result || m
		} else {
			result = result && m
		}
		pending_or = false
	}
	return result, total_hits, ''
}

// ── scoring ───────────────────────────────────────────────────────────

// ft_score computes the TF-IDF or BM25 score of a doc against the set of
// scoring terms (the positive keyword/phrase terms of the query).
fn ft_score(idx &FtIndex, di int, terms []string, mode string) f64 {
	doc := idx.docs[di]
	if doc.length == 0 {
		return 0.0
	}
	n := f64(idx.docs.len)
	mut score := 0.0
	k1 := 1.2
	b := 0.75
	avg_dl := if idx.docs.len > 0 { f64(idx.total_len) / n } else { 1.0 }
	for t in terms {
		df := idx.df[t] or { 0 }
		if df == 0 {
			continue
		}
		tf_count := doc.positions[t] or { []int{} }.len
		if tf_count == 0 {
			continue
		}
		if mode == 'bm25' {
			idf := math.log((n - f64(df) + 0.5) / (f64(df) + 0.5) + 1.0)
			tf := f64(tf_count)
			denom := tf + k1 * (1.0 - b + b * f64(doc.length) / avg_dl)
			score += idf * (tf * (k1 + 1.0)) / denom
		} else {
			tf := f64(tf_count) / f64(doc.length)
			idf := math.log(n / f64(df))
			// guard the degenerate single-doc / all-docs case where idf=0:
			// fall back to a tiny positive so a sole match still scores > 0.
			eff_idf := if idf <= 0.0 { 1e-9 } else { idf }
			score += tf * eff_idf
		}
	}
	return score
}

// ft_collect_positive_terms gathers the keyword/phrase scoring terms from
// the query tree (negations excluded).
fn ft_collect_positive_terms(nodes []FtQueryNode, p FtPipeline, mut out []string) {
	for node in nodes {
		match node.kind {
			.keyword {
				for t in ft_run_pipeline([node.text], p) {
					out << t
				}
			}
			.phrase {
				for t in ft_run_pipeline(ft_segment(node.text), p) {
					out << t
				}
			}
			.field {
				ft_collect_positive_terms(node.children, p, mut out)
			}
			.group {
				ft_collect_positive_terms(node.children, p, mut out)
			}
			else {}
		}
	}
}

// ── search ────────────────────────────────────────────────────────────

struct FtSearchOpts {
mut:
	limit          int = 10
	offset         int
	scoring        string = 'tf-idf'
	min_score      f64
	language       string
	case_sensitive bool
	cs_present     bool
	lang_present   bool
}

fn ft_search_impl(idx &FtIndex, query string, opts FtSearchOpts) cx.Node {
	// §3.2 compatibility check: a language / case-sensitive mismatch raises
	// CXER1203.
	if opts.lang_present && opts.language != idx.language {
		return mk_err('cx-err:CXER1203',
			'E_FT_INDEX_INCOMPATIBLE: search language "${opts.language}" differs from index "${idx.language}"')
	}
	if opts.cs_present && opts.case_sensitive != idx.case_sensitive {
		return mk_err('cx-err:CXER1203',
			'E_FT_INDEX_INCOMPATIBLE: search case-sensitive differs from index')
	}
	trimmed := query.trim_space()
	if trimmed == '' {
		return ft_seq([]cx.Node{})
	}
	clauses, perr := ft_parse_query(query)
	if perr != '' {
		return mk_err('cx-err:CXER1200', 'E_FT_QUERY_PARSE: ${perr}')
	}
	p := ft_pipeline_for_search(idx)
	mut fields_avail := map[string]bool{}
	for f in idx.fields {
		fields_avail[f] = true
	}
	mut pos_terms := []string{}
	ft_collect_positive_terms(clauses, p, mut pos_terms)

	mut matches := []FtMatch{}
	for di in 0 .. idx.docs.len {
		matched, hits, ferr := ft_eval_clause_list(idx, di, clauses, p, '', fields_avail)
		if ferr != '' {
			return mk_err('cx-err:CXER1202', 'E_FT_FIELD_NOT_INDEXED: field "${ferr}" not in index')
		}
		if !matched {
			continue
		}
		sc := ft_score(idx, di, pos_terms, opts.scoring)
		if sc < opts.min_score {
			continue
		}
		matches << FtMatch{
			doc_idx: di
			score:   sc
			matches: hits
		}
	}
	// stable sort by score desc; ties keep insertion (doc) order.
	for i in 0 .. matches.len {
		for j in 0 .. matches.len - 1 - i {
			if matches[j].score < matches[j + 1].score {
				matches[j], matches[j + 1] = matches[j + 1], matches[j]
			}
		}
	}
	// offset + limit
	mut out := []cx.Node{}
	mut start := opts.offset
	if start < 0 {
		start = 0
	}
	mut emitted := 0
	for k in start .. matches.len {
		if opts.limit >= 0 && emitted >= opts.limit {
			break
		}
		m := matches[k]
		out << ft_result_element(idx.docs[m.doc_idx].id, m.score, m.matches)
		emitted++
	}
	return ft_seq(out)
}

fn ft_result_element(doc_id string, score f64, matches int) cx.Node {
	return cx.Element{
		name:  'result'
		attrs: [
			cx.Attribute{
				name:  'doc-id'
				value: cx.ScalarValue(doc_id)
			},
			cx.Attribute{
				name:  'score'
				value: cx.ScalarValue(score)
			},
			cx.Attribute{
				name:  'matches'
				value: cx.ScalarValue(i64(matches))
			},
		]
	}
}

// ── snippets ──────────────────────────────────────────────────────────

struct FtSnippetOpts {
mut:
	context_chars int = 80
	max_snippets  int = 3
	ellipsis      string = '…'
	mark_prefix   string = '<mark>'
	mark_suffix   string = '</mark>'
}

fn ft_snippet_impl(doc cx.Node, query string, opts FtSnippetOpts) cx.Node {
	text, _ := ft_doc_field_texts(doc)
	// derive query terms (lowercased keywords/phrases, raw — snippet match
	// is on the surface text, case-insensitively).
	clauses, perr := ft_parse_query(query)
	if perr != '' {
		return mk_err('cx-err:CXER1200', 'E_FT_QUERY_PARSE: ${perr}')
	}
	mut terms := []string{}
	ft_collect_query_surface(clauses, mut terms)
	if terms.len == 0 {
		// no terms → leading context window.
		if text.runes().len <= opts.context_chars {
			return ft_str(text)
		}
		return ft_str(text.runes()[..opts.context_chars].string() + opts.ellipsis)
	}
	lower := text.to_lower()
	// find first match offset
	mut first := -1
	mut first_len := 0
	for t in terms {
		lt := t.to_lower()
		if lt == '' {
			continue
		}
		idx := lower.index(lt) or { continue }
		if first < 0 || idx < first {
			first = idx
			first_len = lt.len
		}
	}
	if first < 0 {
		// no match found in surface text — return leading window.
		if text.runes().len <= opts.context_chars {
			return ft_str(text)
		}
		return ft_str(text.runes()[..opts.context_chars].string() + opts.ellipsis)
	}
	half := opts.context_chars / 2
	mut start := first - half
	if start < 0 {
		start = 0
	}
	mut end := first + first_len + half
	if end > text.len {
		end = text.len
	}
	mut window := text[start..end]
	// highlight every term in the window (case-insensitive).
	for t in terms {
		window = ft_highlight(window, t, opts.mark_prefix, opts.mark_suffix)
	}
	mut prefix := ''
	mut suffix := ''
	if start > 0 {
		prefix = opts.ellipsis
	}
	if end < text.len {
		suffix = opts.ellipsis
	}
	return ft_str(prefix + window + suffix)
}

// ft_highlight wraps case-insensitive occurrences of `term` in the
// supplied mark prefix/suffix, preserving the original text casing.
fn ft_highlight(text string, term string, pfx string, sfx string) string {
	if term == '' {
		return text
	}
	lower := text.to_lower()
	lt := term.to_lower()
	mut out := []u8{}
	mut i := 0
	for i < text.len {
		if i + lt.len <= text.len && lower[i..i + lt.len] == lt {
			out << pfx.bytes()
			out << text[i..i + lt.len].bytes()
			out << sfx.bytes()
			i += lt.len
		} else {
			out << text[i]
			i++
		}
	}
	return out.bytestr()
}

// ft_collect_query_surface gathers surface (raw, un-stemmed) query terms
// for snippet highlighting.
fn ft_collect_query_surface(nodes []FtQueryNode, mut out []string) {
	for node in nodes {
		match node.kind {
			.keyword {
				out << node.text
			}
			.phrase {
				for w in ft_segment(node.text) {
					out << w
				}
			}
			.field {
				ft_collect_query_surface(node.children, mut out)
			}
			.group {
				ft_collect_query_surface(node.children, mut out)
			}
			else {}
		}
	}
}

// ── option parsing ────────────────────────────────────────────────────

fn ft_opt_str(opts cx.Node, key string, def string) string {
	v := ft_map_get(opts, key) or { return def }
	return ft_node_text(v) or { def }
}

fn ft_opt_int(opts cx.Node, key string, def int) int {
	v := ft_map_get(opts, key) or { return def }
	if v is cx.ScalarNode {
		iv := v.value
		if iv is i64 {
			return int(iv)
		}
		if iv is string {
			return iv.int()
		}
	}
	return def
}

fn ft_opt_float(opts cx.Node, key string, def f64) f64 {
	v := ft_map_get(opts, key) or { return def }
	if v is cx.ScalarNode {
		fv := v.value
		if fv is f64 {
			return fv
		}
		if fv is i64 {
			return f64(fv)
		}
		if fv is string {
			return fv.f64()
		}
	}
	return def
}

fn ft_opt_bool(opts cx.Node, key string, def bool) bool {
	v := ft_map_get(opts, key) or { return def }
	if v is cx.ScalarNode {
		bv := v.value
		if bv is bool {
			return bv
		}
		if bv is string {
			return bv == 'true'
		}
	}
	return def
}

fn ft_opt_present(opts cx.Node, key string) bool {
	ft_map_get(opts, key) or { return false }
	return true
}

// ft_resolve_build_opts builds FtBuildOpts from an opts map, validating
// the language tag (CXER1201). Returns (opts, ?err-node).
fn ft_resolve_build_opts(opts cx.Node) (FtBuildOpts, ?cx.Node) {
	mut o := FtBuildOpts{}
	o.language = ft_opt_str(opts, 'language', 'en')
	if !ft_language_known(o.language) {
		return o, mk_err('cx-err:CXER1201', 'E_FT_UNKNOWN_LANGUAGE: "${o.language}"')
	}
	o.case_sensitive = ft_opt_bool(opts, 'case-sensitive', false)
	o.min_token_len = ft_opt_int(opts, 'min-token-length', 2)
	// stemmer: :default → "en" when language=="en", else "none".
	stemmer := ft_opt_str(opts, 'stemmer', 'default')
	if stemmer == 'default' || stemmer == ':default' {
		o.stemmer = if o.language == 'en' { 'en' } else { 'none' }
	} else if stemmer == 'none' {
		o.stemmer = 'none'
	} else {
		o.stemmer = stemmer
	}
	// stopwords: :none / :default / sequence of strings.
	if sw := ft_map_get(opts, 'stopwords') {
		if sw is cx.ScalarNode {
			swv := sw.value
			if swv is string {
				match swv {
					'none' { o.stopwords_mode = 'none' }
					'default' { o.stopwords_mode = 'default' }
					else { o.stopwords_mode = 'default' }
				}
			}
		} else if items := ft_seq_items(sw) {
			o.stopwords_mode = 'custom'
			for it in items {
				if s := ft_node_text(it) {
					o.stopwords_set[if o.case_sensitive { s } else { s.to_lower() }] = true
				}
			}
		}
	}
	// fields: :auto or a sequence of field names.
	if fv := ft_map_get(opts, 'fields') {
		if fv is cx.ScalarNode {
			fvv := fv.value
			if fvv is string && (fvv == 'auto' || fvv == ':auto') {
				o.fields_auto = true
			}
		} else if items := ft_seq_items(fv) {
			o.fields_auto = false
			for it in items {
				if s := ft_node_text(it) {
					o.fields << s
				}
			}
		}
	}
	return o, none
}

// ── primitive dispatch (env-free) ─────────────────────────────────────

fn ft_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	match name {
		'ft-index' {
			docs := ft_seq_items(args[0]) or { []cx.Node{} }
			return ft_build_index(docs, FtBuildOpts{})
		}
		'ft-index-with-opts' {
			// Reached for the no-tokenizer path; the tokenizer path is
			// handled by the env-aware hook before this dispatch.
			docs := ft_seq_items(args[0]) or { []cx.Node{} }
			o, oerr := ft_resolve_build_opts(args[1])
			if e := oerr {
				return e
			}
			return ft_build_index(docs, o)
		}
		'ft-search' {
			idx := ft_index_of(args[0]) or { return none }
			query := ft_arg_str(args[1]) or { return none }
			limit := if args.len > 2 { ft_int_arg(args[2], 10) } else { 10 }
			return ft_search_impl(idx, query, FtSearchOpts{
				limit: limit
			})
		}
		'ft-search-with-opts' {
			idx := ft_index_of(args[0]) or { return none }
			query := ft_arg_str(args[1]) or { return none }
			opts := args[2]
			mut so := FtSearchOpts{}
			so.limit = ft_opt_int(opts, 'limit', 10)
			so.offset = ft_opt_int(opts, 'offset', 0)
			so.scoring = ft_opt_str(opts, 'scoring', 'tf-idf')
			so.min_score = ft_opt_float(opts, 'min-score', 0.0)
			if ft_opt_present(opts, 'language') {
				so.language = ft_opt_str(opts, 'language', idx.language)
				so.lang_present = true
			}
			if ft_opt_present(opts, 'case-sensitive') {
				so.case_sensitive = ft_opt_bool(opts, 'case-sensitive', idx.case_sensitive)
				so.cs_present = true
			}
			return ft_search_impl(idx, query, so)
		}
		'ft-search-store' {
			return ft_search_store(args)
		}
		'ft-snippet' {
			doc := args[0]
			query := ft_arg_str(args[1]) or { return none }
			cc := if args.len > 2 { ft_int_arg(args[2], 80) } else { 80 }
			return ft_snippet_impl(doc, query, FtSnippetOpts{
				context_chars: cc
			})
		}
		'ft-snippet-with-opts' {
			doc := args[0]
			query := ft_arg_str(args[1]) or { return none }
			opts := args[2]
			mut so := FtSnippetOpts{}
			so.context_chars = ft_opt_int(opts, 'context-chars', 80)
			so.max_snippets = ft_opt_int(opts, 'max-snippets', 3)
			so.ellipsis = ft_opt_str(opts, 'ellipsis', '…')
			so.mark_prefix = ft_opt_str(opts, 'mark-prefix', '<mark>')
			so.mark_suffix = ft_opt_str(opts, 'mark-suffix', '</mark>')
			return ft_snippet_impl(doc, query, so)
		}
		'ft-tokenize' {
			text := ft_arg_str(args[0]) or { return none }
			language := ft_arg_str(args[1]) or { return none }
			if !ft_language_known(language) {
				return mk_err('cx-err:CXER1201', 'E_FT_UNKNOWN_LANGUAGE: "${language}"')
			}
			stem := if language == 'en' { 'en' } else { 'none' }
			p := FtPipeline{
				language:       language
				case_sensitive: false
				stem_lang:      stem
				stopwords_mode: 'default'
				min_token_len:  2
			}
			toks := ft_tokenize_full(text, p)
			mut out := []cx.Node{}
			for t in toks {
				out << ft_str(t)
			}
			return ft_seq(out)
		}
		'ft-doc-ids' {
			results := ft_seq_items(args[0]) or { return ft_seq([]cx.Node{}) }
			mut out := []cx.Node{}
			for r in results {
				if r is cx.Element {
					for a in r.attrs {
						if a.name == 'doc-id' {
							out << ft_str(cx.scalar_value_str_public(a.value))
						}
					}
				}
			}
			return ft_seq(out)
		}
		'ft-score-of' {
			r := args[0]
			if r is cx.Element {
				for a in r.attrs {
					if a.name == 'score' {
						av := a.value
						if av is f64 {
							return ft_float(av)
						}
						if av is i64 {
							return ft_float(f64(av))
						}
						return ft_float(cx.scalar_value_str_public(av).f64())
					}
				}
			}
			return ft_float(0.0)
		}
		'ft-index-stats' {
			idx := ft_index_of(args[0]) or { return none }
			mut langs := []cx.Node{}
			if idx.docs.len > 0 {
				langs << ft_str(idx.language)
			}
			// size-bytes: a representative in-memory footprint estimate.
			mut size := 0
			for d in idx.docs {
				for t in d.tokens {
					size += t.len
				}
			}
			keys := ['doc-count', 'term-count', 'size-bytes', 'languages']
			vals := [
				ft_int(i64(idx.docs.len)),
				ft_int(i64(idx.term_count)),
				ft_int(i64(size)),
				ft_seq(langs),
			]
			return ft_map(keys, vals)
		}
		// ── generic helpers (shared idiom: csv `keys`, re `map-get`) ──
		// Referenced by the ft conformance fixtures but not language-core
		// callables; reached here only when the core builtin set declines
		// (the stdlib chain runs after invoke_builtin, so a core builtin
		// always wins on a name clash). See SPEC-FINDINGS §Q.
		'gte' {
			if args.len != 2 {
				return none
			}
			a := ft_num(args[0]) or { return none }
			b := ft_num(args[1]) or { return none }
			return ft_bool(a >= b)
		}
		'equal' {
			if args.len != 2 {
				return none
			}
			return ft_bool(ft_nodes_equal(args[0], args[1]))
		}
		'contains' {
			if args.len != 2 {
				return none
			}
			items := ft_seq_items(args[0]) or { return none }
			needle := args[1]
			for it in items {
				if ft_nodes_equal(it, needle) {
					return ft_bool(true)
				}
			}
			return ft_bool(false)
		}
		'first' {
			if args.len != 1 {
				return none
			}
			items := ft_seq_items(args[0]) or { return none }
			if items.len == 0 {
				return none
			}
			return items[0]
		}
		else {
			return none
		}
	}
}

fn ft_bool(b bool) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(b)
		data_type: cx.ScalarType.bool_type
	}
}

fn ft_num(n cx.Node) ?f64 {
	if n is cx.ScalarNode {
		v := n.value
		if v is f64 {
			return v
		}
		if v is i64 {
			return f64(v)
		}
		if v is string {
			return v.f64()
		}
	}
	return none
}

// ft_nodes_equal compares two value nodes structurally, coercing scalar
// text for cross-kind compares (mirrors the eval nodes_equal contract).
fn ft_nodes_equal(a cx.Node, b cx.Node) bool {
	ai := ft_seq_items(a) or { []cx.Node{} }
	bi := ft_seq_items(b) or { []cx.Node{} }
	a_is_seq := a is cx.Element && ((a as cx.Element).name == '__cx_seq__'
		|| (a as cx.Element).name == '__cx_arr__' || (a as cx.Element).name == 'sequence'
		|| (a as cx.Element).name == 'array')
	b_is_seq := b is cx.Element && ((b as cx.Element).name == '__cx_seq__'
		|| (b as cx.Element).name == '__cx_arr__' || (b as cx.Element).name == 'sequence'
		|| (b as cx.Element).name == 'array')
	if a_is_seq && b_is_seq {
		if ai.len != bi.len {
			return false
		}
		for i in 0 .. ai.len {
			if !ft_nodes_equal(ai[i], bi[i]) {
				return false
			}
		}
		return true
	}
	at := ft_node_text(a) or { return false }
	bt := ft_node_text(b) or { return false }
	return at == bt
}

fn ft_int_arg(n cx.Node, def int) int {
	if n is cx.ScalarNode {
		v := n.value
		if v is i64 {
			return int(v)
		}
		if v is string {
			return v.int()
		}
	}
	return def
}

// ── store integration ─────────────────────────────────────────────────

// ft_search_store builds an index from a Store's docs and searches it
// (§3.3). Resolves the Store handle directly through the shared store
// registry rather than re-entering CX.
fn ft_search_store(args []cx.Node) ?cx.Node {
	ms, errn, ok := store_get_open(args[0])
	if !ok {
		return errn
	}
	query := ft_arg_str(args[1]) or { return none }
	limit := if args.len > 2 { ft_int_arg(args[2], 10) } else { 10 }
	mut docs := []cx.Node{}
	for h in ms.doc_order {
		docs << store_decode_doc(ms.docs[h])
	}
	idx_node := ft_build_index(docs, FtBuildOpts{})
	idx := ft_index_of(idx_node) or { return none }
	return ft_search_impl(idx, query, FtSearchOpts{
		limit: limit
	})
}

// ── env-aware hook (custom tokenizer) ─────────────────────────────────

// ft_stdlib_builtin_env handles the one ft surface that needs the
// evaluator env: `index-with-opts` carrying a custom `tokenizer` closure
// (§3.1 / §4.4). The closure is applied per-doc to produce the raw token
// stream, then the downstream pipeline stages (case-fold / stopwords /
// stem) run unless disabled. A tokenizer that returns a non-sequence or
// non-string elements raises CXER1204. Returns none when the name is not
// the tokenizer path so the env-free chain handles it.
fn ft_stdlib_builtin_env(name string, args []cx.Node, mut env MatchEnv) ?cx.Node {
	if name != 'ft-index-with-opts' {
		return none
	}
	if args.len < 2 {
		return none
	}
	tok_node := ft_map_get(args[1], 'tokenizer') or { return none }
	if !is_fn_value(tok_node) {
		// `:default` / absent → not a closure; env-free path handles it.
		return none
	}
	o, oerr := ft_resolve_build_opts(args[1])
	if e := oerr {
		return e
	}
	docs := ft_seq_items(args[0]) or { []cx.Node{} }
	p := o.pipeline()
	mut doc_tokens := [][]string{}
	for doc in docs {
		text, _ := ft_doc_field_texts(doc)
		res := apply_fn_value(tok_node, [ft_str(text)], mut env) or {
			return mk_err('cx-err:CXER1204', 'E_FT_TOKENIZER_INVALID: tokenizer raised: ${err.msg()}')
		}
		raw := ft_seq_items(res) or {
			return mk_err('cx-err:CXER1204',
				'E_FT_TOKENIZER_INVALID: tokenizer did not return a sequence')
		}
		mut toks := []string{}
		for it in raw {
			s := ft_arg_str(it) or {
				return mk_err('cx-err:CXER1204',
					'E_FT_TOKENIZER_INVALID: tokenizer returned a non-string element')
			}
			toks << s
		}
		// downstream pipeline stages still run on the tokenizer output.
		doc_tokens << ft_run_pipeline(toks, p)
	}
	mut o2 := o
	o2.pre_tokenized = true
	o2.doc_tokens = doc_tokens
	return ft_build_index(docs, o2)
}

// ── bundled module source ────────────────────────────────────────────

const stdlib_src_ft = $embed_file('../stdlib/ft.cx').to_string()
