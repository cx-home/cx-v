module cx

import strconv

// ── CX Emitter ────────────────────────────────────────────────────────────────

pub fn emit_cx(doc Document) string {
	return cx_emit(doc, false)
}

pub fn emit_cx_compact(doc Document) string {
	return cx_emit(doc, true)
}

pub fn emit_cx_docs(docs []Document) string {
	parts := docs.map(emit_cx(it))
	return parts.join('\n---\n')
}

pub fn emit_cx_compact_docs(docs []Document) string {
	parts := docs.map(emit_cx_compact(it))
	return parts.join('\n---\n')
}

fn cx_emit(doc Document, compact bool) string {
	mut out := []string{}
	for n in doc.prolog { cx_emit_node(n, 0, compact, mut out) }
	if dt := doc.doctype { emit_cx_doctype(dt, mut out) }
	for n in doc.elements { cx_emit_node(n, 0, compact, mut out) }
	result := out.join('')
	return result.trim_right('\n')
}

fn cx_ind(depth int, compact bool) string {
	if compact { return '' }
	mut s := ''
	for _ in 0..depth { s += '  ' }
	return s
}

// cx_emit_node_str renders a SINGLE node to canonical CX text. Used by the
// program-result renderer (code/render.v) so an embedded data-node value
// (raw text `[#…#]`, entity ref `&…;`, a DTD declaration, or `[!DOCTYPE …]`)
// produced by a `node_lit` literal renders identically to the data reading —
// the DATA↔PROGRAM seam. Any trailing newline the node emitter appends is
// trimmed so the caller controls layout.
pub fn cx_emit_node_str(n Node, compact bool) string {
	mut out := []string{}
	cx_emit_node(n, 0, compact, mut out)
	return out.join('').trim_right('\n')
}

fn cx_emit_node(n Node, depth int, compact bool, mut out []string) {
	nl  := if compact { '' } else { '\n' }
	ind := cx_ind(depth, compact)
	match n {
		Element          { cx_emit_element(n, depth, compact, mut out) }
		// #804 leg 2 — a lazy record renders from its span when the scan
		// certified that span IS the canonical image (804-1d, verified
		// with 0 false positives over three corpora); otherwise it
		// materialises and renders like any element. This arm fires on the
		// record's provenance, never on the shape of the program that
		// produced it. Indentation is deliberately not re-applied: a
		// canonical image is complete, and re-indenting it would be the
		// second normalisation the predicate does not model.
		LazyRecord       {
			if n.canonical && !compact && depth == 0 {
				out << n.canonical_string()
			} else {
				cx_emit_element(n.force_or_panic(), depth, compact, mut out)
			}
		}
		TextNode         { out << cx_quote_text_if_needed(n.value) }
		ScalarNode       { out << cx_scalar(n) }
		CommentNode      {
			if n.is_line {
				// #962 — a line comment runs to end-of-line: the terminating
				// newline is SYNTAX, not layout. Even compact emit must keep
				// it, or the comment swallows everything after it (the
				// document's remaining roots, an element's later siblings) on
				// re-parse. cx_emit_node_str trims a trailing newline, so a
				// STANDALONE comment still renders as bare `# value`.
				out << '${ind}# ${n.value}\n'
			} else {
				out << '${ind}[;${n.value}]${nl}'
			}
		}
		PINode           { cx_emit_pi(n, depth, compact, mut out) }
		XMLDeclNode      { emit_cx_xml_decl(n, mut out) }
		CXDirectiveNode  { emit_cx_directive(n, mut out) }
		EntityRefNode    { out << '&${n.name};' }
		RawTextNode      { out << '[#${n.value}#]${nl}' }
		AliasNode        { out << '${ind}[*${n.name}]${nl}' }
		// I1 row 9 (L78): the authorable variable hole — bare `$name`.
		// The STRING "$name" spells '$name' (cx_quote_text_if_needed
		// quotes $-leading images), so the two never collide.
		HoleNode         { out << '\$${n.name}' }
		EntityDeclNode   { cx_emit_entity_decl(n, depth, compact, mut out) }
		ElementDeclNode  { out << '${ind}[!ELEMENT ${n.name} ${n.contentspec}]${nl}' }
		AttlistDeclNode  { cx_emit_attlist_decl(n, depth, compact, mut out) }
		NotationDeclNode { cx_emit_notation_decl(n, depth, compact, mut out) }
		PEReferenceNode  { out << '${ind}%${n.name};${nl}' }
		DoctypeDecl      { emit_cx_doctype(n, mut out) }
		ConditionalSectNode { cx_emit_conditional_sect(n, depth, compact, mut out) }
		BlockContentNode { cx_emit_block_content(n, depth, compact, mut out) }
		InterpolationNode { cx_emit_interpolation(n, depth, compact, mut out) }
		EvalDirectiveNode { cx_emit_eval_directive(n, depth, compact, mut out) }
		SequenceNode      { out << '${ind}${cx_emit_sequence_inline(n, compact)}${nl}' }
		ArrayNode         { out << '${ind}${cx_emit_array_inline(n, compact)}${nl}' }
		MapNode           { out << '${ind}${cx_emit_map_inline(n, compact)}${nl}' }
		IteratorNode      {
			// lazy iterators materialize to eager
			// Sequences at the host boundary. The eval pipeline is
			// responsible for pulling the source before render; this
			// arm renders whatever has accumulated in `memo` (paren-
			// comma form, matching SequenceNode).
			seq := iterator_to_sequence(n)
			out << '${ind}${cx_emit_sequence_inline(seq, compact)}${nl}'
		}
		PathNode          {
			// First-class CXPath AST (grafted I5-s17 W6). Same
			// verbatim-source convention as MatchNode/ModifyNode: the
			// parser populates `source` with the full path text.
			src := n.source or { '' }
			out << '${ind}${src}${nl}'
		}
		MatchNode         {
			// First-class `[?match]` AST. The
			// terse-CX emit here uses the MatchNode `source` snippet
			// when available (the parser populates it with the full
			// verbatim `[?match …]` form); a structural pretty-printer
			// is a follow-up alongside the ProgramExpr graft.
			src := n.source or { '' }
			out << '${ind}${src}${nl}'
		}
		ModifyNode        {
			// First-class `[?modify]` AST. Same
			// verbatim-source convention as MatchNode at this graft.
			src := n.source or { '' }
			out << '${ind}${src}${nl}'
		}
		DocumentNode      {
			// D7 — transparent document carrier: emit prolog, doctype,
			// then elements as bare top-level nodes, exactly as `cx_emit`
			// does for a `Document`. Round-trips multi-root by construction.
			for c in n.prolog { cx_emit_node(c, depth, compact, mut out) }
			if dt := n.doctype { emit_cx_doctype(dt, mut out) }
			for c in n.elements { cx_emit_node(c, depth, compact, mut out) }
		}
	}
}

// cx_emit_sequence_inline renders a `(a, b, c)` literal using canonical
// form: parens, single space after comma, trailing comma
// omitted. Empty sequence: `()`.
pub fn cx_emit_sequence_inline(n SequenceNode, compact bool) string {
	if n.items.len == 0 { return '()' }
	parts := n.items.map(cx_emit_collection_item(it, compact))
	return '(${parts.join(', ')})'
}

// cx_emit_array_inline renders a `[a, b, c]` literal.
// Empty array: `[]`. Trailing commas are omitted per §D14 canonical.
// Single-element arrays emit as `[a]` and rely on context-aware parse
// (EvalDirective ArgArray per resolution 2.i; :table cell per
// read_table_cell's force-array rule) to preserve Array semantics on
// re-parse. In contexts where neither rule applies (raw expression
// position), `[a]` parses as Element per §D1's comma-marker rule —
// this is consistent with the cell-parser's force-array policy
// keeping the canonical-form invariant clean.
pub fn cx_emit_array_inline(n ArrayNode, compact bool) string {
	if n.items.len == 0 { return '[]' }
	parts := n.items.map(cx_emit_array_item_literal(it, compact))
	return '[${parts.join(', ')}]'
}

// cx_emit_array_item_literal renders one item of a BARE ArrayLiteral `[…]`.
// It differs from cx_emit_collection_item in ONE way: a bare-name string item
// (`web`, `admin`) is QUOTED. In ArrayLiteral position an unquoted leading
// bareword re-opens the element-head disambiguation (`[web, prod]` → CXER0100,
// 3a / lexicon §collections [L83]) and a lone `[web]` re-parses as the element
// `web`, so a bare string item would not round-trip. Quoting every bareword
// item keeps the canonical form uniform (`['admin', 'user']`) and bijective.
// Sequence `( … )` and map values are unambiguous, so they keep the bare form
// via cx_emit_collection_item.
//
// #983 — WHY AN OPERATOR-SHAPED ITEM STILL EMITS BARE, and why that is not the
// asymmetry it looks like. `[<=x]` canonicalizes to the bare `[<=x]` even
// though the same string in map-value position emits QUOTED (`{k: '<=x'}`),
// because `cx_collection_bare_safe` — which owns THAT position — requires a
// name-start first byte. The two predicates are INDEPENDENT rules for
// INDEPENDENT positions, not one rule applied inconsistently:
//
//   collection-item (`{k: v}`, `(a, b)`)  cx_collection_bare_safe — the
//     INTERSECTION of the data and program readings (#831 / 831-1a′), which is
//     why it is name-shaped and strict.
//   array-item (`[a, b]`)                 cx_is_bare_name || the boundary
//     predicate cx_array_item_needs_quote. Arrays are the one position where
//     the two readings always agreed, so the safe set is defined by RE-PARSE,
//     not by name shape.
//
// By that array rule `<=x` is bare-safe and MEASURABLY round-trips: a GLUED
// operator glyph is not an operator head (`operator_head_len` requires a
// whitespace / `]` / EOF delimiter — #976), and `<=x` is not a bare name, so
// the emitted `[<=x]` re-enters the array lane and yields the same one-item
// string array. Evidence: `[<=x]` and its quoted twin `['<=x']` both
// canonicalize to `[<=x]` at the SAME Tier-1 digest
// (sha2-256:fde968e0f5f04839653716b5d656e4261755239cd77588d8424ac029c1b80719),
// and re-canonicalizing that image is a fixpoint. oph-403/404 pin the image
// and the digest; oph-409 pins the bare/quoted hash-EQUALITY, which is the
// half this note actually rests on.
//
// So the emitter is NOT changed to quote here, and the reason is not taste:
// Tier-1 identity IS the strict canonical bytes (canonical.md §1.4), so
// emitting `['<=x']` would MOVE the content address of every array document
// carrying such an item — the same class of address move #976 had to name a
// migration for. No ruling and no migration names this one, and the current
// form is already round-trip-sound, so bare stands and this note records why.
fn cx_emit_array_item_literal(n Node, compact bool) string {
	match n {
		TextNode {
			// In an array literal a comma / whitespace splits items, so a text
			// item is quoted when it is a bare NAME (3a — else it re-parses as a
			// bareword head) OR carries any item-boundary char (comma, whitespace,
			// bracket, quote) OR would auto-type. A safe single bare token — e.g.
			// a program path `//variant` — stays bare. (Data comma string items
			// arrive as string ScalarNodes, handled below.)
			if cx_is_bare_name(n.value) || cx_array_item_needs_quote(n.value) {
				return cx_choose_quote(n.value)
			}
			return n.value
		}
		ScalarNode {
			if n.data_type == .string_type {
				sv := match n.value {
					string { n.value as string }
					else   { scalar_value_str(n.value) }
				}
				// A string array item quotes under the SAME rule as the TextNode
				// branch above — bare-eligible (canonical.md §2.3) values emit bare,
				// quoting only when the value is a bare NAME (`web` → re-parses as an
				// element head, 3a) or carries an item-boundary / auto-typing char
				// (`a, b`, `80`). This is the idempotency fixpoint: a comma-body
				// string item (which finalize_comma_array materialises as a string
				// ScalarNode) and the SAME item re-parsed from `[ … ]` literal form
				// (a TextNode) must canonicalise identically, or `cx fmt` oscillates
				// quoted⇄bare on every save. A safe token (`https://a.com`,
				// `//variant`) stays bare in both representations.
				if cx_is_bare_name(sv) || cx_array_item_needs_quote(sv) {
					return cx_choose_quote(sv)
				}
				return sv
			}
			return cx_typed_collection_scalar(n)
		}
		else {
			return cx_emit_collection_item(n, compact)
		}
	}
}

// cx_emit_map_inline renders a `{k: v, k: v}` literal:
// single space after `:` and after `,`. Entries emit in insertion order
// (runtime preservation); canonical mode handled by the caller / hash path
// when lexicographic ordering is required. Empty map: `{}`.
pub fn cx_emit_map_inline(n MapNode, compact bool) string {
	if n.entries.len == 0 { return '{}' }
	mut parts := []string{cap: n.entries.len}
	for entry in n.entries {
		key_str := cx_emit_map_key(entry.key_type, entry.key_value)
		// RULED: MSS-4 (#917): a declaration-only entry renders `k: ::T` —
		// declared kind, value ABSENT (never null).
		if entry.decl_kind != '' {
			parts << '${key_str}: ::${entry.decl_kind}'
			continue
		}
		val_str := cx_emit_collection_item(entry.value, compact)
		parts << '${key_str}: ${val_str}'
	}
	return '{${parts.join(', ')}}'
}

// cx_typed_collection_scalar renders a non-string scalar in collection
// position (I1 stream 11, L43/L45): decimal always carries the postfix
// ascription (its bare image would re-type under the bare rules), bigint
// carries it exactly when the bare image would re-type differently (≤ i64;
// over-i64 auto-promotes to bigint per [L20], so bare is canonical there).
// Every other kind keeps its self-evident image.
fn cx_typed_collection_scalar(n ScalarNode) string {
	img := cx_scalar(n)
	if n.data_type == .decimal_type || n.data_type == .bigint_type || n.data_type == .bytes_type {
		// I1 ruling 2b: annotation-iff-retyping — a fixed-point image IS a
		// decimal and an over-i64 image IS a bigint, so both go bare; only
		// an image that would re-type differently (an integral decimal, a
		// ≤ i64 bigint) carries the postfix ascription.
		// #933: bytes joins the same rule — no bytes image auto-types to
		// bytes (`0x…` is the hex INT literal, base64 is name/string-shaped),
		// so a bare bytes image always re-typed on re-parse: canonical
		// `{0x2a::bytes: 1}` emitted `{0x2a: 1}`, whose re-parse is an INT
		// key — canonical was not a fixpoint (canonical.md §2.11.1: a key
		// "whose kind would not follow from its bare image carries its
		// ascription").
		if re := try_autotype(img) {
			if re.data_type == n.data_type {
				return img
			}
		}
		tag := scalar_type_name(n.data_type)
		return '${img}::${tag}'
	}
	return img
}

// cx_typed_collection_scalar_public exposes the collection-position
// scalar rule to the `code` render lane (#917/MSS-7 exposed the gap:
// the PROGRAM render dropped load-bearing decimal/bigint ascriptions in
// item position — `(2::decimal)` emitted `(2)`, a silent re-type to int
// the data lane never had).
pub fn cx_typed_collection_scalar_public(n ScalarNode) string {
	return cx_typed_collection_scalar(n)
}

// cx_emit_collection_item renders one item inside a sequence / array / map
// value. Reuses the existing emitter helpers; for nested collections it
// recurses through cx_emit_*_inline to keep the inline-canonical form.
fn cx_emit_collection_item(n Node, compact bool) string {
	return match n {
		TextNode      { cx_collection_string(n.value) }
		ScalarNode    {
			// #790 (RULED: 790-1a, 2026-08-15): a STRING scalar in
			// sequence / map-value position renders BARE-WHEN-SAFE
			// through the SAME cx_collection_string authority as
			// TextNode — one semantic string kind, one canonical
			// spelling, one address (I1 one-value-one-spelling; the
			// semantic projection already erases the Text/Scalar
			// distinction, and conversions.md's lossless round-trip
			// requires the single spelling — json carries one string
			// kind). Quote-needing payloads (#473: number-shaped,
			// boundary chars) still quote and re-parse as string
			// scalars (the kind-faithful parse typing of this batch).
			if n.data_type == .string_type {
				sv := match n.value {
					string { n.value as string }
					else   { scalar_value_str(n.value) }
				}
				cx_collection_string(sv)
			} else {
				cx_typed_collection_scalar(n)
			}
		}
		EntityRefNode { '&${n.name};' }
		HoleNode      { '$' + n.name }
		RawTextNode   { '[#${n.value}#]' }
		SequenceNode  { cx_emit_sequence_inline(n, compact) }
		ArrayNode     { cx_emit_array_inline(n, compact) }
		MapNode       { cx_emit_map_inline(n, compact) }
		IteratorNode  { cx_emit_sequence_inline(iterator_to_sequence(n), compact) }
		InterpolationNode { '[?=${n.expr}]' }
		Element {
			mut tmp := []string{}
			cx_emit_element(n, 0, compact, mut tmp)
			tmp.join('').trim_right('\n')
		}
		EvalDirectiveNode {
			mut tmp := []string{}
			cx_emit_eval_directive(n, 0, true, mut tmp)
			tmp.join('').trim_right('\n')
		}
		else { '' }
	}
}

// cx_emit_map_key renders an atomic map key in source-text form. Bare-name
// strings emit unquoted when they would re-parse as the same name; other
// strings (and all non-string keys) emit in their typed scalar form.
fn cx_emit_map_key(kt ScalarType, kv ScalarValue) string {
	if kt == .string_type {
		s := match kv { string { kv } else { scalar_value_str(kv) } }
		// A ':' inside a bare STRING key mis-lexes on re-parse (`{cx:seq: v}`
		// splits at the first colon → key `cx`), breaking the §1 emit/parse
		// fixpoint — QName chars are bare-name chars, so cx_is_bare_name
		// alone admits it. Quote such keys.
		// #777 (RULED: 777-1a): a bare-name STRING key whose image would
		// AUTO-TYPE must quote too, or the key changes KIND across the
		// round trip — `{'true': v}` emitted bare re-parses as a BOOL key,
		// and `'null'` likewise. cx_is_bare_name admits those images (they
		// are name-shaped); only the auto-typing question separates them
		// from an ordinary key like `yes`. Number- and date-shaped images
		// are already covered — they do not start with a name char — so
		// this guard closes the name-shaped remainder.
		if cx_is_bare_name(s) && !s.contains(':') && !cx_would_autotype(s) { return s }
		return cx_choose_quote(s)
	}
	// I1 stream 11 (L47): decimal/bigint keys carry their postfix
	// ascription exactly like collection values.
	return cx_typed_collection_scalar(ScalarNode{ data_type: kt, value: kv })
}

// cx_emit_envelope_map_key_typed renders a `__cx_map__` envelope key that
// CARRIES ITS KIND (#777, RULED: 777-1a). A map literal's keys keep their
// CXDM kinds through eval — stamped on the entry element — and a stamped key
// renders through the SAME authority as the typed data lane
// (cx_emit_map_key). That shared authority is what makes the two readings
// one lane.
//
// Without the kind the envelope erased it to the name image, and the erasure
// was not cosmetic: `{'7': 'a', 7: 'b'}` — a STRING key and an INT key, two
// DISTINCT keys — rendered `{7: 'a', 7: 'b'}`, which `cx canonical` then
// REFUSES with W014 duplicate map key. The program lane emitted canonical
// text the canonicalizer rejects.
pub fn cx_emit_envelope_map_key_typed(s string, kind ?string) string {
	if k := kind {
		if k == 'string' {
			return cx_emit_map_key(ScalarType.string_type, ScalarValue(s))
		}
		if st := scalar_type_from_name(k) {
			return cx_emit_map_key(st, ScalarValue(s))
		}
	}
	return cx_emit_envelope_map_key(s)
}

// cx_emit_envelope_map_key renders an UNSTAMPED envelope key — one whose
// TYPE is not recorded, so only its string image is available. Every
// stdlib-constructed option map builds its entries directly, with bare-name
// keys where the image IS unambiguous, so this path keeps its historical
// behavior byte-identically. The program-side `__cx_map__` envelope
// (vcx/code/eval.v eval_map) stores each key as the entry element's name.
// This is the single home for the envelope-lane key rule; the program
// renderer's `__cx_map__` paths (vcx/code/render.v, #495) delegate here so
// the two lanes cannot drift.
//
// The rule intentionally DIFFERS from cx_emit_map_key's string arm: in the
// typed data lane a number-shaped STRING key must quote (else it re-imports
// as int), but in the envelope a number image is just as likely a genuine
// int/float/bool/date key (`{7: v}`, program-dc-entry-int-key) — quoting it
// would flip it to a string on re-parse. So an auto-typing image stays BARE
// (its text re-parses to the same key image) and quoting is forced only
// when the bare image would structurally mis-parse: a `:` anywhere (a bare
// `cx:seq` key splits at the first colon; QName chars are bare-name chars),
// a `$`-leading name (reads as a binding reference / reserved-envelope
// key, e.g. `$tag`), or an image that is neither a bare name nor an
// auto-typing scalar (spaces, quotes, delimiters, empty, `@`/`#` sigils…).
pub fn cx_emit_envelope_map_key(s string) string {
	if !s.contains(':') && (cx_is_bare_name(s) || cx_would_autotype(s)) {
		return s
	}
	return cx_choose_quote(s)
}

// cx_array_item_needs_quote reports whether a bare text item inside an array
// literal `[…, …]` must be quoted to round-trip as the same string: any
// item-boundary char (whitespace, comma, bracket, quote, `&`), a value that
// would auto-type (number/date/…), or a leading `@`/`:`/`#` sigil forces a
// quote. (Mirrors the program renderer's needs_quote_string_item; the cx module
// cannot import code, so the rule is defined once on each side.)
fn cx_array_item_needs_quote(s string) bool {
	if s.len == 0 {
		return true
	}
	for c in s {
		if c == ` ` || c == `\t` || c == `\n` || c == `\r` || c == `,`
			|| c == `[` || c == `]` || c == `(` || c == `)` || c == `{`
			|| c == `}` || c == `'` || c == `"` || c == `&` {
			return true
		}
	}
	if cx_would_autotype(s) {
		return true
	}
	return s[0] == `@` || s[0] == `:` || s[0] == `#`
}

fn cx_is_bare_name(s string) bool {
	if s.len == 0 { return false }
	if !is_name_start(s[0]) { return false }
	for i in 1 .. s.len {
		if !is_name_char(s[i]) { return false }
	}
	return true
}

// array_render_plan decides the canonical surface for a typed-array element
// body of element-type `base` with `n` scalar items (lexicon.ebnf §9 — D1).
// It is the SINGLE home for the rule — both this canonical-CX emitter and the
// programs renderer (code.render_canonical) call it, so the two renderers
// cannot drift.
//   returns (drop_annotation, use_comma_separator, force_trailing_comma)
//
// A TYPED array ALWAYS keeps its `::T[]` head and emits its items
// whitespace-separated — `[tags::string[] admin user]`, `[scores::int[] 80
// 443]`. This is both LOSSLESS and IDEMPOTENT, which the old drop-annotation
// scheme was not:
//   - dropping `::T[]` and re-signalling the type via the body never recovered
//     the array — a bare comma body `[tags admin, user]` re-parses to an
//     UNTYPED ArrayNode (so `fmt` oscillated typed→comma→bracketed every save),
//     and a whitespace body `[scores 80 443]` re-parses to DISCRETE children,
//     not an array at all (§9: whitespace never auto-arrays);
//   - dropping `::T[]` is also a silent TYPE LOSS whenever the items don't
//     self-identify the declared type — `[xs::float[] 1 2 3]` would re-infer
//     `int`. The explicit `::T[]` head is what makes the whitespace body an
//     array (§9: a `::[]`/`::T[]` head makes an array), so keeping it is the
//     only form that round-trips for every element-type and arity.
// UNTYPED comma arrays (`[tags web, prod]`) are a different AST (a sole
// ArrayNode child) and canonicalise to the bracketed literal `[tags ['web',
// 'prod']]` via the generic element path — unaffected by this plan.
pub fn array_render_plan(base string, n int) (bool, bool, bool) {
	return false, false, false
}

// cx_emit_array_item renders one item of a typed-array body. Dates emit
// unquoted (cx_scalar already does); a dropped-annotation string item quotes
// only when a bare token would split or re-type (cx_quote_text_if_needed).
fn cx_emit_array_item(s ScalarNode, string_item bool) string {
	if string_item && s.value is string {
		return cx_quote_text_if_needed(s.value as string)
	}
	return cx_scalar(s)
}

// try_cx_emit_array_element emits a typed-array element body per decision (a),
// or returns none if `e` is not an all-scalar typed array (caller falls
// through to the generic element emit).
fn try_cx_emit_array_element(e Element) ?string {
	dt := e.data_type() or { return none }
	if !dt.ends_with('[]') { return none }
	if e.attrs.len > 0 { return none }
	base := dt#[..-2]
	mut scalars := []ScalarNode{}
	for it in e.items {
		if it is ScalarNode {
			scalars << it
		} else {
			return none
		}
	}
	cnt := scalars.len
	drop_ann, use_comma, trailing := array_render_plan(base, cnt)
	mut s := '[${e.name}'
	if a := e.anchor() { s += ' &${a}' }
	if m := e.merge()  { s += ' *${m}' }
	if id := e.id()    { s += ' #${id}' }
	if !drop_ann { s += '::${dt}' }
	if cnt > 0 {
		sep := if use_comma { ', ' } else { ' ' }
		mut parts := []string{cap: cnt}
		for sc in scalars {
			parts << cx_emit_array_item(sc, base == 'string')
		}
		s += ' ' + parts.join(sep)
		if trailing { s += ',' }
	}
	s += ']'
	return s
}

fn cx_emit_element(e Element, depth int, compact bool, mut out []string) {
	ind := cx_ind(depth, compact)
	nl  := if compact { '' } else { '\n' }

	// v3.4 (second bullet): body-position [ref @id] form.
	// Emitted as `[ref @<body_ref>]`, no anchors / merge / id meta /
	// attrs / items per the parser's rule that body_ref is set only
	// when the source had exactly that shape.
	if br := e.body_ref() {
		out << '${ind}[ref @${br}]${nl}'
		return
	}

	// v3.4: emit :table form when this Element carries TableData.
	// #469: e.items carries the comments the parser retained between the
	// element name and the `[table[` head — passed through so the pooled
	// emitter re-emits them (they were retained but silently dropped here).
	if td := e.table_opt() {
		cx_emit_table_element(e, td, depth, compact, mut out)
		return
	}

	// §9 / decision (a): typed-array body canonical render.
	if rendered := try_cx_emit_array_element(e) {
		out << '${ind}${rendered}${nl}'
		return
	}

	has_child_elements := e.items.any(it is Element)
	has_text := e.items.any(it is TextNode || it is ScalarNode || it is EntityRefNode
		|| it is RawTextNode || it is HoleNode)
	// #825: a LINE comment has no inline spelling — §2.9 keeps `# text`
	// terminated at end of line rather than converting it to block form, so
	// putting one on a shared line would swallow every following sibling.
	// Its element takes the multiline lane no matter what else the body
	// holds; block comments need no such help and ride the inline lane.
	has_line_comment := e.items.any(it is CommentNode && (it as CommentNode).is_line)
	is_multiline := !compact && (has_line_comment || (has_child_elements && !has_text))

	if is_multiline {
		meta := cx_build_meta(e)
		child_ind := cx_ind(depth + 1, compact)
		out << '${ind}[${e.name}${meta}${nl}'
		for item in e.items {
			// #829 remainder: already written inside the meta run — see
			// cx_meta_zone_comment_index.
			if _ := cx_meta_zone_comment_index(item) {
				continue
			}
			// #825: the multiline lane became reachable for TEXT-bearing
			// bodies (a line comment forces it), and cx_emit_node writes the
			// leaf kinds with neither indent nor newline — correct for the
			// inline lane it was written for, ragged here. Give the leaves
			// the layout their siblings get; every other kind lays itself
			// out already.
			if item is TextNode || item is ScalarNode || item is EntityRefNode
			   || item is HoleNode {
				out << child_ind
				cx_emit_node(item, depth + 1, compact, mut out)
				out << nl
				continue
			}
			cx_emit_node(item, depth + 1, compact, mut out)
		}
		out << '${ind}]${nl}'
	} else if e.items.len == 0 && e.attrs.len == 0 && e.anchor() == none && e.merge() == none
		&& e.data_type() == none && e.id() == none {
		// I1 W-1: the bare-name fast path must not swallow a `#id` — an
		// otherwise-empty element with an id declaration routes through
		// cx_build_meta below so the id survives (canonical was emitting
		// `[a]` for `[a #x1]`, un-reparseable back to the same document).
		out << '${ind}[${e.name}]${nl}'
	} else {
		meta := cx_build_meta(e)
		parent_scalar_typed := if dt := e.data_type() { !dt.ends_with('[]') } else { false }
		body := cx_build_inline_body(e.items, compact, parent_scalar_typed)
		body_sep := if body.len > 0 { ' ' } else { '' }
		out << '${ind}[${e.name}${meta}${body_sep}${body}]${nl}'
	}
}

// v3.4: emit a :table block. Header columns are emitted as
// `name:type` pairs (untyped columns drop the `:type` suffix); rows
// are space-separated cells. Cells use canonical scalar formatting:
// quoted iff the value is empty, contains whitespace, or would
// auto-type differently from its declared column type.
//
// #478: the element's head meta — anchor, merge, id, attributes — is
// ElementMeta like on any other element (grammar [29]: the TableBlock
// occupies only the TypeAnnotation slot) and MUST be re-emitted; this
// lane previously rendered the bare name, dropping every head meta on
// round-trip. The `table` data_type is implied by the `[table[…]]`
// clause and is never rendered as a glued `::table` (the parser rejects
// an explicit annotation on a table-block element). The TableBlock
// closes the head — it always follows the attributes, since the parser
// treats the `[table[` opener as the transition into the row body.
// #469: comments the parser retained (the element's only possible
// items) re-emit between the head meta and the `[table[…]]` clause.
fn cx_emit_table_element(e Element, td TableData, depth int, compact bool, mut out []string) {
	ind := cx_ind(depth, compact)
	nl  := if compact { '' } else { '\n' }
	row_ind := cx_ind(depth + 1, compact)
	name := e.name

	mut meta := ''
	if a := e.anchor() { meta += ' &${a}' }
	if m := e.merge()  { meta += ' *${m}' }
	if id := e.id()    { meta += ' #${id}' }
	for a in e.attrs {
		meta += ' ${cx_attr_scalar(a)}'
	}

	mut header_parts := []string{}
	for col in td.cols {
		if col.type_name == '' {
			header_parts << col.name
		} else {
			header_parts << '${col.name}::${col.type_name}'
		}
	}
	header := header_parts.join(' ')

	// #469: comments the parser retained between the element name and the
	// `[table[` head (its only possible items) re-emit ahead of the head —
	// the reader's ElementMeta loop collects them back into the same slot,
	// so the emit is a fixpoint and `cx fmt` is lossless for them.
	items := e.items
	has_comments := items.any(it is CommentNode)

	if compact || td.rows.len == 0 {
		mut all := []string{}
		for row in td.rows {
			for i, cell in row {
				ct := if i < td.cols.len { td.cols[i].type_name } else { '' }
				all << cx_format_table_cell(cell, ct)
			}
		}
		body := all.join(' ')
		body_sep := if body.len > 0 { ' ' } else { '' }
		mut cparts := ''
		if has_comments {
			// Inline position: block spelling only — a bare `# …` here
			// would comment out the rest of the record, so a retained
			// line comment normalizes to `[;…]` (content preserved).
			for item in items {
				if _ := cx_meta_zone_comment_index(item) {
					continue // #829 remainder — already in the meta run
				}
				if item is CommentNode {
					cparts += '[;${item.value}] '
				}
			}
		}
		out << '${ind}[${name}${meta} ${cparts}[table[${header}]]${body_sep}${body}]${nl}'
		return
	}

	if has_comments {
		// Multiline home: each retained comment on its own line between
		// the head meta and the `[table[…]]` clause, in its own spelling
		// (`[; … ]` block / `# …` line — cx_emit_node keeps both).
		out << '${ind}[${name}${meta}${nl}'
		for item in items {
			if _ := cx_meta_zone_comment_index(item) {
				continue // #829 remainder — already in the meta run
			}
			if item is CommentNode {
				cx_emit_node(item, depth + 1, compact, mut out)
			}
		}
		out << '${row_ind}[table[${header}]]${nl}'
		for row in td.rows {
			mut cells := []string{}
			for i, cell in row {
				ct := if i < td.cols.len { td.cols[i].type_name } else { '' }
				cells << cx_format_table_cell(cell, ct)
			}
			out << '${row_ind}${cells.join(' ')}${nl}'
		}
		out << '${ind}]${nl}'
		return
	}

	out << '${ind}[${name}${meta} [table[${header}]]${nl}'
	for row in td.rows {
		mut cells := []string{}
		for i, cell in row {
			ct := if i < td.cols.len { td.cols[i].type_name } else { '' }
			cells << cx_format_table_cell(cell, ct)
		}
		out << '${row_ind}${cells.join(' ')}${nl}'
	}
	out << '${ind}]${nl}'
}

// cx_format_table_cell formats one cell value for emission. Bare
// when the value matches the column's declared type and contains
// no whitespace; quoted otherwise. col_type is reserved for future
// per-column-type formatting (e.g., float-precision matching the
// declared :f32 width); currently unused.
fn cx_format_table_cell(v TableCellValue, col_type string) string {
	return match v {
		i64       { v.str() }
		f64       { format_float(v) }
		bool      { if v { 'true' } else { 'false' } }
		NullValue { 'null' }
		string    {
			// #485: the cell context's instantiation of the shared #483
			// collection-string rule (cx_collection_string): quote exactly
			// when the bare image would re-read as a DIFFERENT value in
			// cell position. In a string-family column a bare token
			// re-reads as the same string — grammar [29b]: untyped columns
			// default to ::string, read_table_cell never auto-types them —
			// so type-shaped text (`1h30m`, `36`) stays bare losslessly.
			// What MUST quote is anything the cell reader dispatches away
			// from the bare-token path or that derails the row re-parse:
			//   • a NON-string column (#413: bare coerces per column type),
			//   • the literal `null` (the null cell in ANY column),
			//   • whitespace (the cell separator) and `]` (the row closer),
			//   • a leading collection opener `[` / `{` / `(`
			//     (read_table_cell dispatches array / map / sequence
			//     literals on the first byte — `{a:b}` flipped string→map),
			//   • any quote char, either kind (`"q"` re-read as `q` — the
			//     same both-quote rule cx_collection_string carries).
			// #794 (RULED: 1a, the #795 batch): an atom-typed column's
			// cell emits the ATOM spelling `:name` — the quoted-string
			// render erased the kind (re-parse read string cells under
			// an atom column; read_table_cell's coercion strips the
			// leading ':', so `:ok` round-trips exactly). A value that
			// is NOT a denotable atom name keeps the quoted escape —
			// never mint an atom the grammar cannot spell.
			if col_type == 'atom' && is_atom_name(v) && !is_reserved_atom_token(':' + v) {
				return ':' + v
			}
			string_col := col_type == '' || col_type == 'string' || col_type == 's'
			if v.len == 0 || !string_col || v == 'null'
				|| v.contains(' ') || v.contains('\t')
				|| v.contains('\n') || v.contains('\r')
				|| v.contains("'") || v.contains('"')
				|| v.contains(']')
				|| v.starts_with('[') || v.starts_with('{') || v.starts_with('(') {
				cx_choose_quote(v)
			} else {
				v
			}
		}
		// collection-typed cells emit
		// in canonical CX literal form. Reuses the existing inline
		// emitters for ArrayNode / MapNode / SequenceNode so the
		// canonical-form rules (lex-sorted map keys, single-space
		// after comma, etc.) apply identically inside a :table cell.
		ArrayNode    { cx_emit_array_inline(v, true) }
		MapNode      { cx_emit_map_inline(v, true) }
		SequenceNode { cx_emit_sequence_inline(v, true) }
	}
}

// cx_meta_zone_comment_index reports the attribute index a retained
// ELEMENT-META comment sat before (#829 remainder), or none if this node is
// not one. It is THE predicate: cx_build_meta writes exactly the comments it
// answers for, and every body-item loop skips exactly those, so a meta-zone
// comment can never be emitted twice or dropped.
//
// A LINE comment never qualifies. §2.9 terminates `# text` at end of line,
// so writing one into the meta run would swallow every attribute after it
// (the same rule that gives line comments their own multiline lane, #825).
// It keeps the leading-body-item placement it already round-trips through.
fn cx_meta_zone_comment_index(n Node) ?int {
	if n !is CommentNode {
		return none
	}
	c := n as CommentNode
	if c.is_line {
		return none
	}
	return c.meta_attr_index
}

fn cx_build_meta(e Element) string {
	mut s := ''
	if a := e.anchor()    { s += ' &${a}' }
	if m := e.merge()     { s += ' *${m}' }
	if id := e.id()       { s += ' #${id}' }
	if dt := e.data_type() { s += '::${dt}' }
	for i, a in e.attrs {
		// #829 remainder: a meta-zone comment goes back BETWEEN the
		// attributes. Retaining it by prepending to `items` put it after all
		// of them — `[config [; c ] env=dev]` re-emitted as
		// `[config env=dev [; c ]]`, which §2.9 ("comment placement preserved
		// relative to nodes") forbids. The `[; … ]` form is self-delimiting,
		// so it composes inside the meta run exactly as it does beside any
		// inline sibling. Only comments an attribute FOLLOWS are stamped, so
		// nothing needs writing after the loop.
		for item in e.items {
			if idx := cx_meta_zone_comment_index(item) {
				if idx == i {
					s += ' [;${(item as CommentNode).value}]'
				}
			}
		}
		// Attributes are strictly scalar (D2 / #396 ruling 1b) — the v3.5
		// BracketBody round-trip branch is gone with the body channel.
		s += ' ${cx_attr_scalar(a)}'
	}
	return s
}

// cx_run_comment_interleave renders a text run with its MID-RUN comments put
// back where they sat (#829, RULED: 829-1c). The run is ONE TextNode — the
// comments ride it as presentation-only `run_offset`s — so this splits the
// rendered TEXT, never the node, and the Tier-1 hash is untouched (#469).
//
// It answers `none` when the split would not round-trip, and the caller then
// keeps the historical leading placement. Two ways that happens:
//   - a fragment would need QUOTING: `'a b'` + comment + `' c'` re-parses as
//     two separate strings, not one run;
//   - a fragment would AUTO-TYPE: run `x 5` split after `x ` re-parses `5`
//     as an INT, silently changing the value's kind.
// Both are checked per fragment, so the interleave is only taken where the
// emitted bytes provably re-read as the same run.
fn cx_run_comment_interleave(run string, comments []CommentNode) ?string {
	mut cut := []int{}
	for c in comments {
		o := c.run_offset or { return none }
		if o < 0 || o > run.len {
			return none
		}
		cut << o
	}
	if cut.len == 0 {
		return none
	}
	mut frags := []string{}
	mut prev := 0
	for o in cut {
		if o < prev {
			return none
		}
		frags << run[prev..o]
		prev = o
	}
	frags << run[prev..]
	for f in frags {
		trimmed := f.trim_space()
		if trimmed.len == 0 {
			continue
		}
		// The oracle here is try_autotype, the parser's OWN function, not
		// cx_would_autotype: that one deliberately OVER-reports (its #473
		// note calls over-reporting "the safe direction" — it quotes a token
		// that would in fact stay text, e.g. a bare `e`). Over-quoting is
		// harmless when the question is "should this be quoted", but here it
		// silently costs the placement, so ask the parser what the fragment
		// actually re-reads as.
		if _ := try_autotype(trimmed) {
			return none
		}
		if cx_has_control_byte(trimmed) || cx_body_leading_sigil(trimmed)
			|| cx_text_has_boundary_quote(trimmed)
			|| trimmed.contains('[') || trimmed.contains(']')
			|| trimmed.contains('&') || trimmed.contains('\\')
			|| trimmed.contains(',') || trimmed.starts_with(':') {
			return none
		}
	}
	mut outp := []string{}
	for i, f in frags {
		tf := f.trim_space()
		if tf.len > 0 {
			outp << tf
		}
		if i < comments.len {
			outp << cx_emit_node_str(comments[i], false)
		}
	}
	return outp.join(' ')
}

fn cx_build_inline_body(items []Node, compact bool, parent_scalar_typed bool) string {
	mut parts := []string{}
	// #829 (RULED: 829-1c): indices consumed by a run/comment interleave.
	mut consumed := map[int]bool{}
	for idx, item in items {
		if idx in consumed {
			continue
		}
		// #829 remainder: a stamped ELEMENT-META comment was already written
		// inside the meta run by cx_build_meta — emitting it here too would
		// duplicate it.
		if _ := cx_meta_zone_comment_index(item) {
			continue
		}
		match item {
			TextNode {
				// I1 W-6 + companion (owner-ruled): EVERY string is a value —
				// the empty string emits `''`, whitespace-only strings emit
				// quoted (`' '`). The old whitespace-only skip existed to hide
				// XML-import layout text; that now strips at IMPORT
				// (xml_parser.v), so anything still in the tree is a value.
				// ONE exception: a single-space TextNode BETWEEN two siblings
				// is the parser's reconstructed join space (`[p &amp; &lt;]`
				// round-trips it) — the bare spelling is canonical, so the
				// join renders it rather than a quoted `' '`.
				if item.value == ' ' && idx > 0 && idx < items.len - 1 {
					continue
				}
				if item.value.len == 0 {
					parts << "''"
					continue
				}
				// #829: gather the comments that sat INSIDE this run and put
				// them back. Falls through to the plain emit when the split
				// would not round-trip (see cx_run_comment_interleave).
				mut inner := []CommentNode{}
				mut j := idx + 1
				for j < items.len {
					nxt := items[j]
					if nxt is CommentNode {
						if _ := nxt.run_offset {
							inner << nxt
							j++
							continue
						}
					}
					break
				}
				if inner.len > 0 {
					if woven := cx_run_comment_interleave(item.value, inner) {
						parts << woven
						for k in idx + 1 .. idx + 1 + inner.len {
							consumed[k] = true
						}
						continue
					}
				}
				parts << cx_quote_text_if_needed(item.value)
			}
			ScalarNode {
				// A plain (non-atom) string scalar in mixed / untyped body
				// position quotes under the SAME bijective rule as a TextNode
				// — otherwise `cx fmt` re-parses `'CX is a '` (a string
				// ScalarNode here) and re-emits it BARE, dropping the boundary
				// spaces and oscillating quoted⇄bare. When the parent element
				// carries a disambiguating scalar `::T` head (`[zip::string
				// 90210]`), the annotation already pins the type, so the value
				// stays bare via cx_scalar.
				if !parent_scalar_typed && item.data_type == .string_type && item.value is string {
					parts << cx_quote_text_if_needed(item.value as string)
				} else {
					parts << cx_scalar(item)
				}
			}
			EntityRefNode { parts << '&${item.name};' }
			HoleNode      { parts << '$' + item.name }
			RawTextNode   { parts << '[#${item.value}#]' }
			CommentNode   {
			// #825: the inline body lane dropped comments outright — a
			// canonical form that cannot re-parse to the document it came
			// from, against canonical.md §1.1 ("preserves every node: …
			// comments …") and §2.9's explicit "comment placement preserved
			// relative to nodes".
			//
			// Only the BLOCK form is emitted here. `[; … ]` is
			// self-delimiting, so it composes beside any sibling on one
			// line. A LINE comment cannot: §2.9 requires `# text` to stay a
			// line comment "terminated at end of line, not converted to
			// block form", and emitting one inline would swallow every
			// following sibling into it. An element whose body carries a
			// line comment therefore takes the MULTILINE lane instead —
			// see body_has_line_comment at the caller.
			//
			// Routed through cx_emit_node_str so the spelling has ONE
			// authority shared with the multiline lane and the top level.
			//
			// #962 / R-A7 — the multiline escape hatch is NOT universal: two
			// callers reach this lane holding a LINE comment.
			// `cx_emit_eval_directive` always builds its body inline, and the
			// COMPACT element emit (`cx_emit_node_str(n, true)` — the program
			// lane's data-node render) never takes the multiline branch at
			// all. In both, cx_emit_node_str trimming the comment's trailing
			// newline — correct for a STANDALONE comment, which must render
			// bare — let the comment swallow every following sibling and the
			// closing bracket on re-parse. The newline that terminates a line
			// comment is SYNTAX, not layout, so this lane writes it
			// explicitly; the block form stays inline and self-delimiting.
			if item.is_line {
				parts << '# ${item.value}\n'
			} else {
				parts << cx_emit_node_str(item, compact)
			}
		}
		AliasNode     {
				// #736: an alias reference in ELEMENT BODY position was
				// dropped outright by this lane's `else` arm — `[b [*n]]`
				// emitted `[b]`, a canonical form that cannot re-parse to
				// the document it came from. The glued `[*name]` spelling
				// is the SAME one cx_emit_node writes at top level and in
				// the MULTILINE body lane — which is exactly why `[*def]`
				// alone and `[b [*n] [c]]` always round-tripped and only
				// the inline lane lost it. It is a self-delimiting bracket
				// form, so it is safe beside any sibling on one line.
				//
				// Lossless canonical preserves aliases by contract
				// (canonical.md §1.1). STRICT canonical never reaches this
				// arm — cx_canonical_doc_text resolves anchors before it
				// emits — so no Tier-1 address depends on this line.
				parts << '[*${item.name}]'
			}
			Element {
				mut tmp := []string{}
				cx_emit_element(item, 0, compact, mut tmp)
				parts << tmp.join('').trim_right('\n')
			}
			BlockContentNode {
				mut s := '[|'
				for bi in item.items {
					match bi {
						TextNode { s += bi.value }
						Element  {
							mut tmp := []string{}
							cx_emit_element(bi, 0, compact, mut tmp)
							s += tmp.join('').trim_right('\n')
						}
						else {}
					}
				}
				s += '|]'
				parts << s
			}
			InterpolationNode {
				parts << '[?=${item.expr}]'
			}
			EvalDirectiveNode {
				mut tmp := []string{}
				cx_emit_eval_directive(item, 0, true, mut tmp)
				parts << tmp.join('').trim_right('\n')
			}
			SequenceNode { parts << cx_emit_sequence_inline(item, compact) }
			ArrayNode    { parts << cx_emit_array_inline(item, compact) }
			MapNode      { parts << cx_emit_map_inline(item, compact) }
			IteratorNode { parts << cx_emit_sequence_inline(iterator_to_sequence(item), compact) }
			else {}
		}
	}
	return parts.join(' ')
}

fn cx_text_needs_quote(s string) bool {
	// I1 W-6: the empty string has no bare image — it must quote (`''`)
	// everywhere or it vanishes from the emitted body.
	return s.len == 0 || s.starts_with(' ') || s.ends_with(' ')
		|| s.contains('  ') || cx_has_control_byte(s)
		|| s.contains('[') || s.contains(']') || s.contains('&')
		|| s.contains('\\')
		|| s.contains(',')               // a bare comma is the array signal (§9)
		|| s.starts_with(':')
		|| cx_body_leading_sigil(s)       // `+tls` / `-debug` / `*a` / `@r` …
		|| cx_text_has_boundary_quote(s)
		|| cx_would_autotype(s)
}

fn cx_quote_text_if_needed(s string) string {
	if !cx_text_needs_quote(s) { return s }
	return cx_choose_quote(s)
}

// cx_has_control_byte reports whether `s` carries any C0 control byte
// (U+0000–U+001F, which includes LF / CR / tab) or DEL (U+007F). Such a
// value must take a quoted form so the §2.4 escape pass makes every control
// character visible in the canonical bytes (I1 L15 / W-12).
fn cx_has_control_byte(s string) bool {
	for i := 0; i < s.len; i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// cx_collection_string renders a STRING payload in map-value / sequence-item
// position (#473). Beyond the element-body rule (cx_text_needs_quote — which
// carries the would-autotype protection: number / float / bool / null / atom /
// date / datetime / duration / period / bigint / hex shaped strings quote so
// the text lane re-imports them as strings), a collection item must also
// quote when the bare image would derail the COLLECTION re-parse: any quote
// char (a mid-token `'` is safe bare prose in element-body position — core
// 035 — but opens quoted text in `{k: it's}`), or a closer that ends the
// collection early (`}` / `)`). Applied to BOTH TextNode and string-
// ScalarNode payloads so a CX-authored value and the same value imported
// from JSON/YAML canonicalize identically (the idempotency fixpoint).
// cx_collection_bare_safe reports whether a STRING may render BARE in
// collection-ITEM position — a `{k: v}` map value or a `(…)` sequence item —
// and re-read as THE SAME STRING in BOTH readings (#831, RULED: 831-1a′).
//
// The old rule computed "safe" for the DATA reading alone, and that is where
// it broke: `is_name_char` folds `.` and `:` into a name and a single interior
// SPACE is legal body text, so the canonical form emitted `{k: a b}`,
// `{k: a.b}`, `{k: https://a.com}` — none of which the PROGRAM reader can read
// back (`expected ':' after map key`). That is lexicon [L11]'s ONE DELIBERATE
// NAME-CHAR MODE FORK showing through a canonical form: the program lexer
// continues names with `is_ident_part`, which excludes `.`/`:`. Canonical text
// that only half the language can read is not canonical, so the safe set is
// the INTERSECTION of the two readings:
//
//   - the first byte is a name START (a leading `/` reads as a path —
//     `//variant`, `/a/b` — and a leading sigil is already excluded below);
//   - every later byte is an `is_ident_part` char or `/` (`a/b` verified to
//     round-trip to the same STRING through the program reading; `a.b` and
//     `a:b` do not).
//
// Array-literal position was never affected: cx_emit_array_item_literal
// already applies a stricter boundary predicate, which is exactly why arrays
// are the one collection position where the two lanes always agreed.
//
// #983: that independence is load-bearing, not incidental. This predicate
// refusing a string (`<=x`, a glued operator glyph) says NOTHING about whether
// the array emitter may render it bare — array position asks a different
// question (does the image re-parse to the same value?) and answers it with
// cx_is_bare_name / cx_array_item_needs_quote. See the round-trip evidence and
// the address-preservation reasoning on cx_emit_array_item_literal.
pub fn cx_collection_bare_safe(s string) bool {
	if s.len == 0 || !is_name_start(s[0]) {
		return false
	}
	for i := 1; i < s.len; i++ {
		if !is_ident_part(s[i]) && s[i] != `/` {
			return false
		}
	}
	return true
}

pub fn cx_collection_string(s string) string {
	if cx_text_needs_quote(s) || !cx_collection_bare_safe(s) {
		return cx_choose_quote(s)
	}
	return s
}

// cx_body_leading_sigil reports whether a bare-emitted body text would be
// re-lexed as a NON-text token because of its first character. At a body /
// head item boundary these sigils introduce structure rather than prose:
// `+`/`-` (retired boolean-flag sigils — grammar [55b]), `*` (alias), `@`
// (body @id ref), `#` (line comment), `%` (PE reference), `$` (binding ref),
// and the collection / grouping openers+closers `( ) { } =`. A string whose
// value starts with one of these MUST be quoted or `cx fmt` would emit syntax
// the parser then rejects or re-reads as a different node (e.g. `[code '+tls']`
// → bare `[code +tls]` → "retired flag sigil"). `[`/`]`/`&`/`:`/quotes are
// already covered by the caller's checks. NOTE: `$`/`%`/`=`/parens are NOT in
// the set — `$v`/`%x` are program binding/PE references and grouping is opened
// by `(`/`{` which begin a structured value, not prose; a data text run that
// genuinely starts with `(`/`{` is rare and the collection openers are handled
// by the parser's structural dispatch, so quoting only the unambiguous prose-
// breaking sigils avoids mangling embedded program expressions (e.g. the
// `[in $v //variant]` body of a `[?for]`).
fn cx_body_leading_sigil(s string) bool {
	if s.len == 0 { return false }
	// I1 row 9 (L78): `$` joins the set — a bare `$name…` body image
	// re-parses as a variable HOLE (or hole + prose), so a STRING whose
	// image is $-leading must quote ('$x' is the string; $x is the hole).
	// Directive interiors ([?for [in $v …]]) are unaffected: directives
	// preserve their source verbatim and never ride this lane.
	return s[0] in [`+`, `-`, `*`, `@`, `#`, `$`]
}

// cx_text_has_boundary_quote reports whether a bare-emitted body text
// would re-open a quoted string on re-parse. A `'` or `"` at the start of
// a body item — position 0 or immediately after whitespace — is parsed as
// a quoted-string opener (parse_body boundary rule), so the value must be
// wrapped to survive a round-trip. A mid-token quote (a contraction such
// as `it's`, or `Bob's`) is literal bare prose and stays unquoted — see
// conformance core 035-apostrophe-in-bare-prose.
fn cx_text_has_boundary_quote(s string) bool {
	for i := 0; i < s.len; i++ {
		c := s[i]
		if c == `'` || c == `"` {
			if i == 0 { return true }
			pc := s[i - 1]
			if pc == ` ` || pc == `\t` || pc == `\n` || pc == `\r` {
				return true
			}
		}
	}
	return false
}

pub fn cx_choose_quote(s string) string {
	has_single := s.contains("'")
	has_double := s.contains('"')
	if !has_single { return "'" + cx_escape_quoted(s, `'`) + "'" }
	if !has_double { return '"' + cx_escape_quoted(s, `"`) + '"' }
	// Both quote styles present → single-quoted with the `\'` escape
	// (canonical.md §2.3 "Both" row: the disambiguating tiebreak — the `"`
	// needs no escape inside `'…'`). I1 identity epoch, owner-ruled L16
	// (W-13): the data lane converges on this rule, so the render and data
	// lanes emit ONE spelling per value. Triquote is NEVER emitted (L17 /
	// W-2) — multiline and control-bearing content escapes per §2.4 inside
	// the ordinary quoted forms, so no verbatim container is needed.
	return "'" + cx_escape_quoted(s, `'`) + "'"
}

// cx_choose_quote_render is the programs-render lane's quote chooser
// (code.render_canonical → choose_render_quote delegates here so the escape
// rules live in one place). Since the I1 L16 ruling the two lanes share one
// rule — this is now a thin alias kept for the render call-site's name.
pub fn cx_choose_quote_render(s string) string {
	return cx_choose_quote(s)
}

// cx_escape_quoted escapes the content of a single/double-quoted CX string
// scalar so it round-trips through the parser's escape decode (lexicon.ebnf §5
// [L32], canonical.md §2.4). The decode is LENIENT: a backslash followed by a
// byte that is NOT a recognized escape initial is kept verbatim (both bytes),
// so regex patterns such as `\d` / `\.` / `\w` survive without doubling.
// Therefore a literal backslash is doubled ONLY when it would otherwise be
// consumed as the start of a recognized escape (`\ ' " n r t u U`) or it is the
// final byte (where it would pair with the closing delimiter). The active
// delimiter byte, if present in the content, is backslash-escaped. This is the
// minimal re-escape that makes parse(emit(x)) ≡ x (conversions.md §1) without
// churning the verbatim regex surface. Triple-quoted emission does NOT use this
// pass — its content is verbatim.
pub fn cx_escape_quoted(s string, delim u8) string {
	mut out := []u8{cap: s.len + 4}
	for i := 0; i < s.len; i++ {
		c := s[i]
		if c == `\\` {
			if i + 1 >= s.len || cx_is_escape_initial(s[i + 1]) {
				out << `\\`
				out << `\\`
			} else {
				out << c
			}
		} else if c == delim {
			out << `\\`
			out << c
		} else if c == `\n` {
			// §2.4 (I1 L15 / W-12): control characters are EMITTED as escapes
			// — quoted canonical text never carries raw control bytes, so the
			// same value has one spelling and Windows/Unix line-ending
			// differences are visible in the bytes (W-25).
			out << `\\`
			out << `n`
		} else if c == `\r` {
			out << `\\`
			out << `r`
		} else if c == `\t` {
			out << `\\`
			out << `t`
		} else if c < 0x20 || c == 0x7f {
			// Other C0 controls and DEL: \u00xx, lowercase hex (matching the
			// §2.5 lowercase-hex convention).
			out << `\\`
			out << `u`
			out << `0`
			out << `0`
			hi := c >> 4
			lo := c & 0xf
			out << if hi < 10 { `0` + hi } else { `a` + (hi - 10) }
			out << if lo < 10 { `0` + lo } else { `a` + (lo - 10) }
		} else {
			out << c
		}
	}
	return out.bytestr()
}

// cx_is_escape_initial reports whether `c` is the byte that, when it follows a
// backslash, forms one of the recognized escape sequences in lexicon §5 [L32]
// (`\\ \' \" \n \r \t \uXXXX \UXXXXXXXX`).
fn cx_is_escape_initial(c u8) bool {
	return c == `\\` || c == `'` || c == `"` || c == `n` || c == `r` || c == `t`
		|| c == `u` || c == `U`
}

// cx_attr_scalar renders a scalar-valued attribute to its canonical CX
// surface token `name…=value` (no leading space). It is the single source
// of truth for typed-attribute emission (D3), shared by the element-attr
// and eval-directive emit paths. Forms, in priority order:
//   • bare `@id` reference                          → `name=@id`
//   • atom                                          → `name=:click`  (sigil)
//   • auto-recoverable type (int/float/bool/date/datetime) → `name=value` (bare;
//     the lexical form re-types it on XML→CX import, no sidecar needed)
//   • a type the lexical form can't recover (u16/i32/f32/decimal/bigint/bytes)
//                                                    → `name::T=value`  (glued)
//   • explicit / default string                     → `name=value`, quoting when
//     the value would otherwise auto-type (`code='007'`)
pub fn cx_attr_scalar(a Attribute) string {
	name_part, val_part := cx_attr_scalar_parts(a)
	return '${name_part}=${val_part}'
}

// cx_attr_scalar_parts is the implementation behind `cx_attr_scalar`,
// split into the two sides of the `=`: the NAME side (which carries any
// glued `::T` type annotation) and the VALUE side. `cx_attr_scalar` is
// exactly `name_part + '=' + val_part`.
//
// The split exists so an emitter with a different LAYOUT — the format
// module's pretty / diff-friendly forms, which pad between the `=` and
// the value for :attribute-alignment — can reuse this one type-aware
// value decision instead of re-deriving it from the `ScalarValue` union
// alone. That union cannot express the string-carried kinds (decimal,
// bigint, atom, date, datetime, duration, period all park their verbatim
// CX image in a `string` and ride their type on `data_type`), so a
// value-only match reads every one of them as a string and quotes it —
// the #978 round-trip defect (RULED: CO-3). One decision, one place.
pub fn cx_attr_scalar_parts(a Attribute) (string, string) {
	val_str := a.str_value()
	if a.is_ref {
		return a.name, '@${val_str}'
	}
	if dt := a.data_type() {
		if dt == 'atom' {
			// The atom name is stored bare; the `:` sigil is the canonical
			// surface and round-trips losslessly, so atoms keep it rather
			// than the glued `::atom=` form.
			return a.name, ':${val_str}'
		}
		if dt == 'string' {
			v := if cx_would_autotype(val_str) { "'${val_str}'" } else { cx_quote_attr_if_needed(val_str) }
			return a.name, v
		}
		if type_name_is_auto_recoverable(dt) {
			return a.name, cx_quote_attr_if_needed(val_str)
		}
		// I1 stream 11 (L45 + ruling 2b): bigint AND decimal drop the
		// annotation exactly when the bare image re-types the same kind on
		// its own — over-i64 bigints auto-promote ([L20]); fixed-point
		// fractions ARE decimals (2b). Integral-image values keep the
		// glued form (bare would re-type int — a different kind).
		if dt == 'bigint' || dt == 'decimal' {
			want := if dt == 'bigint' { ScalarType.bigint_type } else { ScalarType.decimal_type }
			if re := try_autotype(val_str) {
				if re.data_type == want {
					return a.name, val_str
				}
			}
		}
		// Sized numerics / decimal / small bigint / bytes — no self-evident
		// lexical form, so carry the glued annotation.
		return '${a.name}::${dt}', cx_quote_attr_if_needed(val_str)
	}
	v := if cx_would_autotype(val_str) { "'${val_str}'" } else { cx_quote_attr_if_needed(val_str) }
	return a.name, v
}

pub fn cx_would_autotype(s string) bool {
	if s.contains(' ') { return false }
	if s.starts_with('0x') || s.starts_with('0X')
		|| s.starts_with('-0x') || s.starts_with('-0X') { return true }
	if s == 'true' || s == 'false' || s == 'null' { return true }
	if _ := s.parse_int(10, 64) { return true }
	// #473: align with try_autotype's full shape set — a bare image that
	// re-parses as ANY typed scalar must count, or a string payload with
	// that shape silently type-flips through the CX text lane.
	//   • over-i64 decimal ints auto-promote to bigint ([L20]/D-H) and
	//     underscore-grouped numerics type after strip_underscores. (The
	//     leading-zero `007` class stays covered by parse_int above:
	//     over-reporting quotes a token that would stay text — the safe
	//     direction, and the long-standing surface.)
	if cleaned := strip_underscores(s) {
		if is_v34_decimal_int(cleaned) { return true }
		if cleaned != s && (cleaned.contains('.') || cleaned.contains('e') || cleaned.contains('E')) {
			if has_ascii_digit(cleaned) {
				if _ := strconv.atof64(cleaned) { return true }
			}
		}
	}
	if s.contains('.') || s.contains('e') || s.contains('E') {
		if _ := strconv.atof64(s) { return true }
	}
	if is_datetime(s) { return true }
	if is_date(s) { return true }
	//   • duration / period spans ([L25]/[L26]): `1h30m`, `100ms`, `3mo`.
	if _ := temporal_span_kind(s) { return true }
	//   • atom literals ([L40]): `:click`. The reserved `:true`/`:false`/
	//     `:null` are rejected by the auto-typer and re-parse as text.
	if s.len >= 2 && s[0] == `:` && is_atom_pattern_name(s[1..]) {
		name := s[1..]
		if name != 'true' && name != 'false' && name != 'null' { return true }
	}
	return false
}

fn cx_quote_attr_if_needed(s string) string {
	// Control-bearing values (newline / CR / tab / other C0 / DEL) take a
	// quoted form and the §2.4 escape pass renders every control character
	// as its escape — the attr stays single-line and canonical never emits
	// triquote (I1 rulings L15+L17; the old verbatim-triquote AttValue
	// branch is gone with the epoch).
	if cx_has_control_byte(s) {
		return cx_choose_quote(s)
	}
	// #563: quote-bearing values MUST go through the shared chooser +
	// escape pass — a verbatim `'…'` wrap around an embedded `'` emits
	// text that re-parses as a different document, or fails to parse at
	// all.
	if s.contains("'") || s.contains('"') {
		return cx_choose_quote(s)
	}
	// The remaining quoted wraps still need the minimal backslash
	// re-escape: a `\n`-shaped byte pair inside `'…'` decodes as an
	// escape on re-parse (lenient decode, §2.4), so `C:\new dir` would
	// otherwise round-trip into a literal newline.
	if s.contains(' ') || s.len == 0 {
		return "'" + cx_escape_quoted(s, `'`) + "'"
	}
	// bare `@id` at attribute-value position is a syntactic
	// reference. A literal string starting with '@' must be quoted to
	// preserve the round-trip distinction between is_ref=true (emit as
	// `@id` via cx_build_meta's is_ref branch) and is_ref=false (emit
	// here, must NOT look like a reference token).
	if s.len > 0 && s[0] == `@` {
		return "'" + cx_escape_quoted(s, `'`) + "'"
	}
	// a string value of the form `:NAME` would re-parse as an
	// atom literal on round-trip; quote it to preserve the string kind.
	// (Applies symmetrically with the @id case above.) Reserved-name
	// strings (`:true` / `:false` / `:null`) follow the same rule — the
	// auto-typer rejects them as atoms, but the surface text still
	// looks atom-shaped and must be quoted.
	if s.len > 1 && s[0] == `:` && is_atom_pattern_name(s[1..]) {
		return "'${s}'"
	}
	return s
}

// cx_quote_body_if_needed wraps a substituted scalar that is about to
// be emitted into element-body position with the cheapest quote form
// that survives a re-parse. CX code's `[?=]` and filter directives emit
// their result text into the surrounding element body, and downstream
// tools (e.g. `cx --md`, `cx --xml`) re-parse the emit; bytes like
// `[` `]` `'` `"` or a leading sigil would re-tokenize as structure
// instead of staying as text. Bare-safe strings are returned verbatim
// so the common case (`[h2 [?= sec/@id]]` → `[h2 first]`) does not
// noise up the output with redundant quotes.
fn cx_quote_body_if_needed(s string) string {
	if s.len == 0 {
		return s
	}
	// Structural delimiters anywhere in the value would re-parse as
	// child elements or quoted-string items. Newlines collapse to
	// inter-token whitespace in a bare body and only survive inside a
	// triple-quoted scalar — so multi-line values count as hazardous
	// even when no other structural byte is present. `#` at any
	// position triggers a line-comment scan that eats through the
	// next newline — including a trailing `]` — so a value like
	// `cx hash menu.cx # comment` re-parses as a runaway comment.
	mut needs := s.contains('[') || s.contains(']') || s.contains("'") ||
		s.contains('"') || s.contains('\n') || s.contains('#') ||
		s.contains('&')
	if !needs {
		// Sigil at the start would re-parse as ref / anchor / merge /
		// id / data-type marker (`@id`, `&a`, `*m`, `#i`, `:t`).
		c := s[0]
		if c == `@` || c == `&` || c == `*` || c == `#` || c == `:` {
			needs = true
		}
	}
	if !needs {
		// `name=value` at the head re-parses as an attribute on the
		// containing element. Detect a leading bare-ident followed by
		// `=` and treat it as hazardous.
		mut i := 0
		for i < s.len && (is_ident_cont_byte(s[i])) { i++ }
		if i > 0 && i < s.len && s[i] == `=` {
			needs = true
		}
	}
	if !needs {
		return s
	}
	if s.contains('\n') || s.contains("'") {
		return "'''${s}'''"
	}
	return "'${s}'"
}

// Local byte-classifier matching the CX identifier-continue set,
// scoped to this helper. Keeping it private avoids tangling with the
// parser's identifier scanner in another module.
fn is_ident_cont_byte(c u8) bool {
	if c >= `a` && c <= `z` { return true }
	if c >= `A` && c <= `Z` { return true }
	if c >= `0` && c <= `9` { return true }
	return c == `_` || c == `-` || c == `.`
}

pub fn cx_scalar(s ScalarNode) string {
	// Atom scalar — renders with leading `:`. The payload
	// `value` is the atom's name (UTF-8) stored as a string; the
	// canonical surface is `:NAME`, never bare or quoted.
	if s.data_type == .atom_type {
		name := match s.value {
			string { s.value as string }
			else   { scalar_value_str(s.value) }
		}
		return ':${name}'
	}
	return match s.value {
		i64       { s.value.str() }
		f64       { format_float(s.value as f64) }
		bool      { if s.value as bool { 'true' } else { 'false' } }
		NullValue { 'null' }
		string    { s.value as string }
	}
}

fn cx_emit_pi(p PINode, depth int, compact bool, mut out []string) {
	data := p.data or { '' }
	sep  := if data.len > 0 { ' ' } else { '' }
	nl   := if compact { '' } else { '\n' }
	ind  := cx_ind(depth, compact)
	out << '${ind}[?${p.target}${sep}${data}]${nl}'
}

fn emit_cx_xml_decl(x XMLDeclNode, mut out []string) {
	mut s := '[?xml version=${x.version}'
	if enc := x.encoding   { s += ' encoding=${enc}' }
	if sa  := x.standalone  { s += ' standalone=${sa}' }
	s += ']'
	out << '${s}\n'
}

// v3.5: emit `[?=EXPR]` interpolation. The captured
// expression text round-trips verbatim; no quoting is added because
// the body is opaque to the CX layer (parsed as CXPath by the CX code
// evaluator).
fn cx_emit_interpolation(n InterpolationNode, depth int, compact bool, mut out []string) {
	nl  := if compact { '' } else { '\n' }
	ind := cx_ind(depth, compact)
	out << '${ind}[?=${n.expr}]${nl}'
}

// v3.5: emit `[?Name ... ]` evaluation directive. Attrs
// and body items are emitted in source-like form. BracketBody attrs
// (`:then=[…]`) round-trip via cx_build_meta's body-aware branch is
// not reused here because EvalDirective attrs always emit inline.
fn cx_emit_eval_directive(n EvalDirectiveNode, depth int, compact bool, mut out []string) {
	nl  := if compact { '' } else { '\n' }
	ind := cx_ind(depth, compact)
	mut s := '${ind}[?${n.name}'
	for a in n.attrs {
		val_str := a.str_value()
		if val_str.len == 0 {
			s += ' ${a.name}'
		} else {
			s += ' ${cx_attr_scalar(a)}'
		}
	}
	if n.items.len > 0 {
		body := cx_build_inline_body(n.items, true, false)
		if body.len > 0 { s += ' ${body}' }
	}
	s += ']${nl}'
	out << s
}

fn emit_cx_directive(cx2 CXDirectiveNode, mut out []string) {
	mut parts := []string{cap: cx2.attrs.len}
	for a in cx2.attrs {
		v := a.str_value()
		if a.name == '' {
			// Quoted positional argument (e.g. the `schema-name` title) —
			// re-quote so it round-trips as a single token.
			parts << ' ${cx_quote_attr_if_needed(v)}'
		} else if v == '' {
			parts << ' ${a.name}'
		} else {
			parts << ' ${a.name}=${cx_quote_attr_if_needed(v)}'
		}
	}
	out << '[?cx${parts.join('')}]\n'
}

fn cx_emit_block_content(bc BlockContentNode, depth int, compact bool, mut out []string) {
	ind := cx_ind(depth, compact)
	nl  := if compact { '' } else { '\n' }
	out << '${ind}[|'
	for item in bc.items {
		match item {
			TextNode { out << item.value }
			Element  {
				mut tmp := []string{}
				cx_emit_element(item, 0, compact, mut tmp)
				out << tmp.join('').trim_right('\n')
			}
			else {}
		}
	}
	out << '|]${nl}'
}

fn emit_cx_doctype(d DoctypeDecl, mut out []string) {
	mut header := '[!DOCTYPE ${d.name}'
	if ext := d.external_id {
		if pub_id := ext.public {
			sys := ext.system or { '' }
			header += " PUBLIC '${pub_id}' '${sys}'"
		} else if sys := ext.system {
			header += " SYSTEM '${sys}'"
		}
	}
	if d.int_subset.len == 0 {
		header += ']'
		out << '${header}\n'
	} else {
		header += ' [\n'
		out << header
		for n in d.int_subset { cx_emit_node(n, 1, false, mut out) }
		out << ']]\n'
	}
}

fn cx_emit_entity_decl(e EntityDeclNode, depth int, compact bool, mut out []string) {
	ind         := cx_ind(depth, compact)
	nl          := if compact { '' } else { '\n' }
	kind_marker := if e.kind == .pe { '% ' } else { '' }
	def_str     := match e.def {
		string { "'${e.def}'" }
		ExternalEntityDef {
			ext := e.def as ExternalEntityDef
			mut s := if pub_id := ext.external_id.public {
				sys := ext.external_id.system or { '' }
				"PUBLIC '${pub_id}' '${sys}'"
			} else {
				sys := ext.external_id.system or { '' }
				"SYSTEM '${sys}'"
			}
			if ndata := ext.ndata { s += ' NDATA ${ndata}' }
			s
		}
	}
	out << '${ind}[!ENTITY ${kind_marker}${e.name} ${def_str}]${nl}'
}

fn cx_emit_attlist_decl(a AttlistDeclNode, depth int, compact bool, mut out []string) {
	ind  := cx_ind(depth, compact)
	nl   := if compact { '' } else { '\n' }
	defs := a.defs.map(' ${it.name} ${it.att_type} ${it.default}').join('')
	out << '${ind}[!ATTLIST ${a.name}${defs}]${nl}'
}

fn cx_emit_notation_decl(n NotationDeclNode, depth int, compact bool, mut out []string) {
	ind    := cx_ind(depth, compact)
	nl     := if compact { '' } else { '\n' }
	id_str := if pub_id := n.public_id {
		if sys := n.system_id { "PUBLIC '${pub_id}' '${sys}'" } else { "PUBLIC '${pub_id}'" }
	} else if sys := n.system_id {
		"SYSTEM '${sys}'"
	} else {
		''
	}
	out << '${ind}[!NOTATION ${n.name} ${id_str}]${nl}'
}

fn cx_emit_conditional_sect(c ConditionalSectNode, depth int, compact bool, mut out []string) {
	ind  := cx_ind(depth, compact)
	nl   := if compact { '' } else { '\n' }
	kind := if c.kind == .include { 'INCLUDE' } else { 'IGNORE' }
	out << '${ind}[![${kind}[${nl}'
	for n in c.subset { cx_emit_node(n, depth + 1, compact, mut out) }
	out << '${ind}]]]${nl}'
}

// cx_autotype_kind_name answers the CXDM kind name a BARE image would take
// under §9 auto-typing, or `string` when the image stays text (#777, RULED:
// 777-1a). It is the normalizer that makes an UNSTAMPED envelope key
// comparable with a stamped one: a directly-constructed stdlib entry carries
// no kind, but its key still HAS one — `name` is a string key, `7` an int
// key — and a pattern must match by the same identity either way.
pub fn cx_autotype_kind_name(s string) string {
	if n := try_autotype(s) {
		return scalar_type_name_public(n.data_type)
	}
	return 'string'
}
