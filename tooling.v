module cx

import crypto.sha256
import crypto.sha512
import crypto.blake3

// Canonical-form tooling per spec/canonical.md and spec/abi.md §2.6.
//
// Public V API:
//   cx_text_fmt(input)        -> lossless canonical text CX
//   cx_text_canonical(input)  -> strict canonical text CX
//   cx_text_hash(input)       -> SHA-256 hex of strict canonical bytes
//   cx_text_eq(a, b)          -> true iff strict canonical(a) == strict canonical(b)
//
// Names are prefixed `cx_text_` (rather than just `fmt`/`canonical`/etc.)
// because the V module is `cx`, and the C ABI exports — which use the
// short names — live in cabi.v as `cx_fmt`, `cx_canonical`, `cx_hash`,
// `cx_eq`. The prefix here avoids clashing with V keywords/builtins.
//
// v0 limitations (documented; future enhancement):
//   - Strict canonical strips Comment, RawText, BlockContent, CXDirective,
//     and XMLDecl from prolog/items, and drops Element.anchor /
//     Element.merge metadata. It does NOT resolve anchor/alias references
//     or expand merges to their referent's content. For the vast majority
//     of CX documents (which use neither anchors nor merges) this is a
//     correct strict canonical. Documents that rely on anchor/merge for
//     semantic content will produce incorrect strict canonical bytes;
//     when the merge-resolver lands those will become correct.

// cx_text_fmt parses the input and re-emits it through the lossless
// CX emitter. Property: cx_text_fmt(cx_text_fmt(x)) == cx_text_fmt(x)
// for any valid input.
//
// A document valid under the DATA reading is re-emitted canonically. Input that
// is not valid data but IS a valid PROGRAM (operator heads like `[* a b]`,
// directives, `[$call]`s) is returned UNCHANGED — `cx fmt` no longer rejects
// valid programs (#42), and thus also serves as a structure/bracket check.
// A lossless canonical *program* formatter is follow-on work; until then
// programs pass through. Input invalid under BOTH readings surfaces whichever
// parser's diagnostic sits FURTHEST into the source (#391): the two readers
// fail at unrelated places (the program tokenizer chokes on data-only markers
// like `&anchor` long before the data parser's real offender), and the
// further error is the one nearest the byte a human must actually fix.
pub fn cx_text_fmt(input string) !string {
	mut data_err_msg := ''
	if doc := parse(input) {
		return emit_cx(doc)
	} else {
		data_err_msg = err.msg()
	}
	parse_program(input) or {
		// Program intent wins outright: a token-level `[?directive` scan is
		// string-aware (a directive mentioned inside a quoted string is one
		// string token) and stays available when the DATA reading failed —
		// the case the eval boundary's node-level scan (#11) cannot cover.
		// `cx run` reports the program diagnostic for such files; `cx fmt`
		// must agree (#391).
		if program_tokens_carry_directive(input) {
			return err
		}
		if data_error_is_further(data_err_msg, err) {
			return error(data_err_msg)
		}
		return err
	}
	return input
}

// program_tokens_carry_directive reports whether the tokenized program
// reading of `src` contains a REGISTERED `[?directive` opener — unambiguous
// program intent. The lexer folds `[?name` into one directive_name token for
// ANY identifier (membership is a parse-level concern), so the registered-
// names check happens here: an unregistered `[?custom]` stays data-shaped
// (prolog PIs, `[?cx …]` decls), exactly like the eval boundary's node-level
// scan (#11). Lexes only; returns false when the source does not even
// tokenize (nothing to claim intent from).
fn program_tokens_carry_directive(src string) bool {
	tokens := tokenize(src) or { return false }
	for t in tokens {
		if t.kind == .directive_name && t.text in directive_names {
			return true
		}
	}
	return false
}

// data_error_is_further reports whether the DATA parser's diagnostic (a
// `line:col: message` string, parser.v make_error) points further into the
// source than the PROGRAM parser's structured ParseError. Ties go to the
// program error (the historical default). Unparseable positions → false.
fn data_error_is_further(data_err_msg string, prog_err IError) bool {
	head := data_err_msg.all_before(': ')
	parts := head.split(':')
	if parts.len != 2 {
		return false
	}
	dl := parts[0].int()
	dc := parts[1].int()
	if dl <= 0 || dc <= 0 {
		return false
	}
	if prog_err is ParseError {
		return dl > prog_err.pos.line || (dl == prog_err.pos.line && dc > prog_err.pos.col)
	}
	if prog_err is LexError {
		return dl > prog_err.pos.line || (dl == prog_err.pos.line && dc > prog_err.pos.col)
	}
	return false
}

// cx_text_canonical parses the input, strips presentation nodes,
// canonicalizes namespace prefix usage and xmlns-declaration order
// sorts MapNode entries into lexicographic Unicode
// order / spec/canonical.md §2.11.1, and re-emits
// it. The output is the strict canonical text per spec/canonical.md
// §1.2.
pub fn cx_text_canonical(input string) !string {
	doc := parse(input)!
	resolved := resolve_anchors_doc(doc)!
	mut stripped := canonicalize_doc(resolved)
	canonicalize_namespaces(mut stripped)
	canonicalize_ids(mut stripped)
	canonicalize_collection_literals(mut stripped)
	return emit_cx(stripped)
}

// resolve_anchors_doc performs the strict-canonical anchor resolution pass
// (spec/core/canonical.md §2.8, the Resolved-AST step of ast.md): each
// `[*name]` AliasNode is replaced by a deep copy of the anchored element's
// resolved content; each `*name` MergeRef inlines the anchored element's
// attributes and items into the host (host values override merged values by
// attribute name); every `&name` AnchorDef is dropped. The result has no
// anchor/merge/alias structure, so two documents that differ only in how they
// share data (inline vs anchored/merged) have identical strict-canonical bytes
// — i.e. the same Tier-1 identity (§1.4).
//
// Ordering (made explicit here; proposed for §2.8 in spec/02-working): merged
// attributes form the base in anchor order, a colliding host attribute replaces
// in place, host-only attributes append after; items are the anchor's resolved
// items followed by the host's. A dangling MergeRef is a no-op strip (lint L003
// is warn-level, abi.md), while a dangling Alias or any cyclic reference is a
// hard error (no resolved form exists → no canonical form, §1.3).
fn resolve_anchors_doc(doc Document) !Document {
	mut table := map[string]Element{}
	// One scan populates the anchor table AND reports whether any anchor / alias /
	// merge structure exists at all. Both halves must run (|| would short-circuit
	// the second and under-populate the table).
	saw_prolog := collect_anchors(doc.prolog, mut table)
	saw_elements := collect_anchors(doc.elements, mut table)
	if !saw_prolog && !saw_elements {
		return doc // no anchor/alias/merge anywhere → nothing to resolve (common case)
	}
	mut stack := []string{}
	new_prolog := resolve_anchor_nodes(doc.prolog, table, mut stack)!
	new_elements := resolve_anchor_nodes(doc.elements, table, mut stack)!
	return Document{
		prolog:   new_prolog
		doctype:  doc.doctype
		elements: new_elements
	}
}

// collect_anchors walks the full tree (element bodies + collection values),
// records every `&name` → its defining element (first definition wins, so a
// duplicate anchor name is deterministic), and returns whether ANY anchor /
// alias / merge structure was seen — so a doc with a stray alias-but-no-anchor
// is still routed through resolution (where it errors as dangling) rather than
// silently skipped.
fn collect_anchors(nodes []Node, mut table map[string]Element) bool {
	mut saw := false
	for n in nodes {
		match n {
			Element {
				if a := n.anchor() {
					saw = true
					if a !in table {
						table[a] = n
					}
				}
				if _ := n.merge() {
					saw = true
				}
				if collect_anchors(n.items, mut table) {
					saw = true
				}
			}
			AliasNode {
				saw = true
			}
			SequenceNode {
				if collect_anchors(n.items, mut table) {
					saw = true
				}
			}
			ArrayNode {
				if collect_anchors(n.items, mut table) {
					saw = true
				}
			}
			MapNode {
				for e in n.entries {
					if collect_anchors([e.value], mut table) {
						saw = true
					}
				}
			}
			else {}
		}
	}
	return saw
}

fn resolve_anchor_nodes(nodes []Node, table map[string]Element, mut stack []string) ![]Node {
	mut out := []Node{cap: nodes.len}
	for n in nodes {
		out << resolve_anchor_node(n, table, mut stack)!
	}
	return out
}

fn resolve_anchor_node(n Node, table map[string]Element, mut stack []string) !Node {
	match n {
		AliasNode {
			target := table[n.name] or {
				return error('strict canonical: alias [*${n.name}] references no anchor &${n.name} (spec/core/canonical.md §2.8)')
			}
			if n.name in stack {
				return error('strict canonical: cyclic anchor reference via [*${n.name}]')
			}
			stack << n.name
			resolved := resolve_anchor_element(target, table, mut stack)!
			stack.delete_last()
			return Node(resolved)
		}
		Element {
			return Node(resolve_anchor_element(n, table, mut stack)!)
		}
		SequenceNode {
			mut c := n
			c.items = resolve_anchor_nodes(n.items, table, mut stack)!
			return Node(c)
		}
		ArrayNode {
			mut c := n
			c.items = resolve_anchor_nodes(n.items, table, mut stack)!
			return Node(c)
		}
		MapNode {
			mut entries := n.entries.clone()
			for i := 0; i < entries.len; i++ {
				entries[i].value = resolve_anchor_node(entries[i].value, table, mut stack)!
			}
			return Node(MapNode{
				entries: entries
			})
		}
		else {
			return n
		}
	}
}

fn resolve_anchor_element(e Element, table map[string]Element, mut stack []string) !Element {
	// Merge base: the resolved anchored element's attrs + items (if `*name` set and
	// the anchor exists). A dangling merge inlines nothing (L003 warn-level).
	mut base_attrs := []Attribute{}
	mut base_items := []Node{}
	if mname := e.merge() {
		if target := table[mname] {
			if mname in stack {
				return error('strict canonical: cyclic merge reference via *${mname}')
			}
			stack << mname
			rt := resolve_anchor_element(target, table, mut stack)!
			stack.delete_last()
			base_attrs = rt.attrs.clone()
			base_items = rt.items.clone()
		}
	}
	// Attributes: merged base, host overrides in place by name, host-only append.
	mut out_attrs := base_attrs.clone()
	for ha in e.attrs {
		mut replaced := false
		for i := 0; i < out_attrs.len; i++ {
			if out_attrs[i].name == ha.name {
				out_attrs[i] = ha
				replaced = true
				break
			}
		}
		if !replaced {
			out_attrs << ha
		}
	}
	// Items: merged base (already resolved) then the host's own resolved items.
	mut out_items := base_items.clone()
	for it in e.items {
		out_items << resolve_anchor_node(it, table, mut stack)!
	}
	// Rebuild without anchor/merge meta (§2.8 drops both); id / data_type /
	// body_ref are preserved exactly as canonicalize_node does, namespace meta is
	// recomputed by canonicalize_namespaces downstream.
	mut canon := new_element(e.name, ElementMeta{
		data_type: e.data_type()
		id:        e.id()
		body_ref:  e.body_ref()
	}, out_attrs, out_items)
	if td := e.table_opt() {
		canon = canon.with_table(td)
	}
	return canon
}

// cx_text_hash returns the lowercase hex SHA-256 of the strict
// canonical text bytes.
pub fn cx_text_hash(input string) !string {
	canonical := cx_text_canonical(input)!
	digest := sha256.sum256(canonical.bytes())
	return digest.hex()
}

// cx_text_hash_algo returns the lowercase hex digest of the strict
// canonical text bytes under the named algorithm — one of `sha256`,
// `sha384`, `sha512`, `blake3`. Unlike a single fixed digest, callers
// that advertise a configurable hash algorithm (e.g. the journal chain,
// std-lib/journal §4.2) MUST produce a genuinely DIFFERENT digest per
// algo, or the algorithm choice is a lie and tamper-evidence is hollow
// (sha256 and sha512 of the same bytes must not collide in length or
// value). An unknown algo is an error (the caller maps it to its domain
// code, e.g. CXER4607). sha256 is byte-identical to `cx_text_hash`.
pub fn cx_text_hash_algo(input string, algo string) !string {
	canonical := cx_text_canonical(input)!
	b := canonical.bytes()
	return match algo {
		'sha256' { sha256.sum256(b).hex() }
		'sha384' { sha512.sum384(b).hex() }
		'sha512' { sha512.sum512(b).hex() }
		'blake3' { blake3.sum256(b).hex() }
		else { error('unsupported hash algorithm `${algo}`') }
	}
}

// cx_text_eq returns true iff the strict canonical of `a` equals the
// strict canonical of `b` (byte-identical, not just data-equivalent —
// per the canonical-form spec, byte-identity *is* data equivalence).
pub fn cx_text_eq(a string, b string) !bool {
	ca := cx_text_canonical(a)!
	cb := cx_text_canonical(b)!
	return ca == cb
}

// cx_data_bin_hash returns the lowercase hex SHA-256 of the strict
// canonical text bytes of a CXCol binary input. Compression-invariant
// per spec/core/data-bin.md §3.12.2: row groups wrapped in body-tag 0x90
// are decompressed by parse_data_bin, the resulting Document is run
// through the same canonical pipeline as cx_text_hash, and the
// canonical text bytes are hashed. zstd-1 / zstd-19 / plain
// encodings of the same logical table produce identical hashes
// because parse_data_bin yields the same Document for each, and
// canonical text is a function of Document content only.
//
// HH1 — closes the §3.12.2 promise that was documented but unwired.
// The pipeline composes the chunked decoder (which
// already decompresses 0x90 wrappers internally) with the existing
// canonical pipeline, so no new decompression code path lands; the
// surface is purely an entry-point composition.
pub fn cx_data_bin_hash(input []u8) !string {
	doc := parse_data_bin(input)!
	mut stripped := canonicalize_doc(doc)
	canonicalize_namespaces(mut stripped)
	canonicalize_ids(mut stripped)
	canonicalize_collection_literals(mut stripped)
	canonical_text := emit_cx(stripped)
	digest := sha256.sum256(canonical_text.bytes())
	return digest.hex()
}

// canonicalize_doc returns a new Document with presentation-only
// nodes stripped: Comment, RawText, CXDirective, XMLDecl, BlockContent.
// Anchor/merge metadata on Elements is also dropped (v0 — see note at
// top of file).
fn canonicalize_doc(d Document) Document {
	mut new_prolog := []Node{cap: d.prolog.len}
	for n in d.prolog {
		if keep := canonicalize_node(n) {
			new_prolog << keep
		}
	}
	mut new_elements := []Node{cap: d.elements.len}
	for n in d.elements {
		if keep := canonicalize_node(n) {
			new_elements << keep
		}
	}
	return Document{
		prolog:   new_prolog
		doctype:  d.doctype
		elements: new_elements
	}
}

// canonicalize_node returns Some(stripped node) if it should be kept,
// None if it should be dropped from the parent's items list.
fn canonicalize_node(n Node) ?Node {
	match n {
		CommentNode, RawTextNode, CXDirectiveNode, XMLDeclNode {
			return none
		}
		BlockContentNode {
			// BlockContent is presentation; expand its items in place
			// so callers see a flattened list. Since we can't return
			// multiple nodes from one call, drop the wrapper here and
			// let the caller's list-build flatten via canonicalize_items.
			return none
		}
		Element {
			mut new_items := []Node{cap: n.items.len}
			for item in n.items {
				if item is BlockContentNode {
					// Inline BlockContent's items into the parent.
					for inner in item.items {
						if keep := canonicalize_node(inner) {
							new_items << keep
						}
					}
				} else if keep := canonicalize_node(item) {
					new_items << keep
				}
			}
			mut canon := new_element(n.name, ElementMeta{
				// anchor/merge stripped per strict-canonical
				data_type: n.data_type()
				id:        n.id() // preserved; canonicalize_ids renames in document order
				body_ref:  n.body_ref() // preserved; canonicalize_ids rewrites
			}, n.attrs, new_items)
			// Preserve the `:table` block payload — it lives in the
			// pointer-ized `table` field, NOT in `items`, so rebuilding the
			// element without it silently dropped every row (the surviving
			// `::table` data_type then rendered as a bare `[name::table]`).
			if td := n.table_opt() {
				canon = canon.with_table(td)
			}
			return Node(canon)
		}
		else {
			// TextNode, ScalarNode, EntityRefNode, AliasNode, PINode,
			// DoctypeDecl, SequenceNode, ArrayNode, MapNode: keep as-is.
			// Collection-literal canonicalization (lex key sort for maps,
			// recursive descent) runs in a dedicated pass —
			// canonicalize_collection_literals below.
			return n
		}
	}
}

// canonicalize_collection_literals rewrites every MapNode in the
// document so its entries appear in lexicographic Unicode order of
// the canonical key serialization + spec/canonical.md
// §2.11.1. SequenceNode and ArrayNode items keep their source order
// (sequences are flat at parse time per CXDM §1, arrays are nested-
// preserving per §D3). Recurses into element bodies, sequence /
// array / map values, and map values. Idempotent: a map already in
// canonical order produces the same output.
pub fn canonicalize_collection_literals(mut doc Document) {
	canonicalize_collection_nodes(mut doc.prolog)
	canonicalize_collection_nodes(mut doc.elements)
}

fn canonicalize_collection_nodes(mut nodes []Node) {
	for i := 0; i < nodes.len; i++ {
		mut n := nodes[i]
		if mut n is Element {
			canonicalize_collection_nodes(mut n.items)
			nodes[i] = n
		} else if mut n is SequenceNode {
			canonicalize_collection_nodes(mut n.items)
			nodes[i] = n
		} else if mut n is ArrayNode {
			canonicalize_collection_nodes(mut n.items)
			nodes[i] = n
		} else if mut n is MapNode {
			for j := 0; j < n.entries.len; j++ {
				mut value_nodes := [n.entries[j].value]
				canonicalize_collection_nodes(mut value_nodes)
				n.entries[j].value = value_nodes[0]
			}
			n.entries.sort_with_compare(map_entry_cmp)
			nodes[i] = n
		}
	}
}

// map_entry_cmp implements the canonical-form key ordering rules
// from spec/canonical.md §2.11.1. The primary sort is by type-tag
// name (bool < bytes < date < datetime < float < int < string); ties
// break by lexicographic Unicode order of the canonical-string
// serialization of the key value. Map keys are restricted to
// strings — the type-tag tie-break is in place for the
// CX code 3.1 widening but exercises rarely today.
fn map_entry_cmp(a &MapEntry, b &MapEntry) int {
	a_tag := map_key_type_tag_name(a.key_type)
	b_tag := map_key_type_tag_name(b.key_type)
	if a_tag != b_tag {
		return if a_tag < b_tag { -1 } else { 1 }
	}
	a_key := scalar_value_str(a.key_value)
	b_key := scalar_value_str(b.key_value)
	if a_key < b_key { return -1 }
	if a_key > b_key { return 1 }
	return 0
}

fn map_key_type_tag_name(t ScalarType) string {
	return match t {
		.bool_type     { 'bool' }
		.bytes_type    { 'bytes' }
		.date_type     { 'date' }
		.datetime_type { 'datetime' }
		.float_type    { 'float' }
		.int_type      { 'int' }
		.string_type   { 'string' }
		.null_type     { 'null' }
		.decimal_type  { 'decimal' }
		.bigint_type   { 'bigint' }
		.duration_type { 'duration' }
		.period_type   { 'period' }
		// Atoms are not valid map keys per
		// spec/cxdm.md §2.5 closing note. This branch
		// is unreachable for well-formed inputs; we still spell it so
		// the V exhaustive-match rule passes. Reachable only via a
		// programming bug — surface as 'atom' so the diagnostic
		// matches the underlying type tag.
		.atom_type     { 'atom' }
	}
}
