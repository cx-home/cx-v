module cx

import crypto.sha256

// lib_node.v — LibNode AST.
//
// LibNode is the spec-canonical first-class AST node for the
// `[?lib RESOLVER (:as ALIAS)? (:only (NAMES...))?]` module-import
// directive — — collapsing grammar productions
// [149]–[151] onto a single value kind with a resolver-kind
// discriminator + verbatim resolver source slot plus optional
// `:as` alias and `:only` selective-import slots.
//
// This file is the Phase 2.12 Part 3 (Z3) foundational AST layer:
//   - structs (LibNode, LibLoc, ResolverKind) + helpers
// structural equality (source + loc excluded per the 
// pattern adopted into by symmetry with DefNode
//     ConstNode)
//   - canonical hashing (disjoint-domain hash via `LibNode\x00`-prefixed
//     canonical-string form passed through SHA-256, mirroring the
//     PathNode / MatchNode / ModifyNode / PredicateExpr / DefNode /
//     ConstNode convention — nine-way disjoint)
//   - JSON projection (`{"type":"ProgramLibExpr", …}`)
//
// Out of scope at Phase 2.12 Part 3 (deferred):
//   - Evaluator (module load, resolver dispatch, alias binding,
//     selective-import enforcement, lockfile cross-check) — Phase
//     2.13 + 2.14.
//   - Binary (ast_bin) codec — wire-format slot allocation pending,
//     analogous to the PathNode follow-up tracked at Phase 1.7+ and
//     the DefNode / ConstNode codec deferral at Phase 2.12 Parts
//     1+2.
//   - Node sum-type integration — adding LibNode to `cx.Node`
//     cascades exhaustive match arms across every emitter / decoder,
//     so it lives in a later Phase 2.x slice. The Phase 2.12 Part 3
//     contract is "datum + projection are available as standalone
//     helpers".
//   - SRI verification + HTTPS fetch — Phase 2.14.
//   - `:in-memory` / `:version` / Bearer / Basic-auth modifier slots
// reserved at the grammar level but not
//     parsed by this layer; surfaced via CXLIB_UNKNOWN_MODIFIER.
//   - `cx-err:CXER0208` (insecure transport) raise — Phase 2.14
//     (loader). Parser currently reports CXLIB_INSECURE_TRANSPORT at
// parse time normative wording.
//
// Cross-references:
//   - spec/grammar.ebnf productions [149]–[151]
//   - spec/code.md §12.1 (normative semantics)
//   - spec/lockfile.md (cx.lock companion)
//   - vcx/cx/def_node.v + vcx/cx/const_node.v (Z1/Z2 siblings — same shape conventions)

// ── Structs ───────────────────────────────────────────────────────────────────

// ResolverKind discriminates the resolver shapes admitted by
// `[?lib]` / grammar [150]:
//   - file_path        : resolver string begins with `./`, `../`, or `/`
//   - registered_name  : everything else (looked up in cx.lock)
//   - https_url        : resolver string begins with `https://`
//   - pkg_url          : resolver string begins with `pkg:` — a package
//                        reference resolved through the bound registry with
//                        the full distribution-spec §3 verify chain
//                        (feature-distribution spec §6.2)
//
// `http://` is NOT a kind — it is rejected at parse time per
// (insecure transport — `CXER0208`).
pub enum ResolverKind {
	file_path
	registered_name
	https_url
	pkg_url
}

// resolver_kind_str returns the lowercase canonical string spelling
// of a ResolverKind — used in the JSON projection and canonical-
// bytes encoding so the wire shape is stable across V enum-tag
// re-ordering.
pub fn resolver_kind_str(k ResolverKind) string {
	match k {
		.file_path { return 'file' }
		.registered_name { return 'registered' }
		.https_url { return 'https' }
		.pkg_url { return 'pkg' }
	}
}

// LibLoc carries an optional source-position record. Advisory; not
// part of equality or hashing (symmetric
// with DefLoc / ConstLoc). `start` / `end` are byte offsets into the
// original source string; populated by the parser when source-
// location tracking is enabled, left as 0/0 otherwise.
pub struct LibLoc {
pub mut:
	start int
	end   int
}

// LibNode is the spec-canonical first-class AST node for the
// `[?lib RESOLVER (:as ALIAS)? (:only (NAMES...))?]` module-import
// directive. See file-level comment for the full
// contract.
//
// `resolver_kind` carries the three-way resolver discriminator per
// grammar [150].
//
// `resolver_source` carries the verbatim contents of the quoted
// resolver string — the bytes INSIDE the quotes (e.g.
// `./local-helpers.cx`, `cx-stdlib/json`,
// `https://cdn.example.com/regex-1.2.3.zip`). The lookup-key
// equality rule of spec/lockfile.md §4.1 applies to this string.
//
// `alias` carries the `:as ALIAS` rebind name.
// None when no `:as` modifier was present — the loader derives a
// default name from the last segment of `resolver_source` at module-
// load time (Phase 2.13).
//
// `only_imports` carries the optional `:only (a b c)` selective-
// import list. None when no `:only` modifier
// was present (whole-module import). An empty list is NOT permitted
// by the parser — `:only` with no names raises CXLIB_PARSE.
pub struct LibNode {
pub mut:
	resolver_kind   ResolverKind
	resolver_source string
	alias           ?string
	only_imports    ?[]string
	source          ?string // verbatim source-text snippet of the full [?lib …] form (advisory)
	loc             ?LibLoc // source position (advisory)
}

// ── Constructors ──────────────────────────────────────────────────────────────

// new_lib_node constructs a minimal LibNode with the given resolver
// kind + verbatim resolver source. `alias` / `only_imports` /
// `source` / `loc` are left none.
pub fn new_lib_node(kind ResolverKind, resolver_source string) LibNode {
	return LibNode{
		resolver_kind:   kind
		resolver_source: resolver_source
	}
}

// ── Equality ──────────────────────────────────────────────────────────────────

// eq returns true iff two LibNode values are structurally equal
// under the identity rule (adopted by by
// symmetry). The `source` and `loc` fields are advisory and do NOT
// participate in equality. Two LibNodes parsed from differently-
// formatted source compare equal as long as resolver_kind +
// resolver_source + alias + only_imports match.
//
// V auto-generates `==` for the underlying struct shape which would
// include `source` + `loc`; callers MUST use this method (or the
// canonical-bytes hash) for identity.
pub fn (n LibNode) eq(other LibNode) bool {
	if n.resolver_kind != other.resolver_kind {
		return false
	}
	if n.resolver_source != other.resolver_source {
		return false
	}
	if !lib_opt_string_eq(n.alias, other.alias) {
		return false
	}
	if !lib_opt_string_list_eq(n.only_imports, other.only_imports) {
		return false
	}
	return true
}

fn lib_opt_string_eq(a ?string, b ?string) bool {
	if (a == none) != (b == none) {
		return false
	}
	if av := a {
		bv := b or { '' }
		if av != bv {
			return false
		}
	}
	return true
}

fn lib_opt_string_list_eq(a ?[]string, b ?[]string) bool {
	if (a == none) != (b == none) {
		return false
	}
	if av := a {
		bv := b or { []string{} }
		if av.len != bv.len {
			return false
		}
		for i, x in av {
			if x != bv[i] {
				return false
			}
		}
	}
	return true
}

// ── Canonical bytes + hashing ─────────────────────────────────────────────────

// lib_node_canonical_bytes returns the canonical byte form of a
// LibNode used as input to the disjoint-domain hash function. The
// byte form is a deterministic textual encoding of the identity-
// participating fields (resolver_kind + resolver_source + alias +
// only_imports only) — source + loc are excluded.
//
// Disjoint-domain prefix: the bytes start with the literal ASCII
// `LibNode\x00` followed by `\x01`-delimited slots. The `\x00`
// byte after the type tag cannot occur inside a CX canonical surface
// (UTF-8 content with no in-band NUL), so LibNode hashes inhabit a
// domain disjoint from element / scalar / atom / PathNode /
// MatchNode / ModifyNode / PredicateExpr / DefNode / ConstNode
// hashes by construction.
pub fn lib_node_canonical_bytes(n LibNode) []u8 {
	mut out := []u8{}
	out << 'LibNode'.bytes()
	out << u8(0x00)
	// Resolver-kind slot.
	out << u8(0x10)
	out << resolver_kind_str(n.resolver_kind).bytes()
	out << u8(0x01)
	// Resolver-source slot.
	out << u8(0x11)
	out << n.resolver_source.bytes()
	out << u8(0x01)
	// Alias slot.
	if a := n.alias {
		out << u8(0x12) // alias-present marker
		out << a.bytes()
	} else {
		out << u8(0x13) // alias-absent marker
	}
	out << u8(0x01)
	// Only-imports slot.
	if names := n.only_imports {
		out << u8(0x14) // only-present marker
		for name in names {
			out << u8(0x02)
			out << name.bytes()
		}
		out << u8(0x03) // end-of-only
	} else {
		out << u8(0x15) // only-absent marker
	}
	return out
}

// lib_node_hash returns the lowercase hex SHA-256 of the canonical
// disjoint-domain byte form. Equal LibNodes (per `.eq()`) produce
// equal hashes. The leading `LibNode\x00` prefix guarantees the
// hash cannot collide with element / scalar / atom / PathNode /
// MatchNode / ModifyNode / PredicateExpr / DefNode / ConstNode
// hashes by construction.
pub fn lib_node_hash(n LibNode) string {
	digest := sha256.sum256(lib_node_canonical_bytes(n))
	return digest.hex()
}

// ── JSON projection ───────────────────────────────────────────────────────────

// lib_node_to_json returns the AST-JSON projection of a LibNode.
// The shape:
//
//   {
//     "type":            "ProgramLibExpr",
//     "resolver-kind":   "file" | "registered" | "https",
//     "resolver":        "<resolver_source>",
//     "alias":           "<name>",                          // omit when none
//     "only":            ["a","b","c"],                     // omit when none
//     "source":          "<src>",                           // omit when none
//     "loc":             { "start": N, "end": M }           // omit when none
//   }
//
// "ProgramLibExpr" is the parser-internal JSON `type` tag; at the
// AST-bin boundary the projection will collapse to `"LibNode"` per
// the spec when the wire slot lands.
pub fn lib_node_to_json(n LibNode) string {
	mut pairs := []string{}
	pairs << '"type":"ProgramLibExpr"'
	pairs << '"resolver-kind":${json_str(resolver_kind_str(n.resolver_kind))}'
	pairs << '"resolver":${json_str(n.resolver_source)}'
	if a := n.alias {
		pairs << '"alias":${json_str(a)}'
	}
	if names := n.only_imports {
		mut items := []string{}
		for name in names {
			items << json_str(name)
		}
		pairs << '"only":[${items.join(",")}]'
	}
	if src := n.source {
		pairs << '"source":${json_str(src)}'
	}
	if l := n.loc {
		pairs << '"loc":{"start":${l.start},"end":${l.end}}'
	}
	return '{${pairs.join(',')}}'
}

// ── Binary codec hook (DEFERRED) ──────────────────────────────────────────────

// TODO(Phase 2.12 follow-up): wire codec.
//
// LibNode wire-format slot is pending wire-slot allocation —
// analogous to the PathNode codec landed at Phase 1.7+ and the
// MatchNode / ModifyNode / DefNode / ConstNode codec deferral at
// Phases 2.4 / 2.5 / 2.12. Until the slot lands:
//   - emit_ast_bin MUST reject LibNode values with the standard
//     unknown-kind error (currently moot: LibNode is not yet a
//     Node sum-type variant).
//   - parse_ast_bin MUST surface a clear error if it encounters a
//     wire byte in LibNode's pending slot range.
//
// When the slot lands this file gains:
//   - fn lib_node_to_bin(n LibNode) []u8
//   - fn bin_to_lib_node(bytes []u8, mut pos int) !LibNode
// plus integration into binary.v's emit/parse dispatch and `Node`
// sum-type integration in the matching phase.
