module cx

import os

// lockfile_reader.v — `cx.lock` parse-only reader (Phase 2.12 Part 3).
//
// `cx.lock` is the single source of truth for module resolution per
// and spec/lockfile.md. The file is a CX-data document;
// no new lexer or parser is required — this reader leans on the
// existing `cx.parse(src)` pipeline and then walks the resulting
// Document tree to populate the strongly-typed `Lockfile` /
// `ModuleLock` structs.
//
// This Phase 2.12 Part 3 layer is **parse-only**:
//   - Reads the file bytes.
//   - Parses through the existing CX-data parser.
//   - Validates the root-element name (`cx.lock`) and `:version`
//     attribute.
//   - Walks the `[modules]` block populating one `ModuleLock` per
//     `[module]` entry — `:name`, `:resolved`, `:version`,
//     `:sri` fields.
//   - Optionally walks the `[transitive-graph]` block — captured
//     as `TransitiveEdge` pairs for downstream tooling but not
//     verified.
//
// What is explicitly DEFERRED to later phases:
//   - SRI verification of HTTPS-fetched bytes (Phase 2.14).
// HTTPS fetch + cache (Phase 2.14).
//   - `:resolved` shape validation against the file:// / https:// /
//     bundled: shapes — informational at this layer (spec/lockfile.md
//     §5 + CXER0213).
//   - Transitive-graph closure check / unpinned-dep detection
//     (Phase 2.14, CXER0211).
//   - Cycle detection across imports (Phase 2.14, CXER0210).
//
// Error codes raised:
//   - "CXLOCK_PARSE: ..."         — file-IO / data-parser / shape errors.
//   - "CXLOCK_UNSUPPORTED_VERSION: schema version N not recognised"
//     (per spec/lockfile.md §3.1, surfaces as CXER0212 at the
//     loader boundary in Phase 2.14).
//
// Note on attribute syntax (spec/lockfile.md §3 editorial vs. wire form):
//
//   The lockfile-spec worked examples render lockfile attributes in
//   a `:name VALUE` editorial notation:
//
//     [cx.lock :version 1
//       [modules
//         [module
//           :name "cx-stdlib"
//           :resolved "bundled:0.8.0"]]]
//
//   The lockfile spec asserts this is "a CX-data document parsed via the
//   existing data grammar — no new lexer or parser support is required."
//   The existing CX-data grammar expresses attributes as `name="value"`
//   (grammar [55]); the `:name VALUE` rendering is editorial shorthand.
//   The wire form the reader actually consumes is therefore:
//
//     [cx.lock version="1"
//       [modules
//         [module
//           name="cx-stdlib"
//           resolved="bundled:0.8.0"]]]
//
//   A future syntax-sugar pass MAY teach the data grammar to recognise
//   the `:name VALUE` form on directive-shaped elements (mirroring the
//   `[?def :scope public]` modifier convention); this reader will accept
//   that form transparently because it walks attrs by name regardless of
//   surface syntax.
//
// Cross-references:
//   - spec/lockfile.md (companion normative spec)
//   - vcx/cx/lib_node.v + vcx/cx/lib_parser.v (sibling Z3 work)

// ── Structs ───────────────────────────────────────────────────────────────────

// Lockfile carries the parsed shape of a `cx.lock` file.
//
// `schema_version` carries the value of the root `:version` attribute
// per spec/lockfile.md §3.1. v0.8.0 ships schema version `1`; the
// reader returns CXLOCK_UNSUPPORTED_VERSION for any other value.
//
// `modules` carries one `ModuleLock` per `[module]` entry in source
// order. The lookup discipline of spec/lockfile.md §4.1 (literal-
// string equality on `:name`) is left to the loader; this reader
// simply preserves source order.
//
// `transitive_graph` carries the optional `[transitive-graph]`
// edges. The graph is informational at this layer per
// spec/lockfile.md §6 — captured for downstream tooling but not
// consulted by the loader at resolution time.
pub struct Lockfile {
pub mut:
	schema_version   string
	modules          []ModuleLock
	transitive_graph []TransitiveEdge
}

// ModuleLock carries one `[module]` entry per spec/lockfile.md §4.
//
// `name` is the literal-string lookup key (the `:name` field) —
// matched against `[?lib]` resolver_source bytes byte-identically
// per spec/lockfile.md §4.1.
//
// `resolved` is the fully-resolved bytes-identifier per §4.2 —
// `"file://…"` / `"./…"` for filesystem, `"https://…"` for HTTPS,
// `"bundled:<version>"` for stdlib.
//
// `version` is the optional semver-style version string. v0.8.0
// loader does NOT parse or compare versions per §4.3.
//
// `integrity` is the optional SRI hash (per §4.4); REQUIRED for
// HTTPS modules at the loader boundary (Phase 2.14) but not
// validated here.
pub struct ModuleLock {
pub mut:
	name      string
	resolved  string
	version   ?string
	integrity ?string
}

// TransitiveEdge represents one `[edge]` entry inside the optional
// `[transitive-graph]` block per spec/lockfile.md §6.
pub struct TransitiveEdge {
pub mut:
	from string
	to   string
}

// ── Public entry point ────────────────────────────────────────────────────────

// read_lockfile reads the cx.lock file at the given filesystem path
// and returns a parsed `Lockfile`. The reader is parse-only at Phase
// 2.12 Part 3 — see file-level comment for the list of deferred
// validations.
pub fn read_lockfile(path string) !Lockfile {
	if !os.exists(path) {
		return error('CXLOCK_PARSE: lockfile not found at ${path}')
	}
	src := os.read_file(path) or {
		return error('CXLOCK_PARSE: failed to read ${path}: ${err}')
	}
	return parse_lockfile_text(src)
}

// parse_lockfile_text parses a `cx.lock` document from its in-memory
// source bytes. Separated from `read_lockfile` so tests can drive
// the parser without round-tripping through the filesystem.
pub fn parse_lockfile_text(src string) !Lockfile {
	doc := parse(src) or {
		return error('CXLOCK_PARSE: failed to parse cx.lock as CX-data: ${err}')
	}
	if doc.elements.len == 0 {
		return error('CXLOCK_PARSE: cx.lock contains no root element')
	}
	root_node := doc.elements[0]
	root := match root_node {
		Element { root_node }
		else {
			return error('CXLOCK_PARSE: cx.lock root must be an element, got non-element node')
		}
	}
	if root.name != 'cx.lock' {
		return error('CXLOCK_PARSE: cx.lock root element must be named `cx.lock`, got `${root.name}`')
	}

	mut version := ''
	for attr in root.attrs {
		if attr.name == 'version' {
			version = lockfile_attr_str(attr.value)
		}
	}
	if version == '' {
		return error('CXLOCK_PARSE: cx.lock root missing :version attribute')
	}
	if version != '1' {
		return error('CXLOCK_UNSUPPORTED_VERSION: schema version ${version} not recognised (loader supports v1)')
	}

	mut lf := Lockfile{
		schema_version: version
	}

	for item in root.items {
		child := match item {
			Element { item }
			else { continue }
		}
		match child.name {
			'modules' {
				for mod_item in child.items {
					mod_el := match mod_item {
						Element { mod_item }
						else { continue }
					}
					if mod_el.name != 'module' {
						return error('CXLOCK_PARSE: unexpected child of [modules]: `${mod_el.name}` (expected `module`)')
					}
					ml := lockfile_parse_module(mod_el)!
					lf.modules << ml
				}
			}
			'transitive-graph' {
				for edge_item in child.items {
					edge_el := match edge_item {
						Element { edge_item }
						else { continue }
					}
					if edge_el.name != 'edge' {
						return error('CXLOCK_PARSE: unexpected child of [transitive-graph]: `${edge_el.name}` (expected `edge`)')
					}
					te := lockfile_parse_edge(edge_el)!
					lf.transitive_graph << te
				}
			}
			else {
				// Unknown top-level child — informational only at parse
				// time. Future schema versions may add new children;
				// this branch keeps the reader forward-tolerant within
				// a single schema version (v1 today).
			}
		}
	}

	if lf.modules.len == 0 {
		return error('CXLOCK_PARSE: cx.lock contains no [module] entries')
	}

	return lf
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn lockfile_parse_module(el Element) !ModuleLock {
	mut name := ''
	mut resolved := ''
	mut version := ?string(none)
	mut integrity := ?string(none)
	for attr in el.attrs {
		val := lockfile_attr_str(attr.value)
		match attr.name {
			'name' { name = val }
			'resolved' { resolved = val }
			'version' { version = val }
			'sri' { integrity = val }
			else {
				// Forward-tolerant: accept unknown attributes within
				// schema v1 for cooperating tooling. Loader-side
				// strictness is Phase 2.14.
			}
		}
	}
	if name == '' {
		return error('CXLOCK_PARSE: [module] entry missing :name attribute')
	}
	if resolved == '' {
		return error('CXLOCK_PARSE: [module] entry missing :resolved attribute (name=${name})')
	}
	return ModuleLock{
		name:      name
		resolved:  resolved
		version:   version
		integrity: integrity
	}
}

fn lockfile_parse_edge(el Element) !TransitiveEdge {
	mut from := ''
	mut to := ''
	for attr in el.attrs {
		val := lockfile_attr_str(attr.value)
		match attr.name {
			'from' { from = val }
			'to' { to = val }
			else {}
		}
	}
	if from == '' || to == '' {
		return error('CXLOCK_PARSE: [edge] requires both :from and :to attributes')
	}
	return TransitiveEdge{
		from: from
		to:   to
	}
}

// lockfile_attr_str coerces a ScalarValue to its canonical string
// form for the lockfile fields (all of which are stringly-typed at
// the loader boundary).
fn lockfile_attr_str(v ScalarValue) string {
	return scalar_value_str(v)
}
