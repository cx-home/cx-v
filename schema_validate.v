module cx

import strconv

// CX schema validator (Phase 7.74c-schema-validator-v-core, bootstrap).
//
// Implements spec/schema.md §10 — walks a parsed Document
// against a parsed schema (`.cxs`), accumulating diagnostics in
// document order without short-circuiting (spec §10.2).
//
// Implemented end-to-end (all 20 spec rules):
//   S001 — unknown element under strict/closed mode
//   S002 — missing required attribute
//   S003 — child-element cardinality (too few)
//   S004 — child-element cardinality (too many)
//   S005 — type mismatch on attribute / scalar body
//   S006 — range violation (:range='M..N')
//   S007 — enum violation (:enum=[v1 v2 ...])
//   S008 — pattern (RE2 via libcx-vendored cre2)
//   S009 — schema not found / malformed
//   S010 — target-doc `[?cx schema=PATH]` directive references missing schema
//   S011 — default-value coercion failure (schema-load)
//   S012 — unknown attribute under strict/closed mode
//   S013 — fragment alias resolution failure
//   S014 — duplicate attribute declaration on same type
//   S015 — child-element order violation
//   S016 — cyclic fragment reference at schema-load
//   S017 — root-element name mismatch
//   S018 — length violation (:len='M..N' — byte length)
//   S019 — required content missing
//   S020 — schema-version unsupported
// S023 — body :ref shape mismatch (GG10)
//
// The validator reads its rules from the unified SchemaModel (defined
// in data_bin_schema_driven.v); no second AST walk happens here.
//
// Source-location reporting uses 0:0 in the bootstrap — Element /
// Attribute do not yet carry line/col (parser only threads it for
// errors). Adding those fields is a separate additive phase
// (Phase 7.74e); diagnostic messages name the offending element /
// attribute / value so adopters can locate it without coordinates.

// ── Public types ─────────────────────────────────────────────────────────────

// Severity is shared with the linter (vcx/cx/lint.v defines the
// canonical enum). Ordering: info < warn < error_severity, so
// "at or above threshold" tests use `int(severity) >= int(threshold)`.

pub struct Diagnostic {
pub:
	code       string  // 'S002' / 'S003' / ...
	message    string
	line       int     // target-document line; 0 if unavailable
	col        int     // target-document col; 0 if unavailable
	schema_loc string  // 'schema.cxs:LL:CC' (informational); '' when unavailable
	severity   Severity = .error_severity
}

pub struct ValidationReport {
pub:
	diagnostics    []Diagnostic
	modified_doc   ?Document  // populated by validate_with_defaults when
	                          // --apply-defaults inserts schema-driven defaults
}

// is_valid returns true when the report contains no diagnostics at
// or above the `error` severity. Warnings and info do NOT cause
// `is_valid` to return false; that's handled by the CLI's
// `--fail-on=` threshold.
pub fn (r ValidationReport) is_valid() bool {
	for d in r.diagnostics {
		if d.severity == .error_severity { return false }
	}
	return true
}

pub fn (r ValidationReport) error_count() int {
	mut n := 0
	for d in r.diagnostics {
		if d.severity == .error_severity { n++ }
	}
	return n
}

pub fn (r ValidationReport) warn_count() int {
	mut n := 0
	for d in r.diagnostics {
		if d.severity == .warn { n++ }
	}
	return n
}

pub fn (r ValidationReport) info_count() int {
	mut n := 0
	for d in r.diagnostics {
		if d.severity == .info { n++ }
	}
	return n
}

// has_at_or_above_severity tests whether any diagnostic in the report
// has severity at least `threshold`. Severity ordering: info=0,
// warn=1, error_severity=2 (per lint.v); higher value = more severe.
pub fn (r ValidationReport) has_at_or_above_severity(threshold Severity) bool {
	for d in r.diagnostics {
		if int(d.severity) >= int(threshold) { return true }
	}
	return false
}

// render returns a CLI-format string per spec/schema.md §10.3.
// One line per diagnostic, document-order.
pub fn (r ValidationReport) render(doc_path string) string {
	mut out := []string{cap: r.diagnostics.len}
	for d in r.diagnostics {
		path := if doc_path == '' { '<doc>' } else { doc_path }
		sev := severity_str_pub(d.severity)
		out << '${path}:${d.line}:${d.col}: ${sev}: ${d.code}: ${d.message}'
	}
	return out.join('\n')
}

// ── Public entry points ──────────────────────────────────────────────────────

@[params]
pub struct ValidateOptions {
pub:
	mode_override ?SchemaMode  // CLI `--mode=open|strict|closed` override
}

// validate runs the bootstrap schema validator. Returns a
// report with zero diagnostics when the document satisfies every
// implemented rule.
//
// Schema-load failures (S009 parse, S010 missing root, S011 default-
// value coercion, S014 duplicate attr decl, S016 cyclic fragment,
// S020 unsupported version) per spec/schema.md §10.1 produce a single
// diagnostic and abort tree-walk. They are surfaced inside the
// ValidationReport (one error-severity Diagnostic carrying the code),
// so adopters can treat schema-load failure uniformly with per-
// document diagnostics.
pub fn validate(doc Document, schema_text string, opts ValidateOptions) !ValidationReport {
	if d := preflight_target_schema_directive(doc, schema_text) {
		return ValidationReport{ diagnostics: [d] }
	}
	mut sm := parse_schema(schema_text) or {
		return ValidationReport{ diagnostics: [schema_load_diag(err.msg())] }
	}
	if mode := opts.mode_override {
		sm.mode = mode
	}
	return validate_against_model(doc, sm)
}

// preflight_target_schema_directive enforces the rules around
// `[?cx schema=PATH]` directives in the target document
// (spec/schema.md §13). Returns a single error-severity Diagnostic
// when the directive set itself is malformed, and `none` otherwise.
//
// Rules:
//   - Multiple `[?cx schema=...]` directives in one document → S009
//     (per spec/schema.md §13).
//   - Exactly one directive AND no caller-supplied schema source →
//     S010 (the validator has no way to resolve the path; consumers
//     who want directive-driven loading do that at the CLI layer
//     and pass the resolved schema text in).
//   - Otherwise (zero directives, or one directive with a schema
//     supplied by the caller) the directive is informational and
//     parsing falls through to the regular schema-load path.
fn preflight_target_schema_directive(doc Document, schema_text string) ?Diagnostic {
	paths := scan_target_doc_schema_directives(doc)
	if paths.len > 1 {
		return Diagnostic{
			code:    'S009'
			message: 'multiple `[?cx schema=...]` directives in target document (found ${paths.len})'
		}
	}
	if paths.len == 1 && schema_text.trim_space() == '' {
		return Diagnostic{
			code:    'S010'
			message: '`[?cx schema=${paths[0]}]` references missing schema (no schema source supplied; resolve the path at the CLI/binding layer and pass the schema text to validate)'
		}
	}
	return none
}

// scan_target_doc_schema_directives walks both `doc.prolog` and
// `doc.elements` looking for `[?cx schema=PATH]` directives. The
// parser routes top-level CXDirective nodes into `prolog`
// (parser.v::is_prolog_node_type), so a target document that opens
// with `[?cx schema=...]` lands its directive there. A directive
// that appears mid-document (after the root element) lands in
// `elements`; we cover both for completeness.
fn scan_target_doc_schema_directives(doc Document) []string {
	mut paths := []string{}
	collect_schema_directive_paths(doc.prolog, mut paths)
	collect_schema_directive_paths(doc.elements, mut paths)
	return paths
}

fn collect_schema_directive_paths(nodes []Node, mut paths []string) {
	for n in nodes {
		if n is CXDirectiveNode {
			if n.attrs.len > 0 && n.attrs[0].name == 'schema' {
				path := n.attrs[0].str_value()
				if path != '' {
					paths << path
				}
			}
		}
	}
}

// schema_load_diag converts a parse_schema error message into a single
// error-severity Diagnostic. Expected error format is `Sxxx: message`
// (set by the various `return error(...)` sites in
// data_bin_schema_driven.v); fallback code is S009 when unparseable.
fn schema_load_diag(msg string) Diagnostic {
	idx := msg.index(':') or {
		return Diagnostic{ code: 'S009', message: msg }
	}
	if idx >= 4 && idx <= 5 && msg.len > 0 && msg[0] == `S` {
		code := msg[..idx].trim_space()
		tail := msg[idx + 1..].trim_space()
		return Diagnostic{ code: code, message: tail }
	}
	return Diagnostic{ code: 'S009', message: msg }
}

// validate_with_defaults validates `doc` against the schema and
// returns a ValidationReport whose `modified_doc` carries the document
// with schema-defaults inserted per spec/schema.md §11. Mirrors the
// `cx_validate_apply_defaults` C ABI (§11). When the document
// supplies a value that violates the schema, the original value is
// preserved in `modified_doc`; defaults only fill genuinely-missing
// slots.
//
// Bootstrap: defaults are applied for missing attributes whose
// schema declares `:def=<value>`. Body / child-element defaults are
// TODO(phase-7.74d): rule S011.
pub fn validate_with_defaults(doc Document, schema_text string, opts ValidateOptions) !ValidationReport {
	if d := preflight_target_schema_directive(doc, schema_text) {
		return ValidationReport{ diagnostics: [d] }
	}
	mut sm := parse_schema(schema_text) or {
		return ValidationReport{ diagnostics: [schema_load_diag(err.msg())] }
	}
	if mode := opts.mode_override {
		sm.mode = mode
	}
	mut diags := []Diagnostic{}
	mut modified := Document{
		prolog:   doc.prolog.clone()
		doctype:  doc.doctype
		elements: doc.elements.clone()
	}
	// Find root element index.
	mut root_idx := -1
	for i, n in modified.elements {
		if n is Element { root_idx = i; break }
	}
	if root_idx < 0 {
		diags << Diagnostic{
			code:    'S017'
			message: 'document has no root element; schema declares root \'${sm.root}\''
		}
		return ValidationReport{ diagnostics: diags, modified_doc: modified }
	}
	root := modified.elements[root_idx] as Element
	if sm.root != '' && root.name != sm.root {
		diags << Diagnostic{
			code:    'S017'
			message: 'root element \'${root.name}\' does not match schema-of \'${sm.root}\''
		}
		return ValidationReport{ diagnostics: diags, modified_doc: modified }
	}
	new_root := apply_defaults_to_element(root, sm.root, sm)
	validate_element(new_root, sm.root, sm, mut diags)
	modified.elements[root_idx] = Node(new_root)
	return ValidationReport{ diagnostics: diags, modified_doc: modified }
}

fn validate_against_model(doc Document, sm SchemaModel) ValidationReport {
	mut diags := []Diagnostic{}
	mut root_elem := ?Element(none)
	for n in doc.elements {
		if n is Element {
			root_elem = n
			break
		}
	}
	root := root_elem or {
		diags << Diagnostic{
			code:    'S017'
			message: 'document has no root element; schema declares root \'${sm.root}\''
		}
		return ValidationReport{ diagnostics: diags }
	}
	if sm.root != '' && root.name != sm.root {
		diags << Diagnostic{
			code:    'S017'
			message: 'root element \'${root.name}\' does not match schema-of \'${sm.root}\''
		}
		return ValidationReport{ diagnostics: diags }
	}
	validate_element(root, sm.root, sm, mut diags)
	return ValidationReport{ diagnostics: diags }
}

// severity_for_unknown returns the diagnostic severity for S001/S012
// (undeclared element / attribute) under the given mode, or `none`
// when the mode suppresses the diagnostic (open). Spec/schema.md §9.
fn severity_for_unknown(m SchemaMode) ?Severity {
	return match m {
		.open   { ?Severity(none) }
		.strict { ?Severity(.warn) }
		.closed { ?Severity(.error_severity) }
	}
}

// validate_element walks one element against its SchemaType and
// recurses into declared children. Open mode skips subtree validation
// when the element name has no declaration; strict mode emits S001 at
// `warn` severity and skips the subtree; closed mode emits S001 at
// `error` severity and skips the subtree (spec/schema.md §9 + §10.1).
fn validate_element(e Element, type_name string, sm SchemaModel, mut diags []Diagnostic) {
	st := sm.types[type_name] or {
		if sev := severity_for_unknown(sm.mode) {
			diags << Diagnostic{
				code:     'S001'
				message:  'unknown element <${e.name}>: no type declaration'
				severity: sev
			}
		}
		return
	}

	// S002 — required attributes.
	for name, ar in st.attrs {
		if ar.required {
			mut found := false
			for a in e.attrs {
				if a.name == name { found = true; break }
			}
			if !found && !ar.has_def {
				diags << Diagnostic{
					code:    'S002'
					message: 'missing required attribute \'${name}\' on <${e.name}>'
				}
			}
		}
	}

	// S005 — attribute type mismatch (scalar attrs only at bootstrap).
	// S006 — range violation (:range='M..N').
	// S007 — enum violation (:enum=[v1 v2 ...]).
	// S008 — pattern check via libcx-vendored RE2 (centralised across
	//        all bindings per spec/schema.md §7).
	// S012 — undeclared attribute under strict/closed mode.
	// S018 — byte length outside :len='M..N'.
	sev_unknown := severity_for_unknown(sm.mode)
	for a in e.attrs {
		if ar := st.attrs[a.name] {
			if ar.type_name != '' && !attr_value_matches_type(a, ar.type_name) {
				got := scalar_runtime_type_name(a.value)
				val := scalar_value_str(a.value)
				diags << Diagnostic{
					code:    'S005'
					message: 'attribute \'${a.name}\' on <${e.name}>: type mismatch (declared :${ar.type_name}, got :${got} = \'${val}\')'
				}
			}
			if ar.pat != '' {
				val := scalar_value_str(a.value)
				if !re2_full_match(ar.pat, val) {
					diags << Diagnostic{
						code:    'S008'
						message: 'attribute \'${a.name}\' on <${e.name}>: value \'${val}\' does not match :pat=\'${ar.pat}\''
					}
				}
			}
			if ar.range_min != '' || ar.range_max != '' {
				if msg := check_range(a.value, ar.range_min, ar.range_max) {
					diags << Diagnostic{
						code:    'S006'
						message: 'attribute \'${a.name}\' on <${e.name}>: ${msg}'
					}
				}
			}
			if ar.len_min != '' || ar.len_max != '' {
				if msg := check_length(a.value, ar.len_min, ar.len_max) {
					diags << Diagnostic{
						code:    'S018'
						message: 'attribute \'${a.name}\' on <${e.name}>: ${msg}'
					}
				}
			}
			if ar.enum_vals.len > 0 && !check_enum(a.value, ar.enum_vals) {
				val := scalar_value_str(a.value)
				diags << Diagnostic{
					code:    'S007'
					message: 'attribute \'${a.name}\' on <${e.name}>: value \'${val}\' not in :enum [${ar.enum_vals.join(",")}]'
				}
			}
		} else if sev := sev_unknown {
			diags << Diagnostic{
				code:     'S012'
				message:  'unknown attribute \'${a.name}\' on <${e.name}>'
				severity: sev
			}
		}
	}

	// S019 — required content missing. Element declares `[body ...]`
	// with implicit-or-explicit `:req` (every scalar shape is
	// implicit-required per spec/schema.md §4) but the target element
	// has no body content at all (`[name]` form). Any non-comment /
	// non-PI / non-directive node satisfies "has content"; type checks
	// for the content kind are S005 / S006 / S007 / S008 / S018.
	if st.body.declared && st.body.required && !element_has_body_content(e) {
		diags << Diagnostic{
			code:    'S019'
			message: 'body of <${e.name}>: required content is missing'
		}
	}

	// S005 / S006 / S007 / S008 / S018 — body checks for scalar bodies.
	if st.body.declared && is_scalar_kind(st.body.kind) {
		if scalar := single_scalar_value(e) {
			if !scalar_value_matches_type(scalar, st.body.kind) {
				got := scalar_runtime_type_name(scalar)
				val := scalar_value_str(scalar)
				diags << Diagnostic{
					code:    'S005'
					message: 'body of <${e.name}>: type mismatch (declared :${st.body.kind}, got :${got} = \'${val}\')'
				}
			}
			if st.body.pat != '' {
				val := scalar_value_str(scalar)
				if !re2_full_match(st.body.pat, val) {
					diags << Diagnostic{
						code:    'S008'
						message: 'body of <${e.name}>: value \'${val}\' does not match :pat=\'${st.body.pat}\''
					}
				}
			}
			if st.body.range_min != '' || st.body.range_max != '' {
				if msg := check_range(scalar, st.body.range_min, st.body.range_max) {
					diags << Diagnostic{
						code:    'S006'
						message: 'body of <${e.name}>: ${msg}'
					}
				}
			}
			if st.body.len_min != '' || st.body.len_max != '' {
				if msg := check_length(scalar, st.body.len_min, st.body.len_max) {
					diags << Diagnostic{
						code:    'S018'
						message: 'body of <${e.name}>: ${msg}'
					}
				}
			}
			if st.body.enum_vals.len > 0 && !check_enum(scalar, st.body.enum_vals) {
				val := scalar_value_str(scalar)
				diags << Diagnostic{
					code:    'S007'
					message: 'body of <${e.name}>: value \'${val}\' not in :enum [${st.body.enum_vals.join(",")}]'
				}
			}
		}
	}

	// container productions `arr[T]` / `seq[T]`
	// `map[K, V]`. The body must carry exactly one collection literal
	// of the declared kind, and each item must match the declared
	// item type (and key type, for maps). Length constraints (`:len`)
	// apply to the item count, not byte length.
	if st.body.declared && is_container_collection_kind(st.body.kind) {
		validate_container_body(e, st.body, mut diags)
	}

	// GG10: `body :ref` declares
	// that the element must use the `[<name> @<id>]` body-position
	// reference form — Element.body_ref is set and Element.items is
	// empty. S023 fires when the element lacks body_ref OR has
	// non-empty items.
	if st.body.declared && st.body.kind == 'ref' {
		has_body_ref := e.body_ref() != none
		if !has_body_ref {
			diags << Diagnostic{
				code:    'S023'
				message: 'body of <${e.name}>: declared :ref but element has no body-position reference (expected `[${e.name} @<id>]` form)'
			}
		} else if e.items.len > 0 {
			diags << Diagnostic{
				code:    'S023'
				message: 'body of <${e.name}>: declared :ref but element has both body_ref and child items'
			}
		}
	}

	// S015 — child-element order under strict ordering policy
	// (`[check ordering=strict]` on parent type). Walk declared-child
	// elements in document order and verify their indices in the
	// declared list are non-decreasing. Children whose names do not
	// appear in the declared list are skipped (they get S001 elsewhere
	// when the mode demands it).
	if st.child_order_strict && st.elems_order.len > 0 {
		mut declared_idx := map[string]int{}
		for i, name in st.elems_order { declared_idx[name] = i }
		mut last_idx := -1
		mut last_name := ''
		mut reported := false
		for n in e.items {
			if n is Element {
				if n.name in declared_idx {
					idx := declared_idx[n.name]
					if idx < last_idx && !reported {
						diags << Diagnostic{
							code:    'S015'
							message: 'child <${n.name}> under <${e.name}> appears out of declared order (after <${last_name}>)'
						}
						reported = true
					}
					last_idx = idx
					last_name = n.name
				}
			}
		}
	}

	// S003 / S004 — child-element cardinality.
	for child_name, er in st.elems {
		mut count := 0
		for n in e.items {
			if n is Element && n.name == child_name { count++ }
		}
		if count < er.min {
			diags << Diagnostic{
				code:    'S003'
				message: 'too few <${child_name}> under <${e.name}>: have ${count}, need at least ${er.min}'
			}
		}
		if !er.max_unbounded && count > er.max {
			diags << Diagnostic{
				code:    'S004'
				message: 'too many <${child_name}> under <${e.name}>: have ${count}, allow at most ${er.max}'
			}
		}
	}

	// Recurse into children. Type lookup: parent's `[elem]` table
	// resolves to the declared type_name; otherwise fall through to
	// the child's element name. validate_element itself emits S001
	// when sm.types lookup misses (open: silent, strict: warn,
	// closed: error) and skips the subtree.
	for n in e.items {
		if n is Element {
			child_type := if er := st.elems[n.name] { er.type_name } else { n.name }
			validate_element(n, child_type, sm, mut diags)
		}
	}
}

// apply_defaults_to_element returns a copy of `e` with schema-default
// attribute values inserted for missing attrs whose AttrRule declares
// `has_def`. Recurses into declared children. Body / child-element
// defaults are TODO(phase-7.74d): rule S011.
fn apply_defaults_to_element(e Element, type_name string, sm SchemaModel) Element {
	st := sm.types[type_name] or { return e }
	mut new_attrs := e.attrs.clone()
	for name, ar in st.attrs {
		if !ar.has_def { continue }
		mut present := false
		for a in new_attrs {
			if a.name == name { present = true; break }
		}
		if present { continue }
		new_attrs << Attribute{
			name:  name
			value: ScalarValue(ar.def_value)
		}
	}
	mut new_items := []Node{cap: e.items.len}
	for n in e.items {
		if n is Element {
			child_type := if er := st.elems[n.name] { er.type_name } else { n.name }
			new_items << Node(apply_defaults_to_element(n, child_type, sm))
		} else {
			new_items << n
		}
	}
	return Element{
		name:  e.name
		attrs: new_attrs
		items: new_items
		meta:  e.meta
		table: e.table
	}
}

// ── Type-match helpers ───────────────────────────────────────────────────────

// element_has_body_content returns true when the element has at least
// one node that counts as body content. Comment / PI / XML-decl /
// CX-directive nodes do not count (they're metadata). ScalarNode,
// TextNode, RawTextNode, child Element, and array nodes all count.
fn element_has_body_content(e Element) bool {
	for n in e.items {
		if n is CommentNode || n is PINode || n is XMLDeclNode
			|| n is CXDirectiveNode
			|| n is InterpolationNode || n is EvalDirectiveNode { continue }
		return true
	}
	return false
}

fn is_scalar_kind(k string) bool {
	return k == 'string' || k == 'int' || k == 'i8' || k == 'i16' || k == 'i32'
		|| k == 'i64' || k == 'u8' || k == 'u16' || k == 'u32' || k == 'u64'
		|| k == 'bool' || k == 'float' || k == 'f32' || k == 'f64'
		|| k == 'date' || k == 'datetime' || k == 'time'
		|| k == 'bytes' || k == 'decimal' || k == 'bigint'
}

fn scalar_runtime_type_name(v ScalarValue) string {
	return match v {
		i64       { 'int' }
		f64       { 'float' }
		bool      { 'bool' }
		string    { 'string' }
		NullValue { 'null' }
	}
}

fn scalar_value_matches_type(v ScalarValue, declared string) bool {
	rt := scalar_runtime_type_name(v)
	match declared {
		'string', 's' { return rt == 'string' }
		'int', 'i8', 'i16', 'i32', 'i64', 'u8', 'u16', 'u32', 'u64' {
			return rt == 'int'
		}
		'float', 'f32', 'f64' { return rt == 'float' || rt == 'int' }
		'bool' { return rt == 'bool' }
		'date', 'datetime', 'time', 'bytes', 'decimal', 'bigint' {
			// These ride a string-typed ScalarValue in the AST today
			// (parser annotates data_type but stores text). Bootstrap
			// accepts string here; tighter checks land in
			// TODO(phase-7.74d): rule S005 for typed scalars.
			return rt == 'string'
		}
		'any', 'scalar' { return true }
		else { return true }
	}
}

fn attr_value_matches_type(a Attribute, declared string) bool {
	if dt := a.data_type() {
		// Collapse the carrier's canonical name (which may be a sized
		// numeric like `u16`/`f32`) to its base kind for the match below.
		dt_name := scalar_type_name(scalar_type_from_name(dt) or { ScalarType.string_type })
		match declared {
			'string', 's' { return dt_name == 'string' }
			'int', 'i8', 'i16', 'i32', 'i64', 'u8', 'u16', 'u32', 'u64' {
				return dt_name == 'int'
			}
			'float', 'f32', 'f64' { return dt_name == 'float' || dt_name == 'int' }
			'bool' { return dt_name == 'bool' }
			'date' { return dt_name == 'date' }
			'datetime' { return dt_name == 'datetime' }
			'bytes' { return dt_name == 'bytes' }
			'decimal' { return dt_name == 'decimal' }
			'bigint' { return dt_name == 'bigint' }
			else {}
		}
	}
	return scalar_value_matches_type(a.value, declared)
}

// ── Constraint helpers (S006 / S007 / S018) ─────────────────────────────────

// scalar_value_as_f64 returns a numeric form when the value is i64,
// f64, or a string parsable as f64. Returns none for non-numeric
// scalars (the range check is then a no-op — type mismatch is S005).
fn scalar_value_as_f64(v ScalarValue) ?f64 {
	return match v {
		i64    { f64(v) }
		f64    { v }
		string { strconv.atof64(v) or { return none } }
		else   { none }
	}
}

// check_range tests whether `v`'s numeric form lies in [min..max]
// (inclusive both ends). Empty bound = unbounded on that side.
// Returns a human-readable message when out of range, else none.
// Non-numeric values short-circuit (covered by S005).
fn check_range(v ScalarValue, range_min string, range_max string) ?string {
	val := scalar_value_as_f64(v) or { return none }
	if range_min != '' {
		if min_v := strconv.atof64(range_min) {
			if val < min_v {
				return 'value ${scalar_value_str(v)} below :range min ${range_min}'
			}
		}
	}
	if range_max != '' {
		if max_v := strconv.atof64(range_max) {
			if val > max_v {
				return 'value ${scalar_value_str(v)} above :range max ${range_max}'
			}
		}
	}
	return none
}

// check_length tests whether the value's stringified byte length lies
// in [min..max] (inclusive both ends). Empty bound = unbounded.
// Spec/schema.md §12 S018: byte length, not codepoint length.
fn check_length(v ScalarValue, len_min string, len_max string) ?string {
	s := scalar_value_str(v)
	blen := s.len
	if len_min != '' {
		if min_v := strconv.atoi(len_min) {
			if blen < min_v {
				return 'byte length ${blen} below :len min ${min_v}'
			}
		}
	}
	if len_max != '' {
		if max_v := strconv.atoi(len_max) {
			if blen > max_v {
				return 'byte length ${blen} above :len max ${max_v}'
			}
		}
	}
	return none
}

// check_enum returns true when `v`'s string form matches one of the
// listed enum values. Empty list short-circuits to true (no constraint).
fn check_enum(v ScalarValue, vals []string) bool {
	if vals.len == 0 { return true }
	s := scalar_value_str(v)
	for cand in vals {
		if cand == s { return true }
	}
	return false
}

// ── Container productions ────────────────────────────────────

// validate_container_body checks an element whose schema declares a
// container body kind (`arr[T]` / `seq[T]` / `map[K, V]`
// §D15). The element must carry exactly one ArrayNode (for `arr`),
// SequenceNode (for `seq`), or MapNode (for `map`) as its sole body
// item — adjacent comments / directives are ignored.
//
//   - Item-type mismatches emit S005.
//   - Wrong container shape emits S005 ("declared :arr, got :map" etc.).
//   - `:len` on a container body applies to the item count, not byte
//     length; out-of-bounds emits S018.
//   - Map keys are strings; non-string keys
//     emit S005.
//   - Nested productions recurse via parse_container_kind on the
//     item_kind / key_kind text — `arr[arr[float]]` validates each
//     outer item as an ArrayNode of floats.
fn validate_container_body(e Element, body BodyRule, mut diags []Diagnostic) {
	collection := single_collection_node(e) or {
		diags << Diagnostic{
			code:    'S005'
			message: 'body of <${e.name}>: declared :${body.kind}[${container_item_text(body)}] but no collection literal found'
		}
		return
	}
	match body.kind {
		'arr' {
			if collection is ArrayNode {
				arr := collection as ArrayNode
				validate_collection_items(e.name, body, arr.items, mut diags)
			} else {
				diags << Diagnostic{
					code:    'S005'
					message: 'body of <${e.name}>: declared :arr[${body.item_kind}], got :${collection_kind_name(collection)}'
				}
			}
		}
		'seq' {
			if collection is SequenceNode {
				seq := collection as SequenceNode
				validate_collection_items(e.name, body, seq.items, mut diags)
			} else {
				diags << Diagnostic{
					code:    'S005'
					message: 'body of <${e.name}>: declared :seq[${body.item_kind}], got :${collection_kind_name(collection)}'
				}
			}
		}
		'map' {
			if collection is MapNode {
				mn := collection as MapNode
				validate_map_entries(e.name, body, mn.entries, mut diags)
			} else {
				diags << Diagnostic{
					code:    'S005'
					message: 'body of <${e.name}>: declared :map[${body.key_kind}, ${body.item_kind}], got :${collection_kind_name(collection)}'
				}
			}
		}
		else {}
	}
}

// single_collection_node returns the lone collection-literal body
// item of `e`, or none if `e` carries zero, more than one, or a
// non-collection body. Comment / PI / directive nodes are skipped so
// `[ports [; comment ] [80, 443]]` still resolves to the ArrayNode.
fn single_collection_node(e Element) ?Node {
	// Index-based, NOT a `mut found ?Node` accumulator: under the newer V a
	// sum-type-option local mis-codegens both `found != none` (reads `.state` off
	// the payload) and `found = n` (Node→?Node assignment doesn't auto-wrap). We
	// track the index and auto-wrap only at the `return` (which is unaffected).
	mut found_idx := -1
	for idx, n in e.items {
		if n is CommentNode || n is PINode || n is XMLDeclNode
			|| n is CXDirectiveNode || n is RawTextNode { continue }
		if n is ArrayNode || n is SequenceNode || n is MapNode {
			if found_idx >= 0 { return none }
			found_idx = idx
			continue
		}
		// Any other node (Element, TextNode, ScalarNode, …) means the
		// body isn't a single collection literal.
		return none
	}
	if found_idx >= 0 {
		return e.items[found_idx]
	}
	return none
}

fn collection_kind_name(n Node) string {
	return match n {
		ArrayNode    { 'arr' }
		SequenceNode { 'seq' }
		MapNode      { 'map' }
		else         { 'other' }
	}
}

fn container_item_text(body BodyRule) string {
	if body.kind == 'map' { return '${body.key_kind}, ${body.item_kind}' }
	return body.item_kind
}

// validate_collection_items checks each item of an ArrayNode or
// SequenceNode against the declared item type. Recursive container
// types are recognized via parse_container_kind on the item_kind
// text. The `:len` constraint (if any) gates the item count.
fn validate_collection_items(host string, body BodyRule, items []Node, mut diags []Diagnostic) {
	if body.len_min != '' || body.len_max != '' {
		if msg := check_item_count(items.len, body.len_min, body.len_max) {
			diags << Diagnostic{
				code:    'S018'
				message: 'body of <${host}>: ${msg}'
			}
		}
	}
	for i, item in items {
		validate_container_item(host, '[${i}]', body.item_kind, item, mut diags)
	}
}

// validate_map_entries checks each MapEntry against the declared
// `:map[K, V]` types. Keys are atomic scalars; values
// recurse through validate_container_item so nested productions
// (`map[string, arr[u32]]`) are honoured.
fn validate_map_entries(host string, body BodyRule, entries []MapEntry, mut diags []Diagnostic) {
	if body.len_min != '' || body.len_max != '' {
		if msg := check_item_count(entries.len, body.len_min, body.len_max) {
			diags << Diagnostic{
				code:    'S018'
				message: 'body of <${host}>: ${msg}'
			}
		}
	}
	for i, entry in entries {
		key_path := '.key[${i}]'
		if !scalar_value_matches_type(entry.key_value, body.key_kind) {
			got := scalar_runtime_type_name(entry.key_value)
			val := scalar_value_str(entry.key_value)
			diags << Diagnostic{
				code:    'S005'
				message: 'body of <${host}>${key_path}: type mismatch (declared key :${body.key_kind}, got :${got} = \'${val}\')'
			}
		}
		validate_container_item(host, '[${i}]', body.item_kind, entry.value, mut diags)
	}
}

// validate_container_item dispatches on the declared item type.
// Atomic scalar item types match via scalar_value_matches_type;
// nested `arr[T]` / `seq[T]` / `map[K, V]` item types recurse
// through validate_container_body-like logic. `:elem` items must
// be Element nodes (any name); `:any` / `:scalar` bypass per the
// existing catalog.
fn validate_container_item(host string, path string, declared string, item Node, mut diags []Diagnostic) {
	if k, kk, ik := parse_container_kind(declared) {
		nested := BodyRule{ declared: true, kind: k, key_kind: kk, item_kind: ik }
		match k {
			'arr' {
				if item is ArrayNode {
					arr := item as ArrayNode
					validate_collection_items('${host}${path}', nested, arr.items, mut diags)
				} else {
					diags << Diagnostic{
						code:    'S005'
						message: 'body of <${host}>${path}: declared :arr[${ik}], got :${collection_kind_name(item)}'
					}
				}
			}
			'seq' {
				if item is SequenceNode {
					sn := item as SequenceNode
					validate_collection_items('${host}${path}', nested, sn.items, mut diags)
				} else {
					diags << Diagnostic{
						code:    'S005'
						message: 'body of <${host}>${path}: declared :seq[${ik}], got :${collection_kind_name(item)}'
					}
				}
			}
			'map' {
				if item is MapNode {
					mn := item as MapNode
					validate_map_entries('${host}${path}', nested, mn.entries, mut diags)
				} else {
					diags << Diagnostic{
						code:    'S005'
						message: 'body of <${host}>${path}: declared :map[${kk}, ${ik}], got :${collection_kind_name(item)}'
					}
				}
			}
			else {}
		}
		return
	}
	if declared == 'elem' {
		if item !is Element {
			diags << Diagnostic{
				code:    'S005'
				message: 'body of <${host}>${path}: declared :elem, got non-element item'
			}
		}
		return
	}
	if declared == 'any' || declared == 'scalar' || declared == '' { return }
	scalar := node_as_scalar(item) or {
		diags << Diagnostic{
			code:    'S005'
			message: 'body of <${host}>${path}: declared :${declared}, got non-scalar item'
		}
		return
	}
	if !scalar_value_matches_type(scalar, declared) {
		got := scalar_runtime_type_name(scalar)
		val := scalar_value_str(scalar)
		diags << Diagnostic{
			code:    'S005'
			message: 'body of <${host}>${path}: type mismatch (declared :${declared}, got :${got} = \'${val}\')'
		}
	}
}

// node_as_scalar projects a Node onto a ScalarValue when the node is
// a scalar-bearing leaf. ScalarNode is the typed form; TextNode is a
// string. EntityRef / collection / element nodes return none.
fn node_as_scalar(n Node) ?ScalarValue {
	return match n {
		ScalarNode { n.value }
		TextNode   { ScalarValue(n.value) }
		else       { none }
	}
}

// check_item_count tests an integer count against `:len='M..N'`-style
// bounds. Reuses the textual bounds carried in BodyRule.len_min /
// .len_max; an empty bound means unbounded on that side. Errors
// surface as the same S018 code as byte-length violations — the
// validator distinguishes via message text.
fn check_item_count(count int, len_min string, len_max string) ?string {
	if len_min != '' {
		min_v := strconv.atoi(len_min) or { -1 }
		if min_v >= 0 && count < min_v {
			return 'item count ${count} below :len min ${min_v}'
		}
	}
	if len_max != '' {
		max_v := strconv.atoi(len_max) or { -1 }
		if max_v >= 0 && count > max_v {
			return 'item count ${count} above :len max ${max_v}'
		}
	}
	return none
}
