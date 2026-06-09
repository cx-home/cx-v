module code

import cx

// stdlib_validate.v — native primitives backing the `cx-stdlib/validate`
// module (spec/std-lib/validate.md): the JSON-Schema / pydantic-shaped
// DATA-RECORD validator. Distinct from the document/element-tree
// validator in vcx/cx/schema_validate.v (XSD-shaped, walks a Document
// against a parsed `.cxs` SchemaModel) — the two are siblings sharing the
// scalar-constraint VOCABULARY (§1.2). The shared engine piece reused
// here is RE2 pattern matching (cx.re2_validate / cx.re2_full_match) for
// `pattern=`; the structural walk (fields-of-a-record vs element-tree)
// differs and is implemented natively below.
//
// ── value model ──────────────────────────────────────────────────────
//   schema  → [schema [field name=… type=… …] … strict=.. extends=.. ]
//   record  → an element whose child elements are the fields:
//             [rec [email "a@b.co"] [score 87]] — field `email`'s value
//             is the field element's single body item.
//   result  → [ok $value] | [err [violation code=.. path=.. expected=..
//             got=.. message=..] …]  (§2.2). Violations are child
//             elements with attributes, so `$r/violation/@code` projects.
//
// Errors (the malformed-schema / type-unknown / pattern-invalid family,
// CXER1600..1605, §5) are VALUE nodes via mk_err — surfaced as the
// `[err code=cx-err:CXERxxxx …]` shape whose bare code the conformance
// runner matches in `out-err`. NOTE this `[err code=…]` shape (an error
// value) is NOT the validate `[err [violation …]]` RESULT element; the
// two never collide because the error path returns before a result is
// built.
//
// validate-with= (§3.6) requires invoking a user `[?def]` and inspecting
// its purity. The native dispatch layer has no `env`, so the closure
// cannot be applied here; the custom-validator surface is composed in the
// CX bundle body instead (see stdlib_src_validate) — it pre-applies the
// validator over the field/record value via the evaluator (which owns
// env) and feeds the boolean / [violation …] result back to the native
// `validate-custom-merge` primitive that splices it into the result.

// ── value builders ───────────────────────────────────────────────────

fn val_str(s string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.string_type
	}
}

fn val_bool(b bool) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(b)
		data_type: cx.ScalarType.bool_type
	}
}

fn val_seq(items []cx.Node) cx.Node {
	return cx.Element{
		name:  '__cx_seq__'
		items: items
	}
}

// val_violation builds a [violation …] element with the standard attrs.
// Empty attr strings are omitted so only the populated fields render.
fn val_violation(vcode string, path string, expected string, got string, message string) cx.Node {
	mut attrs := [
		cx.Attribute{
			name:  'code'
			value: cx.ScalarValue(vcode)
		},
		cx.Attribute{
			name:  'path'
			value: cx.ScalarValue(path)
		},
	]
	if expected != '' {
		attrs << cx.Attribute{
			name:  'expected'
			value: cx.ScalarValue(expected)
		}
	}
	if got != '' {
		attrs << cx.Attribute{
			name:  'got'
			value: cx.ScalarValue(got)
		}
	}
	if message != '' {
		attrs << cx.Attribute{
			name:  'message'
			value: cx.ScalarValue(message)
		}
	}
	return cx.Element{
		name:  'violation'
		attrs: attrs
	}
}

fn val_result(violations []cx.Node, value cx.Node) cx.Node {
	if violations.len == 0 {
		return cx.Element{
			name:  'ok'
			items: [value]
		}
	}
	// Failure is an INSPECTABLE outcome value, NOT the control-flow err
	// sentinel `[err …]`. A validation report is data the caller iterates,
	// counts, and renders — modeling it as `[err]` would make it auto-propagate
	// through every inspection call's arguments (code.md §9.2) before
	// `errors-of` / `violation-paths` / `count` could run. `[invalid …]` is
	// plain data: it never propagates, so the §3.3/§3.4 inspection API works on
	// failures. Reserve `[err]` for abort-and-propagate control-flow failures
	// (a malformed schema still raises CXER16xx as a real `[err]`). See §AH.
	return cx.Element{
		name:  'invalid'
		items: violations
	}
}

// ── argument helpers ─────────────────────────────────────────────────

fn val_arg_str(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	return none
}

fn val_attr_str(el cx.Element, name string) ?string {
	for a in el.attrs {
		if a.name == name {
			return cx.scalar_value_str_public(a.value)
		}
	}
	return none
}

fn val_attr_bool(el cx.Element, name string) bool {
	if v := val_attr_str(el, name) {
		return v == 'true'
	}
	return false
}

// ── field-value extraction (the data record) ─────────────────────────
//
// A record is an element whose child elements are the fields. The value
// of field `name` is that child element's single body item (a ScalarNode
// for a scalar field, a nested element for `type="element"`). Returns
// none when the field is absent.
fn val_field_node(record cx.Node, name string) ?cx.Node {
	if record is cx.Element {
		for child in record.items {
			if child is cx.Element && child.name == name {
				if child.items.len == 1 {
					return child.items[0]
				}
				if child.items.len == 0 {
					// an empty field element `[name]` — treat its value as
					// the empty element itself for type="element", or empty
					// string for scalar shapes. Return the element.
					return child
				}
				// multiple body items — wrap as a sequence.
				return cx.Element{
					name:  '__cx_seq__'
					items: child.items
				}
			}
		}
	}
	return none
}

fn val_record_field_names(record cx.Node) []string {
	mut names := []string{}
	if record is cx.Element {
		for child in record.items {
			if child is cx.Element {
				names << child.name
			}
		}
	}
	return names
}

// ── CXDM kind classification (§4.5) ──────────────────────────────────

// val_node_kind returns the CXDM kind name of a value node, matching the
// §4.5 type table vocabulary.
fn val_node_kind(n cx.Node) string {
	match n {
		cx.ScalarNode {
			return match n.data_type {
				.int_type { 'int' }
				.float_type { 'float' }
				.bool_type { 'bool' }
				.null_type { 'null' }
				.string_type { 'string' }
				.date_type { 'date' }
				.datetime_type { 'datetime' }
				.bytes_type { 'bytes' }
				.atom_type { 'atom' }
				.decimal_type { 'float' }
				.bigint_type { 'int' }
				.duration_type { 'string' }
				.period_type { 'string' }
			}
		}
		cx.TextNode {
			return 'string'
		}
		cx.Element {
			match n.name {
				'__cx_seq__' { return 'sequence' }
				'__cx_arr__' { return 'array' }
				'__cx_map__' { return 'map' }
				else { return 'element' }
			}
		}
		cx.SequenceNode { return 'sequence' }
		cx.ArrayNode { return 'array' }
		cx.MapNode { return 'map' }
		else { return 'element' }
	}
}

// val_known_type reports whether `t` is one of the §4.5 type names.
fn val_known_type(t string) bool {
	return t in ['string', 'int', 'float', 'number', 'bool', 'bytes', 'date',
		'datetime', 'duration', 'atom', 'element', 'sequence', 'array', 'map',
		'any', 'null']
}

// val_type_matches implements the §4.5 type matrix, including the
// asymmetric int↦float widening of §4.5.1 (float accepts int; int
// rejects float; number accepts both).
fn val_type_matches(declared string, n cx.Node) bool {
	kind := val_node_kind(n)
	match declared {
		'any' { return true }
		'string' { return kind == 'string' }
		'int' { return kind == 'int' }
		'float' { return kind == 'float' || kind == 'int' }
		'number' { return kind == 'int' || kind == 'float' }
		'bool' { return kind == 'bool' }
		'bytes' { return kind == 'bytes' }
		'date' { return kind == 'date' }
		'datetime' { return kind == 'datetime' }
		'duration' { return kind == 'duration' }
		'atom' { return kind == 'atom' }
		'element' { return kind == 'element' }
		'sequence' { return kind == 'sequence' }
		'array' { return kind == 'array' }
		'map' { return kind == 'map' }
		'null' { return kind == 'null' }
		else { return false }
	}
}

// ── numeric / length / enum helpers ──────────────────────────────────

fn val_node_f64(n cx.Node) ?f64 {
	if n is cx.ScalarNode {
		v := n.value
		match v {
			i64 { return f64(v) }
			f64 { return v }
			else {}
		}
	}
	return none
}

// val_node_length returns the codepoint length for a string value or the
// item count for a sequence/array value; none for anything else.
fn val_node_length(n cx.Node) ?int {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v.runes().len
		}
	}
	if n is cx.TextNode {
		return n.value.runes().len
	}
	if n is cx.Element {
		if n.name == '__cx_seq__' || n.name == '__cx_arr__' {
			return n.items.len
		}
	}
	if n is cx.SequenceNode {
		return n.items.len
	}
	if n is cx.ArrayNode {
		return n.items.len
	}
	return none
}

// val_scalar_text renders a scalar/text value to its comparison string.
fn val_scalar_text(n cx.Node) string {
	match n {
		cx.ScalarNode { return cx.scalar_value_str_public(n.value) }
		cx.TextNode { return n.value }
		else { return '' }
	}
}

// val_is_scalar_comparable reports whether `n` can serve as an enum
// member (scalar kinds only; an element / collection is non-comparable →
// CXER1604).
fn val_is_scalar_comparable(n cx.Node) bool {
	match n {
		cx.ScalarNode { return true }
		cx.TextNode { return true }
		else { return false }
	}
}

// val_enum_members reads the enum= members off a [field …] element.
//
// At the native boundary the `enum=[v …]` attribute has already been
// evaluated to a STRING value carrying the serialized array literal
// (e.g. `['red', 'green', 'blue']` or `[[bad-member]]`). Re-parse that
// text into its item nodes; an element member (e.g. `[bad-member]`) is a
// non-comparable enum value (→ CXER1604, surfaced by the caller). Returns
// (members, ok) where ok=false signals an unparseable enum= body.
fn val_enum_members(field cx.Element) ([]cx.Node, bool) {
	for a in field.attrs {
		if a.name == 'enum' {
			// inline BracketBody (program-eval contexts) — preferred.
			if body := a.body() {
				return val_collection_items_of(body), true
			}
			// data-element path: the attr is a string holding the array
			// literal text. Parse it and flatten the single array item.
			txt := cx.scalar_value_str_public(a.value)
			if txt.trim_space() == '' {
				return []cx.Node{}, true
			}
			doc := cx.parse(txt) or { return []cx.Node{}, false }
			return val_collection_items_of(doc.elements), true
		}
	}
	return []cx.Node{}, true
}

// val_collection_items_of flattens a parsed array/sequence wrapper into
// its item nodes. A top-level array/sequence literal arrives as a single
// ArrayNode / SequenceNode (or its `__cx_arr__` / `__cx_seq__` marker
// element) whose items are the members.
fn val_collection_items_of(body []cx.Node) []cx.Node {
	mut out := []cx.Node{}
	for n in body {
		match n {
			cx.ArrayNode { out << n.items }
			cx.SequenceNode { out << n.items }
			cx.Element {
				if n.name == '__cx_arr__' || n.name == '__cx_seq__' {
					out << n.items
				} else {
					out << n
				}
			}
			else { out << n }
		}
	}
	return out
}

// ── schema introspection ─────────────────────────────────────────────

// val_schema_fields returns the [field …] child elements of a [schema …]
// element.
fn val_schema_fields(schema cx.Element) []cx.Element {
	mut fields := []cx.Element{}
	for child in schema.items {
		if child is cx.Element && child.name == 'field' {
			fields << child
		}
	}
	return fields
}

// val_nested_schema returns the [schema …] element attached to a
// `type="element"` field via `schema=`. At the native boundary the
// `schema=[schema …]` attribute has been evaluated to a STRING carrying
// the serialized nested-schema element text; re-parse it. The inline
// BracketBody path (program-eval contexts) is preferred when present.
// Returns none when no schema= is present or it does not parse to a
// [schema …] element.
fn val_nested_schema(field cx.Element) ?cx.Element {
	for a in field.attrs {
		if a.name == 'schema' {
			if body := a.body() {
				for n in body {
					if n is cx.Element && n.name == 'schema' {
						return n
					}
				}
			}
			txt := cx.scalar_value_str_public(a.value)
			if txt.trim_space() != '' {
				doc := cx.parse(txt) or { return none }
				for n in doc.elements {
					if n is cx.Element && n.name == 'schema' {
						return n
					}
				}
			}
		}
	}
	return none
}

// ── core validation walk ─────────────────────────────────────────────

// validate_max_depth is the nested-schema recursion ceiling. §5 requires
// implementations to accept at least 64 levels; we set the limit to 64
// and raise CXER1605 strictly beyond it (depth > 64).
const validate_max_depth = 64

// ValPendingCustom describes a `validate-with=FN` custom validator that the
// native field-walk could not apply (it has no evaluator env to invoke a user
// `[?def]`). The eval env-hook (validate_stdlib_builtin_env) applies each by
// looking FN up as a closure, invoking it on `value`, and merging the result.
struct ValPendingCustom {
	fn_name string
	value   cx.Node
	path    string
}

// val_validate_record walks `record` against `schema`, accumulating
// violations into `viols` (document order, no short-circuit). `prefix` is
// the CXPath prefix for nested records (''/'/address'). On a structural /
// malformed-schema condition it returns an error VALUE via the (err, ok)
// channel.
fn val_validate_record(record cx.Node, schema cx.Element, prefix string, depth int, mut viols []cx.Node, mut pending []ValPendingCustom) (cx.Node, bool) {
	if depth > validate_max_depth {
		return mk_err('cx-err:CXER1605',
			'E_VALIDATE_NESTED_DEPTH: nested-schema recursion exceeds ${validate_max_depth} levels'), false
	}
	strict := val_attr_bool(schema, 'strict')
	fields := val_schema_fields(schema)

	mut declared := map[string]bool{}
	for field in fields {
		fname := val_attr_str(field, 'name') or { continue }
		declared[fname] = true
		fpath := '${prefix}/${fname}'

		// presence policy (§4.2): default required, optional=true opts out.
		optional := val_attr_bool(field, 'optional')
		fval := val_field_node(record, fname) or {
			if !optional {
				viols << val_violation('REQUIRED_MISSING', fpath, '', '',
					'${fname}: required field is missing')
			}
			continue
		}

		// type check (§4.5).
		mut field_failed := false
		if declared_type := val_attr_str(field, 'type') {
			if !val_known_type(declared_type) {
				return mk_err('cx-err:CXER1601',
					'E_VALIDATE_TYPE_UNKNOWN: type "${declared_type}" is not a known type'), false
			}
			if !val_type_matches(declared_type, fval) {
				got := val_node_kind(fval)
				viols << val_violation('TYPE_MISMATCH', fpath, declared_type, got,
					'${fname}: expected ${declared_type}, got ${got}')
				field_failed = true
			}
		}

		// nested-schema validation (§4.3): type="element" + schema=.
		if !field_failed {
			if nested := val_nested_schema(field) {
				before := viols.len
				ev, ok := val_validate_record(fval, nested, fpath, depth + 1, mut viols, mut pending)
				if !ok {
					return ev, false
				}
				_ = before
				// nested violations already appended with extended paths.
			}
		}

		// pattern (§4.4) — RE2 full-match on the string value.
		if !field_failed {
			if pat := val_attr_str(field, 'pattern') {
				if pat != '' {
					cx.re2_validate(pat, cx.Re2Flags{ unicode: true }) or {
						return mk_err('cx-err:CXER1602',
							'E_VALIDATE_PATTERN_INVALID: ${err.msg()}'), false
					}
					sval := val_scalar_text(fval)
					matched := cx.re2_full_match(pat, sval)
					if !matched {
						viols << val_violation('PATTERN_MISMATCH', fpath, pat, sval,
							'${fname}: value does not match pattern')
						field_failed = true
					}
				}
			}
		}

		// numeric bounds (§3.5).
		if !field_failed {
			if mins := val_attr_str(field, 'min') {
				if num := val_node_f64(fval) {
					minf := mins.f64()
					if num < minf {
						viols << val_violation('MIN_VIOLATION', fpath, mins, val_scalar_text(fval),
							'${fname}: value below minimum ${mins}')
						field_failed = true
					}
				}
			}
		}
		if !field_failed {
			if maxs := val_attr_str(field, 'max') {
				if num := val_node_f64(fval) {
					maxf := maxs.f64()
					if num > maxf {
						viols << val_violation('MAX_VIOLATION', fpath, maxs, val_scalar_text(fval),
							'${fname}: value above maximum ${maxs}')
						field_failed = true
					}
				}
			}
		}

		// length bounds (§3.5).
		if !field_failed {
			if mls := val_attr_str(field, 'min-length') {
				if l := val_node_length(fval) {
					if l < mls.int() {
						viols << val_violation('MIN_LENGTH_VIOLATION', fpath, mls, l.str(),
							'${fname}: length below minimum ${mls}')
						field_failed = true
					}
				}
			}
		}
		if !field_failed {
			if mls := val_attr_str(field, 'max-length') {
				if l := val_node_length(fval) {
					if l > mls.int() {
						viols << val_violation('MAX_LENGTH_VIOLATION', fpath, mls, l.str(),
							'${fname}: length above maximum ${mls}')
						field_failed = true
					}
				}
			}
		}

		// enum membership (§3.5).
		if !field_failed {
			members, _ := val_enum_members(field)
			if members.len > 0 {
				for m in members {
					if !val_is_scalar_comparable(m) {
						return mk_err('cx-err:CXER1604',
							'E_VALIDATE_ENUM_INVALID: enum member is non-comparable'), false
					}
				}
				sval := val_scalar_text(fval)
				mut found := false
				for m in members {
					if val_scalar_text(m) == sval {
						found = true
						break
					}
				}
				if !found {
					viols << val_violation('ENUM_MISMATCH', fpath, '', sval,
						'${fname}: value not in enum')
					field_failed = true
				}
			}
		}
		// field-level custom validator (§3.6 / §4.6): runs AFTER the
		// declarative constraints and is SKIPPED when the field already
		// failed. The native walk cannot invoke a user `[?def]` (no env), so
		// it records a pending descriptor; the eval env-hook applies it.
		if !field_failed {
			if vw := val_attr_str(field, 'validate-with') {
				if vw != '' {
					pending << ValPendingCustom{ fn_name: vw, value: fval, path: fpath }
				}
			}
		}
		_ = field_failed
	}

	// record-level custom validator (§3.6 / §4.6): runs LAST, over the whole
	// record (path `/`, or the nested prefix). Always recorded — record-level
	// rules (cross-field) run after per-field validation regardless of
	// per-field outcomes.
	if vw := val_attr_str(schema, 'validate-with') {
		if vw != '' {
			rpath := if prefix == '' { '/' } else { prefix }
			pending << ValPendingCustom{ fn_name: vw, value: record, path: rpath }
		}
	}

	// strict mode (§4.1): undeclared fields raise UNKNOWN_FIELD.
	if strict {
		for present in val_record_field_names(record) {
			if present !in declared {
				viols << val_violation('UNKNOWN_FIELD', '${prefix}/${present}', '', '',
					'${present}: undeclared field rejected under strict=true')
			}
		}
	}

	return cx.ScalarNode{ value: cx.ScalarValue(cx.NullValue{}), data_type: .null_type }, true
}

// val_schema_extends_chain resolves the merged field set of a schema that
// carries `extends=Base`. Returns the effective [schema …] element with
// the base's fields prepended (child fields override by name) and a
// merged strict / validate-with carried on the returned element. On an
// extends= cycle returns an error VALUE (CXER1603).
//
// The base arrives one of two idiomatic ways (both resolved here, mirroring
// `val_nested_schema`'s nested `schema=` handling):
//   - inline literal `extends=[schema …]` → captured as the attribute body;
//   - a value reference `extends=$BaseConst` (the CX way to reference a bound
//     schema value, §3.7) → the evaluator substitutes `$BaseConst` in the
//     user's env and serialises the resulting `[schema …]` element into the
//     attribute's scalar value, which we re-parse below.
// A bareword `extends=Base` (no `$`) is a literal symbol, not a value
// reference; it carries no schema → unresolved → CXER1603 (the cycle/missing
// signal — e.g. a self-referential `[?const CYCLE [schema extends=$CYCLE …]]`
// whose const is mid-definition).
fn val_resolve_schema(schema cx.Element) (cx.Element, cx.Node, bool) {
	// detect extends=
	mut has_extends := false
	mut base_schema := ?cx.Element(none)
	for a in schema.attrs {
		if a.name == 'extends' {
			has_extends = true
			if body := a.body() {
				for n in body {
					if n is cx.Element && n.name == 'schema' {
						base_schema = n
					}
				}
			}
			// `extends=$Base` value-reference form: the substituted schema
			// element is serialised into the scalar value — re-parse it.
			if base_schema == none {
				txt := cx.scalar_value_str_public(a.value)
				if txt.trim_space() != '' {
					if doc := cx.parse(txt) {
						for n in doc.elements {
							if n is cx.Element && n.name == 'schema' {
								base_schema = n
							}
						}
					}
				}
			}
		}
	}
	if !has_extends {
		return schema, cx.Node(val_bool(true)), true
	}
	base := base_schema or {
		// extends= present but unresolvable → cycle / malformed (§4.7).
		return cx.Element{}, mk_err('cx-err:CXER1603',
			'E_VALIDATE_SCHEMA_MALFORMED: unresolved extends= (cycle or missing base schema)'), false
	}
	// recursively resolve the base (base may itself extend).
	resolved_base, berr, bok := val_resolve_schema(base)
	if !bok {
		return cx.Element{}, berr, false
	}
	// merge: base fields first, child fields override by name.
	mut child_names := map[string]bool{}
	for f in val_schema_fields(schema) {
		if nm := val_attr_str(f, 'name') {
			child_names[nm] = true
		}
	}
	mut merged_items := []cx.Node{}
	for bf in val_schema_fields(resolved_base) {
		bn := val_attr_str(bf, 'name') or { '' }
		if bn in child_names {
			continue
		}
		merged_items << bf
	}
	for it in schema.items {
		merged_items << it
	}
	// carry the child's own attrs (strict / validate-with); the base's
	// record-level validate-with also fires (handled in the CX body).
	return cx.Element{
		name:  'schema'
		attrs: schema.attrs
		items: merged_items
	}, cx.Node(val_bool(true)), true
}

// ── dispatch ──────────────────────────────────────────────────────────

fn validate_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	match name {
		// ── §3.1 validate-shape ──────────────────────────────────────
		'validate-shape' {
			if args.len < 2 {
				return none
			}
			value := args[0]
			schema_arg := args[1]
			if schema_arg !is cx.Element || (schema_arg as cx.Element).name != 'schema' {
				return mk_err('cx-err:CXER1603',
					'E_VALIDATE_SCHEMA_MALFORMED: second argument is not a [schema …] element')
			}
			schema := schema_arg as cx.Element
			resolved, rerr, rok := val_resolve_schema(schema)
			if !rok {
				return rerr
			}
			mut viols := []cx.Node{}
			mut pending := []ValPendingCustom{}
			ev, ok := val_validate_record(value, resolved, '', 0, mut viols, mut pending)
			if !ok {
				return ev
			}
			_ = ev
			// Env-free path: declarative result only. Custom validators
			// (pending) require the evaluator env and are applied by
			// validate_stdlib_builtin_env, which is tried first in dispatch.
			return val_result(viols, value)
		}
		// ── §3.2 validate-against (named registry — unpopulable §3.2) ─
		'validate-against' {
			// The named-schema registry is unpopulable at v0.8.0, so this
			// always raises CXER1600 (§3.2).
			return mk_err('cx-err:CXER1600',
				'E_VALIDATE_SCHEMA_NOT_FOUND: no schema registered under the given name (registry is unpopulable at v0.8.0)')
		}
		// ── §3.3 result inspection ───────────────────────────────────
		'validate-is-ok' {
			if args.len < 1 {
				return none
			}
			r := args[0]
			if r is cx.Element {
				return val_bool(r.name == 'ok')
			}
			return val_bool(false)
		}
		'validate-errors-of' {
			if args.len < 1 {
				return none
			}
			return val_seq(val_violations_of(args[0]))
		}
		// ── §3.4 projections ─────────────────────────────────────────
		'validate-violation-paths' {
			if args.len < 1 {
				return none
			}
			mut items := []cx.Node{}
			for v in val_violations_of(args[0]) {
				if v is cx.Element {
					p := val_attr_str(v, 'path') or { '' }
					items << val_str(p)
				}
			}
			return val_seq(items)
		}
		'validate-violation-messages' {
			if args.len < 1 {
				return none
			}
			mut items := []cx.Node{}
			for v in val_violations_of(args[0]) {
				if v is cx.Element {
					m := val_attr_str(v, 'message') or { '' }
					items << val_str(m)
				}
			}
			return val_seq(items)
		}
		// ── §3.6 custom-validator merge (called from the CX body) ────
		// validate-custom-merge takes (result, fn-result, path) and, when
		// the custom validator rejected the value, splices a
		// CUSTOM_VIOLATION (or the verbatim [violation …]) into the result.
		'validate-custom-merge' {
			return validate_custom_merge(args)
		}
		else {
			return none
		}
	}
}

// val_violations_of returns the [violation …] children of an [invalid …]
// result; empty for [ok …] or any other shape.
fn val_violations_of(r cx.Node) []cx.Node {
	mut out := []cx.Node{}
	if r is cx.Element && r.name == 'invalid' {
		for child in r.items {
			if child is cx.Element && child.name == 'violation' {
				out << child
			}
		}
	}
	return out
}

// validate_custom_merge implements the §4.6 return-to-violation mapping
// for a custom validator whose result the CX bundle body computed by
// applying the validator to the value (the evaluator owns env). Args:
//   [0] current result element ([ok …] / [err …])
//   [1] the validator's return value (bool / [ok] / [violation …] /
//       sequence of [violation …])
//   [2] the field/record CXPath (string) for back-fill
// Returns the updated result element.
fn validate_custom_merge(args []cx.Node) ?cx.Node {
	if args.len < 3 {
		return none
	}
	result := args[0]
	fn_ret := args[1]
	path := val_arg_str(args[2]) or { '/' }

	mut viols := val_violations_of(result)
	mut value_node := cx.Node(cx.ScalarNode{ value: cx.ScalarValue(cx.NullValue{}), data_type: .null_type })
	if result is cx.Element && result.name == 'ok' && result.items.len > 0 {
		value_node = result.items[0]
	}

	new_viols := val_custom_violations(fn_ret, path)
	for v in new_viols {
		viols << v
	}
	return val_result(viols, value_node)
}

// val_custom_violations maps a custom validator's return value to zero or
// more [violation …] nodes per §4.6:
//   true / [ok …] / empty sequence → none.
//   false → one CUSTOM_VIOLATION at `path`.
//   [violation …] → surfaced verbatim, path back-filled if absent.
//   sequence of [violation …] → each surfaced, path back-filled.
fn val_custom_violations(ret cx.Node, path string) []cx.Node {
	mut out := []cx.Node{}
	match ret {
		cx.ScalarNode {
			v := ret.value
			if v is bool {
				if !v {
					out << val_violation('CUSTOM_VIOLATION', path, '', '',
						'custom validator rejected the value')
				}
			}
			// non-bool scalar → treat truthy; no violation.
		}
		cx.Element {
			match ret.name {
				'ok' {}
				'violation' {
					out << val_backfill_path(ret, path)
				}
				'__cx_seq__', '__cx_arr__' {
					for it in ret.items {
						if it is cx.Element && it.name == 'violation' {
							out << val_backfill_path(it, path)
						}
					}
				}
				'invalid' {
					// a custom validator that itself delegated to validate-shape
					// returns the [invalid …] outcome — surface its violations.
					for it in ret.items {
						if it is cx.Element && it.name == 'violation' {
							out << val_backfill_path(it, path)
						}
					}
				}
				else {
					// a bare element that is neither ok/violation/seq is
					// treated as a rejection signal → CUSTOM_VIOLATION.
					out << val_violation('CUSTOM_VIOLATION', path, '', '',
						'custom validator rejected the value')
				}
			}
		}
		cx.SequenceNode {
			for it in ret.items {
				if it is cx.Element && it.name == 'violation' {
					out << val_backfill_path(it, path)
				}
			}
		}
		else {}
	}
	return out
}

// val_backfill_path returns the [violation …] element with `path=`
// back-filled to `path` when the element carries no (or empty) path attr.
fn val_backfill_path(v cx.Element, path string) cx.Node {
	for a in v.attrs {
		if a.name == 'path' && cx.scalar_value_str_public(a.value) != '' {
			return v
		}
	}
	mut attrs := v.attrs.clone()
	attrs << cx.Attribute{
		name:  'path'
		value: cx.ScalarValue(path)
	}
	return cx.Element{
		name:  'violation'
		attrs: attrs
		items: v.items
	}
}

// ── bundled module source ────────────────────────────────────────────
//
// val_validate_shape_collect runs declarative validation (resolving extends=)
// and returns the [ok …] / [invalid …] result PLUS the pending custom-validator
// descriptors the env-hook must apply. On a malformed-schema / structural
// condition it returns the control-flow err value and an empty pending list.
fn val_validate_shape_collect(value cx.Node, schema cx.Element) (cx.Node, []ValPendingCustom) {
	mut pending := []ValPendingCustom{}
	resolved, rerr, rok := val_resolve_schema(schema)
	if !rok {
		return rerr, []ValPendingCustom{}
	}
	mut viols := []cx.Node{}
	ev, ok := val_validate_record(value, resolved, '', 0, mut viols, mut pending)
	if !ok {
		return ev, []ValPendingCustom{}
	}
	return val_result(viols, value), pending
}

// validate_stdlib_builtin_env is the evaluator-env-aware entry for
// `validate-shape`: it applies `validate-with=` custom validators (§3.6), which
// need the env to invoke a user `[?def]`. (`extends=$Base` composition is
// resolved env-free in val_resolve_schema — the value reference is substituted
// by the evaluator at the call site.) Tried before the env-free chain; returns
// the final [ok …] / [invalid …] result, or none for non-validate-shape names
// and for a malformed schema arg (the env-free path produces its CXER16xx).
fn validate_stdlib_builtin_env(name string, args []cx.Node, mut env MatchEnv) ?cx.Node {
	if name != 'validate-shape' {
		return none
	}
	if args.len < 2 {
		return none
	}
	if args[1] !is cx.Element {
		return none
	}
	schema := args[1] as cx.Element
	if schema.name != 'schema' {
		return none
	}
	decl, pending := val_validate_shape_collect(args[0], schema)
	if decl is cx.Element {
		if is_err_value(decl) {
			return decl // malformed-schema control-flow err
		}
	}
	if pending.len == 0 {
		return decl // no custom validators — identical to the env-free result
	}
	mut result := decl
	for pc in pending {
		cl := env.closures[pc.fn_name] or {
			return mk_err('cx-err:CXER1603',
				'E_VALIDATE_SCHEMA_MALFORMED: validate-with= references unknown function `${pc.fn_name}`')
		}
		ret := invoke_closure_l(cl, [pc.value], []string{}, mut env) or {
			return mk_err('cx-err:CXER1603',
				'E_VALIDATE_SCHEMA_MALFORMED: validate-with= validator `${pc.fn_name}` raised: ${err.msg()}')
		}
		result = validate_stdlib_builtin('validate-custom-merge', [result, ret, val_str(pc.path)]) or {
			result
		}
	}
	return result
}

// The canonical cx-stdlib/validate surface. The declarative checks
// forward to native primitives; custom validators (§3.6) and extends=<const>
// references are applied by validate_stdlib_builtin_env (evaluator-env-aware
// dispatch), which has the env to invoke a user `[?def]` / resolve a `[?const]`.
// NOTE: this const is $embed_file-d from stdlib/validate.cx — edit that file.

const stdlib_src_validate = $embed_file('../stdlib/validate.cx').to_string()
