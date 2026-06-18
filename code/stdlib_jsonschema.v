module code

import cx

// stdlib_jsonschema.v — JSON Schema 2020-12 validation (the MCP-tool-schema
// subset), the V backing for `cx-stdlib/jsonschema`. cx-private #6 S1/S7;
// spec/03-approved/std-lib/README.md D3 (frozen `std` substrate — the MCP
// shim that consumes this lives in `x/`).
//
// MCP tool input schemas ARE JSON Schema, so this lets CX consume them without
// reinventing. The schema + the value are ordinary CX values (a JSON object is a
// `__cx_map__`, parsed by `[$json:parse]`); validation is a pure recursive walk
// returning the same [ok] / [invalid [violation …]] outcome shape as
// cx-stdlib/validate (failure is the inspectable [invalid …] value, NOT a
// propagating [err]). Reuses validate's leaf helpers (val_node_kind / val_node_f64
// / val_scalar_text) and the RE2 engine (cx.re2_partial_match — `pattern` is an
// unanchored search per §6.3.3) — same `code` module.
//
// Supported keywords (the common MCP subset): type, enum, const, required,
// properties, items, minimum, maximum, minLength, maxLength, pattern, minItems,
// maxItems. Unsupported keywords are ignored (a permissive superset is still
// schema-valid); nothing is stubbed — every supported keyword is enforced.

const js_err_arg_invalid = 'cx-err:CXER1610' // E_JSONSCHEMA_ARG_INVALID

fn js_str(s string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.string_type
	}
}

fn js_attr(name string, val string) cx.Attribute {
	return cx.Attribute{
		name:  name
		value: cx.ScalarValue(val)
	}
}

// js_map_get returns the value bound to `key` in a map, or none. A CX map has
// two runtime shapes: a `{…}` literal evaluates to a `MapNode` (entries), while
// `[$json:parse]` of a JSON object yields an `Element{name:'__cx_map__'}` (child
// per key). Both are accepted so schemas/values author either way.
fn js_map_get(n cx.Node, key string) ?cx.Node {
	if n is cx.Element && n.name == '__cx_map__' {
		for it in n.items {
			if it is cx.Element && it.name == key {
				if it.items.len > 0 {
					return it.items[0]
				}
				return js_str('')
			}
		}
	}
	if n is cx.MapNode {
		for entry in n.entries {
			if cx.scalar_value_str_public(entry.key_value) == key {
				return entry.value
			}
		}
	}
	return none
}

fn js_map_keys(n cx.Node) []string {
	mut out := []string{}
	if n is cx.Element && n.name == '__cx_map__' {
		for it in n.items {
			if it is cx.Element {
				out << it.name
			}
		}
	}
	if n is cx.MapNode {
		for entry in n.entries {
			out << cx.scalar_value_str_public(entry.key_value)
		}
	}
	return out
}

// js_items returns the member nodes of a sequence/array value, or none if the
// node is not array-shaped.
fn js_items(n cx.Node) ?[]cx.Node {
	if n is cx.Element && (n.name == '__cx_seq__' || n.name == '__cx_arr__') {
		return n.items
	}
	if n is cx.SequenceNode {
		return n.items
	}
	if n is cx.ArrayNode {
		return n.items
	}
	return none
}

// js_type_matches — does `value`'s JSON type satisfy the declared schema `type`?
// integer ⊂ number; a number with no fractional part also satisfies integer.
fn js_type_matches(declared string, value cx.Node) bool {
	k := val_node_kind(value)
	return match declared {
		'string' { k == 'string' }
		'boolean' { k == 'bool' }
		'null' { k == 'null' }
		'object' { k == 'map' }
		'array' { k == 'sequence' || k == 'array' }
		'number' { k == 'int' || k == 'float' }
		'integer' {
			if k == 'int' {
				true
			} else if k == 'float' {
				f := val_node_f64(value) or { return false }
				f == f64(i64(f)) // integral-valued float counts as integer
			} else {
				false
			}
		}
		else { true } // unknown declared type → not constrained here
	}
}

// js_scalar_eq — structural equality for enum/const. Scalars compare by kind +
// text; arrays/maps compare by canonical render (covers nested const).
fn js_scalar_eq(a cx.Node, b cx.Node) bool {
	ka := val_node_kind(a)
	kb := val_node_kind(b)
	if ka in ['map', 'sequence', 'array', 'element'] || kb in ['map', 'sequence', 'array', 'element'] {
		return render_canonical(a) == render_canonical(b)
	}
	// numbers compare numerically (1 == 1.0); else by kind + text.
	if ka in ['int', 'float'] && kb in ['int', 'float'] {
		fa := val_node_f64(a) or { return false }
		fb := val_node_f64(b) or { return false }
		return fa == fb
	}
	return ka == kb && val_scalar_text(a) == val_scalar_text(b)
}

fn js_violation(keyword string, path string, message string) cx.Node {
	return cx.Element{
		name:  'violation'
		attrs: [js_attr('keyword', keyword), js_attr('path', path), js_attr('message', message)]
	}
}

// js_check is the recursive validator: append a violation per failed keyword.
fn js_check(value cx.Node, schema cx.Node, path string, mut viols []cx.Node) {
	// `type`
	if t := js_map_get(schema, 'type') {
		declared := val_scalar_text(t)
		if declared != '' && !js_type_matches(declared, value) {
			got := val_node_kind(value)
			viols << js_violation('type', path, 'expected ${declared}, got ${got}')
			return // a type mismatch makes deeper keyword checks meaningless
		}
	}
	// `const`
	if c := js_map_get(schema, 'const') {
		if !js_scalar_eq(value, c) {
			viols << js_violation('const', path, 'value does not equal const')
		}
	}
	// `enum`
	if e := js_map_get(schema, 'enum') {
		if members := js_items(e) {
			mut ok := false
			for m in members {
				if js_scalar_eq(value, m) {
					ok = true
					break
				}
			}
			if !ok {
				viols << js_violation('enum', path, 'value not in enum')
			}
		}
	}
	kind := val_node_kind(value)
	// object keywords
	if kind == 'map' {
		if req := js_map_get(schema, 'required') {
			if names := js_items(req) {
				keys := js_map_keys(value)
				for nm in names {
					rname := val_scalar_text(nm)
					if rname != '' && rname !in keys {
						viols << js_violation('required', '${path}/${rname}',
							'required property "${rname}" is missing')
					}
				}
			}
		}
		if props := js_map_get(schema, 'properties') {
			for pname in js_map_keys(props) {
				subschema := js_map_get(props, pname) or { continue }
				pval := js_map_get(value, pname) or { continue } // absent handled by `required`
				js_check(pval, subschema, '${path}/${pname}', mut viols)
			}
		}
	}
	// array keywords
	if kind == 'sequence' || kind == 'array' {
		members := js_items(value) or { []cx.Node{} }
		if mins := js_map_get(schema, 'minItems') {
			if n := val_node_f64(mins) {
				if f64(members.len) < n {
					viols << js_violation('minItems', path, 'array shorter than minItems')
				}
			}
		}
		if maxs := js_map_get(schema, 'maxItems') {
			if n := val_node_f64(maxs) {
				if f64(members.len) > n {
					viols << js_violation('maxItems', path, 'array longer than maxItems')
				}
			}
		}
		if items := js_map_get(schema, 'items') {
			for i, m in members {
				js_check(m, items, '${path}/${i}', mut viols)
			}
		}
	}
	// string keywords
	if kind == 'string' {
		s := val_scalar_text(value)
		if minl := js_map_get(schema, 'minLength') {
			if n := val_node_f64(minl) {
				if f64(s.runes().len) < n {
					viols << js_violation('minLength', path, 'string shorter than minLength')
				}
			}
		}
		if maxl := js_map_get(schema, 'maxLength') {
			if n := val_node_f64(maxl) {
				if f64(s.runes().len) > n {
					viols << js_violation('maxLength', path, 'string longer than maxLength')
				}
			}
		}
		if pat := js_map_get(schema, 'pattern') {
			p := val_scalar_text(pat)
			if p != '' {
				// JSON Schema 2020-12 §6.3.3: `pattern` is an UNANCHORED search
				// (matches if the regex matches any substring) — re2_partial_match,
				// NOT re2_full_match. An uncompilable pattern is treated as
				// non-matching rather than crashing validation.
				matched := cx.re2_partial_match(p, s) or { false }
				if !matched {
					viols << js_violation('pattern', path, 'string does not match pattern')
				}
			}
		}
	}
	// number keywords
	if kind == 'int' || kind == 'float' {
		if num := val_node_f64(value) {
			if mn := js_map_get(schema, 'minimum') {
				if b := val_node_f64(mn) {
					if num < b {
						viols << js_violation('minimum', path, 'value below minimum')
					}
				}
			}
			if mx := js_map_get(schema, 'maximum') {
				if b := val_node_f64(mx) {
					if num > b {
						viols << js_violation('maximum', path, 'value above maximum')
					}
				}
			}
		}
	}
}

// jsonschema_validate(value, schema) → [ok] | [invalid [violation …] …].
fn jsonschema_validate(args []cx.Node) cx.Node {
	if args.len < 2 {
		return mk_err(js_err_arg_invalid, 'E_JSONSCHEMA_ARG_INVALID: validate expects (value, schema)')
	}
	mut viols := []cx.Node{}
	js_check(args[0], args[1], '', mut viols)
	if viols.len == 0 {
		return cx.Element{ name: 'ok' }
	}
	return cx.Element{ name: 'invalid', items: viols }
}

fn jsonschema_is_valid(args []cx.Node) cx.Node {
	r := jsonschema_validate(args)
	ok := r is cx.Element && (r as cx.Element).name == 'ok'
	return cx.ScalarNode{
		value:     cx.ScalarValue(ok)
		data_type: cx.ScalarType.bool_type
	}
}

fn jsonschema_violations(args []cx.Node) cx.Node {
	if args.len < 1 || args[0] !is cx.Element {
		return cx.Element{ name: '__cx_seq__' }
	}
	r := args[0] as cx.Element
	if r.name == 'invalid' {
		return cx.Element{ name: '__cx_seq__', items: r.items }
	}
	return cx.Element{ name: '__cx_seq__' }
}

fn jsonschema_violation_paths(args []cx.Node) cx.Node {
	mut out := []cx.Node{}
	if args.len > 0 && args[0] is cx.Element {
		r := args[0] as cx.Element
		if r.name == 'invalid' {
			for v in r.items {
				if v is cx.Element {
					out << js_str(v.attr('path'))
				}
			}
		}
	}
	return cx.Element{ name: '__cx_seq__', items: out }
}

// jsonschema_stdlib_builtin — the env-free dispatch entry (pure).
fn jsonschema_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	return match name {
		'jsonschema-validate' { jsonschema_validate(args) }
		'jsonschema-is-valid' { jsonschema_is_valid(args) }
		'jsonschema-violations' { jsonschema_violations(args) }
		'jsonschema-violation-paths' { jsonschema_violation_paths(args) }
		else { none }
	}
}
