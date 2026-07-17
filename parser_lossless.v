module cx

import strconv

// ── Lossless structure import: the `$tag` envelope inverse ───────────────────
// (conversions.md §2.2.1 / §2.3.1 / §4.1 / §5.1, #475)
//
// apply_lossless_structure walks an imported value tree (the Map / Array /
// scalar model the JSON and YAML readers produce) and reconstructs every
// reserved protocol shape, UNCONDITIONALLY — `$`-envelopes and `cx:` carriers
// are CX's reserved conversion namespace on every read, exactly like the XML
// importer's reserved `cx:` markers and the `cx:type` sidecar
// (apply_cx_type_sidecar, which runs BEFORE this walk on the JSON path):
//
//   • a Map with `$tag` whose keys are all reserved      → Element (envelope)
//   • a single-entry Map `{"$doc": [ … ]}`               → DocumentNode
//   • single-entry Maps `{"cx:seq"|"cx:raw"|"cx:entity"}` → Sequence / RawText
//     / EntityRef
//   • a single-entry Map `{"cx:T": payload}` (typed carrier, §0.2)
//                                                        → typed ScalarNode
//   • a Map's `cx:key-type` sidecar (§0.2)               → re-typed entry keys
//   • `cx:k:`-prefixed Map keys (the reserved-key escape) → unescaped
//
// Shapes that don't validate exactly stay plain maps — reconstruction never
// guesses.

// apply_lossless_structure is the entry point; used by the JSON codec parse
// (vcx/code/stdlib_codec.v) and the YAML reader (parse_yaml).
pub fn apply_lossless_structure(n Node) Node {
	match n {
		MapNode {
			// bottom-up: reconstruct entry values first
			mut entries := []MapEntry{cap: n.entries.len}
			for entry in n.entries {
				entries << MapEntry{
					key_type:  entry.key_type
					key_value: entry.key_value
					value:     apply_lossless_structure(entry.value)
				}
			}
			m := MapNode{
				...n
				entries: entries
			}
			if env := ll_envelope_to_element(m) {
				return env
			}
			if car := ll_carrier_to_node(m) {
				return car
			}
			return ll_plain_map(m)
		}
		ArrayNode {
			return ArrayNode{
				...n
				items: n.items.map(apply_lossless_structure(it))
			}
		}
		SequenceNode {
			return SequenceNode{
				...n
				items: n.items.map(apply_lossless_structure(it))
			}
		}
		Element {
			// elements can pre-exist here (json.md §2 `named` subset built at
			// parse time) — their children may still hold carrier maps, and
			// their auto-typed attrs still need their kind names
			mut e := Element{
				...n
				items: n.items.map(ll_body_item(apply_lossless_structure(it)))
			}
			e.attrs = ll_normalize_attr_kinds(e.attrs)
			return Node(e)
		}
		else {
			return n
		}
	}
}

// ll_entry_key returns a Map entry's key when it is a plain string key.
fn ll_entry_key(entry MapEntry) ?string {
	if entry.key_type != .string_type {
		return none
	}
	kv := entry.key_value
	if kv is string {
		return kv
	}
	return none
}

// ll_unescape_key strips one `cx:k:` reserved-key escape prefix (§2.2.1).
fn ll_unescape_key(k string) string {
	if k.starts_with('cx:k:') {
		return k['cx:k:'.len..]
	}
	return k
}

// ── envelope → Element ────────────────────────────────────────────────────────

// ll_envelope_to_element reconstructs an Element from a `$tag` envelope Map.
// none unless the shape validates exactly: string `$tag` present, every key
// reserved, and every present member well-formed.
fn ll_envelope_to_element(m MapNode) ?Node {
	mut tag := ''
	mut have_tag := false
	mut by_key := map[string]Node{}
	for entry in m.entries {
		k := ll_entry_key(entry) or { return none }
		if k !in lossless_envelope_keys {
			return none
		}
		by_key[k] = entry.value
		if k == '\$tag' {
			tag = ll_string_of(entry.value) or { return none }
			have_tag = true
		}
	}
	if !have_tag || tag.len == 0 {
		return none
	}
	mut el := Element{
		name: tag
	}
	if v := by_key['\$anchor'] {
		el.set_anchor(ll_string_of(v) or { return none })
	}
	if v := by_key['\$merge'] {
		el.set_merge(ll_string_of(v) or { return none })
	}
	if v := by_key['\$id'] {
		el.set_id(ll_string_of(v) or { return none })
	}
	if v := by_key['\$type'] {
		el.set_data_type(ll_string_of(v) or { return none })
	}
	if v := by_key['\$ref'] {
		el.set_body_ref(ll_string_of(v) or { return none })
	}
	if v := by_key['\$attrs'] {
		atypes := ll_attr_types(by_key['\$attr-types'] or { Node(TextNode{}) })
		el.attrs = ll_attrs_of(v, atypes) or { return none }
	} else if _ := by_key['\$attr-types'] {
		return none // $attr-types without $attrs is not a valid envelope
	}
	if v := by_key['\$cols'] {
		mut td := &TableData{}
		td.cols = ll_cols_of(v) or { return none }
		if rv := by_key['\$rows'] {
			td.rows = ll_rows_of(rv) or { return none }
		}
		el.table = td
	} else if _ := by_key['\$rows'] {
		return none // $rows without $cols is not a valid envelope
	}
	if v := by_key['\$children'] {
		if v !is ArrayNode {
			return none
		}
		arr := v as ArrayNode
		if _ := el.data_type() {
			// a `$type`-annotated element pins its scalar children ([zip::string
			// 90210], [tags::string[] a b]): string children stay string
			// SCALARS, which the CX emitter keeps bare under the annotation —
			// a TextNode would re-quote and break the canonical fixpoint
			el.items = arr.items.clone()
		} else {
			el.items = arr.items.map(ll_body_item(it))
		}
	}
	return Node(el)
}

// ll_string_of reads a plain string scalar value.
fn ll_string_of(n Node) ?string {
	if n is ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	if n is TextNode {
		return n.value
	}
	return none
}

// ll_attr_types reads the `$attr-types` object (attr name → type name).
// Empty map when absent / not the expected shape.
fn ll_attr_types(n Node) map[string]string {
	mut out := map[string]string{}
	if n is MapNode {
		for entry in n.entries {
			k := ll_entry_key(entry) or { continue }
			if tn := ll_string_of(entry.value) {
				out[k] = tn
			}
		}
	}
	return out
}

// ll_attrs_of reconstructs the attribute list from the `$attrs` Map, applying
// `$attr-types` (the JSON image of XML's cx:attr-types, D3): `ref` restores a
// reference attr; bytes decodes base64 back to the `0x…` hex text; sized
// numerics keep their native number value and record the width name; the
// text-payload kinds keep their verbatim payload. Import does NOT auto-type —
// a JSON string is a string attribute (JSON strings are typed natively,
// §2.2.1).
fn ll_attrs_of(n Node, atypes map[string]string) ?[]Attribute {
	if n !is MapNode {
		return none
	}
	m := n as MapNode
	mut attrs := []Attribute{cap: m.entries.len}
	for entry in m.entries {
		// escaped attr names were already unescaped by ll_plain_map when the
		// `$attrs` map itself was walked (bottom-up) — key is final here
		key := ll_entry_key(entry) or { return none }
		name := key
		val := entry.value
		if val !is ScalarNode {
			return none
		}
		sv := (val as ScalarNode).value
		mut attr := Attribute{
			name:  name
			value: sv
		}
		if tn := atypes[key] {
			match tn {
				'ref' {
					attr.is_ref = true
				}
				'bytes' {
					payload := ll_string_of(val) or { return none }
					hex := base64_to_bytes_hex(payload) or { payload }
					attr.value = ScalarValue(hex)
					attr.set_data_type('bytes')
				}
				else {
					attr.set_data_type(tn)
				}
			}
		}
		attrs << attr
	}
	return ll_normalize_attr_kinds(attrs)
}

// ll_normalize_attr_kinds restores the kind name on attrs whose value is a
// non-string base scalar (the CX parser records `int` / `float` / `bool` /
// `null` on auto-typed attrs; without it the CX emitter treats the value as
// string-ish text and quotes `tls='true'`).
fn ll_normalize_attr_kinds(attrs []Attribute) []Attribute {
	mut out := attrs.clone()
	for i, a in out {
		if _ := a.data_type() {
			continue
		}
		v := a.value
		dt := match v {
			i64 { 'int' }
			f64 { 'float' }
			bool { 'bool' }
			NullValue { 'null' }
			string { '' }
		}

		if dt != '' {
			out[i].set_data_type(dt)
		}
	}
	return out
}

// ll_cols_of reads `$cols` — canonical header tokens (`name` / `name::type`).
fn ll_cols_of(n Node) ?[]TableColumn {
	if n !is ArrayNode {
		return none
	}
	arr := n as ArrayNode
	mut cols := []TableColumn{cap: arr.items.len}
	for item in arr.items {
		tok := ll_string_of(item) or { return none }
		if i := tok.index('::') {
			cols << TableColumn{
				name:      tok[..i]
				type_name: tok[i + 2..]
			}
		} else {
			cols << TableColumn{
				name: tok
			}
		}
	}
	if cols.len == 0 {
		return none
	}
	return cols
}

// ll_rows_of reads `$rows` — arrays of JSON-native cell values.
fn ll_rows_of(n Node) ?[][]TableCellValue {
	if n !is ArrayNode {
		return none
	}
	arr := n as ArrayNode
	mut rows := [][]TableCellValue{cap: arr.items.len}
	for row_n in arr.items {
		if row_n !is ArrayNode {
			return none
		}
		row_arr := row_n as ArrayNode
		mut row := []TableCellValue{cap: row_arr.items.len}
		for cell_n in row_arr.items {
			row << ll_cell_of(cell_n) or { return none }
		}
		rows << row
	}
	return rows
}

fn ll_cell_of(n Node) ?TableCellValue {
	match n {
		ScalarNode {
			v := n.value
			return match v {
				bool { TableCellValue(v as bool) }
				i64 { TableCellValue(v as i64) }
				f64 { TableCellValue(v as f64) }
				string { TableCellValue(v as string) }
				NullValue { TableCellValue(NullValue{}) }
			}
		}
		TextNode {
			return TableCellValue(n.value)
		}
		ArrayNode {
			return TableCellValue(n)
		}
		MapNode {
			return TableCellValue(n)
		}
		SequenceNode {
			return TableCellValue(n)
		}
		else {
			return none
		}
	}
}

// ll_body_item maps a reconstructed `$children` item to its body-node form:
// a plain string scalar reads back as body TEXT (the emit image of a
// TextNode; strict-canonical-equivalent to a string scalar, §2.2.1) — every
// other node kind is already its body form.
fn ll_body_item(n Node) Node {
	if n is ScalarNode {
		if n.data_type == .string_type {
			v := n.value
			if v is string {
				return TextNode{
					value: v
				}
			}
		}
	}
	return n
}

// ── reserved single-key carriers ──────────────────────────────────────────────

// ll_carrier_to_node reconstructs `{"cx:seq": […]}` / `{"cx:raw": "…"}` /
// `{"cx:entity": "…"}` / `{"cx:T": payload}` (typed per-item carrier, §0.2).
// none when the map is not a recognized single-key carrier.
fn ll_carrier_to_node(m MapNode) ?Node {
	if m.entries.len != 1 {
		return none
	}
	entry := m.entries[0]
	key := ll_entry_key(entry) or { return none }
	if !key.starts_with('cx:') || key.starts_with('cx:k:') {
		return none
	}
	val := entry.value
	match key {
		'cx:seq' {
			if val is ArrayNode {
				return Node(SequenceNode{
					items: val.items
				})
			}
			return none
		}
		'cx:raw' {
			payload := ll_string_of(val) or { return none }
			return Node(RawTextNode{
				value: payload
			})
		}
		'cx:entity' {
			payload := ll_string_of(val) or { return none }
			return Node(EntityRefNode{
				name: payload
			})
		}
		else {
			tname := key['cx:'.len..]
			return ll_typed_payload(tname, val)
		}
	}
}

// ll_typed_payload materializes a `{"cx:T": payload}` carrier as the typed
// scalar. Payload conventions mirror the emit side (§0.2): sized numerics
// ride the native number (the value model carries no width —
// scalar_type_from_name's documented collapse), bytes ride base64, atoms the
// bare name, everything else the verbatim text.
fn ll_typed_payload(tname string, val Node) ?Node {
	if type_name_is_sized_numeric(tname) {
		if val is ScalarNode {
			v := val.value
			if v is i64 || v is f64 {
				return Node(val)
			}
			// tolerate a stringified number (the YAML tag payload shape)
			if v is string {
				if iv := v.parse_int(10, 64) {
					return Node(ScalarNode{
						data_type: .int_type
						value:     ScalarValue(iv)
					})
				}
				if fv := strconv.atof64(v) {
					return Node(ScalarNode{
						data_type: .float_type
						value:     ScalarValue(fv)
					})
				}
			}
		}
		return none
	}
	st := scalar_type_from_name(tname) or { return none }
	payload := ll_string_of(val) or { return none }
	match st {
		.atom_type {
			return Node(ScalarNode{
				data_type: .atom_type
				value:     ScalarValue(payload.trim_string_left(':'))
			})
		}
		.bytes_type {
			hex := base64_to_bytes_hex(payload) or { payload }
			return Node(ScalarNode{
				data_type: .bytes_type
				value:     ScalarValue(hex)
			})
		}
		.date_type, .datetime_type, .decimal_type, .bigint_type, .duration_type, .period_type {
			return Node(ScalarNode{
				data_type: st
				value:     ScalarValue(payload)
			})
		}
		else {
			return none // int / float / bool / null / string never carrier-emit
		}
	}
}

// ── plain maps: `cx:key-type` sidecar + key unescape ─────────────────────────

// ll_plain_map finishes a non-envelope, non-carrier Map: consume the
// `cx:key-type` sidecar (§0.2 — re-typing the named entry keys) and strip
// `cx:k:` escapes. `$doc` (the multi-root document wrapper) is handled here
// as a single-entry reserved shape.
fn ll_plain_map(m MapNode) Node {
	// {"$doc": [ … ]} → transparent document carrier (D7)
	if m.entries.len == 1 {
		if k := ll_entry_key(m.entries[0]) {
			if k == '\$doc' {
				val := m.entries[0].value
				if val is ArrayNode {
					return DocumentNode{
						elements: val.items.map(ll_body_item(it))
					}
				}
			}
		}
	}
	mut ktypes := map[string]string{}
	mut entries := []MapEntry{cap: m.entries.len}
	for entry in m.entries {
		if k := ll_entry_key(entry) {
			if k == 'cx:key-type' {
				if tm := ll_key_type_map(entry.value) {
					for kk, tn in tm {
						ktypes[kk] = tn
					}
					continue // consume the sidecar entry
				}
			}
		}
		entries << entry
	}
	for i, entry in entries {
		k := ll_entry_key(entry) or { continue }
		if tn := ktypes[k] {
			if re := ll_retype_key(k, tn) {
				kt, kv := re.kt, re.kv
				entries[i] = MapEntry{
					key_type:  kt
					key_value: kv
					value:     entry.value
				}
				continue
			}
		}
		unescaped := ll_unescape_key(k)
		if unescaped != k {
			entries[i] = MapEntry{
				key_type:  entry.key_type
				key_value: ScalarValue(unescaped)
				value:     entry.value
			}
		}
	}
	return MapNode{
		...m
		entries: entries
	}
}

fn ll_key_type_map(n Node) ?map[string]string {
	if n !is MapNode {
		return none
	}
	m := n as MapNode
	mut out := map[string]string{}
	for entry in m.entries {
		k := ll_entry_key(entry) or { return none }
		tn := ll_string_of(entry.value) or { return none }
		out[k] = tn
	}
	if out.len == 0 {
		return none
	}
	return out
}

struct LlKeyRetype {
	kt ScalarType
	kv ScalarValue
}

// ll_retype_key re-types one map key per its `cx:key-type` entry. none when
// the payload doesn't parse under the named type (the key stays a string).
fn ll_retype_key(text string, type_name string) ?LlKeyRetype {
	match type_name {
		'int' {
			iv := text.parse_int(10, 64) or { return none }
			return LlKeyRetype{
				kt: .int_type
				kv: ScalarValue(iv)
			}
		}
		'float' {
			fv := strconv.atof64(text) or { return none }
			return LlKeyRetype{
				kt: .float_type
				kv: ScalarValue(fv)
			}
		}
		'bool' {
			if text != 'true' && text != 'false' {
				return none
			}
			return LlKeyRetype{
				kt: .bool_type
				kv: ScalarValue(text == 'true')
			}
		}
		'date', 'datetime', 'bytes' {
			st := scalar_type_from_name(type_name) or { return none }
			return LlKeyRetype{
				kt: st
				kv: ScalarValue(text)
			}
		}
		else {
			return none
		}
	}
}

// ── document assembly ─────────────────────────────────────────────────────────

// lossless_root_to_elements unpacks a reconstructed root into document
// elements: a `$doc` DocumentNode spreads; anything else is the single root.
pub fn lossless_root_to_elements(n Node) []Node {
	if n is DocumentNode {
		return n.elements
	}
	return [n]
}
