module code

import cx
import crypto.sha256
import strings

// stdlib_format.v — native primitives backing the `cx-stdlib/format`
// module (spec/stdlib_format.md). Emits CX values back to CX text in
// canonical / pretty / compact / diff-friendly shapes plus a streaming
// (per-line sequence) variant.
//
// Canonical / compact text is the byte-stable canonical form defined in
// spec/canonical.md. Rather than reimplement that emission, these
// primitives REUSE the program renderer (vcx/code/render.v ::
// render_canonical / render_node) — `format/canonical` MUST be exactly
// the hash preimage (spec/stdlib_format.md §1.1), so it bottoms out in
// the same renderer the eval result path uses. `pretty` and
// `diff-friendly` add an indentation / one-element-per-line layout on
// top of the same value model.
//
// Error values are returned as catchable err-values (`[err :code … :message …]`
// via mk_err) so they render `cx-err:CXERnnnn` and the conformance harness
// can match them against `--- out_err`. CXER2700/2701/2702 per spec §5.

// CXER codes per spec/stdlib_format.md §5.
const format_err_unsupported   = 'cx-err:CXER2700'
const format_err_depth_exceed  = 'cx-err:CXER2701'
const format_err_invalid_opt   = 'cx-err:CXER2702'

// ── value builders ──────────────────────────────────────────────────

fn format_str(s string) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(s), data_type: cx.ScalarType.string_type }
}

fn format_int(n i64) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(n), data_type: cx.ScalarType.int_type }
}

fn format_bytes(buf []u8) cx.Node {
	return cx.ScalarNode{ value: cx.ScalarValue(buf.bytestr()), data_type: cx.ScalarType.bytes_type }
}

fn format_seq(parts []string) cx.Node {
	mut items := []cx.Node{cap: parts.len}
	for p in parts {
		items << format_str(p)
	}
	return cx.SequenceNode{ items: items }
}

// ── pretty-print options (§3.2) ─────────────────────────────────────

struct FormatOpts {
mut:
	indent          string = '  '
	line_width      int    = 80
	attr_alignment  string = 'none'
	sort_attributes bool
	max_depth       int
	max_depth_error bool // true ⇒ "error" policy; false ⇒ "truncate"
	string_quote    string = 'double'
	include_anchors bool   = true
}

// the known opts keys; anything else is CXER2702.
const format_opt_keys = ['indent', 'line-width', 'attribute-alignment', 'sort-attributes',
	'max-depth', 'max-depth-policy', 'string-quote', 'include-anchors']

// scalar_string reads a string scalar value (none for other shapes).
fn format_opt_scalar_str(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	return none
}

fn format_opt_scalar_int(n cx.Node) ?i64 {
	if n is cx.ScalarNode {
		v := n.value
		if v is i64 {
			return v
		}
	}
	return none
}

fn format_opt_scalar_bool(n cx.Node) ?bool {
	if n is cx.ScalarNode {
		v := n.value
		if v is bool {
			return v
		}
	}
	return none
}

// parse_opts reads the `__cx_map__` envelope into a FormatOpts struct.
// Returns an err-value node (CXER2702) on an unknown key or an invalid
// value; returns `none` if the opts arg is not a map at all (lets the
// dispatch fall through / report a type mismatch upstream).
fn parse_opts(opts cx.Node) ?(FormatOpts, cx.Node) {
	mut o := FormatOpts{}
	// opts must be the map envelope; an empty/absent map is fine.
	if opts !is cx.Element {
		return none
	}
	el := opts as cx.Element
	if el.name != '__cx_map__' {
		return none
	}
	for entry in el.items {
		if entry !is cx.Element {
			continue
		}
		ee := entry as cx.Element
		key := ee.name
		if key !in format_opt_keys {
			return o, format_mk_err(format_err_invalid_opt,
				'E_FORMAT_INVALID_OPT: unknown opt key :${key}')
		}
		if ee.items.len == 0 {
			return o, format_mk_err(format_err_invalid_opt,
				'E_FORMAT_INVALID_OPT: opt :${key} has no value')
		}
		val := ee.items[0]
		match key {
			'indent' {
				o.indent = format_opt_scalar_str(val) or {
					return o, format_mk_err(format_err_invalid_opt,
						'E_FORMAT_INVALID_OPT: :indent must be a string')
				}
			}
			'line-width' {
				w := format_opt_scalar_int(val) or {
					return o, format_mk_err(format_err_invalid_opt,
						'E_FORMAT_INVALID_OPT: :line-width must be an int')
				}
				if w <= 0 {
					return o, format_mk_err(format_err_invalid_opt,
						'E_FORMAT_INVALID_OPT: :line-width must be positive')
				}
				o.line_width = int(w)
			}
			'attribute-alignment' {
				a := format_opt_scalar_str(val) or {
					return o, format_mk_err(format_err_invalid_opt,
						'E_FORMAT_INVALID_OPT: :attribute-alignment must be a string')
				}
				if a !in ['none', 'colon', 'value'] {
					return o, format_mk_err(format_err_invalid_opt,
						'E_FORMAT_INVALID_OPT: :attribute-alignment must be none/colon/value')
				}
				o.attr_alignment = a
			}
			'sort-attributes' {
				o.sort_attributes = format_opt_scalar_bool(val) or {
					return o, format_mk_err(format_err_invalid_opt,
						'E_FORMAT_INVALID_OPT: :sort-attributes must be a bool')
				}
			}
			'max-depth' {
				d := format_opt_scalar_int(val) or {
					return o, format_mk_err(format_err_invalid_opt,
						'E_FORMAT_INVALID_OPT: :max-depth must be an int')
				}
				if d < 0 {
					return o, format_mk_err(format_err_invalid_opt,
						'E_FORMAT_INVALID_OPT: :max-depth must be >= 0')
				}
				o.max_depth = int(d)
			}
			'max-depth-policy' {
				p := format_opt_scalar_str(val) or {
					return o, format_mk_err(format_err_invalid_opt,
						'E_FORMAT_INVALID_OPT: :max-depth-policy must be a string')
				}
				match p {
					'truncate' { o.max_depth_error = false }
					'error'    { o.max_depth_error = true }
					else {
						return o, format_mk_err(format_err_invalid_opt,
							'E_FORMAT_INVALID_OPT: :max-depth-policy must be truncate/error')
					}
				}
			}
			'string-quote' {
				q := format_opt_scalar_str(val) or {
					return o, format_mk_err(format_err_invalid_opt,
						'E_FORMAT_INVALID_OPT: :string-quote must be a string')
				}
				if q !in ['double', 'single'] {
					return o, format_mk_err(format_err_invalid_opt,
						'E_FORMAT_INVALID_OPT: :string-quote must be double/single')
				}
				o.string_quote = q
			}
			'include-anchors' {
				o.include_anchors = format_opt_scalar_bool(val) or {
					return o, format_mk_err(format_err_invalid_opt,
						'E_FORMAT_INVALID_OPT: :include-anchors must be a bool')
				}
			}
			else {}
		}
	}
	// no error — sentinel null scalar (callers check `err is cx.Element`).
	return o, cx.Node(cx.ScalarNode{ value: cx.ScalarValue(cx.NullValue{}), data_type: cx.ScalarType.null_type })
}

// format_mk_err builds an err-value via the shared evaluator helper.
fn format_mk_err(err_code string, msg string) cx.Node {
	return mk_err(err_code, msg)
}

// ── pretty / diff-friendly emission ─────────────────────────────────

// PrettyState carries the emit options + a sentinel for depth-policy
// "error" so the recursive emitter can bail out.
struct PrettyState {
	opts FormatOpts
mut:
	depth_exceeded bool
}

// fmt_quote_string applies the configured quote style to a string
// scalar. Mirrors render.v's choose_render_quote (double-preferred) but
// honours the :string-quote opt.
fn fmt_quote_string(s string, quote string) string {
	if quote == 'single' {
		if !s.contains("'") { return "'${s}'" }
		if !s.contains('"') { return '"${s}"' }
		if !s.contains("'''") { return "'''${s}'''" }
		return '"${s}"'
	}
	// default: double
	if !s.contains('"') { return '"${s}"' }
	if !s.contains("'") { return "'${s}'" }
	if !s.contains('"""') { return '"""${s}"""' }
	return '"${s}"'
}

// fmt_string_carried_non_string names the scalar kinds whose ScalarValue
// payload is a `string` even though the kind is NOT `string`: each parks
// its verbatim CX image there and rides its type on `data_type` (see
// cx.ScalarType). That image IS the kind's bare canonical form and
// re-types to the same kind on re-parse, so it must be emitted BARE —
// quoting it re-parses as a string and breaks the round trip (#978,
// RULED: CO-3). `bytes` is string-carried too but re-images through
// fmt_bytes_scalar, and `atom` needs its `:` sigil, so both are handled
// ahead of this list rather than in it.
const fmt_string_carried_non_string = [cx.ScalarType.decimal_type, .bigint_type,
	.date_type, .datetime_type, .duration_type, .period_type]

// fmt_scalar renders a scalar node honoring the quote style. Only a
// STRING scalar is quoted; every other kind emits its bare canonical
// image (#978, RULED: CO-3). Atoms render `:name`; bytes render
// canonical `0x…` / b"…".
//
// The int / bool / null images match the canonical renderer byte-for-byte
// (render.v): pretty must diverge from canonical on string quoting and
// NOTHING else. #991 (RULED: CO-12) made that true of `float` as well —
// both renderers now image an f64 through the CX-owned Ryū renderer
// (`1.5e0`), the only image that re-parses as a float; V's `.str()`
// image (`1.5`) re-parsed as a DECIMAL and collided with decimal 1.5.
fn fmt_scalar(n cx.ScalarNode, opts FormatOpts) string {
	if n.data_type == .atom_type {
		if n.value is string {
			return ':' + (n.value as string)
		}
	}
	v := n.value
	match v {
		string {
			if n.data_type == .bytes_type {
				return fmt_bytes_scalar(v.bytes())
			}
			if n.data_type in fmt_string_carried_non_string {
				return v
			}
			return fmt_quote_string(v, opts.string_quote)
		}
		i64  { return v.str() }
		f64  { return cx.cx_format_float(v) }
		bool { return v.str() }
		cx.NullValue { return 'null' }
	}
}

// fmt_bytes_scalar renders a bytes scalar per §4.5: short (<32) → hex,
// longer → base64.
fn fmt_bytes_scalar(buf []u8) string {
	if buf.len < 32 {
		mut sb := strings.new_builder(2 + buf.len * 2)
		sb.write_string('0x')
		for b in buf {
			sb.write_string(b.hex())
		}
		return sb.str()
	}
	b64 := bytes_to_b64_std(buf)
	return 'b"${b64}"'
}

const format_b64_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

// bytes_to_b64_std produces a standard base64 string.
fn bytes_to_b64_std(buf []u8) string {
	alphabet := format_b64_alphabet
	mut sb := strings.new_builder(((buf.len + 2) / 3) * 4)
	mut i := 0
	for i + 2 < buf.len {
		n := (u32(buf[i]) << 16) | (u32(buf[i + 1]) << 8) | u32(buf[i + 2])
		sb.write_u8(alphabet[(n >> 18) & 0x3f])
		sb.write_u8(alphabet[(n >> 12) & 0x3f])
		sb.write_u8(alphabet[(n >> 6) & 0x3f])
		sb.write_u8(alphabet[n & 0x3f])
		i += 3
	}
	rem := buf.len - i
	if rem == 1 {
		n := u32(buf[i]) << 16
		sb.write_u8(alphabet[(n >> 18) & 0x3f])
		sb.write_u8(alphabet[(n >> 12) & 0x3f])
		sb.write_string('==')
	} else if rem == 2 {
		n := (u32(buf[i]) << 16) | (u32(buf[i + 1]) << 8)
		sb.write_u8(alphabet[(n >> 18) & 0x3f])
		sb.write_u8(alphabet[(n >> 12) & 0x3f])
		sb.write_u8(alphabet[(n >> 6) & 0x3f])
		sb.write_string('=')
	}
	return sb.str()
}

// sorted_attrs returns the element attrs, optionally sorted by name.
fn sorted_attrs(attrs []cx.Attribute, sort bool) []cx.Attribute {
	if !sort {
		return attrs
	}
	mut out := attrs.clone()
	out.sort(a.name < b.name)
	return out
}

// fmt_attr_is_string reports whether an attribute's EFFECTIVE scalar kind
// is `string` — the one kind pretty quotes. A bare `@id` reference is
// never a string; an ascribed type names the kind outright; an untyped
// attribute's kind is whatever its ScalarValue variant says.
fn fmt_attr_is_string(a cx.Attribute) bool {
	if a.is_ref {
		return false
	}
	if dt := a.data_type() {
		return dt == 'string'
	}
	return a.value is string
}

// fmt_attr_parts renders an attribute's two sides: the name (carrying any
// glued `::T` annotation) and the value.
//
// #978 (RULED: CO-3): the value decision is DELEGATED to the canonical
// emitter's cx_attr_scalar_parts, so every non-string attribute emits the
// bare canonical image that re-types to the same kind on re-parse —
// decimals stay `1.5`, atoms keep their `:` sigil, sized numerics and
// durations keep their `::T` annotation. This function's only departure
// from canonical is the STRING case, which takes pretty's always-quote
// path honoring the :string-quote opt (canonical is bare-when-safe) —
// the one deliberate pretty↔canonical divergence, documented in
// stdlib/format.cx and spec/std-lib/format.md.
//
// #991 (RULED: CO-12): the float carve-out CO-3 left here is GONE. It
// existed because CX's two canonical attribute paths disagreed on an f64
// — render.v imaged it with V's `.str()` (`1.5`), cx_attr_scalar_parts
// with the CX-owned Ryū renderer (`1.5e0`) — and pretty followed the
// lossy one so that string quoting stayed its only divergence. The
// disagreement is now settled in Ryū's favour, which [L18] had already
// ruled ("the float surface is Tier-1 identity — the CX-owned Ryū
// renderer owns the bytes"): `1.5` re-parses as a DECIMAL and collides
// with decimal 1.5's image, `1.5e0` re-parses as the float it is. All
// four forms take `val_part` for every non-string kind, float included.
fn fmt_attr_parts(a cx.Attribute, opts FormatOpts) (string, string) {
	name_part, val_part := cx.cx_attr_scalar_parts(a)
	if fmt_attr_is_string(a) {
		return name_part, fmt_quote_string(cx.scalar_value_str_public(a.value), opts.string_quote)
	}
	return name_part, val_part
}

// is_marker reports whether an element is a collection-literal envelope.
fn is_marker(name string) bool {
	return name == '__cx_seq__' || name == '__cx_arr__' || name == '__cx_map__'
}

// node_is_leaf reports whether a node renders on a single line with no
// recursive children (scalars, empty elements, marker-free).
fn node_is_leaf(n cx.Node) bool {
	match n {
		cx.ScalarNode { return true }
		cx.TextNode   { return true }
		cx.Element {
			el := n as cx.Element
			return el.items.len == 0
		}
		cx.SequenceNode { return (n as cx.SequenceNode).items.len == 0 }
		cx.ArrayNode    { return (n as cx.ArrayNode).items.len == 0 }
		cx.MapNode      { return (n as cx.MapNode).entries.len == 0 }
		else { return false }
	}
}

// fmt_pretty emits the multi-line pretty form. `cur` is the current
// indentation prefix. `depth` tracks nesting for :max-depth.
fn fmt_pretty(n cx.Node, cur string, depth int, mut st PrettyState) string {
	// max-depth handling (0 = unlimited)
	if st.opts.max_depth > 0 && depth > st.opts.max_depth {
		if st.opts.max_depth_error {
			st.depth_exceeded = true
			return ''
		}
		return '…'
	}
	match n {
		cx.ScalarNode {
			return fmt_scalar(n, st.opts)
		}
		cx.TextNode {
			t := n as cx.TextNode
			if t.value.trim_space() == '' {
				return t.value
			}
			return fmt_quote_string(t.value, st.opts.string_quote)
		}
		cx.SequenceNode {
			return fmt_pretty_items('(', ')', n.items, cur, depth, mut st)
		}
		cx.ArrayNode {
			return fmt_pretty_items('[', ']', n.items, cur, depth, mut st)
		}
		cx.MapNode {
			el := n as cx.MapNode
			return fmt_pretty_map_node(el, cur, depth, mut st)
		}
		cx.Element {
			return fmt_pretty_element(n, cur, depth, mut st)
		}
		else {
			return '<${n}>'
		}
	}
}

// fmt_pretty_items emits a sequence/array collection one item per line.
fn fmt_pretty_items(open string, close string, items []cx.Node, cur string, depth int, mut st PrettyState) string {
	if items.len == 0 {
		return open + close
	}
	child_indent := cur + st.opts.indent
	mut sb := strings.new_builder(64)
	sb.write_string(open)
	for it in items {
		sb.write_string('\n')
		sb.write_string(child_indent)
		sb.write_string(fmt_pretty(it, child_indent, depth + 1, mut st))
		if st.depth_exceeded {
			return sb.str()
		}
	}
	sb.write_string('\n')
	sb.write_string(cur)
	sb.write_string(close)
	return sb.str()
}

// fmt_pretty_map_node emits a `{k: v, …}` MapNode value, one entry per
// line. The key is the flattened scalar `key_value`.
fn fmt_pretty_map_node(m cx.MapNode, cur string, depth int, mut st PrettyState) string {
	if m.entries.len == 0 {
		return '{}'
	}
	child_indent := cur + st.opts.indent
	mut sb := strings.new_builder(64)
	sb.write_string('{')
	for e in m.entries {
		key_str := fmt_map_key(e.key_value, e.key_type, st.opts)
		val_str := fmt_pretty(e.value, child_indent, depth + 1, mut st)
		sb.write_string('\n')
		sb.write_string(child_indent)
		sb.write_string('${key_str}: ${val_str}')
		if st.depth_exceeded {
			return sb.str()
		}
	}
	sb.write_string('\n')
	sb.write_string(cur)
	sb.write_string('}')
	return sb.str()
}

// fmt_map_key renders a MapNode entry key honoring its scalar type. It
// routes through fmt_scalar so a key obeys exactly the same typing rules
// as a value (#978): only a string key is quoted, an atom key keeps its
// `:` sigil, and every other kind emits its bare canonical image.
fn fmt_map_key(v cx.ScalarValue, t cx.ScalarType, opts FormatOpts) string {
	return fmt_scalar(cx.ScalarNode{ value: v, data_type: t }, opts)
}

// fmt_pretty_element emits a named element (or marker envelope) in
// pretty form. Leaf elements (no items) stay on one line; otherwise the
// items each get their own line.
fn fmt_pretty_element(el cx.Element, cur string, depth int, mut st PrettyState) string {
	// collection-literal envelopes route to paren / bracket / brace
	if el.name == '__cx_seq__' {
		return fmt_pretty_items('(', ')', el.items, cur, depth, mut st)
	}
	if el.name == '__cx_arr__' {
		return fmt_pretty_items('[', ']', el.items, cur, depth, mut st)
	}
	if el.name == '__cx_map__' {
		if el.items.len == 0 {
			return '{}'
		}
		child_indent := cur + st.opts.indent
		mut sb := strings.new_builder(64)
		sb.write_string('{')
		for it in el.items {
			if it is cx.Element {
				val_str := if it.items.len > 0 {
					fmt_pretty(it.items[0], child_indent, depth + 1, mut st)
				} else { '' }
				sb.write_string('\n')
				sb.write_string(child_indent)
				sb.write_string('${it.name}: ${val_str}')
				if st.depth_exceeded {
					return sb.str()
				}
			}
		}
		sb.write_string('\n')
		sb.write_string(cur)
		sb.write_string('}')
		return sb.str()
	}
	// anonymous top-level wrapper: items joined by newline at cur indent
	if el.name == '' {
		mut lines := []string{cap: el.items.len}
		for it in el.items {
			lines << fmt_pretty(it, cur, depth, mut st)
			if st.depth_exceeded {
				return lines.join('\n')
			}
		}
		return lines.join('\n')
	}

	mut head := strings.new_builder(32)
	head.write_string('[')
	head.write_string(el.name)
	if st.opts.include_anchors {
		if a := el.anchor() { head.write_string(' &${a}') }
		if mm := el.merge()  { head.write_string(' *${mm}') }
	}
	if id := el.id()        { head.write_string(' #${id}') }
	if dt := el.data_type() { head.write_string(' :${dt}') }
	attrs := sorted_attrs(el.attrs, st.opts.sort_attributes)
	// Render each attribute to its (name, value) sides up front: the name
	// side may carry a glued `::T` annotation (#978), so the alignment
	// column has to be measured over the RENDERED name, not `a.name`.
	mut names := []string{cap: attrs.len}
	mut values := []string{cap: attrs.len}
	for a in attrs {
		n, v := fmt_attr_parts(a, st.opts)
		names << n
		values << v
	}
	// attribute-alignment "colon"/"value": pad attr names so the columns
	// line up. "none" (default) leaves single-space separation.
	mut max_name := 0
	if st.opts.attr_alignment != 'none' {
		for n in names {
			if n.len > max_name { max_name = n.len }
		}
	}
	for i, n in names {
		head.write_string(' ')
		head.write_string(n)
		head.write_string('=')
		if st.opts.attr_alignment == 'value' && n.len < max_name {
			head.write_string(' '.repeat(max_name - n.len))
		}
		head.write_string(values[i])
	}
	head_str := head.str()

	// no body items → single-line leaf
	if el.items.len == 0 {
		return head_str + ']'
	}

	// body items each on their own line, indented one unit deeper.
	child_indent := cur + st.opts.indent
	mut sb := strings.new_builder(64)
	sb.write_string(head_str)
	for it in el.items {
		if it is cx.Element && it.name.starts_with('__cx_slot:') {
			label := it.name['__cx_slot:'.len..]
			body := if it.items.len > 0 {
				fmt_pretty(it.items[0], child_indent, depth + 1, mut st)
			} else { '' }
			sb.write_string('\n')
			sb.write_string(child_indent)
			sb.write_string(':${label} ${body}')
		} else {
			sb.write_string('\n')
			sb.write_string(child_indent)
			sb.write_string(fmt_pretty(it, child_indent, depth + 1, mut st))
		}
		if st.depth_exceeded {
			return sb.str()
		}
	}
	sb.write_string('\n')
	sb.write_string(cur)
	sb.write_string(']')
	return sb.str()
}

// ── dispatch entry ──────────────────────────────────────────────────

// pretty_render runs the pretty emitter under the given opts and returns
// either the formatted string node or a depth-exceeded err-value.
fn pretty_render(value cx.Node, opts FormatOpts) cx.Node {
	mut st := PrettyState{ opts: opts }
	out := fmt_pretty(value, '', 0, mut st)
	if st.depth_exceeded {
		return format_mk_err(format_err_depth_exceed,
			'E_FORMAT_DEPTH_EXCEEDED: value nesting exceeds :max-depth ${opts.max_depth}')
	}
	return format_str(out)
}

// canonical_text is the byte-stable canonical form — exactly the hash
// preimage (spec §1.1). It reuses the program renderer.
fn canonical_text(value cx.Node) string {
	return render_canonical(value)
}

// count_canonical_tokens returns a deterministic token count over the
// canonical text: a token is a maximal run of non-whitespace, non-
// bracket characters, plus each bracket / paren / brace delimiter. Used
// only as a derived statistic for canonical-with-context (§3.3).
fn count_canonical_tokens(s string) i64 {
	mut count := i64(0)
	mut in_tok := false
	for c in s {
		if c == ` ` || c == `\t` || c == `\n` || c == `\r` {
			in_tok = false
			continue
		}
		if c == `[` || c == `]` || c == `(` || c == `)` || c == `{` || c == `}` {
			count++
			in_tok = false
			continue
		}
		if !in_tok {
			count++
			in_tok = true
		}
	}
	return count
}

fn format_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	match name {
		'format-canonical' {
			if args.len != 1 { return none }
			return format_str(canonical_text(args[0]))
		}
		'format-compact' {
			if args.len != 1 { return none }
			// compact == canonical (the renderer already emits the
			// minimum-whitespace single-space-separated form).
			return format_str(canonical_text(args[0]))
		}
		'format-pretty' {
			if args.len != 1 { return none }
			return pretty_render(args[0], FormatOpts{})
		}
		'format-pretty-with-opts' {
			if args.len != 2 { return none }
			opts, err := parse_opts(args[1]) or {
				// opts arg was not a map — surface an invalid-opt error
				return format_mk_err(format_err_invalid_opt,
					'E_FORMAT_INVALID_OPT: opts argument must be a map')
			}
			if err is cx.Element {
				return err // CXER2702
			}
			return pretty_render(args[0], opts)
		}
		'format-diff-friendly' {
			if args.len != 1 { return none }
			// diff-friendly = pretty with sorted attributes + one element
			// per line (stable across CX versions, spec §3.4).
			mut o := FormatOpts{}
			o.sort_attributes = true
			return pretty_render(args[0], o)
		}
		'format-canonical-with-context' {
			if args.len != 1 { return none }
			text := canonical_text(args[0])
			digest := sha256.sum(text.bytes())
			return cx.Element{
				name: 'canonical-result'
				items: [
					format_slot_child('text', format_str(text)),
					format_slot_child('hash', format_bytes(digest)),
					format_slot_child('length', format_int(i64(text.len))),
					format_slot_child('tokens', format_int(count_canonical_tokens(text))),
				]
			}
		}
		'format-emit-stream' {
			if args.len != 2 { return none }
			opts, err := parse_opts(args[1]) or {
				return format_mk_err(format_err_invalid_opt,
					'E_FORMAT_INVALID_OPT: opts argument must be a map')
			}
			if err is cx.Element {
				return err // CXER2702
			}
			// Concatenation of the chunks MUST equal pretty-with-opts;
			// split the pretty output into per-line chunks where each
			// chunk except the last carries its trailing newline so the
			// join reconstructs the original byte-for-byte (spec §3.5 /
			// §6 streaming-concatenation fixture).
			rendered := pretty_render(args[0], opts)
			if rendered is cx.Element {
				return rendered // depth-exceeded err-value
			}
			full := (rendered as cx.ScalarNode).value as string
			return format_seq(split_keep_newlines(full))
		}
		else {
			return none
		}
	}
}

// format_slot_child builds a labeled-slot child element so the
// canonical-result record renders as `:text "…" :hash … :length … :tokens …`.
fn format_slot_child(label string, value cx.Node) cx.Node {
	return cx.Element{
		name:  '__cx_slot:${label}'
		items: [value]
	}
}

// split_keep_newlines splits a string into chunks, keeping the newline
// at the end of each non-final chunk so that joining the chunks yields
// the original string exactly.
fn split_keep_newlines(s string) []string {
	if s == '' {
		return ['']
	}
	mut out := []string{}
	mut start := 0
	for i := 0; i < s.len; i++ {
		if s[i] == `\n` {
			out << s[start..i + 1]
			start = i + 1
		}
	}
	if start < s.len {
		out << s[start..]
	} else if start == s.len && s.len > 0 && s[s.len - 1] == `\n` {
		// trailing newline already captured; nothing trailing to add.
	}
	return out
}
