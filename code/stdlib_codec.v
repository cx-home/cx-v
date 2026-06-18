module code

import cx

// stdlib_codec.v — registry-driven in-program codec surface (design D2/D6).
//
// ONE dispatch covers EVERY codec in the cx registry: `<fmt>-parse`,
// `<fmt>-emit`, `<fmt>-parse-bytes`, `<fmt>-emit-bytes` route to the
// node-level entry points in `vcx/cx/codec.v` (codec_parse_node /
// codec_emit_node / codec_parse_bytes_node / codec_emit_bytes_node). Adding a
// codec to the registry makes it callable in-program with no edit here — the
// loop reads `cx.codec_names()`.
//
// Chained AFTER the dedicated stdlib codec modules (json/csv/url/html) in
// `stdlib_dispatch.v`, so those keep precedence on a name clash until S3 folds
// their implementations onto this same registry. In practice this dispatch
// serves the codecs that have NO dedicated module today — cx, xml, yaml, toml,
// md, and the binary codecs (cxcol/data-bin/ast, `*-bytes` only).
//
// Purity (§5): codecs are pure `bytes ⇄ tree` transforms. These primitives are
// unclassified → default-pure under purity_checker.v, charge no capability.

const codec_parse_err = 'cx-err:CXER0100' // PARSE_ERROR (conversions.md §)

fn codec_str_node(s string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.string_type
	}
}

fn codec_bytes_node(b []u8) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(b.bytestr())
		data_type: cx.ScalarType.bytes_type
	}
}

fn codec_arg_str(n cx.Node) ?string {
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

// codec_name_of extracts a codec name from a string OR atom scalar (a leading
// `:` is tolerated), or a TextNode.
fn codec_name_of(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v.trim_left(':')
		}
	}
	if n is cx.TextNode {
		return n.value
	}
	return none
}

// codec_is_atom reports whether `n` is the atom `:name`.
fn codec_is_atom(n cx.Node, name string) bool {
	if n is cx.ScalarNode && n.data_type == cx.ScalarType.atom_type {
		v := n.value
		if v is string {
			return v.trim_left(':') == name
		}
	}
	return false
}

// codec_convert implements `[$convert SRC :from <codec> :to <codec>]` (codec.md
// §7) — sugar over the one registry, equivalent to
// `[$<to>:emit [$<from>:parse SRC]]`. It scans for the `:from`/`:to` atom
// markers (codec names accepted as atom OR string), takes the first positional
// string as SRC, and routes through `convert_by_name`. NOT a parallel impl.
fn codec_convert(args []cx.Node) ?cx.Node {
	mut src := ''
	mut have_src := false
	mut from := ''
	mut to := ''
	mut i := 0
	for i < args.len {
		a := args[i]
		if codec_is_atom(a, 'from') && i + 1 < args.len {
			from = codec_name_of(args[i + 1]) or { '' }
			i += 2
			continue
		}
		if codec_is_atom(a, 'to') && i + 1 < args.len {
			to = codec_name_of(args[i + 1]) or { '' }
			i += 2
			continue
		}
		if !have_src {
			if s := codec_arg_str(a) {
				src = s
				have_src = true
			}
		}
		i++
	}
	if !have_src {
		return mk_err(codec_parse_err, 'E_CONVERT: [\$convert] needs a source string')
	}
	if from == '' || to == '' {
		return mk_err(codec_parse_err, 'E_CONVERT: [\$convert] needs :from and :to codec names')
	}
	out := cx.convert_by_name(src, from, to, false) or { return mk_err(codec_parse_err, err.msg()) }
	return codec_str_node(out)
}

fn codec_registry_dispatch(name string, args []cx.Node) ?cx.Node {
	if name == 'convert' {
		return codec_convert(args)
	}
	for fmt in cx.codec_names() {
		// Accept BOTH the flat `<fmt>-<op>` dispatch name and the namespaced
		// `<fmt>:<op>` form documented in codec.md §7 (`[$<from>:parse]`).
		if name == '${fmt}-parse' || name == '${fmt}:parse' {
			if args.len < 1 {
				return none
			}
			s := codec_arg_str(args[0]) or { return none }
			return cx.codec_parse_node(fmt, s) or { return mk_err(codec_parse_err, err.msg()) }
		}
		if name == '${fmt}-parse-bytes' || name == '${fmt}:parse-bytes' {
			if args.len < 1 {
				return none
			}
			s := codec_arg_str(args[0]) or { return none }
			return cx.codec_parse_bytes_node(fmt, s.bytes()) or {
				return mk_err(codec_parse_err, err.msg())
			}
		}
		if name == '${fmt}-emit' || name == '${fmt}:emit' {
			if args.len < 1 {
				return none
			}
			out := cx.codec_emit_node(fmt, args[0], false) or {
				return mk_err(codec_parse_err, err.msg())
			}
			return codec_str_node(out)
		}
		if name == '${fmt}-emit-bytes' || name == '${fmt}:emit-bytes' {
			if args.len < 1 {
				return none
			}
			b := cx.codec_emit_bytes_node(fmt, args[0]) or {
				return mk_err(codec_parse_err, err.msg())
			}
			return codec_bytes_node(b)
		}
	}
	return none
}

// ── json codec parse registration (item C: deprecated-parser retirement) ─────
//
// The lower `cx` registry's `json` entry carries only the emitter — its strict,
// lossless parser lives here in `code` (json_do_parse, vcx/code/stdlib_json.v),
// which `cx` cannot import. At program init we register that parser as the
// canonical `json` codec parse, so the CLI (`--from=json`), the C ABI
// (cx_json_to_*) and convert_by_name all do the SAME lossless map/array/scalar
// read that `[$json:parse]` does — retiring the element-synthesising
// `cx.parse_json_cx` (conversions.md §4.1, json.md §2). V runs this `init`
// before main / the libcx constructor, after const init, so the overlay is
// populated before the first lookup.
fn init() {
	cx.register_codec(cx.Codec{
		name:  'json'
		parse: json_codec_parse
	})
}

// json_codec_parse adapts json_do_parse to the registry's parse signature.
// Strict-parse errors (CXER3100..3106) surface as V errors so the CLI / ABI
// report them rather than emitting a bogus tree. On success the value node's
// collection markers (__cx_map__/__cx_arr__/__cx_seq__) are rewritten to
// cx-native MapNode / ArrayNode / SequenceNode (flatten_node) so the cx-tree
// emitters render the lossless value model. A `$tag`-encoded element decodes
// back to its CX element (json_maybe_named, already applied inside the parser).
fn json_codec_parse(src string) !cx.ParseResult {
	node := json_do_parse(src, map[string]cx.Node{})
	if emsg := codec_node_err(node) {
		return error(emsg)
	}
	return cx.ParseResult{
		is_multi: false
		single:   cx.Document{
			elements: [flatten_node(node)]
		}
	}
}

// codec_node_err returns the formatted message when `n` is a strict-parse error
// sentinel (mk_err: an `err` element whose `code` attribute is a `cx-err:…`
// code). A successfully-parsed JSON object named "err" is a `__cx_map__`
// marker, never this shape, so there is no collision.
fn codec_node_err(n cx.Node) ?string {
	if n is cx.Element && n.name == 'err' {
		mut err_code := ''
		mut msg := ''
		for a in n.attrs {
			val := a.value
			if val is string {
				match a.name {
					'code' { err_code = val }
					'message' { msg = val }
					else {}
				}
			}
		}
		if err_code.starts_with('cx-err:') {
			return if msg != '' { msg } else { err_code }
		}
	}
	return none
}
