@[has_globals]
module code

import cx
import os
import strings

// stdlib_store.v — native primitives + mem:// backend for the
// `cx-stdlib/store` content-addressed object store (spec/std-lib/store.md).
//
// The module's `[?def]` bodies (stdlib_src_store, below) forward to the
// native primitives here, dispatched via stdlib_dispatch.v::stdlib_builtin.
// Storage state cannot be expressed in pure CX (a Store is mutated
// in-place across calls; CX values are immutable), so each open Store is
// a heap MemStore registered in a process-global registry and referenced
// by an integer handle carried on the returned `[store handle=N …]`
// element.
//
// BACKEND COVERAGE (v0.8.0): `mem://` and `file://` are functional.
// `mem://` is the Memory tier (§2.2.1) — pure in-process, no filesystem
// and no network — so per §9 it requires NO host capability (D-STORE-1).
// `file://` is the LocalFiles tier (§2.2.1): it persists the same in-process
// store model to a directory and is capability-gated (`write` for a
// read-write open, `read` for a read-only open) — denied at `open` with
// CXER0271 when ungranted (deny-by-default, security.md §4). On open it
// loads the directory's index (if any); each mutation is written through to
// the index file, so docs/aliases survive across opens of the same path.
// The v0.8.0 on-disk form is a single length-prefixed `.cxstore-index`
// file; the §4.1 sharded/zstd layout is a future on-disk refinement
// (the API contract + content-addressed identity are unaffected). The
// remote/service backends (network I/O) remain deferred to the integration
// suite and are denied at open without a `net` grant.
//
// Doc identity = SHA-256 of the doc's strict canonical bytes (§2.1,
// spec/core/canonical.md §1.2), computed via the Layer-1 text-hash
// surface cx.cx_text_hash over render_canonical(doc) — identical to the
// `cx hash` CLI and cross-binding parity hashes.

// ── mem:// backend state ─────────────────────────────────────────────

// MemStore is the in-process state for one open `mem://` Store handle.
// `docs` maps a doc hash (lowercase hex) → the doc's strict canonical
// text; `doc_order` / `alias_order` preserve insertion order for stable
// list / iter enumeration.
@[heap]
struct MemStore {
mut:
	url         string
	backend     string
	encoding    string
	compression string
	read_only   bool
	is_open     bool
	// root is the filesystem directory for the `file://` backend (the path
	// component of the open URL); empty for the in-process `mem://` backend.
	root        string
	docs        map[string]string
	doc_order   []string
	aliases     map[string]string
	alias_order []string
}

// ── file:// persistence ──────────────────────────────────────────────
//
// The file backend persists the whole store model to a single
// length-prefixed index file under `root`. Records carry an explicit byte
// length so doc text and alias names may contain any bytes (newlines,
// tabs) without an escaping pass. doc_order / alias_order are preserved by
// record order, so a reopened store enumerates identically.

const store_index_name = '.cxstore-index'

fn store_path_from_url(url string) string {
	mut p := url
	if p.starts_with('file://') {
		p = p[7..]
	}
	// `file:///abs` → p starts with '/'; `file://host/abs` → drop the host
	// authority and keep from its first '/'.
	if !p.starts_with('/') {
		if idx := p.index('/') {
			p = p[idx..]
		} else {
			return ''
		}
	}
	return p
}

fn store_find_nl(s string, start int) int {
	for j := start; j < s.len; j++ {
		if s[j] == `\n` {
			return j
		}
	}
	return -1
}

fn store_encode_index(ms &MemStore) string {
	mut sb := strings.new_builder(1024)
	sb.write_string('CXSTORE\tv1\n')
	for h in ms.doc_order {
		body := ms.docs[h]
		sb.write_string('D\t${h}\t${body.len}\n')
		sb.write_string(body)
		sb.write_string('\n')
	}
	for a in ms.alias_order {
		hash := ms.aliases[a]
		sb.write_string('A\t${a.len}\t${hash}\n')
		sb.write_string(a)
		sb.write_string('\n')
	}
	return sb.str()
}

fn store_decode_index(s string, mut ms MemStore) {
	n := s.len
	// skip the header line.
	hnl := store_find_nl(s, 0)
	if hnl < 0 {
		return
	}
	mut i := hnl + 1
	for i < n {
		le := store_find_nl(s, i)
		if le < 0 {
			break
		}
		line := s[i..le]
		i = le + 1
		parts := line.split('\t')
		if parts.len < 3 {
			break
		}
		if parts[0] == 'D' {
			hash := parts[1]
			dlen := parts[2].int()
			if i + dlen > n {
				break
			}
			body := s[i..i + dlen]
			i += dlen + 1 // body + trailing '\n'
			if hash !in ms.docs {
				ms.docs[hash] = body
				ms.doc_order << hash
			}
		} else if parts[0] == 'A' {
			alen := parts[1].int()
			hash := parts[2]
			if i + alen > n {
				break
			}
			name := s[i..i + alen]
			i += alen + 1
			if name !in ms.aliases {
				ms.alias_order << name
			}
			ms.aliases[name] = hash
		} else {
			break
		}
	}
}

// store_persist writes the current store model to `root/.cxstore-index`.
// A no-op for the mem backend. Best-effort: a write failure is swallowed
// (the in-process state remains authoritative for the open handle).
fn store_persist(ms &MemStore) {
	if ms.backend != 'file' || ms.root == '' {
		return
	}
	os.mkdir_all(ms.root) or { return }
	idx := os.join_path(ms.root, store_index_name)
	os.write_file(idx, store_encode_index(ms)) or {}
}

// StoreRegistry holds every open Store keyed by integer handle. Process
// -global and impure — shared across all callers in the process.
//
// The `@[has_globals]` file attribute enables module-level state without
// the `-enable-globals` CLI flag (same as stdlib_random.v / stdlib_uuid.v
// / code/cabi.v). The registry is held behind a nil-default `voidptr`
// global (the proven code/cabi.v streaming-sink form) and lazily
// allocated on first use, since a value initializer carrying a `map`
// field is not const-evaluable.
@[heap]
struct StoreRegistry {
mut:
	stores  map[int]&MemStore
	next_id int
}

__global (
	g_store_reg voidptr
)

fn store_reg() &StoreRegistry {
	if g_store_reg == unsafe { nil } {
		r := &StoreRegistry{
			stores: map[int]&MemStore{}
		}
		g_store_reg = voidptr(r)
	}
	return unsafe { &StoreRegistry(g_store_reg) }
}

fn store_register(ms &MemStore) int {
	mut reg := store_reg()
	reg.next_id++
	id := reg.next_id
	reg.stores[id] = ms
	return id
}

fn store_lookup(id int) ?&MemStore {
	reg := store_reg()
	return reg.stores[id] or { return none }
}

// ── value helpers ────────────────────────────────────────────────────

fn store_str(s string) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(s)
		data_type: cx.ScalarType.string_type
	}
}

fn store_bool(b bool) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(b)
		data_type: cx.ScalarType.bool_type
	}
}

fn store_int(i i64) cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(i)
		data_type: cx.ScalarType.int_type
	}
}

fn store_null() cx.Node {
	return cx.ScalarNode{
		value:     cx.ScalarValue(cx.NullValue{})
		data_type: cx.ScalarType.null_type
	}
}

// store_empty is the absence channel: the empty node-set / empty sequence
// (`code.md` §9.1.2). An alias that does not resolve is "nothing here" — a
// pure, in-memory, optional structural lookup found nothing — absence, NOT a
// `null` value (the §9.1.2.1 no-conflation guard). The caller extracts the
// hash with `[?else]` (getOrElse). SAP C1. (Side-effect unit-null returns —
// set-alias / close — are successful no-payload returns, §9.1.2.1 rule 2b, and
// KEEP `store_null`.)
fn store_empty() cx.Node {
	return cx.Element{
		name:  '__cx_seq__'
		items: []
	}
}

fn store_seq(items []cx.Node) cx.Node {
	return cx.Element{
		name:  seq_marker_name
		items: items
	}
}

fn store_arg_str(n cx.Node) ?string {
	if n is cx.ScalarNode {
		v := n.value
		if v is string {
			return v
		}
	}
	return none
}

// store_handle_of reads the integer Store handle off a `[store handle=N …]`
// element returned by open / open-opts.
fn store_handle_of(n cx.Node) ?int {
	if n is cx.Element {
		for a in n.attrs {
			if a.name == 'handle' {
				return cx.scalar_value_str_public(a.value).int()
			}
		}
	}
	return none
}

const store_closed_msg = 'E_STORE_CLOSED: operation on a closed Store'

// store_get_open resolves a Store argument to its live MemStore. On
// success returns `(store, _, true)`. On failure returns
// `(_, err_node, false)` where err_node is the spec error: CXER0100 for
// an invalid handle, CXER1130 for a closed Store.
fn store_get_open(arg cx.Node) (&MemStore, cx.Node, bool) {
	id := store_handle_of(arg) or {
		return unsafe { nil }, mk_err('cx-err:CXER0100', 'E_OPERAND_KIND: expected a Store element'), false
	}
	ms := store_lookup(id) or {
		return unsafe { nil }, mk_err('cx-err:CXER0100', 'E_OPERAND_KIND: unknown Store handle ${id}'), false
	}
	if !ms.is_open {
		return unsafe { nil }, mk_err('cx-err:CXER1130', store_closed_msg), false
	}
	return ms, store_null(), true
}

// store_doc_hash computes the content identity of a doc node: SHA-256 of
// its strict canonical bytes (lowercase hex), via the Layer-1 text hash.
fn store_doc_hash(doc cx.Node) !string {
	return cx.cx_text_hash(render_canonical(doc))!
}

fn store_url_scheme(url string) string {
	if idx := url.index('://') {
		return url[..idx]
	}
	if ci := url.index(':') {
		return url[..ci]
	}
	return ''
}

// ── open ─────────────────────────────────────────────────────────────

fn store_open_impl(url string, compression string, encoding string, read_only bool) cx.Node {
	scheme := store_url_scheme(url)
	match scheme {
		'mem' {
			comp := if compression == '' { 'none' } else { compression }
			enc := if encoding == '' { 'cxbin' } else { encoding }
			ms := &MemStore{
				url:         url
				backend:     'mem'
				encoding:    enc
				compression: comp
				read_only:   read_only
				is_open:     true
			}
			id := store_register(ms)
			return store_handle_element(id, ms)
		}
		'file' {
			// §9: file/local backend touches the filesystem; the read-path
			// needs `read`, the write-path needs `write`. Gated through the
			// shared cap_guard (Effort A) so the empty default denies with
			// CXER0271 while an Effort-B grant can let it proceed — no longer
			// an unconditional hard-deny.
			cap := if read_only { 'read' } else { 'write' }
			if d := cap_guard(cap, 'store open ${url}') {
				return d
			}
			root := store_path_from_url(url)
			if root == '' {
				return mk_err('cx-err:CXER1100',
					'E_STORE_UNRESOLVED_BACKEND: malformed file URL ${url}')
			}
			comp := if compression == '' { 'none' } else { compression }
			enc := if encoding == '' { 'cxbin' } else { encoding }
			mut ms := &MemStore{
				url:         url
				backend:     'file'
				root:        root
				encoding:    enc
				compression: comp
				read_only:   read_only
				is_open:     true
			}
			// Load the persisted index for this directory, if one exists, so
			// docs/aliases survive across opens. A read-write open creates the
			// directory eagerly so the first put can persist.
			idx := os.join_path(root, store_index_name)
			if os.exists(idx) {
				if content := os.read_file(idx) {
					store_decode_index(content, mut ms)
				}
			} else if !read_only {
				os.mkdir_all(root) or {
					return mk_err('cx-err:CXER1100',
						'E_STORE_UNRESOLVED_BACKEND: cannot create ${root}: ${err.msg()}')
				}
			}
			id := store_register(ms)
			return store_handle_element(id, ms)
		}
		'http', 'https', 'http+dav', 'https+dav', 's3', 'ftp', 'ftps', 'sftp',
		'cx-store', 'cx-store+http', 'cx-store+https' {
			// §9: remote / URL-dispatched backend performs network I/O →
			// requires `net`. Gated through cap_guard; empty default denies
			// (CXER0271), a `net` grant defers to the unimplemented backend.
			if d := cap_guard('net', 'store open ${url}') {
				return d
			}
			return mk_err('cx-err:CXER1100',
				'E_STORE_UNRESOLVED_BACKEND: remote backend not yet implemented (capability granted) in ${url}')
		}
		else {
			return mk_err('cx-err:CXER1100',
				'E_STORE_UNRESOLVED_BACKEND: unknown URL scheme in ${url}')
		}
	}
}

fn store_handle_element(id int, ms &MemStore) cx.Node {
	writable := !ms.read_only
	return cx.Element{
		name:  'store'
		attrs: [
			cx.Attribute{
				name:  'handle'
				value: cx.ScalarValue(i64(id))
			},
			cx.Attribute{
				name:  'backend'
				value: cx.ScalarValue(ms.backend)
			},
			cx.Attribute{
				name:  'url'
				value: cx.ScalarValue(ms.url)
			},
			cx.Attribute{
				name:  'read'
				value: cx.ScalarValue(true)
			},
			cx.Attribute{
				name:  'write'
				value: cx.ScalarValue(writable)
			},
			cx.Attribute{
				name:  'list'
				value: cx.ScalarValue(true)
			},
			cx.Attribute{
				name:  'compression'
				value: cx.ScalarValue(ms.compression)
			},
			cx.Attribute{
				name:  'encoding'
				value: cx.ScalarValue(ms.encoding)
			},
		]
	}
}

// ── primitive dispatch ───────────────────────────────────────────────

fn store_stdlib_builtin(name string, args []cx.Node) ?cx.Node {
	match name {
		'store-open' {
			url := store_arg_str(args[0]) or { return none }
			return store_open_impl(url, '', '', false)
		}
		'store-open-opts' {
			url := store_arg_str(args[0]) or { return none }
			mut compression := ''
			mut encoding := ''
			mut read_only := false
			if args.len > 1 {
				opts := args[1]
				if opts is cx.Element {
					for a in opts.attrs {
						val := cx.scalar_value_str_public(a.value)
						match a.name {
							'compression' { compression = val }
							'encoding' { encoding = val }
							'read-only' { read_only = val == 'true' }
							else {}
						}
					}
				}
			}
			return store_open_impl(url, compression, encoding, read_only)
		}
		'store-put-doc', 'store-put-doc-stream' {
			// mem:// streaming has no distinct wire from the in-process
			// doc: the source's canonical bytes ARE the doc, so the
			// returned hash is identical to put-doc (§3.2).
			mut ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			if ms.read_only {
				return mk_err('cx-err:CXER1110', 'E_STORE_READ_ONLY: ${ms.url}')
			}
			canonical := render_canonical(args[1])
			hash := cx.cx_text_hash(canonical) or {
				return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: hash failed: ${err.msg()}')
			}
			if hash !in ms.docs {
				ms.docs[hash] = canonical
				ms.doc_order << hash
				store_persist(ms)
			}
			return store_str(hash)
		}
		'store-get-doc' {
			mut ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			hash := store_arg_str(args[1]) or { return none }
			if hash !in ms.docs {
				return mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: ${hash}')
			}
			text := ms.docs[hash]
			rehash := cx.cx_text_hash(text) or {
				return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${hash}')
			}
			if rehash != hash {
				return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: stored ${hash} rehashes to ${rehash}')
			}
			parsed := cx.parse(text) or {
				return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: undecodable doc at ${hash}')
			}
			if parsed.elements.len > 0 {
				return parsed.elements[0]
			}
			return store_null()
		}
		'store-list-docs' {
			ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			mut items := []cx.Node{}
			for h in ms.doc_order {
				items << store_str(h)
			}
			return store_seq(items)
		}
		'store-iter-docs' {
			ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			// §3.4: yields [hash $h doc $d] element pairs. mem:// is
			// bounded, so eager materialization keeps the same shape.
			mut items := []cx.Node{}
			for h in ms.doc_order {
				doc_node := store_decode_doc(ms.docs[h])
				items << cx.Element{
					name:  'entry'
					attrs: [cx.Attribute{
						name:  'hash'
						value: cx.ScalarValue(h)
					}]
					items: [doc_node]
				}
			}
			return store_seq(items)
		}
		'store-exists' {
			ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			hash := store_arg_str(args[1]) or { return none }
			return store_bool(hash in ms.docs)
		}
		'store-delete-doc' {
			mut ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			if ms.read_only {
				return mk_err('cx-err:CXER1110', 'E_STORE_READ_ONLY: ${ms.url}')
			}
			hash := store_arg_str(args[1]) or { return none }
			if hash in ms.docs {
				ms.docs.delete(hash)
				idx := ms.doc_order.index(hash)
				if idx >= 0 {
					ms.doc_order.delete(idx)
				}
				store_persist(ms)
				return store_bool(true)
			}
			return store_bool(false)
		}
		'store-modify-doc' {
			return store_modify_doc(args)
		}
		'store-query' {
			return store_query(args)
		}
		'store-capabilities' {
			ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			writable := !ms.read_only
			return cx.Element{
				name:  'map'
				attrs: [
					cx.Attribute{
						name:  'read'
						value: cx.ScalarValue(true)
					},
					cx.Attribute{
						name:  'write'
						value: cx.ScalarValue(writable)
					},
					cx.Attribute{
						name:  'list'
						value: cx.ScalarValue(true)
					},
					cx.Attribute{
						name:  'backend'
						value: cx.ScalarValue(ms.backend)
					},
					cx.Attribute{
						name:  'url'
						value: cx.ScalarValue(ms.url)
					},
					cx.Attribute{
						name:  'compression'
						value: cx.ScalarValue(ms.compression)
					},
					cx.Attribute{
						name:  'encoding'
						value: cx.ScalarValue(ms.encoding)
					},
				]
			}
		}
		'store-close' {
			mut ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			ms.is_open = false
			return store_null()
		}
		'store-set-alias' {
			mut ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			if ms.read_only {
				return mk_err('cx-err:CXER1110', 'E_STORE_READ_ONLY: ${ms.url}')
			}
			alias := store_arg_str(args[1]) or { return none }
			hash := store_arg_str(args[2]) or { return none }
			if hash !in ms.docs {
				return mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: alias target ${hash}')
			}
			if alias !in ms.aliases {
				ms.alias_order << alias
			}
			ms.aliases[alias] = hash
			store_persist(ms)
			return store_null()
		}
		'store-get-alias' {
			ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			alias := store_arg_str(args[1]) or { return none }
			if alias in ms.aliases {
				return store_str(ms.aliases[alias])
			}
			return store_empty() // §9.1.2: alias miss → absence, not null
		}
		'store-list-aliases' {
			ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			mut items := []cx.Node{}
			for a in ms.alias_order {
				items << cx.Element{
					name:  'alias'
					attrs: [
						cx.Attribute{
							name:  'name'
							value: cx.ScalarValue(a)
						},
						cx.Attribute{
							name:  'hash'
							value: cx.ScalarValue(ms.aliases[a])
						},
					]
				}
			}
			return store_seq(items)
		}
		'store-delete-alias' {
			mut ms, errn, ok := store_get_open(args[0])
			if !ok {
				return errn
			}
			if ms.read_only {
				return mk_err('cx-err:CXER1110', 'E_STORE_READ_ONLY: ${ms.url}')
			}
			alias := store_arg_str(args[1]) or { return none }
			if alias in ms.aliases {
				ms.aliases.delete(alias)
				idx := ms.alias_order.index(alias)
				if idx >= 0 {
					ms.alias_order.delete(idx)
				}
				store_persist(ms)
				return store_bool(true)
			}
			return store_bool(false)
		}
		'store-migrate' {
			return store_migrate(args)
		}
		else {
			return none
		}
	}
}

// store_decode_doc parses a stored canonical doc text back to a node.
fn store_decode_doc(text string) cx.Node {
	parsed := cx.parse(text) or { return store_null() }
	if parsed.elements.len > 0 {
		return parsed.elements[0]
	}
	return store_null()
}

// store_modify_doc implements §3.6: fetch the doc at `hash`, apply the
// `action`, store the result as a NEW doc (content-addressed = immutable;
// the original is never deleted), return the new hash.
//
// SUBSET (v0.8.0 first landing): the action verbs supported in the mem://
// backend are `[set-attr name=N value=V]`, `[remove-attr name=N]`,
// `[append CHILD…]`, and `[rename NEW]` on the doc root element. The full
// Layer-1 modify surface (path-targeted edits) is deferred to the
// integration suite; an unsupported action raises CXER0100.
fn store_modify_doc(args []cx.Node) ?cx.Node {
	mut ms, errn, ok := store_get_open(args[0])
	if !ok {
		return errn
	}
	if ms.read_only {
		return mk_err('cx-err:CXER1110', 'E_STORE_READ_ONLY: ${ms.url}')
	}
	hash := store_arg_str(args[1]) or { return none }
	if hash !in ms.docs {
		return mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: ${hash}')
	}
	doc := store_decode_doc(ms.docs[hash])
	if doc !is cx.Element {
		return mk_err('cx-err:CXER0100', 'E_OPERAND_KIND: doc root is not an element')
	}
	mut el := doc as cx.Element
	action := args[2]
	if action !is cx.Element {
		return mk_err('cx-err:CXER0100', 'E_OPERAND_KIND: modify action must be an element')
	}
	act := action as cx.Element
	match act.name {
		'set-attr' {
			mut aname := ''
			mut aval := ''
			for a in act.attrs {
				v := cx.scalar_value_str_public(a.value)
				if a.name == 'name' {
					aname = v
				}
				if a.name == 'value' {
					aval = v
				}
			}
			mut found := false
			for mut a in el.attrs {
				if a.name == aname {
					a.value = cx.ScalarValue(aval)
					found = true
				}
			}
			if !found {
				el.attrs << cx.Attribute{
					name:  aname
					value: cx.ScalarValue(aval)
				}
			}
		}
		'remove-attr' {
			mut aname := ''
			for a in act.attrs {
				if a.name == 'name' {
					aname = cx.scalar_value_str_public(a.value)
				}
			}
			mut kept := []cx.Attribute{}
			for a in el.attrs {
				if a.name != aname {
					kept << a
				}
			}
			el.attrs = kept
		}
		'append' {
			for child in act.items {
				el.items << child
			}
		}
		'rename' {
			mut newname := ''
			for it in act.items {
				if it is cx.ScalarNode {
					newname = cx.scalar_value_str_public(it.value)
				}
			}
			if newname != '' {
				el.name = newname
			}
		}
		else {
			return mk_err('cx-err:CXER0100',
				'E_OPERAND_KIND: unsupported mem:// modify action "${act.name}"')
		}
	}
	new_canonical := render_canonical(el)
	new_hash := cx.cx_text_hash(new_canonical) or {
		return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${err.msg()}')
	}
	if new_hash !in ms.docs {
		ms.docs[new_hash] = new_canonical
		ms.doc_order << new_hash
		store_persist(ms)
	}
	return store_str(new_hash)
}

// store_query implements a SUBSET of §3.5 for the mem:// backend: the
// element-name descendant (`//name`) and direct-child (`/name`) steps.
// Returns a sequence of [hash $h matches [sequence …]] for docs with a
// non-empty match. The full CXPath grammar + parallel scan are deferred
// to the integration suite.
fn store_query(args []cx.Node) ?cx.Node {
	ms, errn, ok := store_get_open(args[0])
	if !ok {
		return errn
	}
	// The CXPath argument is a plain string scalar; take its raw value, NOT
	// render_canonical (which would quote it to `'//user'` and defeat the
	// `//` / `/` prefix check).
	path_text := (store_arg_str(args[1]) or { return none }).trim_space()
	mut descendant := false
	mut target := path_text
	if target.starts_with('//') {
		descendant = true
		target = target[2..]
	} else if target.starts_with('/') {
		target = target[1..]
	}
	mut results := []cx.Node{}
	for h in ms.doc_order {
		doc := store_decode_doc(ms.docs[h])
		mut matches := []cx.Node{}
		store_collect_by_name(doc, target, descendant, mut matches)
		if matches.len > 0 {
			results << cx.Element{
				name:  'result'
				attrs: [cx.Attribute{
					name:  'hash'
					value: cx.ScalarValue(h)
				}]
				items: [store_seq(matches)]
			}
		}
	}
	return store_seq(results)
}

// store_collect_by_name walks `node` collecting elements named `target`.
// When `descendant` is true it recurses into every descendant; otherwise
// it inspects only the direct children of the root element.
fn store_collect_by_name(node cx.Node, target string, descendant bool, mut out []cx.Node) {
	if node is cx.Element {
		for child in node.items {
			if child is cx.Element {
				if child.name == target {
					out << child
				}
			}
			if descendant {
				store_collect_by_name(child, target, descendant, mut out)
			}
		}
	}
}

// store_migrate implements §3.10: copy every doc + alias from `from` to
// `to`, re-validating integrity on fetch. Doc IDs are content hashes, so
// IDs are preserved. Returns the migration-report element.
fn store_migrate(args []cx.Node) ?cx.Node {
	from, ferr, fok := store_get_open(args[0])
	if !fok {
		return ferr
	}
	mut to, terr, tok := store_get_open(args[1])
	if !tok {
		return terr
	}
	if to.read_only {
		return mk_err('cx-err:CXER1110', 'E_STORE_READ_ONLY: ${to.url}')
	}
	mut doc_count := 0
	mut verified := 0
	mut bytes_written := 0
	for h in from.doc_order {
		text := from.docs[h]
		rehash := cx.cx_text_hash(text) or {
			return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: ${h}')
		}
		if rehash != h {
			return mk_err('cx-err:CXER1120', 'E_STORE_INTEGRITY_MISMATCH: stored ${h} rehashes to ${rehash}')
		}
		verified++
		if h !in to.docs {
			to.docs[h] = text
			to.doc_order << h
			bytes_written += text.len
		}
		doc_count++
	}
	for a in from.alias_order {
		if a !in to.aliases {
			to.alias_order << a
		}
		to.aliases[a] = from.aliases[a]
	}
	store_persist(to)
	return cx.Element{
		name:  'migration-report'
		attrs: [
			cx.Attribute{
				name:  'doc-count'
				value: cx.ScalarValue(i64(doc_count))
			},
			cx.Attribute{
				name:  'hashes-verified'
				value: cx.ScalarValue(i64(verified))
			},
			cx.Attribute{
				name:  'bytes-written'
				value: cx.ScalarValue(i64(bytes_written))
			},
		]
	}
}

// ── bundled module source ────────────────────────────────────────────
//
// The canonical cx-stdlib/store surface. Bodies forward to the native
// primitives above. Registered into the module table by stdlib_bundle.v.

const stdlib_src_store = $embed_file('../stdlib/store.cx').to_string()
