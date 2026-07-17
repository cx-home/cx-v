module code

// store_grpc_proto.v — protobuf (proto3) wire codec for the CXStore gRPC
// interface (#105 sub-area 2b, brick 1; contract in
// spec/02-working/cxstore_grpc_design.md §2). Hand-rolled for the fixed, flat
// message set (no nested messages, no repeated fields beyond the streaming
// envelopes) — no codegen toolchain, no external runtime. proto3 semantics:
// scalar fields equal to the type default (false / "" / empty bytes) are NOT
// serialized; a decoder treats a missing field as that default and skips
// unknown fields by wire type (forward-compatible).

// ── proto3 wire primitives ───────────────────────────────────────────────────

// wire types we use: 0 = varint (bool), 2 = length-delimited (string/bytes).
const pb_wt_varint = 0
const pb_wt_len = 2

fn pb_write_varint(mut b []u8, value u64) {
	mut v := value
	for {
		if v < 0x80 {
			b << u8(v)
			break
		}
		b << u8((v & 0x7f) | 0x80)
		v >>= 7
	}
}

fn pb_write_tag(mut b []u8, field int, wire_type int) {
	pb_write_varint(mut b, u64(field) << 3 | u64(wire_type))
}

// proto3: empty string is the default → not emitted.
fn pb_write_string(mut b []u8, field int, s string) {
	if s.len == 0 {
		return
	}
	pb_write_tag(mut b, field, pb_wt_len)
	pb_write_varint(mut b, u64(s.len))
	b << s.bytes()
}

fn pb_write_bytes(mut b []u8, field int, data []u8) {
	if data.len == 0 {
		return
	}
	pb_write_tag(mut b, field, pb_wt_len)
	pb_write_varint(mut b, u64(data.len))
	b << data
}

// proto3: false is the default → not emitted.
fn pb_write_bool(mut b []u8, field int, v bool) {
	if !v {
		return
	}
	pb_write_tag(mut b, field, pb_wt_varint)
	pb_write_varint(mut b, 1)
}

// PbReader is a single-pass cursor over a proto3 message body.
struct PbReader {
	data []u8
mut:
	pos int
}

fn (mut r PbReader) eof() bool {
	return r.pos >= r.data.len
}

fn (mut r PbReader) read_varint() ?u64 {
	mut result := u64(0)
	mut shift := u32(0)
	for {
		if r.pos >= r.data.len {
			return none
		}
		b := r.data[r.pos]
		r.pos++
		result |= u64(b & 0x7f) << shift
		if b & 0x80 == 0 {
			break
		}
		shift += 7
		if shift > 63 {
			return none // malformed (overlong varint)
		}
	}
	return result
}

// read_tag returns (field_number, wire_type).
fn (mut r PbReader) read_tag() ?(int, int) {
	key := r.read_varint()?
	return int(key >> 3), int(key & 0x7)
}

// pb_max_len_delim caps a length-delimited field (#224): V's `int` is 32-bit, so
// int(u64) SILENTLY TRUNCATES a large varint length (e.g. 2^32 → 0, bypassing the
// `n < 0` guard and reading 0 bytes → misparse). Validate the u64 against this cap
// BEFORE narrowing to int. 64 MiB comfortably exceeds any legitimate store field.
const pb_max_len_delim = u64(64 * 1024 * 1024)

fn (mut r PbReader) read_len_delim() ?[]u8 {
	nn := r.read_varint()?
	if nn > pb_max_len_delim {
		return none // #224: reject before the lossy int() narrowing
	}
	n := int(nn)
	if n < 0 || r.pos + n > r.data.len {
		return none
	}
	out := r.data[r.pos..r.pos + n].clone()
	r.pos += n
	return out
}

// skip_field advances past a field whose number we do not recognize, so unknown
// fields are tolerated (forward compatibility).
fn (mut r PbReader) skip_field(wire_type int) ? {
	match wire_type {
		pb_wt_varint {
			r.read_varint()?
		}
		pb_wt_len {
			nn := r.read_varint()?
			if nn > pb_max_len_delim {
				return none // #224: reject before the lossy int() narrowing
			}
			n := int(nn)
			if n < 0 || r.pos + n > r.data.len {
				return none
			}
			r.pos += n
		}
		1 { // 64-bit
			if r.pos + 8 > r.data.len {
				return none
			}
			r.pos += 8
		}
		5 { // 32-bit
			if r.pos + 4 > r.data.len {
				return none
			}
			r.pos += 4
		}
		else {
			return none // groups (3/4) unused; unknown → malformed
		}
	}
}

// ── messages (spec §2) ───────────────────────────────────────────────────────

pub struct GrpcGetRequest {
pub mut:
	store string
	hash  string
}

pub struct GrpcGetResponse {
pub mut:
	body     []u8
	encoding string
}

pub struct GrpcPutRequest {
pub mut:
	store    string
	body     []u8
	encoding string
}

pub struct GrpcPutResponse {
pub mut:
	hash   string
	stored bool
}

pub struct GrpcDeleteRequest {
pub mut:
	store string
	hash  string
}

pub struct GrpcDeleteResponse {
pub mut:
	deleted bool
}

pub struct GrpcStoreRequest {
pub mut:
	store string // List / Iter / Capabilities share the shape {store=1}
}

pub struct GrpcHashItem {
pub mut:
	hash string
}

pub struct GrpcDoc {
pub mut:
	hash     string
	body     []u8
	encoding string
}

pub struct GrpcQueryRequest {
pub mut:
	store string
	query []u8
}

pub struct GrpcQueryRow {
pub mut:
	row      []u8
	encoding string
}

pub struct GrpcModifyRequest {
pub mut:
	store  string
	hash   string
	action []u8
}

pub struct GrpcModifyResponse {
pub mut:
	old_hash string
	new_hash string
	stored   bool
}

pub struct GrpcCapabilitiesResponse {
pub mut:
	capabilities []u8
}

// ── encode / decode ──────────────────────────────────────────────────────────

pub fn pb_encode_get_request(m GrpcGetRequest) []u8 {
	mut b := []u8{}
	pb_write_string(mut b, 1, m.store)
	pb_write_string(mut b, 2, m.hash)
	return b
}

pub fn pb_decode_get_request(data []u8) ?GrpcGetRequest {
	mut m := GrpcGetRequest{}
	mut r := PbReader{
		data: data
	}
	for !r.eof() {
		field, wt := r.read_tag()?
		match field {
			1 { m.store = (r.read_len_delim()?).bytestr() }
			2 { m.hash = (r.read_len_delim()?).bytestr() }
			else { r.skip_field(wt)? }
		}
	}
	return m
}

pub fn pb_encode_get_response(m GrpcGetResponse) []u8 {
	mut b := []u8{}
	pb_write_bytes(mut b, 1, m.body)
	pb_write_string(mut b, 2, m.encoding)
	return b
}

pub fn pb_decode_get_response(data []u8) ?GrpcGetResponse {
	mut m := GrpcGetResponse{}
	mut r := PbReader{
		data: data
	}
	for !r.eof() {
		field, wt := r.read_tag()?
		match field {
			1 { m.body = r.read_len_delim()? }
			2 { m.encoding = (r.read_len_delim()?).bytestr() }
			else { r.skip_field(wt)? }
		}
	}
	return m
}

pub fn pb_encode_put_request(m GrpcPutRequest) []u8 {
	mut b := []u8{}
	pb_write_string(mut b, 1, m.store)
	pb_write_bytes(mut b, 2, m.body)
	pb_write_string(mut b, 3, m.encoding)
	return b
}

pub fn pb_decode_put_request(data []u8) ?GrpcPutRequest {
	mut m := GrpcPutRequest{}
	mut r := PbReader{
		data: data
	}
	for !r.eof() {
		field, wt := r.read_tag()?
		match field {
			1 { m.store = (r.read_len_delim()?).bytestr() }
			2 { m.body = r.read_len_delim()? }
			3 { m.encoding = (r.read_len_delim()?).bytestr() }
			else { r.skip_field(wt)? }
		}
	}
	return m
}

pub fn pb_encode_put_response(m GrpcPutResponse) []u8 {
	mut b := []u8{}
	pb_write_string(mut b, 1, m.hash)
	pb_write_bool(mut b, 2, m.stored)
	return b
}

pub fn pb_decode_put_response(data []u8) ?GrpcPutResponse {
	mut m := GrpcPutResponse{}
	mut r := PbReader{
		data: data
	}
	for !r.eof() {
		field, wt := r.read_tag()?
		match field {
			1 { m.hash = (r.read_len_delim()?).bytestr() }
			2 { m.stored = (r.read_varint()?) != 0 }
			else { r.skip_field(wt)? }
		}
	}
	return m
}

pub fn pb_encode_delete_request(m GrpcDeleteRequest) []u8 {
	mut b := []u8{}
	pb_write_string(mut b, 1, m.store)
	pb_write_string(mut b, 2, m.hash)
	return b
}

pub fn pb_decode_delete_request(data []u8) ?GrpcDeleteRequest {
	mut m := GrpcDeleteRequest{}
	mut r := PbReader{
		data: data
	}
	for !r.eof() {
		field, wt := r.read_tag()?
		match field {
			1 { m.store = (r.read_len_delim()?).bytestr() }
			2 { m.hash = (r.read_len_delim()?).bytestr() }
			else { r.skip_field(wt)? }
		}
	}
	return m
}

pub fn pb_encode_delete_response(m GrpcDeleteResponse) []u8 {
	mut b := []u8{}
	pb_write_bool(mut b, 1, m.deleted)
	return b
}

pub fn pb_decode_delete_response(data []u8) ?GrpcDeleteResponse {
	mut m := GrpcDeleteResponse{}
	mut r := PbReader{
		data: data
	}
	for !r.eof() {
		field, wt := r.read_tag()?
		match field {
			1 { m.deleted = (r.read_varint()?) != 0 }
			else { r.skip_field(wt)? }
		}
	}
	return m
}

pub fn pb_encode_store_request(m GrpcStoreRequest) []u8 {
	mut b := []u8{}
	pb_write_string(mut b, 1, m.store)
	return b
}

pub fn pb_decode_store_request(data []u8) ?GrpcStoreRequest {
	mut m := GrpcStoreRequest{}
	mut r := PbReader{
		data: data
	}
	for !r.eof() {
		field, wt := r.read_tag()?
		match field {
			1 { m.store = (r.read_len_delim()?).bytestr() }
			else { r.skip_field(wt)? }
		}
	}
	return m
}

pub fn pb_encode_hash_item(m GrpcHashItem) []u8 {
	mut b := []u8{}
	pb_write_string(mut b, 1, m.hash)
	return b
}

pub fn pb_decode_hash_item(data []u8) ?GrpcHashItem {
	mut m := GrpcHashItem{}
	mut r := PbReader{
		data: data
	}
	for !r.eof() {
		field, wt := r.read_tag()?
		match field {
			1 { m.hash = (r.read_len_delim()?).bytestr() }
			else { r.skip_field(wt)? }
		}
	}
	return m
}

pub fn pb_encode_doc(m GrpcDoc) []u8 {
	mut b := []u8{}
	pb_write_string(mut b, 1, m.hash)
	pb_write_bytes(mut b, 2, m.body)
	pb_write_string(mut b, 3, m.encoding)
	return b
}

pub fn pb_decode_doc(data []u8) ?GrpcDoc {
	mut m := GrpcDoc{}
	mut r := PbReader{
		data: data
	}
	for !r.eof() {
		field, wt := r.read_tag()?
		match field {
			1 { m.hash = (r.read_len_delim()?).bytestr() }
			2 { m.body = r.read_len_delim()? }
			3 { m.encoding = (r.read_len_delim()?).bytestr() }
			else { r.skip_field(wt)? }
		}
	}
	return m
}

pub fn pb_encode_query_request(m GrpcQueryRequest) []u8 {
	mut b := []u8{}
	pb_write_string(mut b, 1, m.store)
	pb_write_bytes(mut b, 2, m.query)
	return b
}

pub fn pb_decode_query_request(data []u8) ?GrpcQueryRequest {
	mut m := GrpcQueryRequest{}
	mut r := PbReader{
		data: data
	}
	for !r.eof() {
		field, wt := r.read_tag()?
		match field {
			1 { m.store = (r.read_len_delim()?).bytestr() }
			2 { m.query = r.read_len_delim()? }
			else { r.skip_field(wt)? }
		}
	}
	return m
}

pub fn pb_encode_query_row(m GrpcQueryRow) []u8 {
	mut b := []u8{}
	pb_write_bytes(mut b, 1, m.row)
	pb_write_string(mut b, 2, m.encoding)
	return b
}

pub fn pb_decode_query_row(data []u8) ?GrpcQueryRow {
	mut m := GrpcQueryRow{}
	mut r := PbReader{
		data: data
	}
	for !r.eof() {
		field, wt := r.read_tag()?
		match field {
			1 { m.row = r.read_len_delim()? }
			2 { m.encoding = (r.read_len_delim()?).bytestr() }
			else { r.skip_field(wt)? }
		}
	}
	return m
}

pub fn pb_encode_modify_request(m GrpcModifyRequest) []u8 {
	mut b := []u8{}
	pb_write_string(mut b, 1, m.store)
	pb_write_string(mut b, 2, m.hash)
	pb_write_bytes(mut b, 3, m.action)
	return b
}

pub fn pb_decode_modify_request(data []u8) ?GrpcModifyRequest {
	mut m := GrpcModifyRequest{}
	mut r := PbReader{
		data: data
	}
	for !r.eof() {
		field, wt := r.read_tag()?
		match field {
			1 { m.store = (r.read_len_delim()?).bytestr() }
			2 { m.hash = (r.read_len_delim()?).bytestr() }
			3 { m.action = r.read_len_delim()? }
			else { r.skip_field(wt)? }
		}
	}
	return m
}

pub fn pb_encode_modify_response(m GrpcModifyResponse) []u8 {
	mut b := []u8{}
	pb_write_string(mut b, 1, m.old_hash)
	pb_write_string(mut b, 2, m.new_hash)
	pb_write_bool(mut b, 3, m.stored)
	return b
}

pub fn pb_decode_modify_response(data []u8) ?GrpcModifyResponse {
	mut m := GrpcModifyResponse{}
	mut r := PbReader{
		data: data
	}
	for !r.eof() {
		field, wt := r.read_tag()?
		match field {
			1 { m.old_hash = (r.read_len_delim()?).bytestr() }
			2 { m.new_hash = (r.read_len_delim()?).bytestr() }
			3 { m.stored = (r.read_varint()?) != 0 }
			else { r.skip_field(wt)? }
		}
	}
	return m
}

pub fn pb_encode_capabilities_response(m GrpcCapabilitiesResponse) []u8 {
	mut b := []u8{}
	pb_write_bytes(mut b, 1, m.capabilities)
	return b
}

pub fn pb_decode_capabilities_response(data []u8) ?GrpcCapabilitiesResponse {
	mut m := GrpcCapabilitiesResponse{}
	mut r := PbReader{
		data: data
	}
	for !r.eof() {
		field, wt := r.read_tag()?
		match field {
			1 { m.capabilities = r.read_len_delim()? }
			else { r.skip_field(wt)? }
		}
	}
	return m
}

// ── object wire (#129 PR-B item 4): ObjectsHave / ObjectsGet / ObjectsPut / Refs /
//    RefsSet. Every object verb is cxd-text-body in, cxd-text-body out (hex object
//    bytes ride the cxd wire — binary-safe), so ONE request/response shape carries all
//    five RPCs: the gRPC framing simply transports the same body store_csrp_route
//    consumes, giving exact CSRP↔gRPC parity with no per-verb structured schema. ───────

pub struct GrpcObjWireRequest {
pub mut:
	store string // {store=1} routes to the named mount, like every other request
	body  []u8   // {body=2} the verb's cxd-text request document
}

pub struct GrpcObjWireResponse {
pub mut:
	body []u8 // {body=1} the verb's cxd-text result document
}

pub fn pb_encode_objwire_request(m GrpcObjWireRequest) []u8 {
	mut b := []u8{}
	pb_write_string(mut b, 1, m.store)
	pb_write_bytes(mut b, 2, m.body)
	return b
}

pub fn pb_decode_objwire_request(data []u8) ?GrpcObjWireRequest {
	mut m := GrpcObjWireRequest{}
	mut r := PbReader{
		data: data
	}
	for !r.eof() {
		field, wt := r.read_tag()?
		match field {
			1 { m.store = (r.read_len_delim()?).bytestr() }
			2 { m.body = r.read_len_delim()? }
			else { r.skip_field(wt)? }
		}
	}
	return m
}

pub fn pb_encode_objwire_response(m GrpcObjWireResponse) []u8 {
	mut b := []u8{}
	pb_write_bytes(mut b, 1, m.body)
	return b
}

pub fn pb_decode_objwire_response(data []u8) ?GrpcObjWireResponse {
	mut m := GrpcObjWireResponse{}
	mut r := PbReader{
		data: data
	}
	for !r.eof() {
		field, wt := r.read_tag()?
		match field {
			1 { m.body = r.read_len_delim()? }
			else { r.skip_field(wt)? }
		}
	}
	return m
}
