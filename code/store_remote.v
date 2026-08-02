@[has_globals]
module code

// Remote byte-source backends for cx-stdlib/store (GH #91, Phase 0.5).
//
// A content-addressed Store opened against a remote URL scheme treats the
// remote as a key→object store: each doc is ONE object named by its SHA-256
// hash under a base prefix. Ops hit the network lazily per key (never load the
// whole store at open). All operations require the `net` capability (gated at
// open in stdlib_store.v).
//
//   s3://bucket/prefix/   — S3-compatible object store (AWS S3, MinIO, R2, B2,
//                           Wasabi). Full CRUD + list. AWS SigV4 request
//                           signing. Credentials + endpoint from the standard
//                           env chain (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
//                           / AWS_REGION / AWS_S3_ENDPOINT|AWS_ENDPOINT_URL).
//   http:// , https://    — read byte-source (get-doc + exists). GET the object
//                           at base+hash. Per store.md §2.3 the HTTP backend is
//                           read-only (writes go through a future http+dav /
//                           CSRP backend).
//
// Transport is the in-module http client (http_do_single, stdlib_http.v); crypto
// is the in-module crypto_hmac + crypto.sha256 (stdlib_crypto.v / V stdlib).

import cx
import os
import time
import crypto.sha256
import encoding.hex

// RemoteBackend is the network config pinned to one open remote Store handle.
@[heap]
struct RemoteBackend {
mut:
	scheme   string // 's3' | 'http' | 'https' | 'ftp' | 'ftps'
	// HTTP(S): base object URL, normalized to end with '/'.
	base_url string
	// S3:
	endpoint string // 'scheme://host[:port]' — custom (MinIO/R2/…) or AWS-derived
	region   string
	bucket   string
	prefix   string // key prefix under the bucket; '' or 'p/'
	access   string
	secret   string
	// host_hdr is the exact Host header http_do_single will send for this
	// endpoint (the bare host, no port) — SigV4 must sign that exact value.
	host_hdr string
	// FTP/FTPS: control-connection target + credentials + remote directory.
	host string
	port int
	user string
	pass string
	dir  string // remote directory, normalized to end with '/' (docs live here)
	// ftps:// TLS peer verification (RFC 4217). Default true (verify against the
	// OS trust store); a store open-opt `tls-verify=false` accepts a self-signed
	// cert (dev / pinned-host testing only).
	tls_verify bool = true
	// sftp:// (#106): auth + host-key options from open-opts. key_path = private
	// key file (publickey auth; needs `read`); known_hosts = known-hosts file for
	// strict host-key verification; host_key_check = "off" disables verification
	// (dev/test only). Password comes from URL userinfo (rb.pass) or opts.
	key_path       string
	known_hosts    string
	host_key_check string
	// cx-store:// CSRP (#78): the http(s) base URL (scheme://host:port) the
	// Layer-1 ops POST to, the store-name (dir), and the Bearer token.
	bearer string
	// #234.2: §5.3 capability discovery, populated by csrp_client_discover at open.
	// csrp_version is the server's advertised protocol semver (validated: the major
	// must match the client's supported major, else open fails); caps_encodings is
	// the server's advertised body encodings (drives cxbin-vs-cxd negotiation);
	// caps_discovered records that a live discovery round trip succeeded (so ops can
	// tell "validated compatible server" from "discovery was skipped/unreachable").
	csrp_version    string
	caps_encodings  []string
	caps_discovered bool
}

// store_remote_active reports whether a MemStore is backed by a remote byte
// source (set at open). The op dispatcher routes through the network path then.
fn store_remote_active(ms &MemStore) bool {
	return ms.remote != unsafe { nil }
}

// ── URL parsing ──────────────────────────────────────────────────────────

// store_url_redact_userinfo masks the userinfo segment of a URL for LOG /
// BANNER output (#644): a `cx-store+http://<token>@host/…` mount printed
// verbatim leaks the bearer token into logs (ftp/sftp `user:pass@` likewise).
// `scheme://anything@rest` → `scheme://***@rest`; URLs without userinfo pass
// through unchanged. Only the authority's userinfo is considered — an `@`
// after the first `/` past the scheme is path data and left alone.
pub fn store_url_redact_userinfo(url string) string {
	scheme_end := url.index('://') or { return url }
	rest := url[scheme_end + 3..]
	authority_end := rest.index('/') or { rest.len }
	authority := rest[..authority_end]
	at := authority.last_index('@') or { return url }
	return url[..scheme_end + 3] + '***' + authority[at..] + rest[authority_end..]
}

// store_remote_parse builds a RemoteBackend from the open URL. S3 credentials
// and the (optional) custom endpoint come from the standard AWS env chain so a
// MinIO/R2/B2 deployment needs no code change. Returns an [err] node on a
// malformed URL or missing S3 credentials.
fn store_remote_parse(url string) (&RemoteBackend, cx.Node, bool) {
	scheme := store_url_scheme(url)
	match scheme {
		'http', 'https' {
			mut base := url
			if !base.ends_with('/') {
				base += '/'
			}
			_, host, _, _ := http_url_parts(url)
			rb := &RemoteBackend{
				scheme:   scheme
				base_url: base
				host_hdr: host
			}
			return rb, store_null(), true
		}
		's3' {
			// s3://bucket/prefix...  → bucket + key prefix
			rest := url['s3://'.len..]
			mut bucket := rest
			mut prefix := ''
			if sl := rest.index('/') {
				bucket = rest[..sl]
				prefix = rest[sl + 1..]
			}
			if bucket == '' {
				return unsafe { nil }, mk_err('cx-err:CXER1100', 'E_STORE_UNRESOLVED_BACKEND: s3 URL missing bucket: ${url}'), false
			}
			if prefix != '' && !prefix.ends_with('/') {
				prefix += '/'
			}
			region := store_env_or('AWS_REGION', store_env_or('AWS_DEFAULT_REGION', 'us-east-1'))
			access := store_env_or('AWS_ACCESS_KEY_ID', '')
			secret := store_env_or('AWS_SECRET_ACCESS_KEY', '')
			if access == '' || secret == '' {
				return unsafe { nil }, mk_err('cx-err:CXER1131', 'E_STORE_AUTH_FAILED: s3 backend needs AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY (standard credential chain)'), false
			}
			mut endpoint := store_env_or('AWS_S3_ENDPOINT', store_env_or('AWS_ENDPOINT_URL_S3',
				store_env_or('AWS_ENDPOINT_URL', '')))
			if endpoint == '' {
				// AWS virtual-host-style endpoint.
				endpoint = 'https://${bucket}.s3.${region}.amazonaws.com'
			}
			if endpoint.ends_with('/') {
				endpoint = endpoint[..endpoint.len - 1]
			}
			_, ehost, _, _ := http_url_parts(endpoint + '/')
			rb := &RemoteBackend{
				scheme:   's3'
				endpoint: endpoint
				region:   region
				bucket:   bucket
				prefix:   prefix
				access:   access
				secret:   secret
				host_hdr: ehost
			}
			return rb, store_null(), true
		}
		'ftp', 'ftps', 'sftp' {
			// ftp://[user[:pass]@]host[:port]/dir/  (also ftps://, sftp://)
			rest := url[scheme.len + 3..] // strip '<scheme>://'
			mut authority := rest
			mut dir := ''
			if sl := rest.index('/') {
				authority = rest[..sl]
				dir = rest[sl..] // keep leading '/'
			}
			mut user := 'anonymous'
			mut pass := 'anonymous@'
			mut hostport := authority
			if at := authority.last_index('@') {
				userinfo := authority[..at]
				hostport = authority[at + 1..]
				if colon := userinfo.index(':') {
					user = userinfo[..colon]
					pass = userinfo[colon + 1..]
				} else {
					user = userinfo
					pass = ''
				}
			}
			default_port := if scheme == 'sftp' { 22 } else { 21 }
			mut host := hostport
			mut port := default_port
			if colon := hostport.last_index(':') {
				host = hostport[..colon]
				port = hostport[colon + 1..].int()
				if port == 0 {
					port = default_port
				}
			}
			if host == '' {
				return unsafe { nil }, mk_err('cx-err:CXER1100', 'E_STORE_UNRESOLVED_BACKEND: ${scheme} URL missing host: ${url}'), false
			}
			if scheme == 'sftp' {
				// SFTP paths are absolute within the (chrooted) SSH session — keep
				// the leading '/'. Empty path → '/'.
				if dir == '' {
					dir = '/'
				}
				if !dir.ends_with('/') {
					dir += '/'
				}
			} else {
				// Per RFC 1738 the ftp URL path is relative to the LOGIN directory
				// (a sequence of CWDs), not the server filesystem root — strip the
				// leading '/' so docs land under the user's home, not the chroot
				// root (which is typically non-writable).
				dir = dir.trim_left('/')
				if dir != '' && !dir.ends_with('/') {
					dir += '/'
				}
			}
			rb := &RemoteBackend{
				scheme: scheme
				host:   host
				port:   port
				user:   user
				pass:   pass
				dir:    dir
			}
			return rb, store_null(), true
		}
		'cx-store', 'cx-store+http', 'cx-store+https' {
			// cx-store://[token@]host[:port]/store-name/  — CSRP client (#78).
			// cx-store+http forces cleartext (loopback/dev); cx-store and
			// cx-store+https use TLS. The bearer token may be carried in the URL
			// userinfo or supplied via open-opts auth (set later in open_impl).
			http_scheme := if scheme == 'cx-store+http' { 'http' } else { 'https' }
			rest := url[scheme.len + 3..] // strip '<scheme>://'
			mut authority := rest
			mut storename := ''
			if sl := rest.index('/') {
				authority = rest[..sl]
				storename = rest[sl + 1..].trim_right('/')
			}
			mut bearer := ''
			mut hostport := authority
			if at := authority.last_index('@') {
				bearer = authority[..at]
				hostport = authority[at + 1..]
			}
			default_port := if http_scheme == 'http' { 80 } else { 443 }
			mut host := hostport
			mut port := default_port
			if colon := hostport.last_index(':') {
				host = hostport[..colon]
				port = hostport[colon + 1..].int()
				if port == 0 {
					port = default_port
				}
			}
			if host == '' {
				return unsafe { nil }, mk_err('cx-err:CXER1100', 'E_STORE_UNRESOLVED_BACKEND: ${scheme} URL missing host: ${url}'), false
			}
			rb := &RemoteBackend{
				scheme:   scheme
				host:     host
				port:     port
				base_url: '${http_scheme}://${host}:${port}'
				dir:      storename
				bearer:   bearer
			}
			return rb, store_null(), true
		}
		'cx-store+grpc', 'cx-store+grpcs' {
			// cx-store+grpc://[token@]host[:port]/store-name/  — the gRPC client
			// transport (the second listener `cx store-serve` exposes when
			// [grpc enabled=true]). Same URL shape + bearer + store-name routing as
			// CSRP; only the framing differs (HTTP/2 + protobuf). cx-store+grpc is
			// h2c cleartext (loopback/dev); cx-store+grpcs is HTTP/2 over TLS. The
			// store ops dispatch to the gRPC client driver (store_grpc_client.v),
			// which reuses the server's H2/HPACK/proto codec from the dialing side —
			// so client and server speak provably the same wire.
			tls := scheme == 'cx-store+grpcs'
			rest := url[scheme.len + 3..] // strip '<scheme>://'
			mut authority := rest
			mut storename := ''
			if sl := rest.index('/') {
				authority = rest[..sl]
				storename = rest[sl + 1..].trim_right('/')
			}
			mut bearer := ''
			mut hostport := authority
			if at := authority.last_index('@') {
				bearer = authority[..at]
				hostport = authority[at + 1..]
			}
			default_port := if tls { 443 } else { 80 }
			mut host := hostport
			mut port := default_port
			if colon := hostport.last_index(':') {
				host = hostport[..colon]
				port = hostport[colon + 1..].int()
				if port == 0 {
					port = default_port
				}
			}
			if host == '' {
				return unsafe { nil }, mk_err('cx-err:CXER1100', 'E_STORE_UNRESOLVED_BACKEND: ${scheme} URL missing host: ${url}'), false
			}
			// TLS-on is derived from the scheme (cx-store+grpcs) at dial time, NOT a
			// field — tls_verify keeps its real meaning (peer-cert verification,
			// default true, overridable via open-opts).
			rb := &RemoteBackend{
				scheme:   scheme
				host:     host
				port:     port
				base_url: '${host}:${port}' // host:port for net_dial (no http(s):// prefix)
				dir:      storename
				bearer:   bearer
			}
			return rb, store_null(), true
		}
		else {
			return unsafe { nil }, mk_err('cx-err:CXER1100', 'E_STORE_UNRESOLVED_BACKEND: ${url}'), false
		}
	}
}

// store_remote_is_grpc reports whether a backend uses the gRPC client transport.
fn store_remote_is_grpc(rb &RemoteBackend) bool {
	return rb.scheme == 'cx-store+grpc' || rb.scheme == 'cx-store+grpcs'
}

// store_sftp_unbuilt is the honest error when sftp:// is used in a build
// compiled without `-d cx_sftp` (the default — no SSH lib linked). Not a stub:
// it performs no effect and reports plainly how to enable the backend.
fn store_sftp_unbuilt() cx.Node {
	return mk_err('cx-err:CXER1100', 'E_STORE_UNRESOLVED_BACKEND: sftp:// backend not built — rebuild with `-d cx_sftp` (#106)')
}

fn store_env_or(name string, deflt string) string {
	v := os.getenv(name)
	if v == '' {
		return deflt
	}
	return v
}

// store_remote_uses_path_style — a custom (non-AWS) endpoint uses path-style
// addressing (host/bucket/key); MinIO, R2 and friends require it.
fn store_remote_uses_path_style(rb &RemoteBackend) bool {
	return !rb.endpoint.contains('.amazonaws.com')
}

// store_remote_object_url builds the full object URL for an S3 key under the
// configured prefix; path-style for custom endpoints, virtual-host for AWS.
fn store_remote_object_url(rb &RemoteBackend, key string) string {
	full_key := rb.prefix + key
	if store_remote_uses_path_style(rb) {
		return '${rb.endpoint}/${rb.bucket}/${full_key}'
	}
	return '${rb.endpoint}/${full_key}'
}

// store_remote_canonical_uri is the SigV4 canonical (URI-encoded) path that
// matches the object URL — path-style includes /bucket, virtual-host does not.
fn store_remote_canonical_uri(rb &RemoteBackend, key string) string {
	full_key := rb.prefix + key
	if store_remote_uses_path_style(rb) {
		return '/${rb.bucket}/' + aws_uri_encode(full_key, false)
	}
	return '/' + aws_uri_encode(full_key, false)
}

// ── AWS SigV4 ──────────────────────────────────────────────────────────────

const sigv4_unreserved = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~'

// aws_uri_encode percent-encodes per the SigV4 rule: every byte except the
// unreserved set is %XX (uppercase hex). When encode_slash is false, '/' is
// preserved (canonical URI paths); when true, '/' is encoded (query values).
pub fn aws_uri_encode(s string, encode_slash bool) string {
	mut out := []u8{}
	for c in s.bytes() {
		if sigv4_unreserved.contains_u8(c) {
			out << c
		} else if c == `/` && !encode_slash {
			out << c
		} else {
			out << `%`
			hi := c >> 4
			lo := c & 0x0F
			out << aws_hex_digit(hi)
			out << aws_hex_digit(lo)
		}
	}
	return out.bytestr()
}

fn aws_hex_digit(v u8) u8 {
	return if v < 10 { `0` + v } else { `A` + (v - 10) }
}

fn sv_hmac256(key []u8, msg string) []u8 {
	return crypto_hmac('sha256', key, msg.bytes()) or { []u8{} }
}

fn sv_sha256_hex(data []u8) string {
	return hex.encode(sha256.sum256(data))
}

// sigv4_signing_key derives the AWS4 signing key:
//   kDate=HMAC("AWS4"+secret, date); kRegion=HMAC(kDate, region);
//   kService=HMAC(kRegion, service); kSigning=HMAC(kService, "aws4_request").
pub fn sigv4_signing_key(secret string, datestamp string, region string, service string) []u8 {
	k_date := sv_hmac256(('AWS4' + secret).bytes(), datestamp)
	k_region := sv_hmac256(k_date, region)
	k_service := sv_hmac256(k_region, service)
	return sv_hmac256(k_service, 'aws4_request')
}

// sigv4_sign computes the final hex signature over a string-to-sign.
pub fn sigv4_sign(secret string, datestamp string, region string, service string, string_to_sign string) string {
	key := sigv4_signing_key(secret, datestamp, region, service)
	return hex.encode(sv_hmac256(key, string_to_sign))
}

// s3_signed_headers builds the SigV4 Authorization + amz headers for one S3
// request and returns them as the extra-headers list for http_do_single. The
// signed header set is fixed (host;x-amz-content-sha256;x-amz-date); Host is
// added by http_do_single itself (bare host) and signed identically here.
fn s3_signed_headers(rb &RemoteBackend, method string, canonical_uri string, query string, body []u8, amzdate string, datestamp string) [][]string {
	payload_hash := sv_sha256_hex(body)
	canonical_headers := 'host:${rb.host_hdr}\nx-amz-content-sha256:${payload_hash}\nx-amz-date:${amzdate}\n'
	signed_headers := 'host;x-amz-content-sha256;x-amz-date'
	canonical_request := '${method}\n${canonical_uri}\n${query}\n${canonical_headers}\n${signed_headers}\n${payload_hash}'
	scope := '${datestamp}/${rb.region}/s3/aws4_request'
	string_to_sign := 'AWS4-HMAC-SHA256\n${amzdate}\n${scope}\n${sv_sha256_hex(canonical_request.bytes())}'
	signature := sigv4_sign(rb.secret, datestamp, rb.region, 's3', string_to_sign)
	auth := 'AWS4-HMAC-SHA256 Credential=${rb.access}/${scope}, SignedHeaders=${signed_headers}, Signature=${signature}'
	return [
		['x-amz-date', amzdate],
		['x-amz-content-sha256', payload_hash],
		['Authorization', auth],
	]
}

// amz_timestamps returns (amzdate "YYYYMMDDTHHMMSSZ", datestamp "YYYYMMDD") in
// UTC. Split out so the deterministic SigV4 test vectors can pin the time.
fn amz_timestamps() (string, string) {
	t := time.utc()
	z2 := fn (n int) string {
		s := n.str()
		return if s.len < 2 { '0' + s } else { s }
	}
	datestamp := '${t.year:04d}${z2(t.month)}${z2(t.day)}'
	amzdate := '${datestamp}T${z2(t.hour)}${z2(t.minute)}${z2(t.second)}Z'
	return amzdate, datestamp
}

// ── transport: one HTTP exchange → (status, body, err?) ─────────────────────

struct RemoteResp {
	status int
	body   []u8
}

// remote_http extracts (status, body) from an http_do_single result, mapping a
// transport-level [err] to CXER1101 E_STORE_BACKEND_UNREACHABLE.
fn remote_http(method string, url string, headers [][]string, body []u8) (RemoteResp, cx.Node, bool) {
	opts := HttpReqOpts{
		follow_redirects: false
		tls_verify:       true
	}
	node := http_do_single(method, url, headers, body, opts)
	if node is cx.Element {
		if node.name == 'err' {
			return RemoteResp{}, store_remote_unreachable(method, url, node), false
		}
		if node.name == 'response' {
			st := http_attr(node, 'status') or { '0' }
			return RemoteResp{
				status: st.int()
				body:   http_body_octets(node)
			}, store_null(), true
		}
	}
	return RemoteResp{}, mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: ${method} ${url}: malformed transport result'), false
}

fn store_remote_unreachable(method string, url string, errn cx.Element) cx.Node {
	mut detail := ''
	if c := http_attr(errn, 'code') {
		detail = c
	}
	// #655: carry the transport error's MESSAGE, not just its code — a §4.5
	// loopback deny (CXER4504) names the fix ("no admitting literal-IP/
	// localhost grant") only in its message, and the bare code cost the
	// reporter the diagnosis.
	if m := http_attr(errn, 'message') {
		if m != '' {
			detail += ': ${m}'
		}
	}
	return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: ${method} ${store_url_redact_userinfo(url)}: ${detail}')
}

// ── S3 object operations ─────────────────────────────────────────────────────

fn s3_object_op(rb &RemoteBackend, method string, key string, query string, body []u8) (RemoteResp, cx.Node, bool) {
	amzdate, datestamp := amz_timestamps()
	canonical_uri := store_remote_canonical_uri(rb, key)
	headers := s3_signed_headers(rb, method, canonical_uri, query, body, amzdate, datestamp)
	mut url := store_remote_object_url(rb, key)
	if query != '' {
		url += '?' + query
	}
	return remote_http(method, url, headers, body)
}

// s3_bucket_list_op signs a ListObjectsV2 request scoped to the key prefix.
fn s3_bucket_list_op(rb &RemoteBackend, continuation string) (RemoteResp, cx.Node, bool) {
	amzdate, datestamp := amz_timestamps()
	// Canonical query: params sorted by key, each URI-encoded (slash encoded).
	// Built directly in lexicographic key order (continuation-token < list-type
	// < prefix) to avoid a sort closure.
	mut params := [][]string{}
	if continuation != '' {
		params << ['continuation-token', continuation]
	}
	params << ['list-type', '2']
	params << ['prefix', rb.prefix]
	mut qs := []string{}
	for p in params {
		qs << '${aws_uri_encode(p[0], true)}=${aws_uri_encode(p[1], true)}'
	}
	query := qs.join('&')
	// Canonical URI for a bucket-scoped request.
	mut canonical_uri := '/'
	if store_remote_uses_path_style(rb) {
		canonical_uri = '/${rb.bucket}/'
	}
	headers := s3_signed_headers(rb, 'GET', canonical_uri, query, []u8{}, amzdate, datestamp)
	mut url := ''
	if store_remote_uses_path_style(rb) {
		url = '${rb.endpoint}/${rb.bucket}/?${query}'
	} else {
		url = '${rb.endpoint}/?${query}'
	}
	return remote_http('GET', url, headers, []u8{})
}

// ── backend-neutral op surface (called from the stdlib_store dispatcher) ─────

// store_remote_get fetches the doc text for `hash`. Returns (text, true) on a
// hit, ('', false, absent-node) for a 404, or an [err] node on transport fault.
fn store_remote_get(rb &RemoteBackend, hash string) (string, cx.Node, bool) {
	match rb.scheme {
		's3' {
			resp, errn, ok := s3_object_op(rb, 'GET', hash, '', []u8{})
			if !ok {
				return '', errn, false
			}
			if resp.status == 404 {
				return '', mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: ${hash}'), false
			}
			if resp.status != 200 {
				return '', store_remote_status_err('GET', hash, resp.status, resp.body), false
			}
			return resp.body.bytestr(), store_null(), true
		}
		'http', 'https' {
			resp, errn, ok := remote_http('GET', rb.base_url + hash, [][]string{}, []u8{})
			if !ok {
				return '', errn, false
			}
			if resp.status == 404 {
				return '', mk_err('cx-err:CXER1121', 'E_STORE_NOT_FOUND: ${hash}'), false
			}
			if resp.status != 200 {
				return '', store_remote_status_err('GET', hash, resp.status, resp.body), false
			}
			return resp.body.bytestr(), store_null(), true
		}
		'cx-store', 'cx-store+http', 'cx-store+https' {
			return csrp_bin_client_get(rb, hash)
		}
		'cx-store+grpc', 'cx-store+grpcs' {
			return grpc_client_get(rb, hash)
		}
		'ftp', 'ftps' {
			return ftp_get(rb, hash)
		}
		'sftp' {
			$if cx_sftp ? {
				return sftp_get(rb, hash)
			} $else {
				return '', store_sftp_unbuilt(), false
			}
		}
		else {
			return '', mk_err('cx-err:CXER1100', 'E_STORE_UNRESOLVED_BACKEND'), false
		}
	}
}

fn store_remote_put(rb &RemoteBackend, hash string, text string) cx.Node {
	match rb.scheme {
		's3' {
			resp, errn, ok := s3_object_op(rb, 'PUT', hash, '', text.bytes())
			if !ok {
				return errn
			}
			if resp.status != 200 && resp.status != 201 {
				return store_remote_status_err('PUT', hash, resp.status, resp.body)
			}
			return store_null()
		}
		'cx-store', 'cx-store+http', 'cx-store+https' {
			return csrp_bin_client_put(rb, hash, text)
		}
		'cx-store+grpc', 'cx-store+grpcs' {
			return grpc_client_put(rb, hash, text)
		}
		'ftp', 'ftps' {
			return ftp_put(rb, hash, text)
		}
		'sftp' {
			$if cx_sftp ? {
				return sftp_put(rb, hash, text)
			} $else {
				return store_sftp_unbuilt()
			}
		}
		else {
			return mk_err('cx-err:CXER1110', 'E_STORE_READ_ONLY: ${rb.scheme}:// is a read-only byte source')
		}
	}
}

fn store_remote_has(rb &RemoteBackend, hash string) (bool, cx.Node, bool) {
	match rb.scheme {
		's3' {
			resp, errn, ok := s3_object_op(rb, 'HEAD', hash, '', []u8{})
			if !ok {
				return false, errn, false
			}
			return resp.status == 200, store_null(), true
		}
		'http', 'https' {
			resp, errn, ok := remote_http('HEAD', rb.base_url + hash, [][]string{}, []u8{})
			if !ok {
				return false, errn, false
			}
			return resp.status == 200, store_null(), true
		}
		'cx-store', 'cx-store+http', 'cx-store+https' {
			return csrp_bin_client_has(rb, hash)
		}
		'cx-store+grpc', 'cx-store+grpcs' {
			return grpc_client_has(rb, hash)
		}
		'ftp', 'ftps' {
			return ftp_has(rb, hash)
		}
		'sftp' {
			$if cx_sftp ? {
				return sftp_has(rb, hash)
			} $else {
				return false, store_sftp_unbuilt(), false
			}
		}
		else {
			return false, mk_err('cx-err:CXER1100', 'E_STORE_UNRESOLVED_BACKEND'), false
		}
	}
}

fn store_remote_delete(rb &RemoteBackend, hash string) (bool, cx.Node, bool) {
	match rb.scheme {
		's3' {
			resp, errn, ok := s3_object_op(rb, 'DELETE', hash, '', []u8{})
			if !ok {
				return false, errn, false
			}
			// S3 DELETE is 204 on success and also 204 for a missing key.
			deleted := resp.status == 200 || resp.status == 204
			return deleted, store_null(), true
		}
		'cx-store', 'cx-store+http', 'cx-store+https' {
			return csrp_bin_client_delete(rb, hash)
		}
		'cx-store+grpc', 'cx-store+grpcs' {
			return grpc_client_delete(rb, hash)
		}
		'ftp', 'ftps' {
			return ftp_delete(rb, hash)
		}
		'sftp' {
			$if cx_sftp ? {
				return sftp_delete(rb, hash)
			} $else {
				return false, store_sftp_unbuilt(), false
			}
		}
		else {
			return false, mk_err('cx-err:CXER1110', 'E_STORE_READ_ONLY: ${rb.scheme}:// is a read-only byte source'), false
		}
	}
}

// store_remote_query routes a CXPath query to a remote backend. Only the CSRP
// service tier (cx-store://) supports server-side query pushdown; every other
// remote byte-source backend (s3/http/ftp/sftp) has no query surface, so it
// returns CXER1709 E_CSRP_OPERATION_UNSUPPORTED rather than silently scanning an
// empty local doc map (#119 — never a silent empty result).
fn store_remote_query(rb &RemoteBackend, cxpath string) cx.Node {
	match rb.scheme {
		'cx-store', 'cx-store+http', 'cx-store+https' {
			return csrp_bin_client_query(rb, cxpath)
		}
		'cx-store+grpc', 'cx-store+grpcs' {
			return grpc_client_query(rb, cxpath)
		}
		else {
			return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: query pushdown is not supported by the ${rb.scheme}:// backend')
		}
	}
}

// store_remote_iter routes a full-store iteration to a remote backend. The CSRP
// service tier (cx-store://) has a dedicated server-side iter op (one round trip,
// server-authoritative order). Every other remote byte-source backend
// (s3/http/ftp/sftp) has no iter surface, so the generic list+get reassembly in
// the store-iter-docs builtin handles those — this dispatcher is consulted only
// for the cx-store scheme; a non-CSRP scheme returns CXER1709 so the caller falls
// back to the generic path rather than receiving a silent empty result.
fn store_remote_iter(rb &RemoteBackend) cx.Node {
	match rb.scheme {
		'cx-store', 'cx-store+http', 'cx-store+https' {
			return csrp_bin_client_iter(rb)
		}
		'cx-store+grpc', 'cx-store+grpcs' {
			return grpc_client_iter(rb)
		}
		else {
			return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: server-side iter is not supported by the ${rb.scheme}:// backend')
		}
	}
}

// csrp_scheme reports whether a remote scheme is the CSRP service tier (any
// transport: HTTP, HTTPS, gRPC, gRPCs) — the tier that has server-side ops
// beyond the byte-source surface (iter/modify/query pushdown, the object wire,
// and the #248 admin plane).
fn csrp_scheme(s string) bool {
	return s in ['cx-store', 'cx-store+http', 'cx-store+https', 'cx-store+grpc', 'cx-store+grpcs']
}

// store_remote_admin routes an admin-plane op (#248 / CSRP §3.10–3.12: status /
// gc / mounts) to a remote backend. Only the CSRP service tier has an admin
// plane; a byte-source backend (s3/http/ftp/sftp) returns CXER1709 honestly.
// The server enforces admin RBAC + tenant — a 401/403 surfaces as CXER1131.
fn store_remote_admin(rb &RemoteBackend, op string) cx.Node {
	match rb.scheme {
		'cx-store', 'cx-store+http', 'cx-store+https' {
			return csrp_client_admin(rb, op)
		}
		'cx-store+grpc', 'cx-store+grpcs' {
			return grpc_client_admin(rb, op)
		}
		else {
			return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: the admin plane (${op}) is not supported by the ${rb.scheme}:// backend')
		}
	}
}

// store_remote_modify routes a structural modify to a remote backend. Only the
// CSRP service tier supports server-side modify pushdown; a plain byte-source
// backend (s3/http/ftp/sftp) exposes no modify surface, so it returns CXER1709
// E_CSRP_OPERATION_UNSUPPORTED rather than silently failing.
fn store_remote_modify(rb &RemoteBackend, hash string, action_text string) cx.Node {
	match rb.scheme {
		'cx-store', 'cx-store+http', 'cx-store+https' {
			return csrp_bin_client_modify(rb, hash, action_text)
		}
		'cx-store+grpc', 'cx-store+grpcs' {
			return grpc_client_modify(rb, hash, action_text)
		}
		else {
			return mk_err('cx-err:CXER1709', 'E_CSRP_OPERATION_UNSUPPORTED: modify pushdown is not supported by the ${rb.scheme}:// backend')
		}
	}
}

// store_remote_list enumerates doc hashes (64-hex object names under the
// prefix). Paginates via the ListObjectsV2 continuation token.
fn store_remote_list(rb &RemoteBackend) ([]string, cx.Node, bool) {
	match rb.scheme {
		's3' {
			mut out := []string{}
			mut token := ''
			for {
				resp, errn, ok := s3_bucket_list_op(rb, token)
				if !ok {
					return []string{}, errn, false
				}
				if resp.status != 200 {
					return []string{}, store_remote_status_err('GET', 'list', resp.status, resp.body), false
				}
				xml := resp.body.bytestr()
				for k in s3_extract_keys(xml) {
					mut name := k
					if rb.prefix != '' && name.starts_with(rb.prefix) {
						name = name[rb.prefix.len..]
					}
					if store_is_doc_hash(name) {
						out << name
					}
				}
				token = s3_extract_tag(xml, 'NextContinuationToken')
				if token == '' || !xml.contains('<IsTruncated>true</IsTruncated>') {
					break
				}
			}
			return out, store_null(), true
		}
		'cx-store', 'cx-store+http', 'cx-store+https' {
			return csrp_bin_client_list(rb)
		}
		'cx-store+grpc', 'cx-store+grpcs' {
			return grpc_client_list(rb)
		}
		'ftp', 'ftps' {
			return ftp_list(rb)
		}
		'sftp' {
			$if cx_sftp ? {
				return sftp_list(rb)
			} $else {
				return []string{}, store_sftp_unbuilt(), false
			}
		}
		else {
			// Plain HTTP has no portable object listing (WebDAV PROPFIND is a
			// future http+dav backend); fail honestly rather than fake an empty
			// list.
			return []string{}, mk_err('cx-err:CXER1100', 'E_STORE_UNRESOLVED_BACKEND: list-docs is not supported on a ${rb.scheme}:// read byte source (needs S3 or WebDAV)'), false
		}
	}
}

fn store_remote_status_err(method string, key string, status int, body []u8) cx.Node {
	if status == 403 || status == 401 {
		return mk_err('cx-err:CXER1131', 'E_STORE_AUTH_FAILED: ${method} ${key}: HTTP ${status}')
	}
	if status == 429 || status == 503 {
		return mk_err('cx-err:CXER1132', 'E_STORE_RATE_LIMIT: ${method} ${key}: HTTP ${status}')
	}
	return mk_err('cx-err:CXER1101', 'E_STORE_BACKEND_UNREACHABLE: ${method} ${key}: HTTP ${status}: ${body.bytestr()#[..256]}')
}

// store_is_doc_hash — a stored doc object is named by a 64-char lowercase hex
// SHA-256; the list filter excludes any non-doc objects sharing the prefix.
fn store_is_doc_hash(s string) bool {
	if s.len != 64 {
		return false
	}
	for c in s.bytes() {
		if !((c >= `0` && c <= `9`) || (c >= `a` && c <= `f`)) {
			return false
		}
	}
	return true
}

// s3_extract_keys pulls every <Key>…</Key> from a ListObjectsV2 XML body.
fn s3_extract_keys(xml string) []string {
	mut out := []string{}
	mut i := 0
	for {
		open := xml.index_after('<Key>', i) or { break }
		start := open + '<Key>'.len
		end := xml.index_after('</Key>', start) or { break }
		out << xml_unescape(xml[start..end])
		i = end + '</Key>'.len
	}
	return out
}

fn s3_extract_tag(xml string, tag string) string {
	open := xml.index('<${tag}>') or { return '' }
	start := open + tag.len + 2
	end := xml.index_after('</${tag}>', start) or { return '' }
	return xml_unescape(xml[start..end])
}

fn xml_unescape(s string) string {
	return s.replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"').replace('&apos;', "'")
}
