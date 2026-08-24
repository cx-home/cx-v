module platform

import cx
import strings
import sync

// store_observability.v — the daemon's metrics registry + Prometheus text
// exposition (observability sub-area, decision 1a; spec §4.1 / Appendix F).
//
// Cardinality is bounded BY CONSTRUCTION: the only labels are (endpoint, status,
// store), each normalized to a fixed set (obs_norm_endpoint / obs_norm_store)
// before it ever reaches the registry. A client spraying bogus store-names or
// paths can therefore never inflate the series count — the same "no client may
// degrade the shared service" discipline the DoS limiter enforces, applied to
// the metrics plane. The registry is shared across worker threads → mutex-guarded
// like ServiceState / KeyCache / Limiter.

// obs_latency_buckets — request-latency histogram upper bounds in seconds
// (Prometheus convention; ascending, `+Inf` implied). 1ms … 10s spans the range
// from an in-memory hit to a slow networked backend.
const obs_latency_buckets = [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0,
	2.5, 5.0, 10.0]

// obs_known_endpoints — the fixed endpoint label set; any other op normalizes to
// `_other` so the raw request path never becomes a label value. Includes the #129
// object-wire verbs (objects-have/get/put + refs/refs-set) so the content-addressed
// transfer plane is observable per-verb (metrics + trace spans), not collapsed to
// `_other` — the same bounded-cardinality set covers both the document + object wires.
const obs_known_endpoints = ['capabilities', 'get', 'put', 'delete', 'list', 'iter',
	'query', 'modify', 'health', 'ready', 'metrics', 'objects-have', 'objects-get',
	'objects-put', 'refs', 'refs-set', 'aliases', 'aliases-set']

// histogram accumulates per-bucket (non-cumulative) counts plus sum/count; the
// cumulative `le` series are computed at render time.
struct Histogram {
mut:
	counts []u64 // len == obs_latency_buckets.len; counts[i] = observations in (buckets[i-1], buckets[i]]
	sum    f64
	count  u64
}

fn new_histogram() Histogram {
	return Histogram{
		counts: []u64{len: obs_latency_buckets.len}
	}
}

fn (mut h Histogram) observe(secs f64) {
	for i, ub in obs_latency_buckets {
		if secs <= ub {
			h.counts[i]++
			break
		}
	}
	// observations above the largest bucket still count toward +Inf (sum/count).
	h.sum += secs
	h.count++
}

// MetricsRegistry is the daemon-wide, thread-safe metrics store. Keys are the
// pre-normalized label tuples joined by 0x1f (unit separator — never appears in a
// normalized label), so the map can never collide a legitimate label containing
// a delimiter.
@[heap]
pub struct MetricsRegistry {
mut:
	mu        &sync.Mutex = sync.new_mutex()
	requests  map[string]u64       // "endpoint|status|store" -> count
	bytes_in  map[string]u64       // "endpoint|store" -> bytes
	bytes_out map[string]u64       // "endpoint|store" -> bytes
	latency   map[string]Histogram // "endpoint|store" -> Histogram
	inflight  i64
	version   string
	reloads   map[string]u64 // §2.6 config-reload attempts, "outcome" -> count
}

pub fn new_metrics_registry(version string) &MetricsRegistry {
	return &MetricsRegistry{
		version: version
	}
}

const obs_sep = '\x1f'

// obs_norm_endpoint maps a raw op to the bounded endpoint label set.
fn obs_norm_endpoint(op string) string {
	return if op in obs_known_endpoints { op } else { '_other' }
}

// obs_norm_store maps a store-name to a configured mount name or `_unknown`, so a
// bogus / per-request store-name can never become a distinct series.
fn obs_norm_store(sname string, mounts map[string]cx.Node) string {
	return if sname in mounts { sname } else { '_unknown' }
}

// record_request books one served request. endpoint/store MUST already be
// normalized by the caller (svc_handle_request, which holds the mount set).
fn (mut m MetricsRegistry) record_request(endpoint string, status int, store string, bytes_in u64, bytes_out u64, dur_secs f64) {
	m.mu.@lock()
	defer {
		m.mu.unlock()
	}
	rk := endpoint + obs_sep + status.str() + obs_sep + store
	m.requests[rk]++
	lk := endpoint + obs_sep + store
	m.bytes_in[lk] += bytes_in
	m.bytes_out[lk] += bytes_out
	mut h := m.latency[lk] or { new_histogram() }
	h.observe(dur_secs)
	m.latency[lk] = h
}

// record_reload books one §2.6 config-reload attempt by outcome
// (applied | noop | invalid | restart-required — the F.1 label set).
pub fn (mut m MetricsRegistry) record_reload(outcome string) {
	m.mu.@lock()
	m.reloads[outcome]++
	m.mu.unlock()
}

// enter_inflight / exit_inflight track the in-dispatch gauge.
fn (mut m MetricsRegistry) enter_inflight() {
	m.mu.@lock()
	m.inflight++
	m.mu.unlock()
}

fn (mut m MetricsRegistry) exit_inflight() {
	m.mu.@lock()
	if m.inflight > 0 {
		m.inflight--
	}
	m.mu.unlock()
}

// obs_label_esc escapes a Prometheus label value (backslash, double-quote,
// newline) per the text exposition format.
fn obs_label_esc(s string) string {
	return s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
}

// render_prometheus emits the registry in the Prometheus text exposition format.
// Series and label tuples are sorted so the output is deterministic (stable for
// diff-based tests and for scrapers that fingerprint payloads).
pub fn (mut m MetricsRegistry) render_prometheus() string {
	m.mu.@lock()
	defer {
		m.mu.unlock()
	}
	mut b := strings.new_builder(2048)

	// cxstore_build_info
	b.writeln('# HELP cxstore_build_info Static build identification (always 1).')
	b.writeln('# TYPE cxstore_build_info gauge')
	b.writeln('cxstore_build_info{version="${obs_label_esc(m.version)}"} 1')

	// cxstore_requests_total
	b.writeln('# HELP cxstore_requests_total Total CSRP requests served, by endpoint, status, store.')
	b.writeln('# TYPE cxstore_requests_total counter')
	mut rkeys := m.requests.keys()
	rkeys.sort()
	for k in rkeys {
		parts := k.split(obs_sep)
		b.writeln('cxstore_requests_total{endpoint="${obs_label_esc(parts[0])}",status="${obs_label_esc(parts[1])}",store="${obs_label_esc(parts[2])}"} ${m.requests[k]}')
	}

	// cxstore_config_reload_total (§2.6) — emitted once a reload has been
	// attempted (no fabricated zero series, F.1 posture).
	if m.reloads.len > 0 {
		b.writeln('# HELP cxstore_config_reload_total Config reload attempts by outcome (§2.6).')
		b.writeln('# TYPE cxstore_config_reload_total counter')
		mut okeys := m.reloads.keys()
		okeys.sort()
		for k in okeys {
			b.writeln('cxstore_config_reload_total{outcome="${obs_label_esc(k)}"} ${m.reloads[k]}')
		}
	}

	// cxstore_request_duration_seconds (histogram)
	b.writeln('# HELP cxstore_request_duration_seconds CSRP request latency in seconds.')
	b.writeln('# TYPE cxstore_request_duration_seconds histogram')
	mut lkeys := m.latency.keys()
	lkeys.sort()
	for k in lkeys {
		parts := k.split(obs_sep)
		ep := obs_label_esc(parts[0])
		st := obs_label_esc(parts[1])
		h := m.latency[k]
		mut cum := u64(0)
		for i, ub in obs_latency_buckets {
			cum += h.counts[i]
			b.writeln('cxstore_request_duration_seconds_bucket{endpoint="${ep}",store="${st}",le="${obs_fmt_f64(ub)}"} ${cum}')
		}
		b.writeln('cxstore_request_duration_seconds_bucket{endpoint="${ep}",store="${st}",le="+Inf"} ${h.count}')
		b.writeln('cxstore_request_duration_seconds_sum{endpoint="${ep}",store="${st}"} ${obs_fmt_f64(h.sum)}')
		b.writeln('cxstore_request_duration_seconds_count{endpoint="${ep}",store="${st}"} ${h.count}')
	}

	// bytes in / out
	b.writeln('# HELP cxstore_request_bytes_in_total Request body bytes accepted, by endpoint, store.')
	b.writeln('# TYPE cxstore_request_bytes_in_total counter')
	mut bik := m.bytes_in.keys()
	bik.sort()
	for k in bik {
		parts := k.split(obs_sep)
		b.writeln('cxstore_request_bytes_in_total{endpoint="${obs_label_esc(parts[0])}",store="${obs_label_esc(parts[1])}"} ${m.bytes_in[k]}')
	}
	b.writeln('# HELP cxstore_request_bytes_out_total Response body bytes sent, by endpoint, store.')
	b.writeln('# TYPE cxstore_request_bytes_out_total counter')
	mut bok := m.bytes_out.keys()
	bok.sort()
	for k in bok {
		parts := k.split(obs_sep)
		b.writeln('cxstore_request_bytes_out_total{endpoint="${obs_label_esc(parts[0])}",store="${obs_label_esc(parts[1])}"} ${m.bytes_out[k]}')
	}

	// inflight gauge
	b.writeln('# HELP cxstore_inflight_requests Requests currently in dispatch.')
	b.writeln('# TYPE cxstore_inflight_requests gauge')
	b.writeln('cxstore_inflight_requests ${m.inflight}')

	return b.str()
}

// obs_fmt_f64 renders a float for Prometheus without a trailing-zero mess; uses
// the shortest representation V's default gives, which scrapers parse fine.
fn obs_fmt_f64(f f64) string {
	return f.str()
}

// ── Structured request logs (spec Appendix F.3) ──────────────────────────────

// RequestMeta carries per-request observability context populated during
// dispatch (the principal ROLE; the trace-id once tracing is wired) and consumed
// by the structured-log emitter in svc_handle_request. Never holds a token/secret.
struct RequestMeta {
mut:
	role     string = 'anon'
	trace_id string
}

// svc_log_sampled_out reports endpoints whose per-request log is suppressed as
// probe noise (orchestration/LB health+ready hit these constantly). Everything
// else is logged.
fn svc_log_sampled_out(endpoint string) bool {
	return endpoint == 'health' || endpoint == 'ready'
}

// svc_format_log renders one structured request-log record. `json` (from the
// `[observability [log format="json"]]` knob, #207.2) selects a JSON object;
// otherwise the CX-element form. Either carries the principal ROLE only — never
// the bearer token or any secret. Deterministic given its inputs.
fn svc_format_log(endpoint string, store string, status int, latency_ms f64, bytes_in u64, bytes_out u64, role string, trace_id string, ts_unix i64, json bool) string {
	lat := '${latency_ms:.3f}'
	if json {
		mut s := '{"ts":${ts_unix},"endpoint":"${endpoint}","store":"${store}","status":${status},"latency-ms":${lat},"bytes-in":${bytes_in},"bytes-out":${bytes_out},"principal-role":"${role}"'
		if trace_id != '' {
			s += ',"trace-id":"${trace_id}"'
		}
		s += '}'
		return s
	}
	mut s := '[request-log ts=${ts_unix} endpoint="${endpoint}" store="${store}" status=${status} latency-ms=${lat} bytes-in=${bytes_in} bytes-out=${bytes_out} principal-role="${role}"'
	if trace_id != '' {
		s += ' trace-id="${trace_id}"'
	}
	s += ']'
	return s
}

// svc_store_internal_metrics renders the store-internal Prometheus series gauged
// live from each mounted backend (the #105 §7 introspection seam closing the
// gap O1 left). Only truthful series are emitted: a backend that does not track
// a counter contributes nothing (no fabricated zeros), and remote-backed mounts
// — whose doc count is not locally known — are skipped entirely. Series and
// label tuples are store-name-sorted for deterministic output.
fn svc_store_internal_metrics(mounts map[string]cx.Node) string {
	mut names := mounts.keys()
	names.sort()
	mut b := strings.new_builder(256)
	mut stats := map[string]StoreStats{}
	for name in names {
		node := mounts[name] or { continue }
		stats[name] = store_mount_stats(node) or { continue }
	}
	mut ok_names := stats.keys()
	ok_names.sort()

	// docs gauge — every local backend tracks it.
	if ok_names.len > 0 {
		b.writeln('# HELP cxstore_store_docs Unique documents currently held by the store (master-index size).')
		b.writeln('# TYPE cxstore_store_docs gauge')
		for name in ok_names {
			st := stats[name]
			b.writeln('cxstore_store_docs{store="${obs_label_esc(name)}",backend="${obs_label_esc(st.backend)}"} ${st.doc_count}')
		}
	}

	// #129-D object-graph series — ONLY for the content-addressed backend; a flat
	// backend has no object graph, so it contributes nothing here (no fabricated
	// zeros). cxstore_store_objects is the distinct content-addressed objects held;
	// cxstore_store_dedup_ratio is logical-objects / distinct-objects (≥1; how many
	// times over the subtree sharing saved re-storing an object). A store with no
	// resolvable objects yet omits the ratio rather than dividing by zero.
	mut graph_names := []string{}
	for name in ok_names {
		if stats[name].has_object_graph {
			graph_names << name
		}
	}
	if graph_names.len > 0 {
		b.writeln('# HELP cxstore_store_objects Distinct content-addressed objects physically held by the object-graph store.')
		b.writeln('# TYPE cxstore_store_objects gauge')
		for name in graph_names {
			st := stats[name]
			b.writeln('cxstore_store_objects{store="${obs_label_esc(name)}",backend="${obs_label_esc(st.backend)}"} ${st.object_count}')
		}
		b.writeln('# HELP cxstore_store_dedup_ratio Subtree-dedup ratio (logical objects without sharing / distinct objects stored).')
		b.writeln('# TYPE cxstore_store_dedup_ratio gauge')
		for name in graph_names {
			st := stats[name]
			if st.distinct_objects > 0 {
				ratio := f64(st.logical_objects) / f64(st.distinct_objects)
				b.writeln('cxstore_store_dedup_ratio{store="${obs_label_esc(name)}",backend="${obs_label_esc(st.backend)}"} ${obs_fmt_f64(ratio)}')
			}
		}
	}
	return b.str()
}

// svc_resp_status extracts the HTTP status integer from a sw_resp [response …]
// node (-1 if absent — should not happen for daemon-built responses).
fn svc_resp_status(n cx.Node) int {
	if n is cx.Element {
		v := n.attr_val('status') or { return -1 }
		if v is i64 {
			return int(v)
		}
	}
	return -1
}
