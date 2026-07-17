module code

import cx
import crypto.rand as crand
import strings

// store_tracing.v — W3C trace-context propagation + OpenTelemetry span model +
// OTLP/HTTP+JSON export (observability sub-area O3, decision 1a; spec Appendix
// F.2). Export is OFF by default: when disabled, trace/span ids are still minted,
// propagated, and written into the structured log (F.3) so log records correlate
// even with no collector — only the network export is gated.

// TraceContext is the per-request W3C trace-context. `span_id` is THIS server
// span; `parent_id` is the inbound span (empty for a freshly-minted root).
struct TraceContext {
	trace_id  string // 32 lowercase hex (16 bytes), never all-zero
	span_id   string // 16 lowercase hex (8 bytes) — this server span
	parent_id string // 16 hex inbound span, or '' for a root
	sampled   bool
}

// obs_is_lc_hex reports whether `s` is exactly `n` lowercase hex digits.
fn obs_is_lc_hex(s string, n int) bool {
	if s.len != n {
		return false
	}
	for c in s {
		if !((c >= `0` && c <= `9`) || (c >= `a` && c <= `f`)) {
			return false
		}
	}
	return true
}

// obs_all_zero_hex reports an all-`0` id (invalid per the trace-context spec).
fn obs_all_zero_hex(s string) bool {
	for c in s {
		if c != `0` {
			return false
		}
	}
	return true
}

// parse_traceparent parses a `traceparent` header value. Returns none when it is
// absent or malformed (the caller then mints a fresh root). Accepts version `00`
// and tolerates extra `-`-separated fields after the 4-field core (forward-compat
// per the spec); rejects all-zero ids and non-hex.
fn parse_traceparent(h string) ?TraceContext {
	if h == '' {
		return none
	}
	parts := h.split('-')
	// #207.5: W3C — version 00 has EXACTLY 4 fields (a 5-field version-00 header is
	// invalid → fresh root), and every hex field MUST be lowercase (no .to_lower()
	// normalization — an uppercase field is invalid, not to be salvaged).
	if parts.len < 4 || parts[0] != '00' {
		return none // only version 00 is defined
	}
	if parts.len != 4 {
		return none // version-00 is exactly version-traceid-spanid-flags
	}
	trace_id := parts[1]
	span_id := parts[2]
	flags := parts[3]
	if !obs_is_lc_hex(trace_id, 32) || obs_all_zero_hex(trace_id) {
		return none
	}
	if !obs_is_lc_hex(span_id, 16) || obs_all_zero_hex(span_id) {
		return none
	}
	if !obs_is_lc_hex(flags, 2) {
		return none
	}
	sampled := (flags.parse_uint(16, 8) or { u64(0) }) & u64(0x01) != 0
	return TraceContext{
		trace_id:  trace_id
		span_id:   span_id // inbound span becomes our parent below
		parent_id: span_id
		sampled:   sampled
	}
}

// obs_rand_hex returns `nbytes` of CSPRNG output as lowercase hex (2·nbytes
// chars). crypto.rand never realistically fails; the fallback keeps the id
// well-formed (correct length) rather than panicking a request thread.
fn obs_rand_hex(nbytes int) string {
	b := crand.read(nbytes) or { return '0'.repeat(nbytes * 2) }
	return b.hex()
}

fn obs_new_trace_id() string {
	return obs_rand_hex(16) // 16 bytes → 32 hex
}

fn obs_new_span_id() string {
	return obs_rand_hex(8) // 8 bytes → 16 hex
}

// svc_request_header returns the value of a request header by case-insensitive
// name, or '' if absent (mirrors svc_request_bearer's traversal).
fn svc_request_header(req cx.Element, name string) string {
	lname := name.to_lower()
	for it in req.items {
		if it is cx.Element && it.name == 'headers' {
			for h in it.items {
				if h is cx.Element && h.name == 'header' {
					if h.attr('name').to_lower() == lname {
						return h.attr('value').trim_space()
					}
				}
			}
		}
	}
	return ''
}

// svc_trace_for_request derives the server-span trace context from the request's
// `traceparent` header: continue an inbound trace (keep its trace-id, this span
// gets a fresh span-id, parent = the inbound span) or mint a fresh root. The
// sampled flag follows the inbound decision, else `default_sampled`.
fn svc_trace_for_request(req cx.Element, default_sampled bool) TraceContext {
	hdr := svc_request_header(req, 'traceparent')
	if tc := parse_traceparent(hdr) {
		return TraceContext{
			trace_id:  tc.trace_id
			span_id:   obs_new_span_id()
			parent_id: tc.parent_id
			sampled:   tc.sampled
		}
	}
	return TraceContext{
		trace_id:  obs_new_trace_id()
		span_id:   obs_new_span_id()
		parent_id: ''
		sampled:   default_sampled
	}
}

// format_traceparent renders a TraceContext as a `traceparent` header value (for
// propagating THIS span to downstream calls).
fn format_traceparent(tc TraceContext) string {
	flags := if tc.sampled { '01' } else { '00' }
	return '00-${tc.trace_id}-${tc.span_id}-${flags}'
}

// Span is one finished server span ready for OTLP export.
struct Span {
	tc       TraceContext
	name     string            // e.g. "csrp.get"
	start_ns i64               // unix nanos
	end_ns   i64               // unix nanos
	status   int               // HTTP status (mapped to OTLP status code)
	attrs    map[string]string // endpoint, store, principal.role — never a token
}

// obs_json_str escapes a string for embedding in a JSON document.
fn obs_json_str(s string) string {
	mut b := strings.new_builder(s.len + 2)
	b.write_u8(`"`)
	for c in s {
		match c {
			`"` { b.write_string('\\"') }
			`\\` { b.write_string('\\\\') }
			`\n` { b.write_string('\\n') }
			`\t` { b.write_string('\\t') }
			`\r` { b.write_string('\\r') }
			else { b.write_u8(c) }
		}
	}
	b.write_u8(`"`)
	return b.str()
}

// obs_otlp_status maps an HTTP status to an OTLP span status code: 1=Ok for <500,
// 2=Error for 5xx (the OTLP convention; client 4xx are not span errors).
fn obs_otlp_status(http_status int) int {
	return if http_status >= 500 { 2 } else { 1 }
}

// build_otlp_json renders spans as one OTLP/HTTP ExportTraceServiceRequest JSON
// (resourceSpans → scopeSpans → spans). Per the OTLP/JSON mapping, trace/span ids
// are hex strings and timestamps are stringified unix-nanos. Deterministic given
// its inputs (attribute keys sorted) so it is testable without a live collector.
fn build_otlp_json(spans []Span, service_name string) string {
	mut b := strings.new_builder(1024)
	b.write_string('{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":')
	b.write_string(obs_json_str(service_name))
	b.write_string('}}]},"scopeSpans":[{"scope":{"name":"cxstore"},"spans":[')
	for i, sp in spans {
		if i > 0 {
			b.write_u8(`,`)
		}
		b.write_string('{"traceId":')
		b.write_string(obs_json_str(sp.tc.trace_id))
		b.write_string(',"spanId":')
		b.write_string(obs_json_str(sp.tc.span_id))
		if sp.tc.parent_id != '' {
			b.write_string(',"parentSpanId":')
			b.write_string(obs_json_str(sp.tc.parent_id))
		}
		b.write_string(',"name":')
		b.write_string(obs_json_str(sp.name))
		b.write_string(',"kind":2') // SPAN_KIND_SERVER
		b.write_string(',"startTimeUnixNano":')
		b.write_string(obs_json_str(sp.start_ns.str()))
		b.write_string(',"endTimeUnixNano":')
		b.write_string(obs_json_str(sp.end_ns.str()))
		b.write_string(',"attributes":[')
		mut akeys := sp.attrs.keys()
		akeys.sort()
		for j, k in akeys {
			if j > 0 {
				b.write_u8(`,`)
			}
			b.write_string('{"key":')
			b.write_string(obs_json_str(k))
			b.write_string(',"value":{"stringValue":')
			b.write_string(obs_json_str(sp.attrs[k]))
			b.write_string('}}')
		}
		b.write_string('],"status":{"code":')
		b.write_string(obs_otlp_status(sp.status).str())
		b.write_string('}}')
	}
	b.write_string(']}]}]}')
	return b.str()
}

// TraceExporter posts finished spans to an OTLP/HTTP collector. Disabled by
// default; when disabled, export() is a no-op (ids are still minted + logged).
// TraceExporter ships spans to the OTLP collector OFF the request path (#202):
// export() enqueues to a bounded channel and returns immediately; a background
// worker batches and POSTs. A slow/black-hole collector therefore never delays a
// response (it only fills the queue, and overflow drops spans — tracing is a
// best-effort side channel that must never fail or stall the request).
@[heap]
pub struct TraceExporter {
pub:
	enabled  bool
	endpoint string // OTLP/HTTP traces endpoint, e.g. http://collector:4318/v1/traces
	service  string
mut:
	queue chan Span = chan Span{cap: 1024}
}

pub fn new_trace_exporter(enabled bool, endpoint string, service string) &TraceExporter {
	mut e := &TraceExporter{
		enabled:  enabled
		endpoint: endpoint
		service:  service
		queue:    chan Span{cap: 1024}
	}
	if enabled && endpoint != '' {
		spawn e.run_export_worker() // drains the queue off the request path
	}
	return e
}

// export ENQUEUES one span (non-blocking) — never touches the network on the
// request path (#202). Drops on a full queue rather than blocking the response.
fn (e &TraceExporter) export(sp Span) {
	if !e.enabled || e.endpoint == '' {
		return
	}
	q := e.queue
	select {
		q <- sp {}
		else {} // queue full → drop this span (best-effort; never block the request)
	}
}

// run_export_worker drains the span queue, batches (up to 64 spans without
// blocking), and POSTs each batch to the collector. Runs on its own thread.
fn (e &TraceExporter) run_export_worker() {
	q := e.queue
	for {
		first := <-q or { break } // channel closed → exit
		mut batch := [first]
		for batch.len < 64 {
			select {
				s := <-q {
					batch << s
				}
				else {
					break
				}
			}
		}
		e.flush_batch(batch)
	}
}

// flush_batch POSTs one OTLP batch. #200: the export request carries a
// `traceparent` (format_traceparent of the batch's first span) so the collector
// can correlate the export itself — the live consumer that closes the dead seam.
fn (e &TraceExporter) flush_batch(spans []Span) {
	if spans.len == 0 {
		return
	}
	payload := build_otlp_json(spans, e.service)
	mut headers := [['Content-Type', 'application/json']]
	tp := format_traceparent(spans[0].tc)
	if tp != '' {
		headers << ['traceparent', tp]
	}
	_, _, _ := remote_http('POST', e.endpoint, headers, payload.bytes())
}
