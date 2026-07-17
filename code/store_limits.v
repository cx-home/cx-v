module code

import sync
import time

// #105 Phase-2 — DoS fairness (brick E). DEFAULT-ON admission control so no
// single client can monopolize the shared worker pool (the global bounded pool
// caps TOTAL concurrency; this adds PER-PRINCIPAL fairness + a pre-auth cap so a
// flood — authenticated or not — gets backpressure, never starves others).
//
// Two mechanisms, both mutex-guarded (shared across worker threads) and
// time-injected for deterministic tests:
//   - token-bucket RATE limit (per principal, and a global pre-auth bucket),
//   - per-principal CONCURRENCY cap.
// Excess → the caller returns 429 CXER1706 for BOTH (rate and concurrency are
// the client's load — RFC 6585; 503 is reserved for not-serving states).
// `rate <= 0` / `max <= 0` means unlimited (the test/override escape).

pub struct LimitConfig {
pub:
	per_principal_conc  int = 64    // max concurrent requests per principal
	per_principal_rate  f64 = 50.0  // sustained req/s per principal
	per_principal_burst f64 = 100.0 // per-principal bucket capacity
	pre_auth_rate       f64 = 100.0 // sustained req/s across all unauthenticated traffic
	pre_auth_burst      f64 = 200.0
}

struct TokenBucket {
mut:
	tokens  f64
	last_ns i64
}

@[heap]
pub struct Limiter {
mut:
	cfg      LimitConfig // hot-swappable via set_config (§2.6 reload); read under mu
	mu       &sync.Mutex = unsafe { nil }
	buckets  map[string]TokenBucket
	inflight map[string]int
}

pub fn new_limiter(cfg LimitConfig) &Limiter {
	return &Limiter{
		cfg:      cfg
		mu:       sync.new_mutex()
		buckets:  map[string]TokenBucket{}
		inflight: map[string]int{}
	}
}

// allow_rate refills the `key` bucket by the elapsed time and consumes one
// token. `rate <= 0` is unlimited. Pure of wall-clock — `now_ns` is injected.
fn (mut l Limiter) allow_rate(key string, rate f64, burst f64, now_ns i64) bool {
	if rate <= 0 {
		return true
	}
	l.mu.lock()
	defer {
		l.mu.unlock()
	}
	mut b := l.buckets[key] or { TokenBucket{
		tokens:  burst
		last_ns: now_ns
	} }
	elapsed := f64(now_ns - b.last_ns) / 1.0e9
	if elapsed > 0 {
		b.tokens += elapsed * rate
		if b.tokens > burst {
			b.tokens = burst
		}
		b.last_ns = now_ns
	}
	allowed := b.tokens >= 1.0
	if allowed {
		b.tokens -= 1.0
	}
	l.buckets[key] = b
	return allowed
}

// acquire reserves one concurrency slot for `key`; false when at `max`.
fn (mut l Limiter) acquire(key string, max int) bool {
	if max <= 0 {
		return true
	}
	l.mu.lock()
	defer {
		l.mu.unlock()
	}
	cur := l.inflight[key] or { 0 }
	if cur >= max {
		return false
	}
	l.inflight[key] = cur + 1
	return true
}

// release frees one concurrency slot for `key`.
fn (mut l Limiter) release(key string) {
	l.mu.lock()
	cur := l.inflight[key] or { 0 }
	if cur > 0 {
		l.inflight[key] = cur - 1
	}
	l.mu.unlock()
}

// ── daemon-facing API (real wall-clock) ──────────────────────────────────────

// set_config swaps the limits (§2.6 config reload) while PRESERVING per-principal
// bucket and in-flight state — reload must not hand every principal a fresh burst
// allowance (a reload-spam refill loophole) or forget in-flight counts. A
// principal removed from auth is denied at authentication, before the limiter.
pub fn (mut l Limiter) set_config(cfg LimitConfig) {
	l.mu.lock()
	l.cfg = cfg
	l.mu.unlock()
}

// get_cfg reads the live limits under the lock (one consistent snapshot per call).
fn (mut l Limiter) get_cfg() LimitConfig {
	l.mu.lock()
	defer {
		l.mu.unlock()
	}
	return l.cfg
}

// allow_pre_auth rate-limits all unauthenticated admission (one global bucket),
// so an anonymous flood can't drain the pool. true = admit.
pub fn (mut l Limiter) allow_pre_auth() bool {
	c := l.get_cfg()
	return l.allow_rate('__preauth__', c.pre_auth_rate, c.pre_auth_burst, time.now().unix_nano())
}

// allow_principal_rate rate-limits one principal. true = admit.
pub fn (mut l Limiter) allow_principal_rate(id string) bool {
	c := l.get_cfg()
	return l.allow_rate('p:${id}', c.per_principal_rate, c.per_principal_burst,
		time.now().unix_nano())
}

// acquire_principal / release_principal bound one principal's concurrent
// in-flight requests; pair them around the data op.
pub fn (mut l Limiter) acquire_principal(id string) bool {
	return l.acquire('p:${id}', l.get_cfg().per_principal_conc)
}

pub fn (mut l Limiter) release_principal(id string) {
	l.release('p:${id}')
}
