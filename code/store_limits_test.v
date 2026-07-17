module code

// #105 brick E — DoS fairness limiter (deterministic: time injected as now_ns).

fn test_token_bucket_exhausts_and_refills() {
	mut l := new_limiter(LimitConfig{})
	// rate 1/s, burst 2 → two immediate, third denied, refills 1 after 1s.
	t0 := i64(0)
	assert l.allow_rate('k', 1.0, 2.0, t0) // 2 → 1
	assert l.allow_rate('k', 1.0, 2.0, t0) // 1 → 0
	assert !l.allow_rate('k', 1.0, 2.0, t0) // 0 → denied
	assert l.allow_rate('k', 1.0, 2.0, t0 + i64(1_000_000_000)) // +1 token → allowed
	assert !l.allow_rate('k', 1.0, 2.0, t0 + i64(1_000_000_000)) // back to 0
}

fn test_rate_unlimited_when_zero() {
	mut l := new_limiter(LimitConfig{})
	for i in 0 .. 1000 {
		assert l.allow_rate('k', 0.0, 0.0, i64(i)) // rate 0 → always allowed
	}
}

fn test_rate_anti_starvation_per_key() {
	mut l := new_limiter(LimitConfig{})
	// principal A exhausts its bucket; B (separate key) is unaffected.
	assert l.allow_rate('p:A', 1.0, 1.0, 0)
	assert !l.allow_rate('p:A', 1.0, 1.0, 0) // A throttled
	assert l.allow_rate('p:B', 1.0, 1.0, 0) // B still served — no starvation
}

fn test_concurrency_cap_and_release() {
	mut l := new_limiter(LimitConfig{})
	assert l.acquire('p:A', 2)
	assert l.acquire('p:A', 2)
	assert !l.acquire('p:A', 2) // at cap
	l.release('p:A')
	assert l.acquire('p:A', 2) // slot freed
	// a different principal has its own budget
	assert l.acquire('p:B', 2)
}

fn test_concurrency_unlimited_when_zero() {
	mut l := new_limiter(LimitConfig{})
	for _ in 0 .. 1000 {
		assert l.acquire('p:A', 0) // max 0 → unlimited
	}
}

fn test_release_never_negative() {
	mut l := new_limiter(LimitConfig{})
	l.release('p:A') // no-op when nothing held
	assert l.acquire('p:A', 1)
}

fn test_pre_auth_global_bucket() {
	mut l := new_limiter(LimitConfig{
		pre_auth_rate:  1.0
		pre_auth_burst: 1.0
	})
	assert l.allow_pre_auth() // 1 → 0
	assert !l.allow_pre_auth() // global pre-auth flood throttled
}

fn test_defaults_are_on_and_generous() {
	cfg := LimitConfig{}
	assert cfg.per_principal_conc == 64
	assert cfg.per_principal_rate == 50.0
	assert cfg.pre_auth_rate == 100.0
}
