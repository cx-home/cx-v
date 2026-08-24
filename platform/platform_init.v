module platform


// platform_init.v — the Ring-2 module's own init() (#651/#516 I3, seam G
// landed at the module move). V runs every imported module's init()
// before main / the libcx constructor, so importing `platform` (the cx
// CLI's cmd module, libcx's build root, any full-engine binding) is what
// switches the Ring-2 packs on: an artifact that does NOT import
// platform gets a Ring-0/1 evaluator whose ring-2 verb names fall
// through to the not-in-subset refusal — the §4 profile behavior, by
// construction.
//
// Order matters the same way it did in code's init(): the globals are
// seeded once, before any thread, then the pack dispatchers register
// into the Ring-1 registry (code/ring_registry.v — its containers are
// made live by ring_registry_init() in code's OWN init(), which V runs
// before this one because platform imports code).
fn init() {
	// S3 (G1a): the gRPC edge's per-call nonce replay cache — daemon-lifetime,
	// built before any listener thread.
	g_grpc_nonces = new_grpc_nonce_cache()
	// The listener/dispatch/SSE globals live in services_listener_
	// notd_wasm32_emcc.v — their init crosses into the per-variant fn so
	// the wasm build (which excludes that file and its globals) compiles
	// (#329; the wasm variant is a no-op).
	services_listener_init_globals()
	// Wire every Ring-2 pack dispatcher into the Ring-1 registry
	// (ring2_register.v, moved verbatim at the split).
	ring2_register_all()
}
