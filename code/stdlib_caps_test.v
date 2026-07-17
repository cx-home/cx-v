module code

// stdlib_caps_test.v — capability-spec parsing, focused on the net host-scope
// support added for the client-library sub-area (#105 §6.1): a `net:host:port`
// grant must register the host so the grant is least-privilege AND a literal-IP
// scope overrides the §4.5 private-range deny (net.md §4.5; #47). A bare `net`
// stays unscoped.

fn test_caps_net_scope_registers_host() {
	caps_apply_spec('net:127.0.0.1:64999')
	assert cap_allowed('net'), 'net must be granted'
	assert cap_net_specs() == ['127.0.0.1:64999'], 'host scope must be recorded: ${cap_net_specs()}'
	assert !cap_net_is_all(), 'a scoped net grant is not unscoped'
	caps_set_empty()
}

fn test_caps_bare_net_is_unscoped() {
	caps_apply_spec('net')
	assert cap_net_is_all(), 'bare net is unscoped (all hosts, deny-set still applies)'
	assert cap_net_specs().len == 0
	caps_set_empty()
}

fn test_caps_mixed_list_with_net_scope() {
	caps_apply_spec('read,write,net:example.com:443')
	assert cap_allowed('read') && cap_allowed('write') && cap_allowed('net')
	assert cap_net_specs() == ['example.com:443']
	assert !cap_net_is_all()
	caps_set_empty()
}

fn test_caps_empty_is_pure_only() {
	caps_apply_spec('')
	assert !cap_allowed('net') && !cap_allowed('read') && !cap_allowed('write'), 'empty spec grants nothing'
	caps_set_empty()
}

fn test_caps_all_bypasses_scope() {
	caps_apply_spec('all')
	assert cap_allow_all(), 'all/* is the full opt-out'
	caps_set_empty()
}
