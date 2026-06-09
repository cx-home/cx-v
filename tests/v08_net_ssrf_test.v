module main

import code

// v08_net_ssrf_test.v — the §4.5 SSRF / DNS-rebinding CORE: the pure
// canonicalize + deny-set classifier the dial/send-to guard composes. These
// vectors pin the mandatory deny set (loopback/link-local/private/CGNAT/ULA/
// this-host) and the canonicalization that defeats ::ffff: bypass (rev-4 M8).

fn test_ssrf_deny_set_ipv4() {
	// denied ranges
	for ip in ['127.0.0.1', '127.5.5.5', '10.0.0.5', '172.16.0.1', '172.31.255.1',
		'192.168.1.1', '169.254.169.254', '100.64.0.1', '100.127.0.1', '0.0.0.0'] {
		assert code.net_ip_in_deny_set(ip), 'expected ${ip} in deny set'
	}
	// allowed (public) — must NOT be denied
	for ip in ['8.8.8.8', '1.2.3.4', '172.15.0.1', '172.32.0.1', '100.63.0.1',
		'100.128.0.1', '93.184.216.34'] {
		assert !code.net_ip_in_deny_set(ip), 'expected ${ip} allowed (not in deny set)'
	}
}

fn test_ssrf_deny_set_ipv6() {
	for ip in ['::1', '::', 'fe80::1', 'febf::1', 'fc00::1', 'fd12:3456::1'] {
		assert code.net_ip_in_deny_set(ip), 'expected ${ip} in deny set'
	}
	for ip in ['2001:4860:4860::8888', '2606:4700::1111'] {
		assert !code.net_ip_in_deny_set(ip), 'expected ${ip} allowed'
	}
}

fn test_ssrf_canonicalization() {
	// IPv4-mapped IPv6 must unwrap so it classifies as the embedded IPv4
	assert code.net_canonicalize_ip('::ffff:169.254.169.254') == '169.254.169.254'
	assert code.net_ip_in_deny_set('::ffff:169.254.169.254'), 'mapped metadata IP must be denied'
	assert code.net_ip_in_deny_set('::ffff:10.0.0.5'), 'mapped private IP must be denied'
	assert !code.net_ip_in_deny_set('::ffff:8.8.8.8'), 'mapped public IP must be allowed'
	// zone id + brackets stripped
	assert code.net_canonicalize_ip('169.254.169.254%en0') == '169.254.169.254'
	assert code.net_canonicalize_ip('[::1]') == '::1'
}
