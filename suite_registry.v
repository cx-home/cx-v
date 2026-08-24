module cx

// suite_registry.v — the ONE signature-suite registry (I1 identity epoch,
// stream 19, L36): (suite-name, multicodec code, key-len, sig-len,
// status). Verifiers MUST fail closed on any unrecognized suite name —
// `unsupported-suite`, never a fall-through attempt (#702). The reserved
// PQ rows (FIPS 204/205 + the hybrid) hold the migration path: dual-sign,
// not replace.

pub struct CxSigSuite {
pub:
	name        string
	code        u32
	key_len     int
	sig_len     int
	status      string // 'required' | 'optional' | 'reserved'
	implemented bool   // verifiable by THIS build
}

pub const cx_suite_registry = [
	CxSigSuite{ name: 'ed25519',           code: 0xed,   key_len: 32, sig_len: 64, status: 'required', implemented: true },
	CxSigSuite{ name: 'ecdsa-p256',        code: 0x1200, key_len: 33, sig_len: 64, status: 'optional', implemented: false },
	CxSigSuite{ name: 'rsa-2048',          code: 0x1205, key_len: 270, sig_len: 256, status: 'optional', implemented: false },
	// Reserved rows — named now, unimplemented (FIPS 204 ML-DSA, FIPS 205
	// SLH-DSA, and the dual-signing hybrid).
	CxSigSuite{ name: 'ml-dsa-44',         code: 0xd0e0, key_len: 1312, sig_len: 2420, status: 'reserved', implemented: false },
	CxSigSuite{ name: 'ml-dsa-65',         code: 0xd0e1, key_len: 1952, sig_len: 3309, status: 'reserved', implemented: false },
	CxSigSuite{ name: 'ml-dsa-87',         code: 0xd0e2, key_len: 2592, sig_len: 4627, status: 'reserved', implemented: false },
	CxSigSuite{ name: 'slh-dsa-128s',      code: 0xd0f0, key_len: 32, sig_len: 7856, status: 'reserved', implemented: false },
	CxSigSuite{ name: 'ed25519+ml-dsa-65', code: 0xd0ff, key_len: 1984, sig_len: 3373, status: 'reserved', implemented: false },
]!

pub fn cx_suite_by_name(name string) ?CxSigSuite {
	for s in cx_suite_registry {
		if s.name == name {
			return s
		}
	}
	return none
}

// cx_suite_verify_gate is the fail-closed gate every verifier runs BEFORE
// touching signature bytes: an unknown name or an unimplemented suite is
// `unsupported-suite` — never a fall-through attempt with the wrong
// primitive.
pub fn cx_suite_verify_gate(name string) !CxSigSuite {
	s := cx_suite_by_name(name) or {
		return error('unsupported-suite: `${name}` is not in the signature-suite registry (cx-err:CXER0135)')
	}
	if !s.implemented {
		return error('unsupported-suite: `${name}` is ${s.status} and not verifiable by this build (cx-err:CXER0135)')
	}
	return s
}
