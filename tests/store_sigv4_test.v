module main

import code
import encoding.hex

// store_sigv4_test.v — DETERMINISTIC, network-free proof that the AWS Signature
// Version 4 signer behind the s3:// store byte-source backend (GH #91) is
// correct, checked against the canonical vectors published in the AWS
// documentation. No network, no Docker — always-on in `make test`. The live
// MinIO round trip (store_s3_minio_test.v) proves the same signer end-to-end
// against a real S3 server when CX_TEST_S3_ENDPOINT is set.

// AWS doc "Examples of how to derive a signing key for Signature Version 4":
// secret wJalr…, date 20120215, region us-east-1, service iam → known kSigning.
fn test_sigv4_signing_key_aws_vector() {
	key := code.sigv4_signing_key('wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', '20120215',
		'us-east-1', 'iam')
	got := hex.encode(key)
	want := 'f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d'
	assert got == want, 'SigV4 signing key mismatch:\n got ${got}\n want ${want}'
}

// AWS doc "Task 3: Calculate the signature" GET ListUsers example (date
// 20150830). The documented string-to-sign signs to the documented signature.
fn test_sigv4_signature_aws_vector() {
	string_to_sign := 'AWS4-HMAC-SHA256\n' + '20150830T123600Z\n' +
		'20150830/us-east-1/iam/aws4_request\n' +
		'f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59'
	got := code.sigv4_sign('wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', '20150830', 'us-east-1',
		'iam', string_to_sign)
	want := '5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7'
	assert got == want, 'SigV4 signature mismatch:\n got ${got}\n want ${want}'
}

// AWS canonical URI/query percent-encoding rule: unreserved bytes pass through,
// '/' is preserved in paths but encoded in query values, everything else %XX.
fn test_aws_uri_encode() {
	// path mode keeps '/', encodes space, keeps the unreserved '~' '-' '.' '_'
	assert code.aws_uri_encode('/a b/c~d-e.f_g', false) == '/a%20b/c~d-e.f_g'
	// query mode encodes '/'
	assert code.aws_uri_encode('a/b', true) == 'a%2Fb'
	// a 64-hex doc hash is all-unreserved (no encoding)
	hash := '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
	assert code.aws_uri_encode(hash, false) == hash
}
