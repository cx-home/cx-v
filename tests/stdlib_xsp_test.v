module main

import code

// TDD for cx-stdlib/xsp (spec/03-approved/xap/xsp.md; issue #31). XSP is the XAP
// Stream Protocol frame codec: a self-describing, self-delimiting frame whose
// payload dogfoods CX `data-bin`. The whole codec is PURE (no capability grant),
// so these run under eval_code's deny-all caps.

fn xsp_eval(prog string) string {
	out := code.eval_code('', prog, 'text') or {
		assert false, 'eval failed: ${err}'
		return ''
	}
	return out
}

// Round-trip: encode a frame then decode it; the frame metadata and the
// data-bin payload value all survive unchanged.
fn test_xsp_roundtrip_binary_payload() {
	prog := "[?lib 'cx-stdlib/xsp' :as xsp]
[\$xsp:decode [\$xsp:encode [frame type=event stream=7 principal=\"did:key:z6MkABC\"
  [payload [fix lat=37.5 lon=-122.3]]]]]"
	out := xsp_eval(prog)
	assert out.contains('type=event'), 'type lost: ${out}'
	assert out.contains("stream='7'"), 'stream-id lost: ${out}'
	assert out.contains('did:key:z6MkABC'), 'principal lost: ${out}'
	assert out.contains('lat='), 'payload value lost: ${out}'
	assert out.contains('37.5'), 'payload lat value lost: ${out}'
	assert out.contains('-122.3'), 'payload lon value lost: ${out}'
	assert out.contains("binary='true'"), 'binary flag lost: ${out}'
}

// An anonymous frame (no principal) round-trips with an empty principal.
fn test_xsp_anonymous_frame() {
	prog := "[?lib 'cx-stdlib/xsp' :as xsp]
[\$xsp:decode [\$xsp:encode [frame type=request [payload [do :ping]]]]]"
	out := xsp_eval(prog)
	assert out.contains('type=request'), 'type lost: ${out}'
	assert out.contains("stream='0'"), 'default stream should be 0: ${out}'
	// the [do :ping] intent survives as the payload value
	assert out.contains('do') && out.contains('ping'), 'intent payload lost: ${out}'
}

// A text payload (binary=false) carries a UTF-8 string, not data-bin.
fn test_xsp_text_payload() {
	prog := "[?lib 'cx-stdlib/xsp' :as xsp]
[\$xsp:decode [\$xsp:encode [frame type=event binary=false [payload \"hello xsp\"]]]]"
	out := xsp_eval(prog)
	assert out.contains("binary='false'"), 'binary flag should be false: ${out}'
	assert out.contains('hello xsp'), 'text payload lost: ${out}'
}

// end-of-stream flag round-trips.
fn test_xsp_eos_flag() {
	prog := "[?lib 'cx-stdlib/xsp' :as xsp]
[\$xsp:decode [\$xsp:encode [frame type=reply eos=true [payload [ok]]]]]"
	out := xsp_eval(prog)
	assert out.contains("eos='true'"), 'eos flag lost: ${out}'
}

// decode-all splits a buffer of two concatenated frames into a sequence.
fn test_xsp_decode_all_splits_two() {
	prog := "[?lib 'cx-stdlib/xsp' :as xsp]
[?lib 'cx-stdlib/bytes' :as b]
[?let [= \$f1 [\$xsp:encode [frame type=event stream=1 [payload [a x=1]]]]]
[= \$f2 [\$xsp:encode [frame type=event stream=2 [payload [b y=2]]]]]
  [\$xsp:decode-all [\$b:concat (\$f1, \$f2)]]]"
	out := xsp_eval(prog)
	assert out.contains("stream='1'"), 'first frame lost: ${out}'
	assert out.contains("stream='2'"), 'second frame lost: ${out}'
	assert out.contains('x=1') && out.contains('y=2'), 'payloads lost: ${out}'
}

// An unknown version byte is rejected (a failure-channel err value).
fn test_xsp_bad_version_errs() {
	// 18 zero bytes: version byte 0x00 is not XSP/1.
	prog := "[?lib 'cx-stdlib/xsp' :as xsp]
[?lib 'cx-stdlib/bytes' :as b]
[\$xsp:decode [\$b:from-hex \"000000000000000000000000000000000000\"]]"
	out := xsp_eval(prog)
	assert out.contains('CXER-XSP-VERSION'), 'expected version err, got: ${out}'
}

// A truncated buffer (header claims more than is present) is rejected.
fn test_xsp_truncated_errs() {
	prog := "[?lib 'cx-stdlib/xsp' :as xsp]
[?lib 'cx-stdlib/bytes' :as b]
[\$xsp:decode [\$b:from-hex \"0102\"]]"
	out := xsp_eval(prog)
	assert out.contains('CXER-XSP-TRUNCATED'), 'expected truncated err, got: ${out}'
}

// §5.2 (#560): the negotiated-only `credit` frame (type 8) round-trips —
// the payload is a data-bin integer grant.
fn test_xsp_credit_frame_roundtrip() {
	prog := "[?lib 'cx-stdlib/xsp' :as xsp]
[\$xsp:decode [\$xsp:encode [frame type=credit stream=42 [payload 7]]]]"
	out := xsp_eval(prog)
	assert out.contains('type=credit'), 'credit type lost: ${out}'
	assert out.contains("stream='42'") || out.contains('stream=42'), 'stream lost: ${out}'
	assert out.contains('7'), 'grant payload lost: ${out}'
}
