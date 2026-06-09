module code

// mime.v — extension → Content-Type lookup table for [$serve-file]
// Single-source so the wire emitter, in-process echo
// path, and any future asset pipeline can share one table.
//
// Returns 'application/octet-stream' for unknown extensions per the
// HTTP/1.1 default. Case-insensitive on the extension (`.HTML` ≡
// `.html`) — common on Windows-authored content trees.

// content_type_for maps a filename's extension to a Content-Type
// string. Extension lookup is case-insensitive. A filename with no
// extension or an unknown one returns 'application/octet-stream'.
pub fn content_type_for(filename string) string {
	dot := filename.last_index('.') or { return 'application/octet-stream' }
	ext := filename[dot + 1..].to_lower()
	return match ext {
		'html', 'htm'     { 'text/html; charset=utf-8' }
		'css'             { 'text/css; charset=utf-8' }
		'js', 'mjs'       { 'application/javascript; charset=utf-8' }
		'json'            { 'application/json; charset=utf-8' }
		'svg'             { 'image/svg+xml' }
		'wasm'            { 'application/wasm' }
		'png'             { 'image/png' }
		'jpg', 'jpeg'     { 'image/jpeg' }
		'gif'             { 'image/gif' }
		'webp'            { 'image/webp' }
		'ico'             { 'image/x-icon' }
		'woff'            { 'font/woff' }
		'woff2'           { 'font/woff2' }
		'ttf'             { 'font/ttf' }
		'otf'             { 'font/otf' }
		'txt', 'md', 'log' { 'text/plain; charset=utf-8' }
		'xml'             { 'application/xml; charset=utf-8' }
		'pdf'             { 'application/pdf' }
		'zip'             { 'application/zip' }
		else              { 'application/octet-stream' }
	}
}
