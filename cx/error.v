module cx

pub struct CxError {
pub:
	message string
	line    int
	col     int
}

fn (e CxError) msg() string {
	return '${e.line}:${e.col}: ${e.message}'
}

fn cx_error(message string, line int, col int) CxError {
	return CxError{ message: message, line: line, col: col }
}
