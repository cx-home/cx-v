module main

import cx

fn main() {
	println('sizeof(cx.Element)       = ${sizeof(cx.Element)}')
	println('sizeof(cx.ElementMeta)   = ${sizeof(cx.ElementMeta)}')
	println('sizeof(cx.Attribute)     = ${sizeof(cx.Attribute)}')
	println('sizeof(cx.AttributeMeta) = ${sizeof(cx.AttributeMeta)}')
	println('sizeof(cx.Node)          = ${sizeof(cx.Node)}')
	println('sizeof(cx.TableData)     = ${sizeof(cx.TableData)}')
	println('sizeof(cx.TextNode)      = ${sizeof(cx.TextNode)}')
	println('sizeof(cx.ScalarNode)    = ${sizeof(cx.ScalarNode)}')
	println('sizeof(cx.ScalarValue)   = ${sizeof(cx.ScalarValue)}')
	println('sizeof(string)           = ${sizeof(string)}')
	println('sizeof(?string)          = ${sizeof(?string)}')
	println('sizeof([]u8)             = ${sizeof([]u8)}')
}
