// `cx scaffold <kind>` subcommand per the evaluation-experience checklist
// (1-5min tier). Drops a typed, commented skeleton on stdout.
//
// Kinds: config | data | doc | log | table
//
// All output is canonical CX that parses cleanly through `cx fmt`.

module main

const scaffold_config = '# A CX config skeleton — typed, commented, format-stable.
# Convert: cx --json this.cx hash: cx canonical this.cx | cx hash

[config
 [- environment selector: dev / staging / prod ]
 env=dev

 [server
 host=localhost
 port:u16=8080
 +tls
 -debug
 ]

 [database
 url=postgres://localhost:5432/app
 pool_size:u8=16
 connect_timeout_ms:u32=5000
 ]

 [allowed_origins
 https://app.example.com
 https://admin.example.com
 ]
]
'

const scaffold_data = '# A CX data skeleton — typed entities, repeated structures.

[catalog
 [product id=001 name=widget price:decimal=12.50 +in_stock]
 [product id=002 name=gadget price:decimal=29.99 +in_stock]
 [product id=003 name=gizmo price:decimal=8.75 -in_stock]
]
'

const scaffold_doc = '# A CX document skeleton — mixed prose + structured data.

[article
 [title CX evaluation notes]
 [author erik]
 [date :date 2026-05-12]

 [- The intro paragraph below mixes prose with inline data references. ]
 [p
 We evaluated CX as a replacement for our YAML configs. Key wins:
 [strong real types], [strong canonical hashing], and
 [strong one-syntax-everywhere].
 ]

 [section [heading Tabular section]
 [paragraph A `:table` block carries rows directly inside the doc.]
 [_ :table[metric value:int]
 requests 1024
 errors 3
 latency_p99_ms 47
 ]
 ]
]
'

const scaffold_log = '# A CX log skeleton — logfmt mode (top-level key=value, one line per event).

ts=2026-05-12T10:30:00Z level=info svc=api req_id=abc123 latency_ms=45
ts=2026-05-12T10:30:01Z level=warn svc=api req_id=def456 latency_ms=210 slow=true
ts=2026-05-12T10:30:01Z level=error svc=api req_id=ghi789 err=\'connection refused\'
'

const scaffold_table = '# A CX :table skeleton — column-typed rows.

[users :table[id:int name age:int city email]
 1 alice 30 portland alice@example.com
 2 bob 25 austin bob@example.com
 3 carol 40 lisbon carol@example.com
]

[- Convert: cx --csv this.cx round-trip: cx table dump this.cx --to=cx ]
'

fn run_scaffold(args []string) {
	if args.len == 0 {
		eprintln('Usage: cx scaffold <kind>')
		eprintln(' kind ∈ {config, data, doc, log, table}')
		eprintln('')
		eprintln('Examples:')
		eprintln(' cx scaffold config > my_config.cx')
		eprintln(' cx scaffold table | cx --json')
		eprintln(' cx scaffold doc > article.cx && cx --md article.cx')
		exit(2)
	}
	kind := args[0]
	body := match kind {
		'config' { scaffold_config }
		'data' { scaffold_data }
		'doc' { scaffold_doc }
		'log' { scaffold_log }
		'table' { scaffold_table }
		else {
			eprintln('cx scaffold: unknown kind "${kind}"; expected config|data|doc|log|table')
			exit(2)
		}
	}
	print(body)
}
