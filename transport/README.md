# `vcx/transport/` — vendored event-loop HTTP transport

CX owns its HTTP/SSE/XAP transport in its own tree. These three modules are
**vendored verbatim** from the V standard library (`vlib/`) so CX no longer
depends on the V fork carrying them — the fork can converge back to stock
upstream V (see `spec/_archived/evict_cx_from_v_PLAN.md`).

| Module | Vendored from | Upstream C original |
|---|---|---|
| `picoev` | `vlib/picoev` | [kazuho/picoev](https://github.com/kazuho/picoev) — "a tiny, lightning fast event loop for network applications" |
| `pico_http_parser` | `vlib/pico_http_parser` | (V shim re-exporting `picohttpparser`) |
| `picohttpparser` | `vlib/picohttpparser` | [h2o/picohttpparser](https://github.com/h2o/picohttpparser) — "a tiny, primitive, fast HTTP request/response parser" |

Imported as `transport.picoev` / `transport.pico_http_parser` /
`transport.picohttpparser`. The only edits to the verbatim sources are the
cross-module `import` paths (re-namespaced under `transport.`); all logic,
platform loop backends (default/linux/macos/freebsd/openbsd/termux + windows
constants), and public symbols are unchanged.

## CX-added file

`picoev/cx_shared_listener.v` is **not** part of upstream picoev — it is the
CX transport patch (shared-listener multi-reactor + held-open SSE fd support)
that previously lived in the fork. It carries:
- `cx_hold_fd` / `cx_release_fd` / `cx_is_held` — held-open (SSE) fd set, exempt
  from picoev's idle timeout.
- `cx_set_sse_on_close` — close callback for held fds.
- `listen_socket` / `new_with_listen_fd` — N event loops sharing one bound
  socket (portable multicore HTTP without `SO_REUSEPORT` load-balancing).

The integration hooks in `picoev/picoev.v` (the `cx_is_held` idle-timeout
exemption and the `cx_sse_on_close` close path) are the in-place picoev edits
that accompany `cx_shared_listener.v`.

## License

picoev, pico_http_parser, and picohttpparser are part of the V project and are
distributed under the **MIT License**:

> Copyright (c) 2019-2024 Alexander Medvednikov
>
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the above copyright notice and this permission
> notice being included in all copies or substantial portions of the Software.
