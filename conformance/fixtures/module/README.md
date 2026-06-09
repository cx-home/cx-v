# Module-system fixture tree

Per-test on-disk scaffolding for the module-system gate fixtures in
`conformance/code.txt`. The runner is expected to resolve each
`[?lib]` resolver string relative to the test's per-test subtree
under this directory.

## Layout

- `<test-name>/` — one subtree per fixture that needs external
  files. The test's `in_code` sees this directory as its
  importing-module cwd.
- `<test-name>/cx.lock` — synthetic lockfile if the test needs
  registered-name or HTTPS resolution.
- `<test-name>/cx.pkg` — package manifest, when the test exercises
  manifest-gated sub-paths or multi-file packages.
- `<test-name>/*.cx` — module files referenced by `[?lib]`.

## Status (v0.8.0, 2026-05-23)

Module-system V impl is Phase 2 work. The runner contract for these
fixtures is documented but not yet implemented; these files exist
so the test bodies are self-contained and the impl session has
ready-to-use inputs.

Subtrees populated:

- `program-def-visibility-private-unreachable/` —
  `helper-module.cx` with `[?def]`s that lack `scope=public`,
  exercising CXER0216 (E_VISIBILITY) when an importer references
  them.
- `module-lib-resolver-file/` — single local-helpers.cx for the
  `./local-helpers.cx` file-path resolver fixture.
- `module-visibility-public/` + `module-visibility-private/` +
  `module-visibility-mixed/` — shared `public-only-module.cx` /
  `mixed-module.cx` exercising `scope=public` vs private default.
- `module-import-cycle/` — paired `cycle-a.cx` / `cycle-b.cx`
  files to exercise CXER0210 cycle detection.
- `cx-stdlib/` — synthetic minimal stdlib package layout for the
  bundled-resolution + sub-path + re-export fixtures
  (`strings.cx`, `json/main.cx`, `json/encoder.cx`,
  `json/decoder.cx`, `json/internal-util.cx`, `http/main.cx`,
  `cx.pkg`).
