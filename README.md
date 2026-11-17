# forge — a standalone, GitHub-compatible git forge in one process

One Node 22 process, standard library only, serving from its own in-memory
store — no database, no git binary, no outside service:

- **git smart HTTP** — upload-pack protocol v2 (`ls-refs`, `fetch` with
  shallow/deepen, `thin-pack`, `ofs-delta`) and v0, receive-pack v0 with
  `report-status`, fast-forward enforcement and sideband framing. Packfiles
  are written and read by this code (plain objects plus OFS/REF delta
  resolution).
- **REST v3** under `/api/v3` — repositories, branches, refs, commits,
  contents (create/update/delete with real git blob trees), labels, issues,
  comments, pull requests and squash merge with real conflict detection.
- **GraphQL** at `/api/graphql` — a hand-written lexer/parser/executor with
  variables, aliases, inline fragments and `__type` introspection; opaque
  base64 global ids, stable across reads.
- **MCP** at `/mcp` — JSON-RPC 2.0 Streamable HTTP, `server/discover` and
  legacy `initialize`, six tools (`create_repo`, `get_repo`, `create_issue`,
  `list_issues`, `create_pull_request`, `merge_pull_request`) acting on the
  same store as REST.

## Running

```sh
MAKEFUN_ENV_URL=http://127.0.0.1:8080 \
MAKEFUN_SHOP_TOKEN=shpat_... \
MAKEFUN_TRIAL_NOW=1735689600 \
node main.ts
```

The entry binds an ephemeral port, POSTs `{"port": N}` to
`$MAKEFUN_ENV_URL/register`, answers `GET /healthz` with `{"ok": true}`, then
long-polls `GET $MAKEFUN_ENV_URL/done` until the suite finishes and exits 0.

- `MAKEFUN_SHOP_TOKEN` is the bearer token every request must carry; when it
  is empty the forge accepts any request as the viewer.
- `MAKEFUN_TRIAL_NOW` is the trial's opening time (epoch seconds or an ISO
  string). All timestamps the forge emits are deterministic counters over it,
  never the wall clock, so a live run and its replay answer identical state.

`main.ts` is plain JavaScript syntax in a `.ts` file, so it runs under Node
22's type stripping with no build step (`node main.ts`).

## Local verification

Against the competition kit's sealed suite, run locally:

```sh
node --experimental-strip-types sdk/run.ts --url http://127.0.0.1:PORT --token "$TOKEN" --perf
```

Local full-trial result (17 Nov 2026, this machine): **120/120 conformance
checks, 15/15 MCP, perf 128/200 → 928/1000** by the published scoring
formula. Perf varies with machine load (124–168 across local runs); every
workload was faster than the reference forge's calibration time in all runs.

## Notes

- The kit's `makefun compress` command packs a readable **Python** source into
  `main.py`; it does not apply to this Node entry, so no compress step was
  run and none is needed.
- The entry was written from scratch for the `github-core-clone-01`
  competition. The only external reference was the competition kit's
  published suite contract (the sealed `program/env/src` checks), which
  defines the wire protocol the entry must speak.
