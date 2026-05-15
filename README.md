# data-masking-policy

A MuleSoft Flex Gateway / Omni Gateway custom policy that performs
**bidirectional, format-preserving masking** of sensitive data. The
policy:

1. Scans the **outbound request body** for matches against any of the
   configured rules (built-in named patterns, custom regex, or static
   value lists), replaces each match with a format-preserving stand-in
   (`Amir Khan` -> `Kosn Angg`, `123-45-6789` -> `482-91-3047`), and
   stores the `(mask, original)` pairs in an in-memory vault that lives
   only for the duration of that request.
2. On the **inbound response**, replaces any of the vault's masks with
   the original values so the calling client sees real data again.

The upstream sees only masked data; the client sees only original data.

This is the standard pattern for protecting traffic to external LLMs,
third-party SaaS, BPO endpoints, lower environments, observability
pipelines, and any other place where sensitive identifiers shouldn't
leave your trust boundary.

## Build

```bash
make setup    # installs cargo-anypoint
make build    # cargo build --target wasm32-wasip1 --release + GCL gen
make test     # cargo test (unit + pdk-unit integration)
make run      # spins up Flex Gateway + httpbin in docker compose
```

## Test

The repo ships with two layers of tests:

- **Unit tests** (`cargo test --lib`): exercise each module in isolation.
  36 tests covering catalog correctness, config validation,
  format-preserving masking shape preservation, the matcher's
  longest-match-wins and span-based rewrite, the JSON walker (keys are
  never touched), and the unmask round-trip.
- **Integration tests** (`tests/it_round_trip.rs`): drive the full
  policy through `pdk-unit`'s in-process Proxy-Wasm stub, capture what
  the upstream actually receives, and verify both:
  - The upstream never sees the original sensitive value.
  - The client receives the original value back after unmask.

Run both:

```bash
cargo test
```

## Local playground

```bash
make run
```

Brings up Flex Gateway (port 8081) + httpbin as the upstream. httpbin
echoes the request body back inside its JSON response, which is exactly
what we need to see the round-trip end to end.

```bash
curl -s -X POST http://localhost:8081/anything \
  -H "content-type: application/json" \
  -d '{"customer":"Amir Khan","ssn":"123-45-6789","email":"amir@khan.com"}'
```

The response will contain the original values (because the policy
unmasks them on the way back). In the `local-flex` Docker logs you can
see the body that actually went to the upstream, which contains masked
values only:

```bash
docker compose -f playground/docker-compose.yaml logs local-flex \
  | grep -i "data-masking"
```

To verify the upstream-side masking directly, point a tcpdump or sniffer
at the `local-flex -> backend` link, or temporarily flip
`unmaskResponseBody: false` in `playground/config/api.yaml` so the
client sees what httpbin saw.

## Configuration

See `definition/gcl.yaml` for the full schema and `definition/home.md`
for operator documentation. Quick overview:

| Field | Default | Notes |
| --- | --- | --- |
| `maskRequestBody` | `true` | Apply masking to the outbound request body. |
| `unmaskResponseBody` | `true` | Reverse the masking on the inbound response body. |
| `contentTypeMode` | `auto` | `auto` / `json` / `text`. JSON-aware mode masks only string and number leaf values; keys are always preserved. |
| `maxBodySizeBytes` | `5 MB` | Larger bodies pass through unmodified (with a warning). |
| `maxVaultEntries` | `100000` | Cap on per-request vault size. |
| `maskingRules` | `[]` | List of rules. Each rule has `name`, `type`, and type-specific fields. |

### Rule types

- **`builtin`**: pick a named pattern from the catalog dropdown
  (~100 entries: government IDs for 16+ countries, financial
  identifiers, network, secrets, dates, geographic, hashes, identifiers,
  files, currency).
- **`customRegex`**: provide your own regex string. Standard Rust regex
  syntax. The whole match is masked.
- **`static`**: provide a list of literal values. Compiled into a single
  Aho-Corasick automaton at policy load, so a list of thousands of
  values still scans in O(n) per request.

### Scope

- `both` (default): mask on request, unmask on response.
- `request`: mask on the way out only — the client also sees the
  masked form. Useful for "redact outbound, never restore" flows
  like lower-environment data sharing or BPO offshoring.
- `response`: scan the response body for matches and mask there.
  Rare; included for symmetry.

## Architecture

```
client                                                upstream
   |                                                     ^
   | request body (with PII)                             | masked body
   v                                                     |
+------------------- Flex Gateway ----------------+      |
|   on_request:                                   |      |
|     1. read request body                        |      |
|     2. scan against all rules                   |      |
|     3. replace each match with format-preserving|      |
|        mask, enroll (mask, original) into Vault |--->--+
|     4. forward masked body to upstream          |
|                                                 |
|   ((upstream processes the request))            |
|                                                 |
|   on_response:                                  |
|     1. read response body                       |
|     2. Aho-Corasick over Vault.masks            |
|     3. substitute originals back                |<--<--+ response body (still has masks)
|     4. forward unmasked body to client          |      |
+-------------------------------------------------+      |
   |                                                     |
   v                                                     v
client (sees originals)
```

## Project layout

```
.
|-- Cargo.toml
|-- Makefile
|-- README.md          (this file)
|-- ROADMAP.md
|-- policy-config.json (sample runtime config)
|
|-- src/
|   |-- lib.rs          entrypoint, request/response filter wiring
|   |-- config.rs       3-layer config (codegen -> raw -> validated)
|   |-- catalog.rs      ~100 named built-in patterns
|   |-- matcher.rs      regex + Aho-Corasick scan, span resolution
|   |-- mask.rs         Vault + format-preserving char masker
|   |-- unmask.rs       response-side Aho-Corasick replace
|   |-- json_walk.rs    JSON-aware tree walk (mask only leaf values)
|   `-- generated/      auto-regenerated by `make build` from gcl.yaml
|
|-- definition/
|   |-- gcl.yaml        policy schema (operator-facing)
|   `-- home.md         Anypoint Exchange documentation
|
|-- playground/
|   |-- docker-compose.yaml
|   `-- config/
|       |-- api.yaml         API instance + sample policy config
|       |-- logging.yaml
|       `-- registration.yaml  (you create this with flexctl)
|
`-- tests/
    `-- it_round_trip.rs     5 end-to-end pdk-unit tests
```

## Deployment

```bash
make publish   # publishes a dev version to Anypoint Exchange
make release   # publishes a release version
make upload-docs   # uploads definition/home.md as the asset's home page
```

After release, apply via Anypoint API Manager UI or:

```bash
anypoint-cli-v4 api-mgr policy apply <api-instance-id> data-masking-policy \
    --policyVersion <version> \
    --groupId <org-uuid> \
    --configFile ./policy-config.json \
    --environment <env-name>
```

## Limitations / Roadmap

See `ROADMAP.md`. Highlights:

- Streaming / SSE responses (text/event-stream) are not unmasked in v1.
- Compressed responses (Content-Encoding: gzip) are not decompressed.
- The vault is per-request and per-replica; if a Flex Gateway with
  multiple replicas serves the response on a different replica than the
  request, unmask won't find the entries. Use a single replica for now,
  or wait for the Redis-backed vault planned for v2.
