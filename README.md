# data-masking-policy

A MuleSoft Flex Gateway / Omni Gateway custom policy that performs
**bidirectional, format-preserving masking** of sensitive data inside
HTTP request and response bodies — applied at the gateway, transparent
to client and upstream alike.

## What it does

```
   client                gateway                upstream
     |                      |                      |
     |  PII in cleartext    |  masked body         |
     |--------------------->|--------------------->|
     |                      |                      |
     |  PII restored        |  masked body         |
     |<---------------------|<---------------------|
```

1. **Outbound:** scans the request body for matches against the
   configured rules (built-in named patterns, custom regex, or static
   value lists) and replaces each match with a format-preserving
   stand-in: `Amir Khan` -> `Kosn Angg`, `123-45-6789` -> `482-91-3047`,
   `CN-2024-EUR` -> `QI-1975-KJA`. The `(mask, original)` pairs go into
   an in-memory vault scoped to that single request.
2. **Inbound:** replaces any of the vault's masks back with the
   originals on the response body, so the calling client sees real data
   while the upstream only ever saw masks.

The vault is destroyed when the response phase finishes — no shared
state, no persistence, no cross-request leakage.

## Why it matters

| Problem | Without this policy | With this policy |
| --- | --- | --- |
| Sending customer data to an external LLM (OpenAI, Anthropic, Bedrock) for summarisation, classification, or RAG | Names, IDs, account numbers, contracts visible to the model provider — DPA / GDPR / data-residency exposure | Provider sees masked stand-ins. Client gets the real summary back, with the originals re-inserted. |
| Calling a third-party SaaS or BPO endpoint that processes payloads but doesn't need the real PII | Sensitive identifiers cross your trust boundary; logs, telemetry, and incident dumps at the vendor leak it | Vendor receives only masks. Client behaviour is unchanged. |
| Sharing prod-shaped data with lower environments or partner sandboxes | Either you copy real data (compliance risk) or you build a separate sanitisation pipeline (cost, drift) | Set `unmaskResponseBody: false` and the gateway redacts in-flight; no separate ETL. |
| Routing traffic through observability / analytics pipelines that store request bodies | Sensitive values land in log indices and snapshot exports | Pipeline sees masks; the originals never leave the gateway boundary. |

**Business value, in one line:** unblock LLM, SaaS, and analytics
integrations that legal/compliance would otherwise reject — without
asking application teams to refactor anything.

Format-preserving masks keep payloads syntactically identical
(`\d{3}-\d{2}-\d{4}` stays `\d{3}-\d{2}-\d{4}`), so upstream validation,
schema checks, and length-sensitive logic continue to work.

## How to use it

### 1. Apply the policy to an API instance

After publishing (`make release`), apply it via Anypoint API Manager UI
or the CLI:

```bash
anypoint-cli-v4 api-mgr policy apply <api-instance-id> data-masking-policy \
    --policyVersion 1.0.0 \
    --groupId <org-uuid> \
    --configFile ./policy-config.json
```

A minimal `policy-config.json`:

```json
{
  "maskRequestBody": true,
  "unmaskResponseBody": true,
  "contentTypeMode": "auto",
  "maskingRules": [
    {
      "name": "us-ssn",
      "ruleType": "builtin",
      "builtinPattern": "GovernmentId/UsSsn",
      "dataType": "number",
      "scope": "both"
    },
    {
      "name": "premier-customer-names",
      "ruleType": "static",
      "dataType": "name",
      "values": ["Amir Khan", "Johan Koeppel", "Kevin Koeppner"],
      "scope": "both"
    },
    {
      "name": "contract-numbers",
      "ruleType": "customRegex",
      "customRegex": "\\bCN-\\d{4}-[A-Z]{3}\\b",
      "dataType": "alphanumeric",
      "scope": "both"
    }
  ]
}
```

### 2. Send a request

```bash
curl -sS -X POST "https://<gateway-host>/<route>" \
  -H "Content-Type: application/json" \
  -d '{"contract":"CN-2024-EUR","customer":"Amir Khan","ssn":"123-45-6789"}'
```

### 3. What each side sees

| Surface | Body |
| --- | --- |
| Client request (sent) | `{"contract":"CN-2024-EUR","customer":"Amir Khan","ssn":"123-45-6789"}` |
| Upstream receives | `{"contract":"QI-1975-KJA","customer":"Yaqy Hnkp","ssn":"252-96-8556"}` |
| Client response (sees) | `{"contract":"CN-2024-EUR","customer":"Amir Khan","ssn":"123-45-6789"}` |

Same value within a single request always gets the same mask (so
`"123-45-6789"` appearing twice maps to one consistent stand-in). Across
requests, masks differ — each request has its own seed.

### Demo: prove the masking visually

To show in a demo what the upstream actually receives, point the API at
a request-inspector like [webhook.site](https://webhook.site):

1. Open webhook.site, copy your unique URL.
2. Set the API's upstream to that URL.
3. `curl` the gateway with PII in the body.
4. Refresh webhook.site — you'll see the **masked** body land in real
   time, while your terminal shows the **original** values restored in
   the response.

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
  the upstream actually receives, and verify:
  - The upstream never sees the original sensitive value.
  - The client receives the original value back after unmask.
  - The response body's byte length is preserved exactly through unmask
    (so the gateway's forwarded `Content-Length` header stays correct).

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
| `maskingRules` | `[]` | List of rules. Each rule has `name`, `ruleType`, and type-specific fields. |

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

### Common patterns

| Use case | Configuration |
| --- | --- |
| **LLM / RAG calls** — protect customer data in prompts, restore in completions | `scope: both`, `unmaskResponseBody: true`, builtin rules for the IDs you care about + a static list for VIP customer names |
| **BPO / offshoring** — redact outbound, never restore | `scope: request`, `unmaskResponseBody: false` (or `scope: both` with `unmaskResponseBody: false`) |
| **Lower-environment fan-out** — masked test data for sandboxes | Same as BPO — masks are stable per request, format-preserving, deterministic enough for downstream reproduction |
| **Outbound-only logging redaction** | `scope: response`, `maskRequestBody: false` — scans responses leaving the gateway and masks before the body lands in your logging tap |

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
    `-- it_round_trip.rs     end-to-end pdk-unit tests
```

## Publishing

```bash
make publish       # dev version to Anypoint Exchange (every push gets a unique timestamped suffix)
make release       # release version (immutable; bump Cargo.toml for the next one)
make upload-docs   # uploads definition/home.md as the asset's home page on Exchange
```

See "How to use it" above for the apply step.

## Limitations / Roadmap

See `ROADMAP.md`. Highlights:

- Streaming / SSE responses (text/event-stream) are not unmasked in v1.
- Compressed responses (Content-Encoding: gzip) are not decompressed.
- The vault is per-request and per-replica; if a Flex Gateway with
  multiple replicas serves the response on a different replica than the
  request, unmask won't find the entries. Use a single replica for now,
  or wait for the Redis-backed vault planned for v2.
