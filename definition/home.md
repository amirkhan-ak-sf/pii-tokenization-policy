# PII Tokenization Policy

Bidirectional, format-preserving tokenization of sensitive data inside
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
   stand-in: `Amir Khan` → `Kosn Angg`, `123-45-6789` → `482-91-3047`,
   `CN-2024-EUR` → `QI-1975-KJA`. The (mask, original) pairs go into an
   in-memory vault scoped to that single request.
2. **Inbound:** replaces any of the vault's masks back with the
   originals on the response body, so the calling client sees real data
   while the upstream only ever saw masks.

The vault is destroyed when the response phase finishes — no shared
state, no persistence, no cross-request leakage.

## Why it matters

| Problem | Without this policy | With this policy |
| --- | --- | --- |
| Sending customer data to an external LLM (OpenAI, Anthropic, Bedrock) for summarisation, classification, or RAG | Names, IDs, account numbers, contracts visible to the model provider — DPA / GDPR / data-residency exposure | Provider sees masked stand-ins. Client gets the real summary back, with the originals re-inserted. |
| Calling a third-party SaaS, BPO, or analytics endpoint that processes payloads but doesn't need real PII | Sensitive identifiers cross your trust boundary; the vendor's logs, telemetry, and incident dumps leak it | Vendor receives only masks. Client behaviour is unchanged. |
| Reducing PCI-DSS or HIPAA scope before forwarding to non-scoped systems | Every system on the path inherits compliance scope | Tokenize PAN / PHI at the gateway; downstream systems stay out of scope. |
| Sharing prod-shaped data with lower environments or partner sandboxes | Either you copy real data (compliance risk) or you build a separate sanitisation pipeline (cost, drift) | Set `unmaskResponseBody: false` and the gateway redacts in-flight; no separate ETL. |
| Routing traffic through observability / analytics pipelines that store request bodies | Sensitive values land in log indices, snapshots, and SIEM exports | Pipeline sees masks; the originals never leave the gateway boundary. |

**Business value, in one line:** unblock LLM, SaaS, and analytics
integrations that legal/compliance would otherwise reject — without
asking application teams to refactor anything.

Format-preserving masks keep payloads syntactically identical
(`\d{3}-\d{2}-\d{4}` stays `\d{3}-\d{2}-\d{4}`), so upstream validation,
schema checks, and length-sensitive logic continue to work.

## End-to-end example

Apply the policy with this configuration:

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

Send a request:

```bash
curl -sS -X POST "https://<gateway-host>/<route>" \
  -H "Content-Type: application/json" \
  -d '{"contract":"CN-2024-EUR","customer":"Amir Khan","ssn":"123-45-6789"}'
```

What each side sees:

| Surface | Body |
| --- | --- |
| Client request (sent) | `{"contract":"CN-2024-EUR","customer":"Amir Khan","ssn":"123-45-6789"}` |
| Upstream receives | `{"contract":"QI-1975-KJA","customer":"Yaqy Hnkp","ssn":"252-96-8556"}` |
| Client response (sees) | `{"contract":"CN-2024-EUR","customer":"Amir Khan","ssn":"123-45-6789"}` |

The same value within a single request always gets the same mask, so
`"123-45-6789"` appearing twice maps to one consistent stand-in. Across
requests, masks differ — each request has its own seed, so an
attacker watching multiple requests cannot correlate masked values.

## Common deployment patterns

| Use case | Configuration |
| --- | --- |
| **LLM / RAG calls** — protect customer data in prompts, restore in completions | `scope: both`, `unmaskResponseBody: true`, builtin rules for the IDs you care about + a static list for VIP customer names |
| **BPO / offshoring** — redact outbound, never restore | `scope: request`, `unmaskResponseBody: false` (or `scope: both` with `unmaskResponseBody: false`) |
| **Lower-environment fan-out** — masked test data for sandboxes | Same as BPO — masks are stable per request, format-preserving, deterministic enough for downstream reproduction |
| **PCI-DSS / HIPAA scope reduction** | `scope: both` for PAN / PHI patterns, with `unmaskResponseBody: true` so the calling app remains in-scope but every downstream hop is out of scope |
| **Outbound-only logging redaction** | `scope: response`, `maskRequestBody: false` — scans responses leaving the gateway and masks before the body lands in your logging tap |

### Example: protect outbound traffic to an external LLM

```json
{
  "maskRequestBody": true,
  "unmaskResponseBody": true,
  "contentTypeMode": "auto",
  "maskingRules": [
    {
      "name": "Email addresses",
      "ruleType": "builtin",
      "builtinPattern": "Contact/Email",
      "scope": "both"
    },
    {
      "name": "US SSNs",
      "ruleType": "builtin",
      "builtinPattern": "GovernmentId/UsSsn",
      "scope": "both"
    },
    {
      "name": "DE social-security numbers",
      "ruleType": "builtin",
      "builtinPattern": "GovernmentId/GermanSvnr",
      "scope": "both"
    },
    {
      "name": "Premier customer names",
      "ruleType": "static",
      "dataType": "name",
      "values": ["Amir Khan", "Johan Koeppel", "Kevin Koeppner"],
      "scope": "both"
    },
    {
      "name": "Internal account IDs",
      "ruleType": "static",
      "dataType": "number",
      "values": ["2029", "29183", "28282", "112"],
      "scope": "both"
    },
    {
      "name": "Custom contract numbers",
      "ruleType": "customRegex",
      "customRegex": "\\bCN-\\d{4}-[A-Z]{3}\\b",
      "scope": "both"
    }
  ]
}
```

The LLM provider only ever sees the masked variants. The calling
application gets the model's response back with originals re-inserted,
so its downstream logic is unaffected.

### Example: redact only (lower-environment data sharing)

```json
{
  "maskRequestBody": true,
  "unmaskResponseBody": false,
  "maskingRules": [
    {
      "name": "All emails",
      "ruleType": "builtin",
      "builtinPattern": "Contact/Email",
      "scope": "request"
    },
    {
      "name": "All SSNs",
      "ruleType": "builtin",
      "builtinPattern": "GovernmentId/UsSsn",
      "scope": "request"
    }
  ]
}
```

In this profile, downstream services and their logs only ever see
masked values. Original data never reappears.

## Configuration reference

| Field | Default | Description |
| --- | --- | --- |
| `maskRequestBody` | `true` | Apply masking to the outbound request body. |
| `unmaskResponseBody` | `true` | Reverse the masking on the inbound response body. |
| `contentTypeMode` | `auto` | `auto` / `json` / `text`. JSON-aware parsing rewrites only string and number leaf values; keys are always preserved. |
| `maxBodySizeBytes` | `5 MB` | Bodies larger than this pass through unmodified (with a warning). |
| `maxVaultEntries` | `100000` | Hard cap on the per-request vault size; protects against runaway memory. |
| `maskingRules` | `[]` | List of rules. Each rule has `name`, `ruleType`, and type-specific fields. |

### Rule types

- **`builtin`** — pick a named pattern from the catalog dropdown
  (~100 entries: government IDs for 16+ countries, financial
  identifiers, network, secrets, dates, geographic, hashes, identifiers,
  files, currency). Format is `Category/Name`, e.g.
  `GovernmentId/GermanSvnr`, `Financial/Iban`, `Network/Ipv4`.
- **`customRegex`** — supply your own regex string in `customRegex`.
  Standard Rust regex syntax. The full match is masked.
- **`static`** — supply a list of literal values. Compiled into a
  single Aho-Corasick automaton at policy load, so a list of thousands
  of names scans in O(n) per request. Two ways to supply entries:
  - `values: ["Amir Khan", "Lena Vogelsang", ...]` — one entry per
    item in a JSON array. Use this for short lists or programmatic
    config.
  - `valuesText: "..."` — bulk-input alternative for pasting many
    entries at once into a single text field. Accepts a JSON array
    (`["Amir","Lena"]`), one-value-per-line, or comma-separated.
    Whitespace around each entry is trimmed; empty entries are
    skipped. If both `values` and `valuesText` are set, the lists are
    merged and de-duplicated (first occurrence wins for ordering).

### Scope

Each rule has a `scope`:

- `both` (default): mask on request, unmask on response — the standard
  round-trip flow.
- `request`: mask on the way out but do not enroll into the unmask
  vault. The client also sees the masked form. Useful for
  redact-only flows.
- `response`: scan the response body and mask there (no request-phase
  work). Useful for outbound logging redaction.

### Format-preserving masking

The masker preserves character classes:

| Original char | Replacement |
| --- | --- |
| `a`-`z` | random `a`-`z` |
| `A`-`Z` | random `A`-`Z` |
| `0`-`9` | random `0`-`9` |
| punctuation / whitespace | unchanged |

The `dataType` hint adjusts which punctuation passes through:

- `email` keeps `@`, `.`, `-`, `_` intact.
- `number` keeps everything except digits unchanged.
- `identifier` keeps `-`, `/` intact.

The replacement is seeded with a per-request random seed, so the same
original value within a single request always gets the same mask
(important for unmask consistency), but the same value across two
different requests gets different masks (no cross-request correlation).

## Operational notes

### Limitations in v1

- **Streaming / SSE** responses (`text/event-stream`) are forwarded
  without unmasking. If you put this policy in front of a streaming LLM
  endpoint, set `scope=request` for now and expect masked tokens in the
  client's stream. Streaming unmask is on the roadmap.
- **Compressed responses** (`Content-Encoding: gzip` etc.) are forwarded
  without unmasking; the masks won't be in the compressed bytes. Strip
  `Accept-Encoding` upstream of this policy or have the upstream return
  identity-encoded responses.
- **Large numbers in JSON** are stringified for masking and reparsed
  back to numbers. JSON's float representation is not bit-exact for
  integers > 2^53; document any concerns in your integration tests.
- **Multiple replicas:** the vault is per-request and per-replica. If
  request and response are served by different replicas, unmask won't
  find the entries. Use a single replica for now, or wait for the
  Redis-backed vault planned for v2.

### Performance

- Static literal lists scan in O(n + matches) regardless of list size,
  thanks to Aho-Corasick. Lists of tens of thousands of values are fine.
- Regex rules use a `RegexSet` to find which patterns hit in a single
  pass, then re-run only the hit patterns to extract spans.
- Bodies above `maxBodySizeBytes` pass through unmodified rather than
  blocking the gateway thread.

### Security

- The vault never leaves the filter struct's memory and never crosses
  request boundaries.
- The masking PRNG seed is per-request and includes a SHA-256 of
  request entropy, so masks are not predictable across requests.
- Format-preserving masking is *not* encryption — it is one-way
  pseudonymization. If an attacker who recovers the masked form must be
  unable to recover the original, use the FF1 variant (planned for v2)
  or back the vault with a KMS-managed key.
