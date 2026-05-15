# Data Masking Policy

Bidirectional, format-preserving masking and unmasking for sensitive data
flowing through Flex Gateway / Omni Gateway.

## What it does

On the **request** path, the policy scans the body for matches against the
configured rules (built-in named patterns, custom regex, or static value
lists), replaces each match with a format-preserving stand-in
(`Amir Khan` -> `Kosn Angg`, `123-45-6789` -> `482-91-3047`), and stores
the (mask, original) pairs in an in-memory vault that lives only for the
duration of the request.

On the **response** path, the policy scans the upstream's response body
for any of the masks recorded in that request's vault and substitutes the
original values back. The vault is then dropped.

The net effect: the upstream sees **only masked data** and the calling
client sees **only original data**.

## When this is the right control

This is the standard pattern for:

- Sending enterprise data to external LLMs (OpenAI, Anthropic, hosted
  Hugging Face) without violating GDPR / Schrems II / data-residency
  laws. The LLM still gets useful context; the LLM provider never sees
  identifiable data.
- Routing requests through third-party SaaS (credit-scoring, enrichment,
  translation, OCR, sentiment) where the vendor's logging is opaque.
- Reducing PCI-DSS or HIPAA scope by tokenizing PAN / PHI before
  forwarding to non-scoped systems.
- Sharing production-shaped traffic with lower environments / BPO
  operations / offshore dev contractors. (Set `unmaskResponseBody=false`
  for "redact outbound, never restore" mode.)
- Cleaning logs / observability streams: if the gateway masks before
  forwarding, your SIEM and log archives stop being a PII liability.

## Configuration

| Field | Default | Description |
| --- | --- | --- |
| `maskRequestBody` | `true` | Apply masking to the outbound request body. |
| `unmaskResponseBody` | `true` | Reverse the masking on the inbound response body. |
| `contentTypeMode` | `auto` | `auto` / `json` / `text`. JSON-aware parsing rewrites only string and number leaf values. |
| `maxBodySizeBytes` | `5 MB` | Bodies larger than this pass through unmodified (with a warning). |
| `maxVaultEntries` | `100000` | Hard cap on the per-request vault size; protects against runaway memory. |
| `maskingRules` | `[]` | List of rules. Each rule has `name`, `type`, and type-specific fields. |

### Rule types

- **`builtin`** — pick a named pattern from the catalog dropdown. Format
  is `Category/Name` (e.g. `GovernmentId/GermanSvnr`,
  `Financial/Iban`, `Network/Ipv4`).
- **`customRegex`** — supply your own regex string in `customRegex`.
  Standard Rust regex syntax. The full match is masked.
- **`static`** — supply a list of literal values in `values`.
  Compiled into a single Aho-Corasick automaton, so a list of thousands
  of names scans in O(n) per request.

### Scope

Each rule has a `scope`:

- `both` (default): mask on request, unmask on response.
- `request`: mask on the way out but do not enroll into the unmask
  vault — useful when the client should also see the masked form.
- `response`: scan the response body and mask there (no request-phase
  work). Rare; included for symmetry.

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
  pseudonymization. If you need an attacker who recovers the masked
  form to be unable to recover the original, use the FF1 variant
  (planned for v2) or back the vault with a KMS-managed key.

## Example: protect outbound traffic to an external LLM

```json
{
  "maskRequestBody": true,
  "unmaskResponseBody": true,
  "contentTypeMode": "auto",
  "maskingRules": [
    {
      "name": "Email addresses",
      "type": "builtin",
      "builtinPattern": "Contact/Email",
      "scope": "both"
    },
    {
      "name": "US SSNs",
      "type": "builtin",
      "builtinPattern": "GovernmentId/UsSsn",
      "scope": "both"
    },
    {
      "name": "DE social-security numbers",
      "type": "builtin",
      "builtinPattern": "GovernmentId/GermanSvnr",
      "scope": "both"
    },
    {
      "name": "Premier customer names",
      "type": "static",
      "dataType": "name",
      "values": ["Amir Khan", "Johan Koeppel", "Thomas Koeppner"],
      "scope": "both"
    },
    {
      "name": "Internal account IDs",
      "type": "static",
      "dataType": "number",
      "values": ["2029", "29183", "28282", "112"],
      "scope": "both"
    },
    {
      "name": "Custom contract numbers",
      "type": "customRegex",
      "customRegex": "\\bCN-\\d{4}-[A-Z]{3}\\b",
      "scope": "both"
    }
  ]
}
```

## Example: redact only (lower-environment data sharing)

```json
{
  "maskRequestBody": true,
  "unmaskResponseBody": false,
  "maskingRules": [
    {
      "name": "All emails",
      "type": "builtin",
      "builtinPattern": "Contact/Email",
      "scope": "request"
    },
    {
      "name": "All SSNs",
      "type": "builtin",
      "builtinPattern": "GovernmentId/UsSsn",
      "scope": "request"
    }
  ]
}
```

In this profile, downstream services and their logs only ever see masked
values. Original data never reappears.
