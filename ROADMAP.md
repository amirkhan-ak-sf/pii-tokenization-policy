# Roadmap

Tracking known limitations and planned features for the
data-masking-policy. Items are grouped by priority and reviewed at
each release.

## P0 — known v1 limitations to address before GA

### Multi-replica vault

The per-request `Vault` lives on the filter struct in memory. If Flex
Gateway is horizontally scaled and the response from upstream lands on
a different replica than the request, the vault on that replica is
empty and the response cannot be unmasked.

**Mitigation in v1:** run a single replica, or scope this policy to APIs
that already have request affinity at the load-balancer layer.

**Plan:** offer an optional Redis-backed vault. Each request gets a
correlation id; the masks are written to Redis under that id with a
short TTL (default 60s); the response phase reads them back. Trade-off
is one Redis round-trip per masked request, plus the operational cost
of running Redis alongside Flex.

### Compressed responses

When the upstream returns `Content-Encoding: gzip` (or `br`, `deflate`),
the policy currently forwards the response unchanged because the masks
won't appear in the compressed bytes.

**Mitigation in v1:** strip `Accept-Encoding` from the request upstream
of this policy, or have the upstream return identity-encoded responses.
Document the limitation prominently in `home.md`.

**Plan:** add an opt-in `decompressResponse: true` setting that
`gunzip`s the response, runs the unmask, and re-compresses. WASM gzip
is feasible but adds 5-15 ms p95 latency on a 100 KB body.

### Streaming / SSE responses

`Content-Type: text/event-stream` and chunked text responses cannot be
buffered to end-of-stream because the client expects to see tokens
arrive incrementally. Any response with `Transfer-Encoding: chunked` and
without a definite Content-Length triggers buffering today, which
breaks streaming semantics.

**Mitigation in v1:** for streaming endpoints, set `scope: request` so
the policy masks the request only and lets the response pass through
unchanged. Document the trade-off in `home.md`.

**Plan:** implement a streaming unmask state machine. Maintain a
sliding window equal to the longest mask in the vault; on each chunk,
look for masks that end inside the window, replace them with the
original, and flush everything before the window. The fixed-shape
masks our format-preserving algorithm produces make this tractable.

## P1 — desirable for v2

### Format-preserving encryption (FF1)

The current masker uses a CSPRNG to pick replacement characters. The
mask is unrecoverable without the in-memory vault. That's fine for the
mask-then-unmask round-trip, but means that anyone who somehow gets
access to a stale masked log file cannot reverse it (which is a
feature) and cannot match it back to the production store either
(which is sometimes a constraint, e.g. for cross-system correlation).

**Plan:** add an opt-in `maskingMode: ff1` that uses a tenant-keyed
NIST FF1 cipher. The mask is then deterministic given the key, and a
holder of the key can detokenize offline. Adds AES-FF1 (or a
WASM-friendly substitute) and KMS-style key management.

### Per-route / per-tenant configuration

Right now the policy config is per-API-instance. A single instance
serving multiple tenants needs per-tenant rules.

**Plan:** allow `tenantHeaderName` to identify the requester and
load tenant-scoped rules from a separate config or external store.

### NLP-based PII detection

For free-text payloads (LLM prompts, support tickets) regex misses
unstructured names, addresses, etc. Microsoft Presidio or spaCy NER
is the obvious upgrade.

**Plan:** offer an external service call-out to a Presidio sidecar.
Adds latency and an external dependency, so opt-in only.

### Custom replacement tokens

Some operators want masks like `Customer-001`, `Customer-002` rather
than format-preserving stand-ins. Useful when downstream analytics
groups by mask.

**Plan:** add `replacementFormat` to each rule:
`format-preserving` (default), `numbered` (`{name}-{n}`),
`opaque` (`##MASK_{rule}_{n}##`).

### Bigger built-in catalog

Candidates flagged for future inclusion:

- More EU government IDs (Belgian Rijksregisternummer, Czech RC,
  Hungarian TAJ).
- Healthcare codes (CPT, NDC, SNOMED CT lookups).
- Crypto secrets (Stripe keys, Twilio SIDs, Anthropic/OpenAI keys).
- Cloud secrets (GCP service-account JSON, Azure connection strings).

## P2 — nice-to-have

### Metrics and Prometheus export

Expose counters for mask hits per rule, vault size, body-size
truncations, and response-side parse fallbacks. Tied into Flex
Gateway's metrics exporter.

### Automatic config validation in CI

`make validate-config policy-config.json` that runs the same
`PolicyConfig::from_raw()` validation pipeline as the live policy, so
operators can catch bad configs before deploy.

### "Audit-only" mode

Log every match that *would have been masked* without mutating the
body. Useful for evaluating new rules in production traffic before
turning them on.
