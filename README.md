# Sentry-MCP

A fetch-and-scan MCP service. Hand it a single URL; get back page content that
has been rendered, trimmed, and screened for prompt injection before it reaches
the calling agent.

> **Status: specification only.** No implementation yet. The design lives in
> [`injection-scan-proxy-spec.md`](injection-scan-proxy-spec.md), which is the
> authoritative document — this README is orientation, not a substitute.

> **Name is provisional.** `sentry-mcp` collides with Sentry (sentry.io), which
> ships its own MCP server. `mind-the-gap-mcp` is the leading alternative and is
> unregistered on npm.

## What it does

Three tiers, one call (spec §1.2):

1. **Execute the JavaScript** — read pages that only render client-side, or that
   answer a plain fetch with a refusal.
2. **Strip the boilerplate** — sponsored padding, navigation, footers. Also a
   defence: injected payloads favour exactly those regions.
3. **Rendered page image** — when JavaScript or bot-detection defeats the rest.

Every tier is risk-assessed. The proxy scores rather than blocks by default:
callers get a `risk` score, a `coverage` score, and a warning level, and decide
for themselves. Blocking is a config threshold, not baked in.

## Reuse and attribution

**Reuse is preferred over rebuilding.** Where prior art exists and its licence
permits, this project incorporates it rather than reimplementing.

### VaultMCP corpus (MIT)

The pattern corpus and precomputed embeddings under `sentry_mcp/corpus/` come
from [vaultmcp/vault](https://github.com/vaultmcp/vault) at commit `66db948`,
under the MIT licence. Full attribution is in [`NOTICE`](NOTICE).

Two things worth knowing about that corpus:

- It is the **post-contamination rebuild**. The upstream project discovered it
  had been tuning detection against its own holdout set, published a postmortem,
  burned the holdout, and rebuilt the corpus from 13 public sources with a
  mandatory per-entry `source` field. 200 entries, 141 distinct sources, citing
  published attack research (garak probes and similar) rather than observed
  misses. The provenance discipline is visible in the data.
- The upstream project's own honest measurement puts its deterministic layers
  (heuristics + embeddings, no LLM judge) at **45.2% TPR**, versus ~99% with the
  judge in the loop. That figure is why this spec gives its LLM judge a wide
  role rather than a tie-breaker's role (§5.2).

**Only data is incorporated — no upstream source code.** The upstream detection
implementation is TypeScript; this project is Python (matching the deployment
idiom of the VPS it shares). The corpus, the embeddings, and the shape of the
judge's tool schema port cleanly across that boundary; ~53KB of TypeScript
orchestration does not, and is cheaper to rewrite than to bridge.

Upstream is also carrying an on-chain attestation feature (`viem`, Solidity
contracts, trade/ledger modules) that this project has no use for. Vendoring the
corpus rather than depending on `@aimcpvault/mcp-proxy` avoids pulling any of
that into the dependency tree.

## Licensing

- **AGPL-3.0-or-later** for all original code here — see [`LICENSE`](LICENSE).
- Third-party incorporations and their licences — see [`NOTICE`](NOTICE).

AGPL was chosen deliberately over a permissive licence: it closes the network-use
loophole plain GPL leaves open, so a hosted fork with modifications must share
source with its users. Upstream dependencies are Apache-2.0/MIT, which impose no
copyleft obligations upward. Reasoning is recorded in spec §11.
