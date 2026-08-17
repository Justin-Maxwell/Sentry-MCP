# Spec: sentry-mcp — Prompt-Injection Scanning MCP Proxy

## 1. Purpose

### 1.1 The brief

Hand the proxy a **single named URL** and get back something usable and
reasonably safe. This is not scraping and not indexing — it is "fetch this
page for me", for pages that a plain fetch cannot read: sites behind a
robots.txt refusal, sites that render their content in JavaScript, sites
that pad the article with sponsored filler.

The motivating case: a `claude.ai/share/<uuid>` link renders client-side, so
a plain fetch returns the SPA shell. The content actually lives at
`claude.ai/api/chat_snapshots/<uuid>`. Executing the page's own JavaScript
gets there without the caller ever needing to know that mapping — and that
generalises to most of the sites this exists for.

### 1.2 The capability ladder

1. **Execute the JavaScript.** The common case and the bulk of the value.
2. **Strip the boilerplate.** Sponsored padding, navigation, footers.
   Also a defence — see §5.4.
3. **Rendered page image.** Fires when complex JavaScript or bot-detection
   defeats everything above. Required, not optional.

Risk assessment runs across all three tiers, including tier 3 (§5.5).

### 1.3 Scoring posture

This is **not** a blocking filter by default. It produces a **risk score**, a
**coverage score**, and a **warning level**, all attached to the response, so
the caller (or a downstream gate) can decide what to do. A hard block
threshold is a configuration knob, not a hardcoded behaviour.

Binary content is **not** out of scope. Image scanning is specified in §5.5;
the v1 exclusion that previously lived here was a cost assumption that does
not survive contact with actual pricing.

## 2. Position in the request path

Transparent MCP proxy, matching the pattern used by Vault
(`@aimcpvault/mcp-proxy`): the calling agent's MCP client config points at
this proxy instead of at the upstream server directly. The proxy:

1. Accepts the MCP connection from the agent.
2. **Synthesises a single `fetch_rendered` tool** (§2.1) and presents it in
   `tools/list` alongside — or instead of — the upstream tool set.
3. Forwards `tools/call` and all other MCP methods to the configured
   upstream server, **except**:
4. For tool responses that contain fetched web content (see §4.2 for
   detection), intercepts the response, runs it through the scoring
   pipeline (§5), and rewrites the response to include scan metadata
   (§6) before returning it to the agent.
5. All other traffic passes through unmodified with no scanning overhead —
   any tool not on the `content_tools` list (§4.2), e.g. `browser_click`,
   `browser_press_key`.

### 2.1 The synthesised fetch tool

The brief in §1.1 is *issue a fetch*. Playwright MCP presents twenty-plus
`browser_*` automation primitives — navigate, click, type, snapshot. Passing
that surface through unmodified would mean every retrieval is a two-call
browser-driving exercise, which is not the tool the caller asked for.

So the proxy **must** expose one tool that takes a URL and returns page
content, internally sequencing whatever upstream calls that requires
(navigate → wait → snapshot → optional screenshot). Whether the raw
`browser_*` tools remain visible alongside it is a config decision;
defaulting to hiding them keeps the agent's tool surface honest.

This deliberately replaces the earlier "proxy `tools/list` unmodified"
requirement, which contradicted §1.1.

### 2.2 Upstream agnosticism

Swapping the upstream fetcher should be *possible*, and minor rework on a
swap is acceptable. It is **not** a design driver — do not contort the
architecture to avoid ever naming Playwright MCP. The upstream is identified
concretely in §2.3.

### 2.3 The upstream

- **Microsoft Playwright MCP** — `mcr.microsoft.com/playwright/mcp`
- Licence: Apache-2.0
- Transport: HTTP, port 8931
- Deployment: Docker container on the same VPS (§3)

Relevant flags: `--user-agent` (bot-detection mitigation), `--extension`
(attach to a running browser), `--blocked-origins` (§5.4),
`--block-service-workers`.

## 3. Deployment

- **Distinct service.** Not merged into Clautana or Tanasaurus. Own
  repository, own process, own systemd unit.
- **Same VPS**, same general deployment idiom as the existing
  aiohttp-based Clautana proxy: Python, systemd-managed, restart-on-failure.
- **Isolated trust boundary**, not identical to Clautana's deployment:
  - Own systemd unit (`sentry-mcp.service`), independent start/stop/restart
    from Clautana.
  - Own local port, distinct from Clautana's.
  - Runs as its own dedicated system user, not the user Clautana runs as,
    if the VPS's existing convention allows this without disproportionate
    effort. Flag as a TODO if the existing setup makes this awkward — don't
    block the spec on it.
- **Same Tailscale node** as Clautana (no new tunnel infrastructure), but:
  - Own local port.
  - Own path on the existing Funnel, e.g. `https://<node>.<tailnet>.ts.net/scan`
    routing to the new local port, alongside the existing `/mcp` path to
    Clautana. Confirm the exact Funnel path-routing syntax against the
    Tailscale Funnel docs at implementation time — don't assume it matches
    the `serve`/`funnel` config already in use for Clautana without
    checking the current config file.
- Config file (`.env` or `config.yaml`, match whatever convention
  `tana_proxy.py` already uses) holds: upstream MCP server URL, local
  listen port, LLM-judge API key (optional), threshold values (§7),
  heuristic weights (§5.1).

## 4. MCP protocol handling

### 4.1 Pass-through requirements

- Must correctly proxy the MCP handshake (`initialize`, capability
  negotiation) so the agent sees a valid MCP server.
- `tools/list` is **modified**, not passed through: the proxy adds the
  synthesised `fetch_rendered` tool (§2.1) and may hide the raw `browser_*`
  primitives behind config. Any upstream tool that *is* exposed must be
  advertised with its upstream schema unaltered.
- Must proxy `tools/call` requests for **upstream tools** unmodified. The one
  exception is `fetch_rendered` (§2.1), which the proxy owns: it originates
  the upstream call sequence rather than forwarding one. The proxy never
  rewrites an agent's call to an upstream tool.
- Errors from upstream (connection failure, upstream 5xx, malformed
  response) propagate as MCP errors, not silently swallowed.
- Transport is settled (§12.1): **HTTP in** from the agent via the Funnel
  path (§3), **HTTP out** to Playwright MCP on port 8931. Request/response
  correlation, session lifetime, and server-initiated notifications must all
  survive the hop.

### 4.2 Identifying content-bearing responses

A response is a scan candidate if:

- It comes from a tool in the configured `content_tools` list (default:
  `browser_navigate`, `browser_snapshot`, `fetch`, or whatever the
  upstream server's actual tool names are — confirm against the live
  Playwright MCP tool list at implementation time, tool names in this
  spec are illustrative, not authoritative), **and**
- The response payload contains a text/markdown/HTML content block (per
  §1, binary-only responses are marked `scanned: false` and passed
  through without scoring).

Only `tools/call` results are intercepted in v1. If the upstream server
also serves fetched web content via `resources/read` or `prompts/get`,
those paths are unscanned — see §12.

## 5. Scoring pipeline

Layered, cheapest-first, matching the general shape of the Vault
four-layer approach referenced in prior research (decoder → heuristics →
embedding similarity → LLM judge), but simplified for v1:

### 5.1 Layer 1 — Heuristics (always runs, no external calls)

A set of independently-scored signals, each contributing a weighted
sub-score. Suggested starting signals (weights are tunable config, not
hardcoded):

| Signal | Detection method | Rationale |
|---|---|---|
| Imperative instruction phrases | Regex/keyword match against a maintained list (`ignore previous instructions`, `you are now`, `disregard the above`, `system prompt`, `new instructions:`, etc.) | Direct injection language |
| Screen-reader-only text | Imperative or instruction-shaped prose in `aria-label`, `aria-labelledby`, `aria-describedby`, `alt` attributes, or off-canvas-positioned nodes | **The accessibility tree inverts this problem.** `display:none`, `visibility:hidden`, and the `hidden` attribute are *excluded* from the snapshot, so crude hiding never reaches the agent at all. What *survives* is the sophisticated kind: aria attributes, alt text, and the standard `.sr-only` off-screen pattern — text a screen reader speaks aloud and a sighted viewer never sees. An earlier draft of this row listed the excluded techniques, i.e. exactly the wrong half. |
| Visible-vs-extracted mismatch | Compare Playwright's rendered/visible text against the raw text content returned to the agent (if the upstream tool exposes both, e.g. accessibility snapshot vs raw HTML) | Same class of attack as above, caught structurally rather than by keyword |
| Zero-width / control-character Unicode | Scan for zero-width space, zero-width joiner, other invisible Unicode codepoints, especially clustered | Used to hide or obfuscate injected text from human proofreading |
| Role-play / persona reassignment | Regex/keyword match for phrases attempting to redefine the assistant's identity or instructions mid-content (`You are a`, `Act as`, `Your new role is`) | Common injection framing |
| Suspicious structural placement | Injection-like text appearing outside the page's main content region (e.g. in `<meta>`, `alt` text, `title`, comments, or far outside visible article/body content) | Injected text often doesn't need to render correctly, only to be present in extracted text |
| Excessive HTML comments/CDATA with prose content | HTML comments containing full sentences or imperative phrasing (comments aren't meant to carry prose) | Comments are a common LLM-injection hiding spot |

Each signal produces a 0–1 sub-score. Combine via configurable weighted
sum, normalized to 0–100 for the final heuristic score. Document the
combination formula plainly in code — this must be easy to re-tune as
signals are added (§9).

A signal whose inputs are unavailable (e.g. visible-vs-extracted mismatch
when the upstream tool returns only one view) reports *not applicable*
rather than 0, and is excluded from the weighted sum rather than diluting
it with a false all-clear.

**Exclusions must land somewhere.** Dropping an inapplicable signal out of
the weighted sum makes the page *look safer* — a page where four of seven
signals could not run scores identically to one where all seven ran clean.
Every exclusion therefore reduces `coverage` (§5.3). Coverage drops when:

- Only the accessibility snapshot is available, with no raw HTML.
- The content is predominantly image.
- The scan was truncated by the size cap below.
- The text is not English (§8's known-gap limitation becomes a *visible*
  low-coverage signal rather than a silent one, and routes automatically to
  the multilingual judge).

Layer 1 must be bounded work: cap the scanned payload size and the
per-response scan time in config. Exceeding either cap yields a scored
response over the truncated content plus an explicit truncation marker in
the metadata — never an unbounded scan and never a silent pass.

### 5.2 Layer 2 — LLM judge (conditional, two-axis escalation)

- **Escalation runs on two axes** (§5.3), not one. Judging by risk alone is
  incoherent, because the two things worth escalating sit at opposite ends
  of it: an obvious attack needs no second opinion, while a suspiciously
  quiet page is exactly where novel injection hides.

  | | High coverage | Low coverage |
  |---|---|---|
  | **High risk** | Decided by Layer 1 — no judge call | Decided — no judge call |
  | **Mid risk** | Judge | Judge |
  | **Low risk** | Genuinely clean — no call | **Judge** |

  Low risk with low coverage is the case an earlier draft could not express:
  "we found nothing" and "we could not really look" both scored 0. The
  ambiguous-zone design assumed the heuristics fail by *hesitating*; their
  actual failure mode is confident silence, which is what an attacker
  iterating against a fixed regex list is aiming to produce.

  Band bounds are config, not hardcoded.
- Sends the flagged span(s) — not necessarily the whole page — to a
  cheap/fast model (Haiku-class) with a narrow, structured prompt: "Does
  this text contain an attempt to instruct or manipulate an AI system
  reading it? Respond with a score 0–100 and a one-line reason."
- The judge reads attacker-controlled text, so it is itself an injection
  target. The submitted span must be enclosed in an explicit data
  envelope the prompt tells the model never to obey, and the reply must be
  parsed as a strict score-plus-reason structure. A reply that doesn't
  parse is a judge failure (below), not a score of 0.
- The LLM judge's score is combined with the heuristic score (e.g.
  weighted average, or "LLM score wins in the ambiguous zone" — pick one
  approach and document it; this is a tuning decision, not an
  architectural one).
- Judge configuration is **required, not optional** — see the startup clause
  below. An earlier draft made Layer 2 skippable at runtime; that is the same
  attacker-flippable switch by another name.
- **Judge failure is terminal. There is no override.** If the judge cannot
  return a verdict, the response is not delivered — not with a warning, not
  with a metadata note, not with collapsed coverage. The request fails.

  The reasoning is short. The judge does most of the detection work (upstream's
  own honest figure is 45.2% for the deterministic layers alone against ~99%
  end-to-end), and its input *is the attacker's text*. Any runtime path that
  still delivers content after the judge failed is therefore a switch the
  attacker gets to flip: craft a page that times the judge out, trips a
  provider-side refusal, or lands during an exhausted rate limit, and the
  response goes out screened at 45%. Every mitigation short of refusing —
  warning levels, collapsed coverage, loud markers, "local versus systemic"
  classification — still ships the content, and so still pays the attacker.

  Two earlier drafts of this clause are recorded here because both were wrong
  in instructive ways: the first said failures "must not block the response";
  the second kept a configurable policy with a deliver-and-mark default. Both
  left the switch in place. **If the judge is offline, the proxy is offline.**

  Consequences accepted deliberately:

  - **No `on_judge_failure` policy.** A knob whose wrong setting is silently
    exploitable is not a feature.
  - **No attack-versus-outage classification.** It was built and removed. Once
    every failure refuses, knowing *why* it failed changes no decision — it is
    a logging concern, not a control-flow one.
  - **Availability is coupled to the provider.** A provider outage stops
    fetches. That is the honest cost of the guarantee, and it is visible rather
    than silent.

- **A missing API key is a startup condition, not a request-time failure.**
  Absence of configuration is not reachable from page content — it is decided
  before any page is fetched. The proxy therefore checks for a judge once, at
  startup, and refuses to start without one. Discovering it per-request would
  make every fetch fail for a reason the operator could have been told at boot.

  This replaces the earlier "Layer 2 is skipped entirely and the heuristic
  score stands alone; this must degrade gracefully" language, which is
  incompatible with the clause above.

- A fast-fail guard (N consecutive failures ⇒ refuse immediately rather than
  waiting out the timeout) is permitted purely as a latency and cost
  optimisation. It must not be able to change an outcome, because every
  outcome it could reach is already a refusal.
- Note the egress consequence: invoking the judge sends fetched page content to
  a third-party API, off the VPS. Document it prominently. Given the startup
  requirement above, this is no longer a per-deployment toggle — **running this
  proxy means accepting that egress.** An operator unwilling to accept it
  should not run the proxy rather than run it unscreened; that is the honest
  form of the choice, and it is a real cost of the fail-closed guarantee.

### 5.3 Two axes: risk and coverage

One number cannot carry both "how dangerous does this look" and "how much
were we actually able to check". Conflating them is what made §5.2's
escalation rule incoherent.

- **`risk`** — integer 0–100. Evidence of an injection attempt found.
  0 = no signal. 100 = maximum confidence of attack.
- **`coverage`** — integer 0–100. How much of the applicable checking
  actually ran. 100 = every signal applied and completed. Reduced by each
  exclusion listed in §5.1.

**Both axes ascend with the quantity named.** Do not invert `risk` so that
high means safe: §7's `block_at_or_above` depends on high meaning dangerous,
and inverting it silently turns the gate into a fail-open. For the same
reason, **no field may be named `trust` or `safety`** — a high-is-good field
sitting beside a high-is-bad field is precisely how this class of defect gets
written.

`warning_level` (§6) is derived from `risk`.

#### Determinism

- Store the **per-signal breakdown** alongside the aggregates in scan
  metadata (§6) — not just the totals. This is what makes the system
  re-tunable: when a new heuristic is added or a weight is adjusted, past
  scan logs (if retained) can be re-scored without re-fetching content.
- **Record the heuristic breakdown separately from the judge verdict.** The
  heuristic layer is deterministic and replayable; the judge is not. Merging
  them into one score destroys the re-scoring property above.
- Retention is a config decision, defaulting to off. If scan logs are kept,
  they hold the signal breakdown and the same truncated excerpts as §6 —
  not whole pages.

### 5.4 Boilerplate removal (tier 2)

Stripping sponsored padding, navigation and footers is a usability feature
(§1.2 tier 2) that doubles as a defence: injected payloads favour exactly
those regions — footers, comments, and the `alt` text of advert images. Less
chrome delivered means less surface to scan and fewer tokens spent.

- **Network-level blocking:** Playwright MCP's `--blocked-origins`
  (semicolon-separated) accepts an ad/tracker blocklist;
  `--block-service-workers` closes a related channel. There is no cosmetic
  filtering — no element hiding — so this removes requests, not layout.
- **Main-content extraction:** no upstream support exists.
  `--snapshot-mode` is `full` or `none`, with nothing between. Extraction
  must therefore happen in the proxy, and Readability does not drop in
  because the accessibility snapshot is not HTML.
- **Interaction with §8:** extraction *is* rewriting, which §8 otherwise
  forbids. The carve-out: **scan the full page, deliver the extracted
  version, and let the verdict cover both.** Never scan only the extract —
  that would hand an attacker a trivially exploitable blind spot.

### 5.5 Image scanning (tier 3)

Tier 3 fires precisely when a site is most hostile, so leaving it unscanned
puts the weakest protection where the risk is highest. Injected text rendered
as pixels reaches the agent through vision and bypasses every text layer.

**Cost is not an obstacle.** A full-page screenshot costs ~1560 visual tokens
at the standard resolution tier; at Haiku-class pricing that is roughly
**$1.56 per thousand screenshots**. Tier 3 is by definition the rare path.

Two layers, mirroring §5.1/§5.2:

1. **OCR (cheap, local, no egress).** Extract text from the screenshot and
   run it through the Layer 1 signals unchanged. No per-image cost, nothing
   leaves the VPS, and the existing heuristics are reused wholesale.
2. **Vision judge (escalation).** A multimodal Haiku-class model, invoked on
   the same two-axis rule as §5.2 — including OCR-hostile images, which
   register as low coverage.

The judge's reply is schema-constrained (structured outputs), so page content
cannot make it emit anything off-schema; it can only push a wrong value into
the schema. The judge holds no tools and no task, so its worst case is a
wrong verdict, not a wrong action — the same reasoning that makes §5.2's text
judge acceptable.

#### Resolution parity (mandatory)

A judge reading the standard tier (1568px long edge) can be handed an image
whose small text is legible to an agent reading the high-resolution tier
(2576px). That gap is directly exploitable.

**Downscale once, judge that artefact, deliver that same artefact.** Nothing
the agent can read is then something the judge could not. This is not a
tunable: any configuration that raises delivered fidelity must raise the
judge to match.

Downscaling also cuts agent-side cost roughly threefold on large screenshots
(4784 → 1560 visual tokens for a 4K capture). Fidelity loss is acceptable
because a caller who needs the fine detail crops and pastes it directly
rather than routing it through this proxy.

**Egress:** a screenshot leaving the VPS discloses far more than a flagged
text span. OCR-first means most images never leave. State this plainly
alongside §5.2's egress note rather than burying it.

## 6. Response metadata format

Every scanned response gets a metadata block attached (exact MCP-legal
mechanism TBD at implementation — likely an added field in the tool
result's structured content, or a prefixed text block; confirm what the
MCP spec/SDK allows for augmenting tool results without breaking client
compatibility). Fields:

```json
{
  "sentry_scan": {
    "version": "1.0",
    "scanned": true,
    "tier": 1,
    "risk": 42,
    "coverage": 71,
    "warning_level": "elevated",
    "heuristics": {
      "risk": 38,
      "signals": {
        "imperative_phrases": 0.1,
        "screen_reader_text": 0.6,
        "visible_extracted_mismatch": null,
        "zero_width_unicode": 0.0,
        "roleplay_reassignment": 0.0,
        "structural_placement": 0.2,
        "comment_prose": 0.0
      },
      "coverage_reductions": ["no_raw_html"]
    },
    "llm_judge": {
      "invoked": true,
      "modality": "text",
      "risk": 55,
      "reason": "aria-label carries an instruction to disregard prior context."
    },
    "flagged_spans": [
      {"excerpt": "...(truncated, max ~200 chars)...", "signal": "screen_reader_text"}
    ]
  }
}
```

- `warning_level` is a small enum derived from `risk` via configurable
  bucket boundaries (§7) — e.g. `none` / `low` / `elevated` / `high` /
  `critical`. This is the human/agent-legible signal; `risk` is the
  machine-tunable one.
- `tier` records which rung of the §1.2 ladder produced the content, so a
  caller can tell a rendered-text response from a screenshot without
  inspecting the payload.
- A signal that did not apply (§5.1) reports `null`, distinct from a
  sub-score of `0.0`, **and** appears in `coverage_reductions`.
- `heuristics.risk` is the deterministic, replayable score; the top-level
  `risk` may incorporate the judge. Keeping both is what preserves §5.3's
  re-scoring property.
- `flagged_spans`: short excerpts only, truncated, never the full injected
  payload verbatim — no reason to reproduce the attack content in full in
  logs or responses beyond what's needed to explain the flag.
- Excerpts are attacker text being handed back to the very agent being
  protected. Defang before emitting: strip zero-width and control
  characters, and wrap the excerpt in a delimiter the surrounding
  metadata declares as inert data.
- If Layer 2 wasn't invoked (score outside ambiguous zone, or no API key
  configured), `llm_judge.invoked: false` and no `score`/`reason`.
- If content genuinely was not scanned: `scanned: false` plus `skip_reason`
  (e.g. `no_judge_configured`, `size_cap`, `ocr_unavailable`), and no
  `risk`/`warning_level`/`signals`. `binary_content` is **no longer** a valid
  skip reason — images are scanned per §5.5.
- **A tier-3 response with `scanned: false` must be loud.** A quiet
  `scanned: false` on the path that fires when a site is most hostile is the
  worst possible failure mode. Emit an explicit
  `"no screening performed"` marker in the human-legible surface, not just a
  boolean a caller may not check.

### 6.1 Integrity of the metadata channel

A fetched page can contain text that mimics a `sentry_scan` block. Anything
downstream that reads the verdict must be able to tell the proxy's block
from a forged one:

- Strip or neutralise any `sentry_scan` marker occurring in fetched
  content before the proxy attaches its own.
- Prefer a channel the content cannot occupy at all — a structured result
  field rather than an in-band text block — if the MCP SDK allows it (§12).

## 7. Open/closed gate behaviour

- **Default mode: pass-through with metadata.** The proxy does not block
  by default. It scores, attaches metadata, and forwards. This matches
  the "scored not boolean" requirement — gating is a decision made by
  config, not baked into the proxy's core behaviour.
- **Configurable hard-block threshold** (`block_at_or_above: <int>`,
  default: disabled/null), evaluated against `risk`. If set, responses at or
  above this value are **not** forwarded; instead the proxy returns an MCP
  error (or a stub response — decide at implementation, document the choice)
  explaining the block, with `risk` and `coverage` included so the caller
  knows why. Per §5.3, this threshold is the concrete reason `risk` must not
  be inverted.
- **No judge-failure policy exists, by design** (§5.2). Judge failure refuses
  the response unconditionally. This is deliberately *not* configurable: a knob
  here would be an attacker-flippable switch, since the judge's input is the
  attacker's text. `block_at_or_above` governs what happens when the scanner
  formed an opinion; nothing governs what happens when it could not, because
  there is only one safe answer.
- **Image rendering defaults.** Screenshots are downscaled to the standard
  resolution tier before both scanning and delivery (§5.5). The knob exists
  for operators who need more fidelity, but raising delivered fidelity
  **must** raise judge fidelity in the same step — the config loader should
  refuse a combination that breaks resolution parity rather than silently
  reopening the gap.
- **Configurable warning-level bucket boundaries** are separate config
  from the block threshold, so operators can widen/narrow the `elevated`
  vs `high` distinction without touching block behaviour, and vice versa.
- All thresholds live in one config section so they can be tuned without
  touching code — this is the "adjustment as heuristics are added"
  requirement from the brief: adding a new signal only requires adding
  its weight to config, not changing the gate logic.

## 8. Non-goals / explicit limitations (document these, don't apologise for them)

- Not a guarantee — heuristics and a cheap LLM judge will miss novel or
  adversarially-tuned injections. This is risk reduction, not elimination.
  The deterministic layer in particular is enumerable: an attacker can
  iterate against a fixed regex list offline. That is the standing argument
  for the judge doing real work (§5.2) rather than only breaking ties.
- **Screenshots and images are in scope** (§5.5). PDFs remain out of scope
  unless rendered through the same screenshot path.
- The **English-only** limitation of the keyword heuristics stands, but is no
  longer a silent gap: non-English content reduces `coverage` (§5.1) and
  routes to the multilingual judge automatically.
- Does not attempt to sanitize or rewrite *flagged* content — it scores and
  labels, it does not "clean" the page text. Rewriting risks silently
  destroying legitimate content and creating a false sense of safety.
  Three narrow exceptions: the defanging in §6, the marker-stripping in
  §6.1, and boilerplate extraction under §5.4 — which is permitted only
  because the full page is scanned regardless of what is delivered.

## 9. Extensibility requirement

Adding a new heuristic signal must require:

1. A new scoring function following a defined interface (input: parsed
   page content in whatever normalized form Layer 1 uses; output: 0–1
   sub-score or *not applicable*, plus optional flagged span).
2. A new entry in the weights config.
3. No changes to the aggregation, metadata format, or gate logic.

Document this interface explicitly in the code (a short `SIGNALS.md` or
docstring on the base signal class/function) so future additions are
mechanical, not exploratory.

Each signal ships with fixture pages exercising it — one that should fire,
one near-miss that should not. The re-tuning claim in §5.3 is only real if
a weight change can be re-run against a corpus.

## 10. Suggested repo shape

```
sentry-mcp/
  sentry_mcp/
    proxy.py          # MCP protocol pass-through + interception
    signals/
      __init__.py      # signal registry + interface
      imperative.py
      screen_reader_text.py
      mismatch.py
      zero_width.py
      roleplay.py
      structural.py
      comment_prose.py
    scorer.py          # aggregation, LLM judge invocation, final score
    config.py          # load thresholds/weights/upstream URL/API key
  tests/
    fixtures/          # injection and near-miss pages, per §9
  config.example.yaml
  sentry-mcp.service    # systemd unit
  README.md             # deployment steps, Funnel path config, tuning guide
  SIGNALS.md             # signal interface doc, per §9
```

## 11. Licensing

- **AGPL-3.0** for all original code in this repository.
- Rationale: upstream dependencies (Playwright, playwright-mcp, MCP SDK,
  MCP spec) are Apache-2.0/MIT — permissive, no copyleft obligations flow
  upward onto this project from consuming them as a client/dependency.
  AGPL-3.0 chosen independently, matching existing convention across
  Justin's other projects, and specifically closes the network-use
  loophole plain GPL leaves open (a hosted fork with modifications must
  share source with its users).
- Include a `LICENSE` file (standard AGPL-3.0 text) at repo root and an
  SPDX header (`SPDX-License-Identifier: AGPL-3.0-or-later`) on source
  files, matching whatever convention the license-checking tooling in
  this ecosystem expects.
- Third-party notices: since this project only *speaks to* playwright-mcp
  as an MCP client over the wire (per §2, transparent proxy architecture)
  rather than vendoring its source, no upstream copyright-notice
  preservation is required. If any upstream code is ever copied in
  directly (rather than depended on), flag it and add a `NOTICE` file at
  that point — not needed for v1 as specified.

## 12. Open questions for Justin (flag, don't guess)

- Exact MCP-legal way to attach `sentry_scan` metadata to a tool result
  without breaking client compatibility — needs a check against current
  MCP SDK/spec at implementation time. Whether a structured field is
  available decides §6.1's preferred option.
- Whether dedicated system user is worth the friction on the current VPS
  setup (§3).
- Exact Funnel path-routing config for a second local port alongside
  Clautana's existing `/mcp` path — confirm against current Tailscale
  `serve`/`funnel` config before assuming syntax.
- Default block threshold, if any — recommend shipping with blocking
  **disabled** (metadata-only) until real scan data exists to tune
  against, then revisit.
- Whether `resources/read` and `prompts/get` need scanning too (§4.2), or
  whether the upstream servers in use never serve fetched content that
  way.
- Project name — Sentry (sentry.io) ships an official MCP server, so
  `sentry-mcp` collides in search and in config files. `mind-the-gap-mcp`
  is the leading candidate and is unregistered on npm. Rename now if it is
  going to be renamed at all.

### 12.1 Settled — do not re-open

These were decided by explicit Q&A and are recorded here so a later reader
does not mistake them for open:

- **Architecture:** transparent MCP proxy wrapping the fetch/render server —
  agent points at the scanner, scanner calls upstream.
- **Scoring:** heuristics plus optional LLM-judge escalation.
- **Deployment:** isolated, but sharing the existing tunnel.
- **Exposure:** same Tailscale node, separate local port, separate Funnel
  path (`/scan` vs Clautana's `/mcp`).
- **Transport:** HTTP in from the agent, **HTTP** out to Playwright MCP on
  port 8931 — *not* stdio, which an earlier draft of §4.1 assumed.
- **Scope:** the fetcher is in scope (§2.2/§2.3), not a separately
  specified service.
- **Licence:** AGPL-3.0 (§11).
- **Build vs adopt:** adopt, for data only. Vault's MIT-licensed pattern
  corpus and precomputed embeddings are vendored under `sentry_mcp/corpus/`;
  no upstream source code is incorporated, the TypeScript orchestration being
  cheaper to rewrite than to bridge. Pipelock was not adopted — stdio-only.
  Settled by `a41b788`, and confirmed by the Python port of the Layer 2 judge
  that followed it.
