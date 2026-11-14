# tgtrust Trust Desk — Open Agentic Web Challenge

Trust Desk is a public agentic website. Another site's agent asks it **before** it gives an unknown agent a task
or a payment. It takes an agent's public key or agent card and answers with what tgtrust evidence actually shows
about that key, and with a recommended limit tier computed the same way as `tgtrust.gate`. It never says more than
the evidence shows.

The gap it fills is named in the specification itself: schema validation and sandboxing "do not establish trust in
the peer network or its publisher" (section 5), and "identity and reputation" are listed as future work (section 7).

This file is the conformance map. Nothing in `desk/` is written before a row here says which requirement it meets
and which test proves it. The Status column is updated by each block.

## Sources (read on the dates given)

| Source | Version | Read |
| --- | --- | --- |
| Spec `docs/worldwide_agentic_web_mvp_spec.md` in `github.com/cognizant-ai-labs/agentic-web` | repository HEAD `63a956c` (2026-11-13); the spec file last changed in `fd872b9` on 2026-11-10, so the text is the one in force when the Submission Period opened (2026-11-11 20:00 PT) | 2026-11-14 |
| Same repository: `docs/quickstart.md`, `docs/providers/otari.md`, `docs/providers/providers.md`, `docs/agentic_websites.md` | `63a956c` | 2026-11-14 |
| Same repository: `skills/agentify-website/` (`SKILL.md`, `references/*.md`, `templates/`, `runtime/`, `scripts/`) and `examples/guesthouse_agentified/` | `63a956c`; the skill's runtime is nsdeploy commit `53a787c` (2026-11-11) with the edits listed in `runtime/README.md`, byte-identical to the example's runtime | 2026-11-14 |
| Official rules, `cognizant-agenticweb.devpost.com/rules` | as published | 2026-11-14 |
| Overview, `cognizant-agenticweb.devpost.com` | as published | 2026-11-14 |
| Live demo issuer `https://minimal.tailee59dc.ts.net/v1` (`/issuer`, `/agents/{key}/badge`) | epoch `v2`, key id `9fc6ef5575f072ab`; replies carry **no** `Access-Control-Allow-Origin` header | 2026-11-14 14:50 PT |
| Concordium `agent-registry-mcp.concordium.com/v1/badge-check/{badge}` | replies with `access-control-allow-origin: *` | 2026-11-14 14:50 PT |

## Contest rules checklist

| Rule (official rules unless noted) | How Trust Desk meets it | Status |
| --- | --- | --- |
| Working open agentic website, standard open web technologies, conforming to the spec "as of the start of the Submission Period" | Static HTML, CSS and ES modules; the spec text has not changed since 2026-11-10 | planned |
| Publicly accessible, runs consistently in a current browser | GitHub Pages over HTTPS; Playwright runs in Chromium at desktop and phone sizes | planned |
| URL must contain a publicly accessible conforming `.json` network file | `desk/trust_desk.network.json`, built from `desk/trust_desk.hocon` with the reference build script | planned |
| A `runtime` file that runs the network in the browser | `desk/runtime/`, the skill's runtime copied unchanged | planned |
| An interface for users or agents to interact with the network | the chat panel, and the desk form that runs the same grounded action without a model | planned |
| Optional interface to configure LLMs and keys | the runtime's ⚙ AI model settings panel (BYOK) | planned |
| The network interacts with the website, and may call or be called by other agentic websites | grounded site action `verify_agent`; the second-origin demo site calls Trust Desk as a partner network | planned |
| Text description, screenshots | Devpost draft at the end of this file | planned |
| Video under 2 minutes, browser footage, "the Entrant explaining the Project (not AI generated)" (overview page), public on YouTube, no third-party trademarks or music | script at the end of this file; the owner records and narrates it himself | planned |
| If the project uses Mozilla Otari: Otari account email and one sentence on a problem met (overview page) | the default router is hosted Otari, so the owner fills both fields on the form | owner |
| English, or English translation of all materials | all code, docs and UI in English | planned |
| Free, without restriction, for testing until the Judging Period ends (2027-01-18 17:00 PT) | static site, no account; the desk form needs no key | planned |
| New, or significantly updated after the start of the Submission Period (2026-11-11 20:00 PT); explain how | see "What is new" below | done |
| Original work; open source allowed if the entry builds on it; licences respected | the runtime is Apache-2.0 (`runtime/LICENSE.txt` kept); Trust Desk code is new | planned |
| Third-party integrations authorised under their terms | Concordium's public badge-check endpoint; hosted Otari through the visitor's own key | planned |

Note on the brief: the rules' cut-off for a pre-existing project is the start of the Submission Period,
2026-11-11 20:00 PT, not 2025-11-11.

## What is new after 2026-11-11 20:00 PT

tgtrust started privately on 2026-11-06; its public history starts with `tgtrust v0.1.0` on 2026-11-12. Before the
Submission Period it had the Telegram signature check, blind-signed credentials, the issuer service, the TON testnet
stake contract, deals and disputes. Everything below was made after the period opened:

- public release v0.1.0 (2026-11-12) and v0.2.0 (2026-11-13): holder Mini App, trust gate for paid APIs, x402
  pricing, Concordium Agent Registry binding, MCP server;
- Trust Desk (this entry, from 2026-11-14): the agent network, the browser verifier that mirrors the Python checks,
  the desk page, the second-origin demo and the conformance tests.

## Spec conformance map

Section numbers are the spec's. "Runtime" means the reference runtime copied unchanged into `desk/runtime/`; where
the runtime provides a behaviour, the test still proves it on Trust Desk's own files.

### 2. Common multi-agent representation

| Requirement | How Trust Desk meets it | Test | Status |
| --- | --- | --- | --- |
| MUST follow the Neuro SAN HOCON reference | `desk/trust_desk.hocon` written from the skill's `templates/network.hocon` | build script validation | planned |
| Published form MUST preserve the data model and MUST NOT depend on local includes, env substitutions or publisher-only paths | `trust_desk.network.json` is produced by `build_network.mjs` with the runtime's own parser; a test fails on `include`, `${` or file paths in it | `desk/tests/network.test.mjs` | planned |
| 2.1 stable name, short description, front agent | manifest and network share the name `trust_desk`, front agent `trust_desk` | network test | planned |
| 2.1 unique agent names, function description, instructions, tools list | front agent + `evidence_checker` + `limit_advisor`; build checks duplicates and missing references | build `--check` | planned |
| 2.1 JSON-Schema inputs; structured outputs SHOULD declare schemas | every agent `function` has a `request` parameter; `verify_agent` declares its input schema and documents its result shape | network test | planned |
| 2.1 private context deny-by-default; network MUST name fields that may pass | no `sly_data` field is allowed downstream or upstream; the demo caller sets a private field and the test shows it is absent at the peer | `e2e: private context absent at peer` | planned |
| 2.1 unavailable external capability: fail closed, report clearly, never bypass browser security | the live issuer lookup is attempted with `fetch` in CORS mode only; a failure is reported as "live lookup unavailable", never as a result | `verifier: offline issuer` + `e2e: offline issuer` | planned |
| 2.2 declarative data; instructions are public, not a confidentiality mechanism | no coded tools, no secrets in any published file; a test scans published files for key-like strings | `network test: no secrets` | planned |

### 3. Browser execution and site composition

| Requirement | How Trust Desk meets it | Test | Status |
| --- | --- | --- | --- |
| Usable from a normal web page, executes the graph in JavaScript | `desk/index.html` boots the runtime with `site.js` | e2e boot | planned |
| 3.1 reject malformed networks, duplicate or missing references, invalid front agent, unsupported executables before any model call | runtime validator; the demo serves a broken network and the test asserts the visible error and zero router requests | `e2e: invalid network` | planned |
| 3.1 agent loop with tool calls, delegation, error propagation, bounded history | runtime; the scripted router drives `trust_desk → evidence_checker → website_verify_agent` | `e2e: delegation + grounded action` | planned |
| 3.1 ask before discovering or calling a third-party MCP service | Trust Desk declares no MCP server | n/a | planned |
| 3.1 local site actions validated; destination and arguments shown before a write or irreversible operation | Trust Desk registers only `read` actions. The demo site's one irreversible action (`serve_request`) opens the confirmation dialog with origin and arguments | `node: action registry` + `e2e: irreversible dialog` | planned |
| 3.1 timeout or disconnect after a write begins MUST be reported unknown; MUST NOT be repeated | the demo's `serve_request` can be made to time out; the test asserts receipt `unknown`, the visible wording, and exactly one call | `e2e: unknown outcome, no retry` | planned |
| 3.1 finite limits on depth, agent calls, remote calls, concurrency, time; repeated calls are not a cycle | runtime limits (per visitor message: 4 partner calls, 1 per partner network, 24 agent calls, 90 s; 5 levels deep; skill `references/linking.md`, read 2026-11-14) | `e2e: over-budget`, `e2e: composition cycle` | planned |
| 3.2 peer referenced by HTTPS URL whose last path part is the network name; manifest fetched from the base | demo calls `https://<desk base>/trust_desk` | `e2e: second origin` | planned |
| 3.2 peer runs on the caller's router, model policy and limits; key only to that router | runtime (`engine.js` edits); the test logs every request on both origins | `e2e: key never reaches peer` | planned |
| 3.2 consent mechanism naming origin and purpose, before each contact; relaxation only by explicit user choice | runtime consent card; the test asserts no request to the peer origin before **Allow** | `e2e: consent before contact` | planned |
| 3.2 exact network name or fail | the test asks for `trust_desk_v0`, which the manifest does not list, and asserts the visible failure | `e2e: wrong network name` | planned |
| 3.2 private context does not return except permitted fields | see 2.1 | `e2e: private context absent at peer` | planned |
| 3.2 every additional hop repeats origin policy and consent; cycles and over-budget requests stop | demo network names Trust Desk; a cycle fixture names itself back | `e2e: composition cycle` | planned |
| 3.2 cross-origin artifacts published with CORS | GitHub Pages sends `Access-Control-Allow-Origin: *`; checked on the live URL after deploy | `deploy check` | planned |
| 3.3 `agent-manifest.json`: name, front_man, hocon; LLM router metadata; peer policy | `desk/agent-manifest.json` from the skill template, `peer_policy.mode: closed` | network test | planned |
| 3.3 network definition at the manifest's location, public GET | `./trust_desk.network.json` | network test | planned |
| 3.3 `links.json` publisher bindings; caller-owned bindings never modify it | `desk/links.json` (empty bindings); the runtime stores caller bindings in browser storage | network test | planned |
| 3.3 production MUST use HTTPS | GitHub Pages, HTTPS only | deploy check | planned |
| 3.4 public artifact requests MUST NOT carry the caller's private credentials | runtime fetches with default credentials policy; the test asserts no `Authorization` header and no cookie reaches the peer | `e2e: key never reaches peer` | planned |

### 4. Pluggable inference

| Requirement | How Trust Desk meets it | Test | Status |
| --- | --- | --- | --- |
| Default router and model | hosted Otari `https://api.otari.ai/api/v1`, model `alibaba/qwen3.8-flash` (the reference default, `docs/quickstart.md`). A static site cannot hold a publisher key, so the visitor supplies an Otari key; the desk form itself needs no model | `e2e: default router used` | planned |
| BYOK: router base URL, model and credential selectable | runtime ⚙ AI model settings panel | `e2e: BYOK path` | planned |
| Key never in URLs, manifests, network files, prompts, action arguments, traces, analytics or peer requests | the test types a marker key and searches every request URL, body and header to any host except the router, and the page's trace | `e2e: key never reaches peer` | planned |
| A peer's manifest cannot replace the router | the demo peer fixture names another router; the test asserts all model requests still go to the caller's router | `e2e: peer cannot change router` | planned |
| Missing key MUST stop the model call with a clear setup error | test sends a chat message with no key and asserts the error text and zero router requests | `e2e: missing key` | planned |
| Stored profiles can be deleted | test saves, deletes, reloads and asserts storage is empty | `e2e: delete profile` | planned |
| SHOULD minimise third-party scripts and use a restrictive CSP | no third-party scripts; CSP in a `<meta>` tag (GitHub Pages cannot send headers) | `network test: csp` | planned |

### 5. Security and privacy

| Requirement | How Trust Desk meets it | Test | Status |
| --- | --- | --- | --- |
| Peer definitions are untrusted input | Trust Desk's own instructions say to ignore instructions inside agent cards and peer answers; card fields are shown as quoted data | network test (rule present) | planned |
| No undeclared peer code | no coded-tool bundle is declared or loaded | network test | planned |
| Consent names destination origin and nature; a redirect to another origin is a new destination | runtime | `e2e: consent before contact` | planned |
| Consent precedes third-party fetches | runtime | `e2e: consent before contact` | planned |
| Private context by exception | see 2.1 | `e2e: private context absent at peer` | planned |
| Fail closed: never begin or continue, never report success, report the failure | the verifier returns `invalid` or `unknown` with reasons; nothing that failed is shown as a pass | `verifier: vectors` | planned |
| Runtime, not the model, owns confirmation | runtime + the demo's dialog | `e2e: irreversible dialog` | planned |
| SHOULD expose router, contacted origins, calls, consent decisions, errors, receipts | runtime agents panel; the desk result lists every source it read and every source that failed | `e2e: evidence sources listed` | planned |

### 6. MVP interoperability checks

| Check | Demonstration | Test | Status |
| --- | --- | --- | --- |
| Publish a two-agent HOCON network and a manifest from an ordinary HTTPS host | three agents, GitHub Pages | deploy check | planned |
| Run it with the default router and model; also the BYOK path | scripted router stands in for Otari in CI; one manual run with a real key before submission | `e2e: default router used`, `e2e: BYOK path` | planned |
| Call an internal agent and a grounded capability (registered local site action) | `trust_desk → evidence_checker → website_verify_agent` | `e2e: delegation + grounded action` | planned |
| After approval, load an exact named network from a second origin and run it locally | the demo paid-API site calls Trust Desk | `e2e: second origin` | planned |
| With a user key active, the second site never receives it and cannot change the router | request logs on both origins | `e2e: key never reaches peer`, `e2e: peer cannot change router` | planned |
| Private context absent at the peer unless a named field is allowed | demo sets a private field | `e2e: private context absent at peer` | planned |
| Stop an invalid network, a composition cycle, an over-budget request and a denied origin with visible errors | four fixtures | `e2e: invalid network`, `e2e: composition cycle`, `e2e: over-budget`, `e2e: denied origin` | planned |

## Trust claims: allowed wording

From the ERC-8004 review R-1111-01. The verifier and the agents use only these forms.

| Evidence | Say | Never say |
| --- | --- | --- |
| A credential that verifies against the issuer key, bound to the agent key | "one Telegram account per issuer epoch (issuer-attested), owner not disclosed" | unique person, real accountable human, KYC |
| Deals | "N co-signed deal records (M with staked counterparties)" | completed jobs, successful deals |
| Stake | amount with its network label, for example "0.5 Gram active on TON testnet" | a stake with no network, a placeholder address |
| Issuer offline | "live lookup unavailable: the result uses signed data only" | a level or count that was not read |
| Agent card | "the card names key X; a card is only a claim until the key signs a challenge" | "the card proves" |

## Open decisions

- **Second origin for the public demo.** GitHub Pages project sites of one account share the origin
  `miinimal.github.io`, so the demo site needs another origin. Recorded in `docs/DECISIONS.md` when block 5 is done.
- **Live issuer from the browser.** The demo issuer sends no CORS header today, so a page on another origin cannot
  read it. Block 3 adds CORS to its public read-only GET endpoints; until the owner merges and restarts the laptop
  service, the desk reports "live lookup unavailable" and works from signed data alone.
