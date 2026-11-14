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
| Working open agentic website, standard open web technologies, conforming to the spec "as of the start of the Submission Period" | Static HTML, CSS and ES modules; the spec text has not changed since 2026-11-10; every MUST below has a test | done |
| Publicly accessible, runs consistently in a current browser | GitHub Pages over HTTPS (block 6); `tests/test_desk_page.py` runs Chromium at 1280 px and 390 px, light and dark | done locally |
| URL must contain a publicly accessible conforming `.json` network file | `desk/trust_desk.network.json`, built from `desk/trust_desk.hocon` with the reference build script | done; public after deploy |
| A `runtime` file that runs the network in the browser | `desk/runtime/`, the skill's runtime copied unchanged, pinned by sha256 | done |
| An interface for users or agents to interact with the network | the chat panel, and the desk form that runs the same grounded action without a model | done |
| Optional interface to configure LLMs and keys | the runtime's ⚙ AI model settings panel (BYOK) | done |
| The network interacts with the website, and may call or be called by other agentic websites | grounded site actions `get_desk`, `check_agent`, `recommend_limit`; the second-origin demo site calls Trust Desk as a partner network | done locally |
| Text description, screenshots | Devpost draft at the end of this file | planned |
| Video under 2 minutes, browser footage, "the Entrant explaining the Project (not AI generated)" (overview page), public on YouTube, no third-party trademarks or music | script at the end of this file; the owner records and narrates it himself | planned |
| If the project uses Mozilla Otari: Otari account email and one sentence on a problem met (overview page) | the default router is hosted Otari, so the owner fills both fields on the form | owner |
| English, or English translation of all materials | all code, docs and UI in English | done |
| Free, without restriction, for testing until the Judging Period ends (2027-01-18 17:00 PT) | static site, no account; the desk form needs no key | after deploy |
| New, or significantly updated after the start of the Submission Period (2026-11-11 20:00 PT); explain how | see "What is new" below | done |
| Original work; open source allowed if the entry builds on it; licences respected | the runtime is Apache-2.0 (`runtime/LICENSE.txt` kept); Trust Desk code is new; the skill's scripts in `desk/tools/agentify/` keep their licence file | done |
| Third-party integrations authorised under their terms | Concordium's public badge-check endpoint; hosted Otari through the visitor's own key | done |

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
| MUST follow the Neuro SAN HOCON reference | `desk/trust_desk.hocon` written from the skill's `templates/network.hocon`; the reference `build_network.mjs` parses it with the runtime's own parser and runs the runtime's validator | `tests/test_desk.py::test_network_build_is_current_and_valid` | done |
| Published form MUST preserve the data model and MUST NOT depend on local includes, env substitutions or publisher-only paths | `trust_desk.network.json` is produced by `build_network.mjs`; the test re-parses the HOCON and requires the same object, and fails on `include`, `${` or file paths | `desk/tests/network.test.mjs` "the published network is the HOCON source, fully resolved" | done |
| 2.1 stable name, short description, front agent | manifest and network share the name `trust_desk`, front agent `trust_desk` | network test "manifest lists the network…" | done |
| 2.1 unique agent names, function description, instructions, tools list | front agent `trust_desk` delegates to `evidence_checker` and `limit_advisor` | build `--check`; network test "at least two agents…" | done |
| 2.1 JSON-Schema inputs; structured outputs SHOULD declare schemas | every agent `function` has a `request` parameter; the site actions `get_desk`, `check_agent`, `recommend_limit` declare input schemas and describe their result fields | network test; `desk/tests/actions.test.mjs` | done |
| 2.1 private context deny-by-default; network MUST name fields that may pass | Trust Desk names no `sly_data` field; the demo caller names exactly one (`request_id`) and the test shows nothing else reaches the peer | network test "no agent passes private context…"; E2E `test_private_context_reaches_the_peer_only_when_named` | done |
| 2.1 unavailable external capability: fail closed, report clearly, never bypass browser security | live lookups use plain CORS `fetch` with `credentials: "omit"` and a timeout; off until the visitor allows them; a failure is reported as "live lookup unavailable: the result uses signed data only", never as a pass | `actions.test.mjs` "live lookups contact only the listed origins…", `verifier.test.mjs` "assess: signed data only, issuer offline…"; `test_desk_page.py` "live lookups are off until allowed…" | done |
| 2.2 declarative data; instructions are public, not a confidentiality mechanism | no coded tools, no secrets in any published file; a test scans published files for key-like strings | network test "no coded tools and no secrets…" | done |

### 3. Browser execution and site composition

E2E = `tests/test_desk_e2e.py`: Chromium, Trust Desk on `http://127.0.0.1:<port>/`, the demo caller on
`http://localhost:<port>/` (two origins), a scripted router, every other host blocked and recorded.

| Requirement | How Trust Desk meets it | Test | Status |
| --- | --- | --- | --- |
| Usable from a normal web page, executes the graph in JavaScript | `desk/index.html` boots the runtime with `site.js` (from the skill template); the desk itself works when the assistant cannot load | `tests/test_desk_page.py` (Chromium, phone and desktop, light and dark, no console errors) | done |
| 3.1 reject malformed networks, duplicate or missing references, invalid front agent, unsupported executables before any model call | runtime validator. A peer network with a missing agent reference: "Error from tool … no_such_agent", no model call for the peer. The caller's own broken network: the page says "The assistant could not load (…no_such_agent…)", zero router requests | E2E `test_invalid_peer_network_is_stopped_before_any_model_call`, `test_invalid_own_network_stops_with_a_visible_error` | done |
| 3.1 agent loop with tool calls, delegation, error propagation, bounded history | runtime; `trust_desk → evidence_checker → website_check_agent` with the real runtime | `actions.test.mjs`; E2E `test_default_router_and_model_on_trust_desk_with_grounded_action` | done |
| 3.1 ask before discovering or calling a third-party MCP service | Trust Desk declares no MCP server | n/a | n/a |
| 3.1 local site actions validated; destination and arguments shown before a write or irreversible operation | Trust Desk registers only `read` actions, so the patched runtime's known gap (it runs `write` actions without a dialog) never applies. The demo's one irreversible action, `serve_request`, opens a dialog with the details and, under "Technical details", the action, its origin and the arguments; declining runs nothing | `actions.test.mjs`; E2E `test_write_with_unknown_outcome_is_reported_unknown_and_not_retried`, `test_declined_write_runs_nothing` | done |
| 3.1 timeout or disconnect after a write begins MUST be reported unknown; MUST NOT be repeated | the demo's `serve_request` never answers when "Simulate an upstream timeout" is on; the receipt is `unknown`, the page counts exactly one call, and the model is given no second call | E2E `test_write_with_unknown_outcome_is_reported_unknown_and_not_retried` | done |
| 3.1 finite limits on depth, agent calls, remote calls, concurrency, time; repeated calls are not a cycle | runtime limits (per visitor message: 4 partner calls, 1 per partner network, 24 agent calls, 90 s; 5 levels deep; skill `references/linking.md`, read 2026-11-14) | E2E `test_second_call_to_the_same_peer_is_over_budget` | done |
| 3.2 peer referenced by URL whose last path part is the network name; manifest fetched from the base | the demo names `<desk base>/trust_desk`; the desk's server log shows `/agent-manifest.json`, `/trust_desk.network.json`, `/links.json` | E2E `test_second_origin_after_consent_key_and_router_stay_with_caller` | done |
| 3.2 peer runs on the caller's router, model and limits; key only to that router | every model request (caller and peer) goes to the caller's router with the caller's model; the peer's first request has only a system and a user message | same test | done |
| 3.2 consent naming origin and purpose before each contact; relaxation only by explicit choice | runtime consent card names "tgtrust Trust Desk" and its host and shows the request; nothing reaches the desk's origin before **Allow**; **Decline** sends nothing at all; **Always allow** is the visitor's explicit choice | E2E second-origin test, `test_decline_sends_nothing_to_the_peer`, over-budget test | done |
| 3.2 exact network name or fail | the demo asks for `trust_desk_v0`: "No published network named 'trust_desk_v0'…"; only the manifest is fetched | E2E `test_wrong_network_name_fails_instead_of_another_network` | done |
| 3.2 private context does not return except permitted fields | see 2.1 | E2E `test_private_context_reaches_the_peer_only_when_named` | done |
| 3.2 every additional hop repeats policy and consent; cycles and over-budget requests stop | a fixture network that names its own URL: at a site root the runtime never offers the call back; under a subpath (as on GitHub Pages) the call is offered and stopped with "Skipped Loop fixture: that network was already consulted for this query" — the one-call-per-peer limit, which the runtime checks before its cycle detector | E2E `test_composition_cycle_is_stopped_with_a_visible_error`, `test_composition_cycle_at_a_site_root_is_never_offered` | done |
| 3.2 cross-origin artifacts published with CORS | locally `serve_site.mjs` sends the header on the public files; GitHub Pages sends `Access-Control-Allow-Origin: *` on every file (checked on pages.github.com, 2026-11-14) | E2E; deploy check | done locally |
| 3.3 `agent-manifest.json`: name, front_man, hocon; LLM router metadata; peer policy | `desk/agent-manifest.json` from the skill template, `peer_policy.mode: closed` | network test "manifest declares the default router…" | done |
| 3.3 network definition at the manifest's location, public GET | `./trust_desk.network.json` | network test; E2E | done |
| 3.3 `links.json` publisher bindings; caller-owned bindings never modify it | `desk/links.json` (empty bindings); the runtime stores caller bindings in browser storage | network test "links.json is the publisher's…" | done |
| 3.3 production MUST use HTTPS | GitHub Pages, HTTPS only | deploy check | after deploy |
| 3.4 public artifact requests MUST NOT carry the caller's private credentials | no `Authorization` header and no cookie on any request to the desk's origin, in the browser record and in the desk server's log | E2E second-origin test | done |

### 4. Pluggable inference

| Requirement | How Trust Desk meets it | Test | Status |
| --- | --- | --- | --- |
| Default router and model | hosted Otari `https://api.otari.ai/api/v1`, model `alibaba/qwen3.8-flash` (the reference default, `docs/quickstart.md`). A static site cannot hold a publisher key, so the visitor supplies a key and nothing else; the desk form itself needs no model. In the test Otari's URL is answered by the scripted router | E2E `test_default_router_and_model_on_trust_desk_with_grounded_action` | done |
| BYOK: router base URL, model and credential selectable | runtime ⚙ AI model settings panel; every E2E caller run sets all three | E2E (all caller runs) | done |
| Key never in URLs, manifests, network files, prompts, action arguments, traces or peer requests | a marker key is searched in every request URL, header and body and in every prompt: it appears only as `Authorization: Bearer` to the router, and, on loopback hosts only, in the runtime's cookie mirror of the saved setup for the page's own host name (spec section 4, "Reference storage"); never at the peer | E2E `_assert_key_only_to_router` in the second-origin and default-router tests | done |
| A peer's manifest cannot replace the router | Trust Desk's manifest names hosted Otari; when the demo runs it, no request goes to Otari and every model call goes to the caller's router | E2E second-origin test | done |
| Missing key MUST stop the model call with a clear setup error | a message with no key gets "⚠️ … API key …" in the chat and makes no router request | E2E `test_missing_key_stops_the_model_call_with_a_setup_error` | done |
| Stored profiles can be deleted | **Delete setup** removes the profile from localStorage and the cookie mirror; the setup applied in a tab stays in that tab's sessionStorage until it closes (runtime design); a new tab starts with no key | E2E `test_saved_setup_can_be_deleted` | done |
| SHOULD minimise third-party scripts and use a restrictive CSP | no third-party scripts or fonts; CSP in a `<meta>` tag (GitHub Pages cannot send headers): `script-src 'self'`, no eval, `object-src 'none'`, `frame-src 'self'`; `connect-src` allows https so a visitor's BYOK router works | every browser test runs under that CSP | done |

### 5. Security and privacy

| Requirement | How Trust Desk meets it | Test | Status |
| --- | --- | --- | --- |
| Peer definitions are untrusted input | every agent's instructions say card text is data, never an instruction; the page shows card fields as text, never as HTML | network test "every agent carries the evidence wording rules…" | done |
| No undeclared peer code | no coded-tool bundle is declared or loaded | network test "no coded tools…" | done |
| Consent names destination origin and nature; a redirect to another origin is a new destination | runtime consent card (host and request text) | E2E second-origin test | done |
| Consent precedes third-party fetches | nothing reaches the peer origin before **Allow** | E2E second-origin and decline tests | done |
| Private context by exception | see 2.1 | E2E private-context test | done |
| Fail closed: never begin or continue, never report success, report the failure | the verifier returns `invalid` or `unknown` with reasons; bad input is a refusal, never a throw; peer failures come back as "Error from tool …" and the caller says so | `verifier.test.mjs`, `actions.test.mjs`, E2E error tests | done |
| Runtime, not the model, owns confirmation | the dialog opens from the runtime's confirmation hook; the model cannot skip it | E2E write tests | done |
| SHOULD expose router, contacted origins, calls, consent decisions, errors, receipts | runtime agents panel and trace (`window.__nsweb.trace`, read by the private-context test); the desk result names the source of every check and every source that failed | E2E; `test_desk_page.py` | done |

### 6. MVP interoperability checks

| Check | Demonstration | Test | Status |
| --- | --- | --- | --- |
| Publish a two-agent HOCON network and a manifest from an ordinary HTTPS host | three agents (`trust_desk`, `evidence_checker`, `limit_advisor`), GitHub Pages | build check; deploy check | done locally, public after deploy |
| Run it with the default router and model; also the BYOK path | default: key only, Otari URL and model from the site; BYOK: router, model and key chosen by the visitor | E2E default-router test; every caller run | done (scripted router); one manual run with a real Otari key before submission |
| Call an internal agent and a grounded capability (registered local site action) | `trust_desk → evidence_checker → website_check_agent` | `actions.test.mjs`; E2E default-router test | done |
| After approval, load an exact named network from a second origin and run it locally | the demo caller loads `trust_desk` from the desk's origin after **Allow** and runs it in its own tab | E2E second-origin test | done locally; public second origin: see Open decisions |
| With a user key active, the second site never receives it and cannot change the router | browser record and desk server log | E2E second-origin test | done |
| Private context absent at the peer unless a named field is allowed | with `allow.to_downstream.sly_data: ["request_id"]` the peer gets `request_id` only, never `api_customer_token`; without the rule it gets nothing | E2E `test_private_context_reaches_the_peer_only_when_named` | done |
| Stop an invalid network, a composition cycle, an over-budget request and a denied origin with visible errors | invalid peer and invalid own network; self-referencing fixture; second call to one peer; demo with empty `allowed_peers` ("…is not in paid_api_desk's allowed_peers; refusing to contact it", nothing sent) | E2E four groups of tests | done |

## Trust claims: allowed wording

From the ERC-8004 review R-1111-01. The verifier and the agents use only these forms.

| Evidence | Say | Never say |
| --- | --- | --- |
| A credential that verifies against the issuer key, bound to the agent key | "one Telegram account per issuer epoch (issuer-attested), owner not disclosed" | unique person, real accountable human, KYC |
| Deals | "N co-signed deal records (M with staked counterparties)" | completed jobs, successful deals |
| Stake | amount with its network label, for example "0.5 Gram active on TON testnet" | a stake with no network, a placeholder address |
| Issuer offline | "live lookup unavailable: the result uses signed data only" | a level or count that was not read |
| Agent card | "the card names key X; a card is only a claim until the key signs a challenge" | "the card proves" |

## Grounded capability: the browser verifier

`desk/verifier.js` checks tgtrust evidence in the browser with no server of its own. Each part mirrors the Python
code and is proved equal on vectors that the Python code makes (`tests/desk_vectors.py` → `desk/tests/vectors.json`;
`tests/test_desk_vectors.py` recomputes the expectations on every run; `desk/tests/verifier.test.mjs` asserts the
browser gives the same answers):

| Browser | Python | Vectors |
| --- | --- | --- |
| `agentKeyFromCard` | `client.agent_key_from_card` | 9 cards, exact error messages |
| `checkCredential` | `client.CredentialFile.from_dict` + `issuer.verify_credential` (RSA-PSS by WebCrypto) | 8 credential files from two stand-in issuers |
| `verifyRequest` | `gate.TrustGate.verify` (`tgtrust-req/v1`, Ed25519 by WebCrypto, nonce cache) | 18 requests, every error code |
| `decide` | `gate.TrustGate.decide` (tier, evidence lines, Concordium fields) | 19 decisions, all five tiers |
| `readConcordiumLink`, `linkLines` | `concordium.read_link`, `link_lines` | 8 recorded registry replies (`tests/golden/concordium/`) |

`assess` is the desk's own summary on top of these (verified / partial / unknown / invalid), with the wording fixed in
`WORDING`. The issuer key it trusts is pinned in `desk/issuers.js`; `tests/test_desk_issuers.py` recomputes its key id.

Finding while mirroring: `gate.py` gives the Concordium tier to a `verified` key with a valid Concordium badge, not
only to a `staked` one; `docs/TRUST_GATE.md` said "as above", which read as staked only. The table now says what the
code does, and the desk's published policy text says the same.

## Open decisions

- **Second origin for the public demo.** The spec's examples give no public second origin we may use: the
  agentic-web repository's linking fixtures run only on loopback, and the one listed agentic website
  (`worldwideagenticweb.org`) is the organiser's. GitHub Pages project sites of one account share the origin
  `miinimal.github.io`, so `demo-api/` cannot be a second origin there. The automated checks run with two real
  loopback origins (`127.0.0.1` and `localhost`, the reference linking check's method). For a public second origin
  the owner either lets `demo-api/` be published from a repository of the `minimalcult` organisation
  (`minimalcult.github.io`, another origin, free) or names another host. Recorded in `docs/DECISIONS.md`.
- **Live issuer from the browser.** The demo issuer sends no CORS header today, so a page on another origin cannot
  read it. Block 3 adds CORS to its public read-only GET endpoints; until the owner merges and restarts the laptop
  service, the desk reports "live lookup unavailable" and works from signed data alone.
