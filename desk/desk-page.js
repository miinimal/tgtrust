// The desk's own page: the form, the samples, the live-lookup choice and the result. It calls the same Desk
// methods as the agents' site actions. Everything it shows is set with textContent, never as HTML.
import { App } from "./app.js";

const $ = (id) => document.getElementById(id);
const desk = App.desk;

const STATE_NAMES = { verified: "Verified", partial: "Partial", unknown: "Unknown", invalid: "Invalid" };
const ICONS = { pass: "✓", fail: "✕", claim: "!", unavailable: "–", absent: "·" };
const STATE_WORDS = { pass: "pass", fail: "fail", claim: "claim", unavailable: "not read", absent: "not given" };

function tierMeaning(tier) {
  if (!tier) return "";
  if (!tier.allowed) return "Denied: do not serve or pay this caller.";
  if (tier.prepay) return "Prepay only: no credit.";
  return `Credit up to ${Number(tier.creditLimit).toLocaleString("en-US")} (your API's own smallest unit).`;
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

export class DeskPage {
  static async start() {
    $("challenge-text").textContent = DeskPage.challengeText();
    $("challenge-command").textContent =
      `python -m tgtrust.client sign-request --key-file agent.key --path ${desk.challenge().path}`;
    $("network-url").textContent = new URL("trust_desk", new URL("./", document.baseURI)).href;
    DeskPage.renderLive();
    $("desk-form").addEventListener("submit", (e) => {
      e.preventDefault();
      DeskPage.submit();
    });
    $("desk-form").addEventListener("reset", () => {
      DeskPage.showError(null);
      $("result").hidden = true;
      $("result-empty").hidden = false;
    });
    $("live-toggle").addEventListener("click", () => {
      desk.setLiveAllowed(!desk.liveAllowed);
      DeskPage.renderLive();
      if (desk.current) DeskPage.check(desk.current);
    });
    $("copy-challenge").addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(JSON.stringify(desk.challenge()));
        $("copy-challenge").textContent = "Copied";
      } catch {
        $("copy-challenge").textContent = "Select and copy";
      }
    });
    for (const button of document.querySelectorAll("[data-sample]")) {
      button.addEventListener("click", () => DeskPage.sample(button.dataset.sample));
    }
    // The agents can also put a result on the desk; show it whenever the desk changes.
    desk.onChange(() => DeskPage.renderResult());
    document.documentElement.dataset.deskReady = "true";
  }

  static challengeText() {
    const c = desk.challenge();
    return `${c.method} ${c.path} (empty body)`;
  }

  static fields() {
    return { key: $("f-key").value, credential: $("f-credential").value, proof: $("f-proof").value };
  }

  static showError(text) {
    const box = $("form-error");
    box.hidden = !text;
    box.textContent = text || "";
  }

  /** The key field takes a key or a whole card. */
  static async submit() {
    const { key, credential, proof } = DeskPage.fields();
    const trimmed = key.trim();
    const isCard = trimmed.startsWith("{");
    const loaded = desk.load({ key: isCard ? "" : trimmed, card: isCard ? trimmed : "", credential, proof });
    if (!loaded.ok) {
      DeskPage.showError(loaded.reason);
      const field = { key: "f-key", card: "f-key", credential: "f-credential", proof: "f-proof" }[loaded.field];
      if (field === "f-credential" || field === "f-proof") $("more-evidence").open = true;
      if (field) $(field).focus();
      return;
    }
    DeskPage.showError(null);
    await DeskPage.check(loaded.key);
  }

  static async check(key) {
    const panel = $("result-panel");
    panel.setAttribute("aria-busy", "true");
    $("check-button").disabled = true;
    $("check-button").textContent = desk.liveAllowed ? "Checking, with live lookups…" : "Checking…";
    try {
      await desk.check(key);
    } catch (err) {
      DeskPage.showError(`The check could not run: ${err.message}`);
    } finally {
      panel.setAttribute("aria-busy", "false");
      $("check-button").disabled = false;
      $("check-button").textContent = "Check agent";
    }
  }

  static async sample(name) {
    DeskPage.showError(null);
    $("f-credential").value = "";
    $("f-proof").value = "";
    if (name === "concordium") {
      const card = await (await fetch("samples/concordium-agent-card.json")).text();
      $("f-key").value = card.trim();
    } else if (name === "forged") {
      const credential = await (await fetch("samples/forged-credential.json")).text();
      $("f-key").value = JSON.parse(credential).agent_public_key;
      $("f-credential").value = credential.trim();
      $("more-evidence").open = true;
    } else if (name === "fresh") {
      try {
        const loaded = await desk.makeDemoAgent();
        const c = desk.cases.get(loaded.key);
        $("f-key").value = loaded.key;
        $("f-proof").value = JSON.stringify(c.proof, null, 1);
        $("more-evidence").open = true;
      } catch (err) {
        DeskPage.showError(`This browser cannot make an Ed25519 key (${err.message}). Try a current Chrome, Safari or Firefox.`);
        return;
      }
    }
    await DeskPage.submit();
  }

  static renderLive() {
    const on = desk.liveAllowed;
    $("live-state").textContent = on ? "On for this tab" : "Off";
    $("live-state").classList.toggle("on", on);
    $("live-toggle").textContent = on ? "Turn off" : "Allow for this tab";
    $("live-toggle").setAttribute("aria-pressed", String(on));
    $("live-text").textContent = on
      ? "Trust Desk reads public data from these origins when you check an agent. Nothing you paste is sent to them except the agent's public key."
      : "Off by default. Signed evidence is checked in your browser without contacting anyone. To also read the public badge and the Concordium binding, allow Trust Desk to contact:";
    const list = $("live-origins");
    list.replaceChildren(...desk.liveOrigins().map((o) => {
      const li = el("li");
      li.append(el("code", "", o.origin), document.createTextNode(` — to ${o.purpose}`));
      return li;
    }));
  }

  static renderResult() {
    const key = desk.current;
    const r = key ? desk.results.get(key) : null;
    if (!r) return;
    $("result-empty").hidden = true;
    $("result").hidden = false;
    const state = $("result-state");
    state.className = `state ${r.state}`;
    state.textContent = STATE_NAMES[r.state] || r.state;
    $("result-key").textContent = r.key ? `${r.key.slice(0, 12)}…${r.key.slice(-12)}` : "";
    $("result-key").title = r.key || "";
    $("result-summary").textContent = r.summary;
    $("tier-now").textContent = r.tier ? r.tier.tier.name : "—";
    $("tier-now-meaning").textContent = r.tier ? tierMeaning(r.tier.tier) : "";
    $("tier-proven").textContent = r.tierIfProven ? r.tierIfProven.tier.name : "—";
    $("tier-proven-meaning").textContent = r.tierIfProven ? tierMeaning(r.tierIfProven.tier) : "";
    const rows = r.checks.map((c) => {
      const li = el("li", `check ${c.state}`);
      li.dataset.check = c.id;
      li.append(el("span", "check-icon", ICONS[c.state] || "?"));
      const body = el("div");
      const head = el("div");
      head.append(el("span", "check-label", c.label), el("span", "check-state", STATE_WORDS[c.state] || c.state));
      body.append(head, el("p", "check-text", c.text));
      if (c.source) body.append(el("p", "check-source", `Source: ${c.source}`));
      li.append(body);
      return li;
    });
    if (r.cardLink) {
      const li = el("li", `check ${r.cardLink.badge_valid && r.cardLink.binding_status === "Active" ? "pass" : "unavailable"}`);
      li.append(el("span", "check-icon", r.cardLink.badge_valid ? ICONS.pass : ICONS.unavailable));
      const body = el("div");
      body.append(el("span", "check-label", `Concordium ${r.cardLink.network} (named by the card)`),
        el("p", "check-text", `binding ${r.cardLink.binding_status || "none"}, badge ${r.cardLink.badge || "none"} ${r.cardLink.badge_valid ? "valid" : "not valid"}${r.cardLink.error ? ` (${r.cardLink.error})` : ""}`),
        el("p", "check-source", `Source: Concordium ${r.cardLink.network} Agent Registry`));
      li.append(body);
      rows.push(li);
    }
    $("result-checks").replaceChildren(...rows);
    $("result-evidence").textContent = [...(r.tier?.evidence || []), "", "If the key signs the challenge:", ...(r.tierIfProven?.evidence || [])].join("\n");
    $("result-meta").textContent = `Checked ${new Date(r.checkedAt * 1000).toLocaleString("en-US")} · evidence: ${r.source} · live lookups ${desk.liveAllowed ? "on" : "off"}`;
  }
}

if (typeof window !== "undefined") {
  DeskPage.start();
}
