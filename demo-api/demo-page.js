// The operator desk's page: the queue and its buttons. Text is set with textContent only.
import { App } from "./app.js";

const $ = (id) => document.getElementById(id);
const api = App.api;

function render() {
  const r = api.request;
  $("queue-empty").hidden = Boolean(r);
  $("queue").hidden = !r;
  $("serve-calls").textContent = String(api.serveCalls);
  if (!r) return;
  $("q-id").textContent = r.id;
  $("q-agent").textContent = r.agent;
  $("q-path").textContent = `${r.method} ${r.path}`;
  $("q-price").textContent = r.price;
  const ins = api.inspection && api.inspection.requestId === r.id ? api.inspection : null;
  $("q-tier").textContent = ins ? `${ins.tier.name}${ins.proven ? " (key proven)" : ""}` : "not inspected";
  const served = api.served.find((s) => s.requestId === r.id);
  $("q-status").textContent = served ? `served on ${served.terms}` : "waiting";
}

api.onChange(render);
$("new-request").addEventListener("click", () => api.newRequest());
$("simulate-timeout").addEventListener("change", (e) => {
  api.simulateTimeout = e.target.checked;
});
await api.newRequest();
document.documentElement.dataset.demoReady = "true";
