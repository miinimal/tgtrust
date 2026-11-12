// Page code of the tgtrust holder Mini App: wires holder-core.js to the buttons and texts.
// Author: Aleksandr Shcherbakov (@miinimal), MINIMALCULT.

import {
  HolderError, clearPending, completeCredential, createApi, credentialPackage, ed25519Supported,
  generateAgentKey, loadIssuer, loadPending, parseAgentPublicKey, prepareRequest, registerAgent,
  requestBlindSignature, savePending,
} from "./holder-core.js";

const TEXT = {
  en: {
    title: "Agent credential",
    lead: "One credential per Telegram account. The issuer signs it without seeing it, so nobody, the issuer included, can tell which account stands behind your agent.",
    checks: "Checks",
    check_tg: "Opened inside Telegram",
    check_issuer: "Issuer key",
    check_epoch: "Issuer epoch",
    check_premium: "Requirement",
    premium_needed: "Telegram Premium",
    choose: "Which agent is this for?",
    own_title: "My agent already has a key",
    own_text: "Safest. The private key never leaves the agent; paste only its public key.",
    own_label: "Agent public key (64 hex characters)",
    own_hint: "Create one with: python -m tgtrust.client new-key --out agent.key",
    new_title: "Create a key for a new agent here",
    new_text: "Quickest. This page makes the key, registers the agent and shows you the key once.",
    new_unsupported: "This browser cannot create agent keys. Use the first option.",
    resume_title: "Unfinished request found",
    resume_text: "This device holds a request that was sent but not finished. Finish it: the issuer answers the same request again.",
    stale_title: "Saved request no longer fits",
    stale_text: "The issuer key changed since this request was made, so it cannot be finished. Remove it to start again.",
    discard: "Remove saved request",
    go: "Get credential",
    go_resume: "Finish the request",
    copy: "Copy",
    copied: "Copied.",
    copy_failed: "Copy failed. Select the text and copy it by hand.",
    key_warning: "Whoever holds this file controls the agent. It exists only on this device and is shown only here. Save it somewhere safe before you leave.",
    forget: "I saved it. Remove it from this device",
    forgotten: "Removed from this device.",
    how_title: "What this page sends",
    how_1: "To the issuer: Telegram's signed init data and a blinded request. The request reveals nothing about the credential or the agent.",
    how_2: "The issuer answers with a blind signature. This page removes the blinding and checks the result twice.",
    how_3: "If you let this page register a new agent, it also sends the finished credential and the agent's public key. Registering from here right after issuance lets the service guess the link by timing; for strict anonymity use your own key and register later from the agent.",
    how_4: "Nothing is sent anywhere else. The private key and the blinding secret never leave this device.",
    yes: "yes",
    no: "no",
    agent_prefix: "Agent: ",
    step_key: "Creating the agent key…",
    step_blind: "Blinding the request…",
    step_issue: "Asking the issuer…",
    step_unblind: "Checking the signature…",
    step_register: "Registering the agent…",
    done_own_title: "Credential ready",
    done_own_text: "Give this file to your agent. It is bound to the agent's key and is useless to anyone else.",
    done_own_label: "credential.json",
    done_own_next: "On the agent's machine: python -m tgtrust.client register --credential credential.json --key-file agent.key",
    done_new_title: "Agent registered",
    done_new_text: "The agent is in the registry. This file is the agent: its key and its credential.",
    done_new_label: "agent.json",
    done_new_next: "Load it in your agent with tgtrust.client.AgentIdentity.from_agent_file(\"agent.json\").",
    e_no_telegram: "Open this page as a Mini App from the bot. A normal browser has no Telegram data to prove an account.",
    e_bad_agent_key: "The public key must be exactly 64 hex characters.",
    e_network: "No answer from the issuer. Check the connection and press the button again; nothing is lost.",
    e_invalid_init_data: "Telegram data is missing, altered or older than 15 minutes. Close this page, open it again from the bot and press the button.",
    e_already_issued: "This Telegram account already received its credential for this epoch. A second one cannot be issued.",
    e_bot_account: "Bot accounts cannot receive credentials.",
    e_premium_required: "This issuer serves only Telegram Premium accounts.",
    e_rate_limited: "Too many requests. Wait a minute and press the button again.",
    e_storage_unavailable: "This browser does not let the page save the request, so it would be unsafe to send it. Open the page in the Telegram app.",
    e_issuer: "The issuer did not describe itself in a way this page can verify. Nothing was sent.",
    e_bad_signature: "The issuer's answer did not verify. Nothing was accepted; press the button to ask again.",
    e_agent_key_failed: "This browser could not create the agent key. Use the first option.",
    e_error: "The issuer refused the request. Press the button to try again.",
  },
  ru: {
    title: "Удостоверение агента",
    lead: "Одно удостоверение на одну учётную запись Telegram. Издатель подписывает его вслепую, поэтому никто, включая издателя, не узнает, какая учётная запись стоит за вашим агентом.",
    checks: "Проверки",
    check_tg: "Открыто внутри Telegram",
    check_issuer: "Ключ издателя",
    check_epoch: "Период издателя",
    check_premium: "Требование",
    premium_needed: "Telegram Premium",
    choose: "Для какого агента?",
    own_title: "У моего агента уже есть ключ",
    own_text: "Самый безопасный путь. Закрытый ключ не покидает агента; вставьте только открытый.",
    own_label: "Открытый ключ агента (64 шестнадцатеричных символа)",
    own_hint: "Создать ключ: python -m tgtrust.client new-key --out agent.key",
    new_title: "Создать ключ для нового агента здесь",
    new_text: "Самый быстрый путь. Страница создаст ключ, зарегистрирует агента и один раз покажет ключ.",
    new_unsupported: "Этот браузер не умеет создавать ключи агентов. Выберите первый вариант.",
    resume_title: "Найден незавершённый запрос",
    resume_text: "На этом устройстве сохранён запрос, который был отправлен, но не завершён. Завершите его: издатель ответит на тот же запрос ещё раз.",
    stale_title: "Сохранённый запрос больше не подходит",
    stale_text: "Ключ издателя сменился после создания запроса, завершить его нельзя. Удалите его и начните заново.",
    discard: "Удалить сохранённый запрос",
    go: "Получить удостоверение",
    go_resume: "Завершить запрос",
    copy: "Скопировать",
    copied: "Скопировано.",
    copy_failed: "Не удалось скопировать. Выделите текст и скопируйте вручную.",
    key_warning: "Тот, у кого этот файл, управляет агентом. Он существует только на этом устройстве и показан только здесь. Сохраните его в надёжном месте, прежде чем уйти.",
    forget: "Я сохранил. Удалить с этого устройства",
    forgotten: "Удалено с этого устройства.",
    how_title: "Что отправляет эта страница",
    how_1: "Издателю: подписанные Telegram данные запуска и ослеплённый запрос. Запрос ничего не раскрывает ни об удостоверении, ни об агенте.",
    how_2: "Издатель отвечает слепой подписью. Страница снимает ослепление и дважды проверяет результат.",
    how_3: "Если страница сама регистрирует нового агента, она отправляет ещё готовое удостоверение и открытый ключ агента. Регистрация сразу после выдачи позволяет сервису угадать связь по времени; для строгой анонимности используйте свой ключ и регистрируйте агента позже, с его стороны.",
    how_4: "Больше никуда ничего не отправляется. Закрытый ключ и секрет ослепления не покидают устройство.",
    yes: "да",
    no: "нет",
    agent_prefix: "Агент: ",
    step_key: "Создаю ключ агента…",
    step_blind: "Ослепляю запрос…",
    step_issue: "Спрашиваю издателя…",
    step_unblind: "Проверяю подпись…",
    step_register: "Регистрирую агента…",
    done_own_title: "Удостоверение готово",
    done_own_text: "Передайте этот файл своему агенту. Он привязан к ключу агента и бесполезен для кого-либо ещё.",
    done_own_label: "credential.json",
    done_own_next: "На машине агента: python -m tgtrust.client register --credential credential.json --key-file agent.key",
    done_new_title: "Агент зарегистрирован",
    done_new_text: "Агент внесён в реестр. Этот файл и есть агент: его ключ и его удостоверение.",
    done_new_label: "agent.json",
    done_new_next: "Загрузите его в агенте: tgtrust.client.AgentIdentity.from_agent_file(\"agent.json\").",
    e_no_telegram: "Откройте эту страницу как мини-приложение из бота. В обычном браузере нет данных Telegram, которые подтверждают учётную запись.",
    e_bad_agent_key: "Открытый ключ — ровно 64 шестнадцатеричных символа.",
    e_network: "Издатель не ответил. Проверьте связь и нажмите кнопку ещё раз; ничего не потеряно.",
    e_invalid_init_data: "Данные Telegram отсутствуют, изменены или старше 15 минут. Закройте страницу, откройте её снова из бота и нажмите кнопку.",
    e_already_issued: "Эта учётная запись Telegram уже получила удостоверение за текущий период. Второе выдать нельзя.",
    e_bot_account: "Учётные записи ботов не получают удостоверений.",
    e_premium_required: "Этот издатель обслуживает только учётные записи с Telegram Premium.",
    e_rate_limited: "Слишком много запросов. Подождите минуту и нажмите кнопку снова.",
    e_storage_unavailable: "Браузер не даёт странице сохранить запрос, отправлять его небезопасно. Откройте страницу в приложении Telegram.",
    e_issuer: "Издатель описал себя так, что страница не может это проверить. Ничего не отправлено.",
    e_bad_signature: "Ответ издателя не прошёл проверку. Ничего не принято; нажмите кнопку, чтобы спросить снова.",
    e_agent_key_failed: "Браузеру не удалось создать ключ агента. Выберите первый вариант.",
    e_error: "Издатель отклонил запрос. Нажмите кнопку, чтобы попробовать снова.",
  },
};

const ERROR_TEXT = {
  bad_agent_key: "e_bad_agent_key", network: "e_network", invalid_init_data: "e_invalid_init_data",
  already_issued: "e_already_issued", bot_account: "e_bot_account", premium_required: "e_premium_required",
  rate_limited: "e_rate_limited", storage_unavailable: "e_storage_unavailable", unsupported_scheme: "e_issuer",
  bad_issuer_key: "e_issuer", bad_response: "e_issuer", bad_signature: "e_bad_signature",
  agent_key_failed: "e_agent_key_failed", issuer_changed: "e_issuer",
};

const $ = (id) => document.getElementById(id);
const app = window.Telegram && window.Telegram.WebApp;
const initData = app && typeof app.initData === "string" ? app.initData : "";
const userLanguage = (app && app.initDataUnsafe && app.initDataUnsafe.user && app.initDataUnsafe.user.language_code)
  || navigator.language || "en";
const lang = String(userLanguage).toLowerCase().startsWith("ru") ? "ru" : "en";
const t = (key) => TEXT[lang][key] || TEXT.en[key] || key;

const apiBase = new URL("../v1/", window.location.href).href;
const api = createApi(apiBase);
const storage = (() => { try { return window.localStorage; } catch (err) { return null; } })()
  || { getItem: () => null, setItem: () => { throw new Error("no storage"); }, removeItem: () => {} };

let issuer = null;
let pending = null;
let busy = false;

function applyLanguage() {
  document.documentElement.lang = lang;
  for (const el of document.querySelectorAll("[data-t]")) el.textContent = t(el.dataset.t);
}

function setCheck(id, text, state) {
  const el = $(id);
  el.textContent = text;
  el.className = state;
}

function setStatus(text, isError = false) {
  const el = $("status");
  el.textContent = text;
  el.className = isError ? "error" : "";
}

function showError(err) {
  const code = err instanceof HolderError ? err.code : "error";
  setStatus(t(ERROR_TEXT[code] || "e_error"), true);
}

function selectedMode() {
  return document.querySelector('input[name="mode"]:checked').value;
}

function refresh() {
  const stale = Boolean(pending && issuer && pending.key_id !== issuer.keyId);
  const finished = Boolean(pending && !stale && pending.signature && (pending.mode === "own" || pending.registered));
  const resumable = Boolean(pending && !stale && !finished);

  $("stale").hidden = !stale;
  $("resume").hidden = !resumable;
  $("choose").hidden = Boolean(pending);
  $("own-fields").hidden = selectedMode() !== "own";
  $("result").hidden = !finished;
  $("go").hidden = finished || stale;
  $("go").textContent = t(resumable ? "go_resume" : "go");
  $("go").disabled = busy || !issuer || !initData;
  if (resumable) $("resume-agent").textContent = t("agent_prefix") + pending.agent;
  if (finished) renderResult();
}

function renderResult() {
  const isNew = pending.mode === "new";
  const credential = credentialPackage(apiBase.replace(/\/$/, ""), pending);
  const file = isNew
    ? { format: "tgtrust-agent/v1", agent_public_key: pending.agent, agent_private_key: pending.seed, credential }
    : credential;
  $("result-title").textContent = t(isNew ? "done_new_title" : "done_own_title");
  $("result-text").textContent = t(isNew ? "done_new_text" : "done_own_text");
  $("result-label").textContent = t(isNew ? "done_new_label" : "done_own_label");
  $("result-next").textContent = t(isNew ? "done_new_next" : "done_own_next");
  $("result-file").value = JSON.stringify(file, null, 2);
  $("result-warning").hidden = !isNew;
}

async function run() {
  if (busy || !issuer) return;
  if (!initData) { setStatus(t("e_no_telegram"), true); return; }
  busy = true;
  refresh();
  try {
    if (!pending) {
      let agentPublicKey;
      let seed = null;
      if (selectedMode() === "new") {
        setStatus(t("step_key"));
        ({ publicKey: agentPublicKey, seed } = await generateAgentKey());
      } else {
        try {
          agentPublicKey = parseAgentPublicKey($("agent-key").value);
        } catch (err) {
          $("agent-key").classList.add("invalid");
          $("agent-key").focus();
          throw err;
        }
      }
      setStatus(t("step_blind"));
      const record = await prepareRequest(issuer, agentPublicKey, { seed });
      savePending(storage, record); // saved before anything is sent: only this exact request can be asked twice
      pending = record;
    }
    if (!pending.signature) {
      setStatus(t("step_issue"));
      const blindSignature = await requestBlindSignature(api, initData, pending);
      setStatus(t("step_unblind"));
      const done = await completeCredential(issuer, pending, blindSignature);
      savePending(storage, done);
      pending = done;
    }
    if (pending.mode === "new" && !pending.registered) {
      setStatus(t("step_register"));
      const done = await registerAgent(api, pending);
      savePending(storage, done);
      pending = done;
    }
    setStatus("");
    if (app && app.HapticFeedback) app.HapticFeedback.notificationOccurred("success");
  } catch (err) {
    showError(err);
  } finally {
    busy = false;
    refresh();
  }
}

async function copyResult() {
  const text = $("result-file").value;
  let ok = false;
  try {
    await navigator.clipboard.writeText(text);
    ok = true;
  } catch (err) {
    const area = $("result-file");
    area.focus();
    area.select();
    try { ok = document.execCommand("copy"); } catch (inner) { ok = false; }
  }
  setStatus(t(ok ? "copied" : "copy_failed"), !ok);
}

function forget() {
  clearPending(storage);
  pending = null;
  $("result-file").value = "";
  refresh();
  setStatus(t("forgotten"));
}

async function boot() {
  applyLanguage();
  if (app) {
    try { app.ready(); app.expand(); } catch (err) { /* older clients */ }
  }
  setCheck("check-tg", t(initData ? "yes" : "no"), initData ? "ok" : "bad");
  pending = loadPending(storage);

  $("go").addEventListener("click", run);
  $("copy").addEventListener("click", copyResult);
  $("forget").addEventListener("click", forget);
  $("discard").addEventListener("click", forget);
  $("agent-key").addEventListener("input", () => $("agent-key").classList.remove("invalid"));
  for (const radio of document.querySelectorAll('input[name="mode"]')) radio.addEventListener("change", refresh);

  if (!(await ed25519Supported())) {
    const radio = document.querySelector('input[name="mode"][value="new"]');
    radio.disabled = true;
    $("option-new").classList.add("disabled");
    $("new-unsupported").hidden = false;
  }

  try {
    issuer = await loadIssuer(api);
    setCheck("check-issuer", issuer.keyId, "ok");
    setCheck("check-epoch", issuer.epoch, "ok");
    $("row-premium").hidden = !issuer.requirePremium;
  } catch (err) {
    setCheck("check-issuer", t("no"), "bad");
    setCheck("check-epoch", "—", "bad");
    showError(err);
  }
  if (!initData && issuer) setStatus(t("e_no_telegram"), true);
  refresh();
}

boot();
