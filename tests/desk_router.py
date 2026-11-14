"""A scripted, OpenAI-compatible model router for the Trust Desk browser tests. It makes no model call.

It listens on 127.0.0.1, answers CORS preflights, and streams chat completions the way runtime/llm.js reads them.
Each request is recorded with flags only (was a key sent, was it the expected one), never the key itself.

Who is asking is told from the system prompt:
- the operator desk's front agent (``Paid API operator desk``) follows ``plan``: one tool per step, in order, then an
  answer that quotes every tool result, prefixed ``CALLER_FINAL:``;
- Trust Desk's front agent with its site tools (on its own page) delegates to ``evidence_checker``, which calls
  ``website_check_agent``; then both answer with the result;
- Trust Desk's front agent without site tools (run by another site) answers ``DESK_ANSWER:`` at once;
- a fixture network marked ``LOOP_PEER`` calls its own hand-off tool once, then answers with the result.
"""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HANDOFF = "Hand off to the "
CORS = {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "*", "Access-Control-Allow-Methods": "*"}


def _handoff_tool(tools):
    for tool in tools:
        fn = tool.get("function") or {}
        if str(fn.get("description", "")).startswith(HANDOFF):
            return fn["name"]
    return None


def _text(content: str) -> str:
    try:
        parsed = json.loads(content)
        if isinstance(parsed, dict) and isinstance(parsed.get("text"), str):
            return parsed["text"]
    except ValueError:
        pass
    return content


class MockRouter:
    def __init__(self, key: str, plan: list[str] | None = None, desk_request: str = "Key proven by signature; badge not read. Which tier?"):
        self.key = key
        self.plan = plan or ["inspect", "desk"]
        self.desk_request = desk_request
        self.serve_terms = "prepay"
        self.records: list[dict] = []
        self.lock = threading.Lock()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}/v1"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

    def chats(self) -> list[dict]:
        with self.lock:
            return [r for r in self.records if r.get("kind") == "chat"]

    # --- scripting --------------------------------------------------------------------------------------------

    def decide(self, system: str, tools: list, results: list[str], last_user: str) -> dict:
        names = [str((t.get("function") or {}).get("name")) for t in tools]
        if "Paid API operator desk" in system:
            if len(results) < len(self.plan):
                step = self.plan[len(results)]
                if step == "inspect":
                    return {"tool": "website_inspect_caller", "args": {}}
                if step in ("desk", "desk_again"):
                    tool = _handoff_tool(tools) or "missing_handoff_tool"
                    return {"tool": tool, "args": {"request": self.desk_request}}
                if step.startswith("call:"):
                    return {"tool": step[5:], "args": {"request": self.desk_request}}
                if step == "serve":
                    req = re.search(r'"requestId":"(req-[A-Za-z0-9_-]+)"', "".join(results))
                    return {"tool": "website_serve_request",
                            "args": {"requestId": req.group(1) if req else "req-none", "terms": self.serve_terms}}
            return {"text": "CALLER_FINAL: " + " || ".join(_text(r)[:600] for r in results)}
        if "You check evidence for the tgtrust Trust Desk assistant" in system:
            if not results:
                key = re.search(r"[0-9a-f]{64}", last_user or "")
                return {"tool": "website_check_agent", "args": {"agentKey": key.group(0) if key else "0" * 64}}
            return {"text": "CHECKER: " + _text(results[-1])[:1500]}
        if "You are the assistant on the tgtrust Trust Desk website" in system:
            if "website_check_agent" in names and "evidence_checker" in names:
                if not results:
                    key = re.search(r"[0-9a-f]{64}", last_user or "")
                    return {"tool": "evidence_checker", "args": {"request": f"Check {key.group(0) if key else ''}"}}
                return {"text": "DESK_FINAL: " + _text(results[-1])[:1500]}
            return {"text": "DESK_ANSWER: prepay only; these facts were stated by the caller and not checked by Trust Desk."}
        if "LOOP_PEER" in system:
            tool = _handoff_tool(tools)
            if tool and not results:
                return {"tool": tool, "args": {"request": "loop"}}
            return {"text": "LOOP_ANSWER: " + (_text(results[-1]) if results else "no tool")}
        return {"text": "UNSCRIPTED: " + system[:80]}

    def _stream(self, model: str, reply: dict) -> bytes:
        if "tool" in reply:
            with self.lock:
                n = len(self.records)
            delta = {"role": "assistant", "tool_calls": [{"index": 0, "id": f"call_{n}", "type": "function",
                                                          "function": {"name": reply["tool"],
                                                                       "arguments": json.dumps(reply["args"])}}]}
        else:
            delta = {"role": "assistant", "content": reply["text"]}
        chunk = {"id": "mock", "object": "chat.completion.chunk", "model": model,
                 "choices": [{"index": 0, "delta": delta, "finish_reason": "tool_calls" if "tool" in reply else "stop"}]}
        usage = {"id": "mock", "object": "chat.completion.chunk", "model": model, "choices": [],
                 "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}
        return f"data: {json.dumps(chunk)}\n\ndata: {json.dumps(usage)}\n\ndata: [DONE]\n\n".encode()

    def _handler(self):
        router = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # quiet
                pass

            def _send(self, status: int, body: bytes, ctype: str):
                self.send_response(status)
                for k, v in CORS.items():
                    self.send_header(k, v)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _record(self, kind: str, **extra) -> dict:
                auth = self.headers.get("Authorization")
                rec = {"kind": kind, "method": self.command, "path": self.path, "origin": self.headers.get("Origin"),
                       "authorization": auth is not None, "key_ok": auth == f"Bearer {router.key}", **extra}
                with router.lock:
                    router.records.append(rec)
                return rec

            def do_OPTIONS(self):
                self._record("preflight")
                self._send(204, b"", "text/plain")

            def do_GET(self):
                if self.path.rstrip("/").endswith("/models"):
                    self._record("models")
                    body = {"object": "list", "data": [{"id": "test-model", "object": "model"}]}
                    return self._send(200, json.dumps(body).encode(), "application/json")
                self._record("other")
                self._send(404, b"not found", "text/plain")

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
                messages = body.get("messages") or []
                system = messages[0].get("content", "") if messages and messages[0].get("role") == "system" else ""
                results = [str(m.get("content")) for m in messages if m.get("role") == "tool"]
                users = [m.get("content") for m in messages if m.get("role") == "user"]
                tools = body.get("tools") or []
                reply = router.decide(system if isinstance(system, str) else "", tools, results,
                                      users[-1] if users else "")
                self._record("chat", model=body.get("model"), first_line=str(system).split("\n")[0][:160],
                             roles=[m.get("role") for m in messages],
                             tools=[str((t.get("function") or {}).get("name")) for t in tools],
                             reply=reply, messages_text=json.dumps(messages)[:20000])
                self._send(200, router._stream(body.get("model") or "test-model", reply), "text/event-stream")

        return Handler
