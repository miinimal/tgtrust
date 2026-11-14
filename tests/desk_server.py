"""Serve desk/ (and other static sites) for browser tests with the reference serve_site.mjs, which sends the CORS
header on the public agent files as a static host would."""

from __future__ import annotations

import re
import shutil
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVE = ROOT / "desk" / "tools" / "agentify" / "scripts" / "serve_site.mjs"
NODE = shutil.which("node")


@contextmanager
def serve_static(folder: Path):
    """Serve a folder the way GitHub Pages does: every file with Access-Control-Allow-Origin: *, any subpath."""
    import functools
    import threading
    from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

    class Handler(SimpleHTTPRequestHandler):
        def end_headers(self):
            self.send_header("Access-Control-Allow-Origin", "*")
            super().end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(Handler, directory=str(folder)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()
        server.server_close()


@contextmanager
def serve(folder: Path, open_as: str = "127.0.0.1", log: Path | None = None):
    """Start the server on a free port; yield its base URL ending in '/'."""
    args = [NODE, str(SERVE), str(folder), "--port", "0", "--open-as", open_as]
    if log is not None:
        args += ["--log", str(log)]
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8")
    try:
        deadline = time.time() + 20
        url = None
        while time.time() < deadline and url is None:
            line = proc.stdout.readline()
            if not line and proc.poll() is not None:
                raise RuntimeError("serve_site.mjs exited before it printed its URL")
            m = re.search(r"(http://[^\s]+)", line)
            if m:
                url = m.group(1)
        if url is None:
            raise RuntimeError("serve_site.mjs did not print its URL")
        yield url if url.endswith("/") else url + "/"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
