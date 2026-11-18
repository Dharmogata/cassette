"""Local HTTP replay server with deterministic matching, nearest-miss diagnostics, and chaos injection."""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from cassette.matcher import match_request
from cassette.models import CassetteFile, RecordedRequest


class CassetteReplayServer:
    """In-process or standalone HTTP server that replays recorded CassetteFile interactions."""

    def __init__(
        self,
        cassette: CassetteFile,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        extra_latency_ms: float = 0.0,
        chaos_status: int | None = None,
    ) -> None:
        self.cassette = cassette
        self.host = host
        self.port = port
        self.extra_latency_ms = extra_latency_ms
        self.chaos_status = chaos_status
        self.hits: int = 0
        self.misses: int = 0
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        if self._httpd is None:
            return f"http://{self.host}:{self.port}"
        addr, bound_port = self._httpd.server_address[:2]
        return f"http://{addr}:{bound_port}"

    def _make_handler(self) -> type[BaseHTTPRequestHandler]:
        parent = self

        class ReplayHandler(BaseHTTPRequestHandler):
            def _handle_all(self) -> None:
                length = int(self.headers.get("Content-Length", "0") or "0")
                raw_body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
                parsed = urlsplit(self.path)
                query = dict(parse_qsl(parsed.query, keep_blank_values=True))
                req_headers = {k: v for k, v in self.headers.items()}
                incoming = RecordedRequest(
                    method=self.command.upper(),
                    path=parsed.path or "/",
                    query=query,
                    headers=req_headers,
                    body=raw_body,
                )

                if parent.extra_latency_ms > 0:
                    time.sleep(parent.extra_latency_ms / 1000.0)

                if parent.chaos_status is not None:
                    payload = json.dumps(
                        {"error": "Cassette chaos fault injected", "status": parent.chaos_status}
                    ).encode("utf-8")
                    self.send_response(parent.chaos_status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return

                match = match_request(parent.cassette, incoming)
                if match.matched and match.interaction is not None:
                    parent.hits += 1
                    resp = match.interaction.response
                    body_bytes = resp.body.encode("utf-8")
                    self.send_response(resp.status)
                    sent_ct = False
                    for k, v in resp.headers.items():
                        if k.lower() in {"content-length", "transfer-encoding"}:
                            continue
                        if k.lower() == "content-type":
                            sent_ct = True
                        self.send_header(k, v)
                    if not sent_ct:
                        self.send_header("Content-Type", "application/json")
                    self.send_header("X-Cassette-Interaction", match.interaction.interaction_id)
                    self.send_header("X-Cassette-Fingerprint", match.incoming_fingerprint)
                    self.send_header("Content-Length", str(len(body_bytes)))
                    self.end_headers()
                    self.wfile.write(body_bytes)
                else:
                    parent.misses += 1
                    miss_payload: dict[str, Any] = {
                        "error": "Cassette interaction miss",
                        "incoming_fingerprint": match.incoming_fingerprint,
                        "nearest_interaction_id": match.nearest_interaction_id,
                        "mismatch_reasons": match.mismatch_reasons,
                    }
                    body_bytes = json.dumps(miss_payload, indent=2).encode("utf-8")
                    self.send_response(404)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("X-Cassette-Miss", "true")
                    self.send_header("Content-Length", str(len(body_bytes)))
                    self.end_headers()
                    self.wfile.write(body_bytes)

            def do_GET(self) -> None:  # noqa: N802
                self._handle_all()

            def do_POST(self) -> None:  # noqa: N802
                self._handle_all()

            def do_PUT(self) -> None:  # noqa: N802
                self._handle_all()

            def do_DELETE(self) -> None:  # noqa: N802
                self._handle_all()

            def do_PATCH(self) -> None:  # noqa: N802
                self._handle_all()

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

        return ReplayHandler

    def start_background(self) -> str:
        """Start the replay server on a daemon thread and return its base URL."""
        self._httpd = ThreadingHTTPServer((self.host, self.port), self._make_handler())
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self.base_url

    def serve_forever(self) -> None:
        """Run the replay server in the foreground until interrupted."""
        self._httpd = ThreadingHTTPServer((self.host, self.port), self._make_handler())
        try:
            self._httpd.serve_forever()
        finally:
            self._httpd.server_close()

    def stop(self) -> None:
        """Stop a running background replay server."""
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
