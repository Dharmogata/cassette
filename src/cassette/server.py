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

    def dispatch(
        self,
        method: str,
        path_with_query: str,
        headers: dict[str, str] | None = None,
        body: str = "",
    ) -> tuple[int, dict[str, str], str]:
        """Dispatch a request against the cassette in memory or from the HTTP handler."""
        parsed = urlsplit(path_with_query)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        incoming = RecordedRequest(
            method=method.upper(),
            path=parsed.path or "/",
            query=query,
            headers=dict(headers or {}),
            body=body,
        )

        if self.extra_latency_ms > 0:
            time.sleep(self.extra_latency_ms / 1000.0)

        if self.chaos_status is not None:
            payload = json.dumps(
                {"error": "Cassette chaos fault injected", "status": self.chaos_status}
            )
            return self.chaos_status, {"Content-Type": "application/json"}, payload

        match = match_request(self.cassette, incoming)
        if match.matched and match.interaction is not None:
            self.hits += 1
            resp = match.interaction.response
            out_headers: dict[str, str] = {}
            sent_ct = False
            for k, v in resp.headers.items():
                if k.lower() in {"content-length", "transfer-encoding"}:
                    continue
                if k.lower() == "content-type":
                    sent_ct = True
                out_headers[k] = v
            if not sent_ct:
                out_headers["Content-Type"] = "application/json"
            out_headers["X-Cassette-Interaction"] = match.interaction.interaction_id
            out_headers["X-Cassette-Fingerprint"] = match.incoming_fingerprint
            return resp.status, out_headers, resp.body

        self.misses += 1
        miss_payload: dict[str, Any] = {
            "error": "Cassette interaction miss",
            "incoming_fingerprint": match.incoming_fingerprint,
            "nearest_interaction_id": match.nearest_interaction_id,
            "mismatch_reasons": match.mismatch_reasons,
        }
        return (
            404,
            {"Content-Type": "application/json", "X-Cassette-Miss": "true"},
            json.dumps(miss_payload, indent=2),
        )

    def _make_handler(self) -> type[BaseHTTPRequestHandler]:
        parent = self

        class ReplayHandler(BaseHTTPRequestHandler):
            def _handle_all(self) -> None:
                length = int(self.headers.get("Content-Length", "0") or "0")
                raw_body = (
                    self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
                )
                req_headers = {k: v for k, v in self.headers.items()}
                status, resp_headers, resp_body = parent.dispatch(
                    self.command, self.path, req_headers, raw_body
                )
                body_bytes = resp_body.encode("utf-8")
                self.send_response(status)
                for k, v in resp_headers.items():
                    self.send_header(k, v)
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
