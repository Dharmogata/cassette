"""Unit and integration tests for Cassette."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stdout
from pathlib import Path

from cassette.audit import audit_cassette, diff_cassettes
from cassette.cli import main
from cassette.matcher import (
    compute_request_fingerprint,
    load_cassette,
    match_request,
    sanitize_cassette,
    save_cassette,
)
from cassette.models import (
    CassetteFile,
    CassetteInteraction,
    RecordedRequest,
    RecordedResponse,
)
from cassette.server import CassetteReplayServer


def _sample_cassette() -> CassetteFile:
    req1 = RecordedRequest(
        method="POST",
        path="/v1/charges",
        query={"currency": "usd"},
        headers={"Authorization": "Bearer sk_live_1234567890abcdef", "Content-Type": "application/json"},
        body='{"amount": 2500, "customer": "cus_01"}',
    )
    resp1 = RecordedResponse(
        status=200,
        headers={"Content-Type": "application/json"},
        body='{"id": "ch_01", "paid": true, "amount": 2500}',
        latency_ms=42.5,
    )
    req2 = RecordedRequest(
        method="GET",
        path="/v1/customers/cus_01",
        query={},
        headers={},
        body="",
    )
    resp2 = RecordedResponse(
        status=503,
        headers={},
        body='{"error": "upstream unavailable"}',
        latency_ms=110.0,
    )
    return CassetteFile(
        name="stripe-checkout",
        interactions=[
            CassetteInteraction(
                interaction_id="step-001",
                request=req1,
                response=resp1,
                recorded_at="2026-01-01T00:00:00Z",
                fingerprint=compute_request_fingerprint(req1),
            ),
            CassetteInteraction(
                interaction_id="step-002",
                request=req2,
                response=resp2,
                recorded_at="2026-11-10T00:00:00Z",
                chaos_expected=False,
                fingerprint=compute_request_fingerprint(req2),
            ),
        ],
    )


class CassetteTestSuite(unittest.TestCase):
    def test_canonical_fingerprint_ignores_json_key_order(self) -> None:
        r1 = RecordedRequest(
            method="post",
            path="/v1/charges",
            query={"b": "2", "a": "1"},
            body='{"customer": "cus_01", "amount": 2500}',
        )
        r2 = RecordedRequest(
            method="POST",
            path="/v1/charges?a=1&b=2",
            query={},
            body='{"amount":2500,"customer":"cus_01"}',
        )
        self.assertEqual(compute_request_fingerprint(r1), compute_request_fingerprint(r2))

    def test_match_request_and_nearest_miss_diagnostics(self) -> None:
        cassette = _sample_cassette()
        exact = RecordedRequest(
            method="POST",
            path="/v1/charges",
            query={"currency": "usd"},
            body='{"customer": "cus_01", "amount": 2500}',
        )
        hit = match_request(cassette, exact)
        self.assertTrue(hit.matched)
        self.assertEqual(hit.interaction.interaction_id, "step-001")

        miss = RecordedRequest(
            method="POST",
            path="/v1/charges",
            query={"currency": "eur"},
            body='{"customer": "cus_01", "amount": 9999}',
        )
        miss_res = match_request(cassette, miss)
        self.assertFalse(miss_res.matched)
        self.assertEqual(miss_res.nearest_interaction_id, "step-001")
        self.assertIn("request body payload differed", miss_res.mismatch_reasons)

    def test_sanitize_cassette_redacts_secrets(self) -> None:
        cassette = _sample_cassette()
        cleaned, count = sanitize_cassette(cassette)
        self.assertEqual(count, 1)
        self.assertEqual(
            cleaned.interactions[0].request.headers["Authorization"],
            "[REDACTED]",
        )

    def test_audit_rules_cs001_to_cs005(self) -> None:
        cassette = _sample_cassette()
        dup_req = cassette.interactions[0].request
        cassette.interactions.append(
            CassetteInteraction(
                interaction_id="step-003",
                request=dup_req,
                response=RecordedResponse(
                    status=400,
                    headers={"Content-Type": "application/json"},
                    body='{"error": "bad"}',
                ),
                recorded_at="2026-11-15T00:00:00Z",
                fingerprint=compute_request_fingerprint(dup_req),
            )
        )
        report = audit_cassette(
            cassette,
            reference_date="2026-11-18T00:00:00Z",
            max_age_days=90,
        )
        rule_ids = {f.rule_id for f in report.findings}
        self.assertEqual(rule_ids, {"CS001", "CS002", "CS003", "CS004", "CS005"})

    def test_contract_diff_between_cassettes(self) -> None:
        base = _sample_cassette()
        cand, _ = sanitize_cassette(_sample_cassette())
        cand.interactions[0].response.status = 201
        cand.interactions[0].response.body = '{"id": "ch_01", "currency": "usd"}'
        diffs = diff_cassettes(base, cand)
        change_types = {d.change_type for d in diffs}
        self.assertIn("status-code-changed", change_types)
        self.assertIn("response-keys-removed", change_types)
        self.assertIn("response-keys-added", change_types)

    def test_live_replay_server_hit_and_miss(self) -> None:
        cassette = _sample_cassette()
        server = CassetteReplayServer(cassette, host="127.0.0.1", port=0)
        base_url = server.start_background()
        try:
            req = urllib.request.Request(
                f"{base_url}/v1/charges?currency=usd",
                data=b'{"amount": 2500, "customer": "cus_01"}',
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                self.assertEqual(resp.status, 200)
                self.assertEqual(resp.headers.get("X-Cassette-Interaction"), "step-001")
                payload = json.loads(resp.read().decode("utf-8"))
                self.assertTrue(payload["paid"])

            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(f"{base_url}/v1/unknown", timeout=5)
            self.assertEqual(ctx.exception.code, 404)
            ctx.exception.close()
            self.assertEqual(server.hits, 1)
            self.assertEqual(server.misses, 1)
        finally:
            server.stop()

    def test_cli_commands_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            c_path = tmp_dir / "sample.json"
            save_cassette(_sample_cassette(), c_path)

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["inspect", str(c_path), "--format", "json"])
            self.assertEqual(rc, 0)
            self.assertEqual(json.loads(buf.getvalue())["total_interactions"], 2)

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["audit", str(c_path), "--fail-on-findings"])
            self.assertEqual(rc, 1)

            clean_path = tmp_dir / "clean.json"
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["sanitize", str(c_path), "--output", str(clean_path)])
            self.assertEqual(rc, 0)
            loaded = load_cassette(clean_path)
            self.assertEqual(loaded.interactions[0].request.headers["Authorization"], "[REDACTED]")

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = main(["rules", "--format", "markdown"])
            self.assertEqual(rc, 0)
            self.assertIn("CS001", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
