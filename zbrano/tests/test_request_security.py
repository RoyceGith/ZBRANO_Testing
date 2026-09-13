from __future__ import annotations

import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from app import main
from app.services import assist_bridge
from app.services.request_security import RequestSecurityMiddleware
from tests import test_app_integration as fixtures


class RequestSecurityTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.fixture = fixtures.ApplicationIntegrationTests()
        await self.fixture.asyncSetUp()
        self.ingress = self.fixture.client
        self.direct = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app, client=("192.0.2.10", 12345)),
            base_url="http://zbrano.test",
        )

    async def asyncTearDown(self):
        await self.direct.aclose()
        await self.fixture.asyncTearDown()

    async def test_anonymous_and_spoofed_headers_cannot_access_ui_data_or_mutations(self):
        spoofed = {
            "X-Forwarded-For": "172.30.32.2", "X-Real-IP": "172.30.32.2",
            "Forwarded": "for=172.30.32.2", "X-Ingress-Path": "/api/hassio_ingress/fake",
            "X-Remote-User-Id": "owner", "X-Remote-User-Admin": "true",
        }
        cases = [
            ("GET", "/", None), ("GET", "/api/docs", None),
            ("GET", "/api/openapi.json", None), ("GET", "/api/settings/backup", None),
            ("GET", "/api/settings", None), ("GET", "/api/chats", None),
            ("GET", "/api/plugins", None),
            ("POST", "/api/files/shared/folders", {"parent": "", "name": "unauthorized"}),
            ("POST", "/api/assist/bridge/pair", None),
            ("POST", "/api/settings/restore", {"backup": {}}),
            ("PUT", "/api/settings", {}),
        ]
        for headers in ({}, spoofed):
            for method, path, body in cases:
                with self.subTest(method=method, path=path, spoofed=bool(headers)):
                    result = await self.direct.request(method, path, json=body, headers=headers)
                    self.assertEqual(result.status_code, 403)
                    self.assertEqual(result.headers["cache-control"], "no-store")
        self.assertEqual((await self.ingress.get("/api/files/shared/folders")).json()["folders"], [])
        self.assertEqual((await self.ingress.get("/api/settings/backup")).status_code, 200)
        self.assertEqual((await self.ingress.get("/plugin-setup.html")).status_code, 200)

    async def test_static_containment_rejects_encoded_traversal_and_absolute_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            static = root / "static"
            static.mkdir()
            (static / "index.html").write_text("public-index", encoding="utf-8")
            (static / "valid.js").write_text("public-script", encoding="utf-8")
            (root / "private.txt").write_text("PRIVATE-DUMMY", encoding="utf-8")
            with patch.object(main, "STATIC_DIR", static):
                for path in ("/%2e%2e/private.txt", "/..%2fprivate.txt", "/%2e%2e%2fprivate.txt", "/%00"):
                    with self.subTest(path=path):
                        result = await self.ingress.get(path)
                        self.assertEqual(result.status_code, 404)
                        self.assertNotIn("PRIVATE-DUMMY", result.text)
                with self.assertRaises(main.HTTPException) as error:
                    await main.frontend(str(root / "private.txt"))
                self.assertEqual(error.exception.status_code, 404)
                result = await self.ingress.get("/valid.js")
                self.assertEqual(result.status_code, 200)
                self.assertEqual(result.text, "public-script")

    async def test_static_symlink_cannot_escape_root(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            static = root / "static"
            static.mkdir()
            target = root / "private.txt"
            target.write_text("PRIVATE-DUMMY", encoding="utf-8")
            try:
                (static / "link.txt").symlink_to(target)
            except OSError:
                self.skipTest("Symlink creation unavailable on this host; exercised in Linux image builds")
            with patch.object(main, "STATIC_DIR", static):
                self.assertEqual((await self.ingress.get("/link.txt")).status_code, 404)

    async def test_direct_assist_is_opt_in_and_token_cannot_access_other_routes(self):
        token = assist_bridge.create_pairing_token()["pairing_token"]
        headers = {"Authorization": f"Bearer {token}"}
        with patch.dict(os.environ, {"ZBRANO_ENABLE_DIRECT_ASSIST": "false"}):
            self.assertEqual((await self.direct.get("/api/assist/health", headers=headers)).status_code, 403)
        with patch.dict(os.environ, {"ZBRANO_ENABLE_DIRECT_ASSIST": "true"}):
            for authorization in ("", "Bearer invalid", f"Basic {token}"):
                self.assertEqual((await self.direct.get("/api/assist/health", headers={"Authorization": authorization})).status_code, 401)
            self.assertEqual((await self.direct.get("/api/assist/health", headers=headers)).status_code, 200)
            for method, path in (("GET", "/api/settings/backup"), ("POST", "/api/assist/bridge/pair"), ("GET", "/"), ("POST", "/api/assist/health")):
                self.assertEqual((await self.direct.request(method, path, headers=headers)).status_code, 403)
            with patch.object(main, "run_zbrano", AsyncMock(return_value={"reply": "Test reply"})) as run:
                result = await self.direct.post("/api/assist/conversation", headers=headers, json={"text": "test", "request_id": "security-fixture"})
                self.assertEqual(result.status_code, 200)
                run.assert_awaited_once()
            assist_bridge.create_pairing_token()
            self.assertEqual((await self.direct.get("/api/assist/health", headers=headers)).status_code, 401)

    async def test_oauth_callback_requires_ingress_and_preserves_state_validation(self):
        state = "security-review-state"
        flow = {"expires_at": time.time() + 60, "issuer": "https://accounts.google.com"}
        with patch.dict(main.PLUGIN_OAUTH_FLOWS, {state: flow}, clear=True):
            result = await self.direct.get("/api/plugin-oauth/callback", params={"state": state, "error": "access_denied"})
            self.assertEqual(result.status_code, 403)
            self.assertIn(state, main.PLUGIN_OAUTH_FLOWS)
            result = await self.ingress.get("/api/plugin-oauth/callback", params={"state": state, "error": "access_denied"})
            self.assertEqual(result.status_code, 200)
            self.assertIn("access_denied", result.text)
            self.assertNotIn(state, main.PLUGIN_OAUTH_FLOWS)
            result = await self.ingress.get("/api/plugin-oauth/callback", params={"state": state, "code": "unused"})
            self.assertIn("already used", result.text)

    async def test_no_peer_loopback_and_websocket_do_not_bypass_boundary(self):
        reached = AsyncMock()
        boundary = RequestSecurityMiddleware(reached, direct_assist_enabled=lambda: True, valid_assist_token=lambda token: True)
        for client in (None, ("127.0.0.1", 1), ("::1", 1), ("192.0.2.2", 1)):
            sent = []
            async def send(message):
                sent.append(message)
            scope = {"type": "websocket", "path": "/", "client": client, "headers": [(b"x-forwarded-for", b"172.30.32.2")]}
            await boundary(scope, AsyncMock(), send)
            self.assertEqual(sent, [{"type": "websocket.close", "code": 1008}])
        reached.assert_not_awaited()
        await boundary({"type": "websocket", "path": "/", "client": ("172.30.32.2", 1)}, AsyncMock(), AsyncMock())
        reached.assert_awaited_once()
