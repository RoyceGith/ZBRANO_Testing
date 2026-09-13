"""Fail-closed transport boundary for the Home Assistant add-on.

Run Uvicorn with --no-proxy-headers: scope['client'] must be the socket peer,
not a user-supplied forwarding header. Only Supervisor's documented Ingress
peer may access the UI/API. Optional direct Assist access is token-scoped.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Callable

from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send


INGRESS_PEER = ipaddress.ip_address("172.30.32.2")
ASSIST_ROUTES = frozenset({
    ("GET", "/api/assist/health"),
    ("POST", "/api/assist/conversation"),
})


def is_ingress_peer(scope: Scope) -> bool:
    client = scope.get("client")
    if not client:
        return False
    try:
        address = ipaddress.ip_address(client[0])
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address == INGRESS_PEER


class RequestSecurityMiddleware:
    def __init__(
        self, app: ASGIApp, *, direct_assist_enabled: Callable[[], bool],
        valid_assist_token: Callable[[str], bool],
    ) -> None:
        self.app = app
        self.direct_assist_enabled = direct_assist_enabled
        self.valid_assist_token = valid_assist_token

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return
        if is_ingress_peer(scope):
            await self.app(scope, receive, send)
            return
        if (scope["type"] == "http"
                and (scope["method"], scope["path"]) in ASSIST_ROUTES
                and self.direct_assist_enabled()):
            authorization = Headers(scope=scope).get("authorization", "")
            if self.valid_assist_token(authorization):
                await self.app(scope, receive, send)
                return
            response = JSONResponse({"detail": "Invalid ZBRANO Assist pairing key"}, status_code=401)
        else:
            response = JSONResponse(
                {"detail": "Open ZBRANO through Home Assistant. Direct browser and API access is disabled."},
                status_code=403,
            )
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        response.headers["Cache-Control"] = "no-store"
        await response(scope, receive, send)
