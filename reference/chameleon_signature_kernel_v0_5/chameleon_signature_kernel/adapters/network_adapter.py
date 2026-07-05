from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Protocol
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from ..objects import SurfaceObject
from ..policy import AuthorizationManifest


class NetworkAdapterError(ValueError):
    pass


@dataclass(frozen=True)
class NetworkRequest:
    url: str
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None


@dataclass(frozen=True)
class NetworkResponse:
    url: str
    method: str
    status: int
    headers: dict[str, str]
    body: bytes
    duration_ms: int
    truncated: bool = False


@dataclass(frozen=True)
class NetworkAdapterConfig:
    allowed_schemes: tuple[str, ...] = ("http", "https")
    allowed_methods: tuple[str, ...] = ("GET", "HEAD")
    allowed_hosts: tuple[str, ...] = ()
    timeout_seconds: float = 10.0
    max_body_bytes: int = 65536
    include_body: bool = False
    user_agent: str = "ChameleonSignatureKernel/0.6"
    redacted_headers: tuple[str, ...] = ("authorization", "cookie", "set-cookie")


class NetworkTransport(Protocol):
    def send(self, request: NetworkRequest, config: NetworkAdapterConfig) -> NetworkResponse:
        ...


class UrlLibNetworkTransport:
    def send(self, request: NetworkRequest, config: NetworkAdapterConfig) -> NetworkResponse:
        headers = {"User-Agent": config.user_agent}
        headers.update(request.headers)
        opener_request = Request(
            request.url,
            data=request.body,
            headers=headers,
            method=request.method.upper(),
        )
        started = time.perf_counter()
        try:
            with urlopen(opener_request, timeout=config.timeout_seconds) as response:
                body = response.read(config.max_body_bytes + 1)
                truncated = len(body) > config.max_body_bytes
                if len(body) > config.max_body_bytes:
                    body = body[:config.max_body_bytes]
                duration_ms = int((time.perf_counter() - started) * 1000)
                return NetworkResponse(
                    url=response.geturl(),
                    method=request.method.upper(),
                    status=int(getattr(response, "status", response.getcode())),
                    headers={str(k): str(v) for k, v in response.headers.items()},
                    body=body,
                    duration_ms=duration_ms,
                    truncated=truncated,
                )
        except URLError as exc:
            raise NetworkAdapterError(f"network request failed: {exc}") from exc


class NetworkAdapter:
    """Authorized HTTP observation adapter for real network sources."""

    def __init__(
        self,
        authorization: AuthorizationManifest,
        *,
        config: NetworkAdapterConfig | None = None,
        transport: NetworkTransport | None = None,
    ):
        if not (
            authorization.is_valid_for("network_observation")
            or authorization.is_valid_for("adapter_operation")
        ):
            raise NetworkAdapterError("valid network observation authorization is required")
        self.authorization = authorization
        self.config = config or NetworkAdapterConfig()
        self.transport = transport or UrlLibNetworkTransport()

    def fetch(self, request: NetworkRequest) -> SurfaceObject:
        self._validate_request(request)
        response = self.transport.send(
            NetworkRequest(
                url=request.url,
                method=request.method.upper(),
                headers=dict(request.headers),
                body=request.body,
            ),
            self.config,
        )
        return self._response_to_object(request=request, response=response)

    def fetch_urls(self, urls: tuple[str, ...] | list[str]) -> list[SurfaceObject]:
        return [self.fetch(NetworkRequest(url=url)) for url in urls]

    def _validate_request(self, request: NetworkRequest) -> None:
        parsed = urlparse(request.url)
        if parsed.scheme.lower() not in self.config.allowed_schemes:
            raise NetworkAdapterError(f"scheme_not_allowed:{parsed.scheme}")
        method = request.method.upper()
        if method not in self.config.allowed_methods:
            raise NetworkAdapterError(f"method_not_allowed:{method}")
        if self.config.allowed_hosts:
            host = (parsed.hostname or "").lower()
            allowed = {h.lower() for h in self.config.allowed_hosts}
            if host not in allowed:
                raise NetworkAdapterError(f"host_not_allowed:{host}")
        if request.body and method in {"GET", "HEAD"}:
            raise NetworkAdapterError("body_not_allowed_for_observation_method")

    def _response_to_object(self, *, request: NetworkRequest, response: NetworkResponse) -> SurfaceObject:
        request_headers = self._sanitize_headers(request.headers)
        response_headers = self._sanitize_headers(response.headers)
        fields: dict[str, object] = {
            "protocol": "http",
            "method": response.method,
            "url": response.url,
            "status": response.status,
            "request_headers": request_headers,
            "request_header_order": tuple(request_headers.keys()),
            "headers": response_headers,
            "response_header_order": tuple(response_headers.keys()),
            "duration_ms": response.duration_ms,
            "body_length": len(response.body),
            "body_truncated": response.truncated,
        }
        if self.config.include_body:
            fields["body"] = response.body.decode("utf-8", errors="replace")

        return SurfaceObject(
            media_type="application/network-observation+http",
            fields=fields,
            ordering=tuple(fields),
            timing_model={"duration_ms": response.duration_ms},
            declared_protocol_class="http",
            provenance={
                "source_name": self.authorization.source_name,
                "owner_or_controller": self.authorization.owner_or_controller,
                "authorization_evidence_ref": self.authorization.evidence_ref,
                "adapter": "network",
            },
        )

    def _sanitize_headers(self, headers: dict[str, str]) -> dict[str, str]:
        redacted = {name.lower() for name in self.config.redacted_headers}
        return {
            key: "<redacted>" if key.lower() in redacted else value
            for key, value in headers.items()
        }
