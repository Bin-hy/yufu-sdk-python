"""Shared fixtures for the yufu Runtime SDK test suite."""

from __future__ import annotations

import json
import os
import re
import threading
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from yufu import AsyncClient, Client


def _fixture_root() -> Path | None:
    candidates: list[Path] = []
    configured = os.environ.get("YUFU_CONTRACT_FIXTURES")
    if configured:
        candidates.append(Path(configured))
    here = Path(__file__).resolve()
    workspace = here.parents[2]
    candidates.extend(
        [
            here.parent / "contract-fixtures",
            workspace / "cobot-for" / "sdk" / "contract-fixtures",
            workspace / "yufu" / "sdk" / "contract-fixtures",
        ]
    )
    for candidate in candidates:
        if (candidate / "manifest.json").is_file():
            return candidate
    return None


@dataclass(slots=True)
class Contract:
    root: Path
    manifest: dict[str, Any]
    endpoints: dict[str, Any]
    expectations: dict[str, Any]

    @property
    def issuer(self) -> str:
        return str(self.manifest["issuer"])

    @property
    def clock(self) -> int:
        return int(self.manifest["clock"])

    @property
    def flow(self) -> dict[str, Any]:
        return dict(self.manifest["flow"])

    def now(self) -> datetime:
        return datetime.fromtimestamp(self.clock, timezone.utc)

    def path(self, relative: str) -> Path:
        return self.root / relative

    def read_token(self, relative: str) -> str:
        return self.path(relative).read_text(encoding="utf-8").strip()


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise RuntimeError(f"contract fixture {path} is not a JSON object")
    return value


def _load_contract(root: Path) -> Contract:
    manifest = _load_json(root / "manifest.json")
    files = manifest["files"]
    referenced = [
        files["discovery"],
        files["jwks"],
        files["endpoints"],
        files["expectations"],
        *files["keys"].values(),
    ]
    for relative in referenced:
        if not (root / relative).is_file():
            raise RuntimeError(f"contract fixture is missing {relative}")

    endpoints = _load_json(root / files["endpoints"])
    expectations = _load_json(root / files["expectations"])
    for group in ("access_token", "id_token", "logout_token"):
        for item in expectations.get(group, []):
            if not (root / item["token"]).is_file():
                raise RuntimeError(f"contract fixture is missing {item['token']}")
    for endpoint in endpoints.get("endpoints", []):
        for spec in [endpoint.get("default", {}), *endpoint.get("cases", [])]:
            response = spec.get("response", spec)
            body_file = response.get("body_file")
            if body_file and not (root / body_file).is_file():
                raise RuntimeError(f"contract fixture is missing {body_file}")
    return Contract(root=root, manifest=manifest, endpoints=endpoints, expectations=expectations)


def pytest_generate_tests(metafunc: Any) -> None:
    if "token_case" not in metafunc.fixturenames:
        return
    root = _fixture_root()
    if root is None:
        metafunc.parametrize("token_case", [])
        return
    manifest = _load_json(root / "manifest.json")
    expectations = _load_json(root / manifest["files"]["expectations"])
    cases = []
    for kind in ("access_token", "id_token", "logout_token"):
        for item in expectations.get(kind, []):
            cases.append(pytest.param((kind, item), id=f"{kind}-{item['id']}"))
    metafunc.parametrize("token_case", cases)


class _FixtureHandler(BaseHTTPRequestHandler):
    contract: Contract
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")

    def log_message(self, format: str, *args: object) -> None:
        return

    def _handle(self, method: str) -> None:
        path = urlsplit(self.path).path
        files = self.contract.manifest["files"]
        if path == "/.well-known/openid-configuration":
            self._serve_file(files["discovery"])
            return
        if path == "/.well-known/jwks.json":
            self._serve_file(files["jwks"])
            return

        endpoint = next(
            (item for item in self.contract.endpoints.get("endpoints", []) if item["path"] == path),
            None,
        )
        if endpoint is None:
            self._send(404, b"not found", "text/plain")
            return
        if str(endpoint["method"]).upper() != method:
            self._send(405, b"method not allowed", "text/plain")
            return

        form = self._read_form()
        for case in endpoint.get("cases", []):
            if self._matches(case, form):
                self._write_response(case["response"])
                return
        self._write_response(endpoint["default"])

    def _read_form(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else b""
        parsed = parse_qs(body.decode("utf-8"), keep_blank_values=True)
        return {key: values[0] if values else "" for key, values in parsed.items()}

    def _matches(self, case: dict[str, Any], form: dict[str, str]) -> bool:
        for key, want in case.get("form_equals", {}).items():
            if form.get(key) != want:
                return False
        for key in case.get("form_present", []):
            if key not in form:
                return False
        for key, pattern in case.get("headers_match", {}).items():
            if re.search(pattern, self.headers.get(key, "")) is None:
                return False
        return True

    def _serve_file(self, relative: str) -> None:
        self._send(200, self.contract.path(relative).read_bytes(), "application/json")

    def _write_response(self, spec: dict[str, Any]) -> None:
        headers = dict(spec.get("headers", {}))
        body = b""
        if spec.get("body_file"):
            body = self.contract.path(spec["body_file"]).read_bytes()
            headers.setdefault("Content-Type", "application/json")
        elif "json" in spec:
            body = json.dumps(spec["json"]).encode("utf-8") + b"\n"
            headers.setdefault("Content-Type", "application/json")
        self._send(int(spec.get("status", 200)), body, headers=headers)

    def _send(
        self,
        status: int,
        body: bytes,
        content_type: str = "",
        headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        response_headers = dict(headers or {})
        if content_type:
            response_headers.setdefault("Content-Type", content_type)
        for key, value in response_headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)


@pytest.fixture(scope="session")
def contract() -> Contract:
    root = _fixture_root()
    if root is None:
        pytest.skip(
            "contract fixtures not found; set YUFU_CONTRACT_FIXTURES to "
            "<yufu>/sdk/contract-fixtures"
        )
    return _load_contract(root)


@pytest.fixture(scope="session")
def fixture_server(contract: Contract) -> Iterator[ThreadingHTTPServer]:
    issuer = urlsplit(contract.issuer)
    if not issuer.hostname or not issuer.port:
        raise RuntimeError(f"invalid fixture issuer {contract.issuer!r}")

    handler = type("_BoundFixtureHandler", (_FixtureHandler,), {"contract": contract})
    try:
        server = ThreadingHTTPServer((issuer.hostname, issuer.port), handler)
    except OSError as exc:
        raise RuntimeError(
            f"fixture issuer {contract.issuer} is unavailable: {exc} "
            "(another consumer may be running)"
        ) from exc
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture
def client(contract: Contract, fixture_server: ThreadingHTTPServer) -> Iterator[Client]:
    flow = contract.flow
    with Client(
        issuer=contract.issuer,
        client_id=flow["client"]["client_id"],
        client_secret=flow["client"]["client_secret"],
        redirect_uri=flow["redirect_uri"],
        scopes=flow["scopes"],
        now=contract.now,
    ) as instance:
        yield instance


@pytest.fixture
def reader(contract: Contract, fixture_server: ThreadingHTTPServer) -> Iterator[Client]:
    flow = contract.flow
    with Client(
        issuer=contract.issuer,
        client_id=flow["reader"]["client_id"],
        client_secret=flow["reader"]["client_secret"],
        now=contract.now,
    ) as instance:
        yield instance


@pytest.fixture
async def async_client(
    contract: Contract, fixture_server: ThreadingHTTPServer
) -> AsyncIterator[AsyncClient]:
    flow = contract.flow
    instance = AsyncClient(
        issuer=contract.issuer,
        client_id=flow["client"]["client_id"],
        client_secret=flow["client"]["client_secret"],
        redirect_uri=flow["redirect_uri"],
        scopes=flow["scopes"],
        now=contract.now,
    )
    try:
        yield instance
    finally:
        await instance.aclose()


@pytest.fixture
async def async_reader(
    contract: Contract, fixture_server: ThreadingHTTPServer
) -> AsyncIterator[AsyncClient]:
    flow = contract.flow
    instance = AsyncClient(
        issuer=contract.issuer,
        client_id=flow["reader"]["client_id"],
        client_secret=flow["reader"]["client_secret"],
        now=contract.now,
    )
    try:
        yield instance
    finally:
        await instance.aclose()
