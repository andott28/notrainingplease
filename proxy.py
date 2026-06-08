import copy
import json
import os
import threading
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import requests

from env_loader import load_dotenv
from intercept_core import handle_chat_completion_request
from semantic_masking import MaskingEngine, RequestVault


UPSTREAM_URL = "https://integrate.api.nvidia.com/v1/chat/completions"
VALID_PROTECTION_MODES = {"off", "balanced", "strict"}
VALID_STRICT_BACKENDS = {"local", "reject"}
VALID_MASKING_STRATEGIES = {"token_substitution", "opaque"}


def _parse_bool_env(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Config:
    api_key: str
    local_api_key: str = ""
    model: str = "moonshotai/kimi-k2.6"
    host: str = "127.0.0.1"
    port: int = 8787
    upstream_timeout_s: float = 60.0
    protection_mode: str = "balanced"
    strict_backend: str = "reject"
    strict_local_url: str = ""
    strict_local_timeout_s: float = 30.0
    masking_strategy: str = "token_substitution"
    session_vault_enabled: bool = True
    session_vault_ttl_s: float = 86400.0
    session_vault_max_sessions: int = 1000

    @classmethod
    def from_env(cls) -> "Config":
        api_key = os.environ.get("NVIDIA_API_KEY", "").strip()
        if not api_key:
            raise RuntimeError("NVIDIA_API_KEY is required.")
        model = os.environ.get("NVIDIA_MODEL", "moonshotai/kimi-k2.6")
        host = os.environ.get("PROXY_HOST", "127.0.0.1")
        port = int(os.environ.get("PROXY_PORT", "8787"))
        upstream_timeout_s = float(os.environ.get("UPSTREAM_TIMEOUT_S", "60"))

        protection_mode = os.environ.get("PROTECTION_MODE", "balanced").strip().lower()
        legacy_masking_enabled = os.environ.get("MASKING_ENABLED")
        if legacy_masking_enabled is not None:
            enabled = legacy_masking_enabled.strip().lower() in ("1", "true", "yes", "on")
            protection_mode = "balanced" if enabled else "off"
        if protection_mode not in VALID_PROTECTION_MODES:
            raise RuntimeError(f"Invalid PROTECTION_MODE={protection_mode}. Valid values: {sorted(VALID_PROTECTION_MODES)}")

        strict_backend = os.environ.get("STRICT_BACKEND", "reject").strip().lower()
        if strict_backend not in VALID_STRICT_BACKENDS:
            raise RuntimeError(f"Invalid STRICT_BACKEND={strict_backend}. Valid values: {sorted(VALID_STRICT_BACKENDS)}")
        strict_local_url = os.environ.get("STRICT_LOCAL_URL", "").strip()
        strict_local_timeout_s = float(os.environ.get("STRICT_LOCAL_TIMEOUT_S", "30"))
        masking_strategy = os.environ.get("MASKING_STRATEGY", "token_substitution").strip().lower()
        if masking_strategy not in VALID_MASKING_STRATEGIES:
            raise RuntimeError(
                f"Invalid MASKING_STRATEGY={masking_strategy}. Valid values: {sorted(VALID_MASKING_STRATEGIES)}"
            )
        session_vault_enabled = _parse_bool_env("SESSION_VAULT_ENABLED", True)
        session_vault_ttl_s = float(os.environ.get("SESSION_VAULT_TTL_S", "86400"))
        session_vault_max_sessions = int(os.environ.get("SESSION_VAULT_MAX_SESSIONS", "1000"))
        if session_vault_ttl_s <= 0:
            raise RuntimeError("SESSION_VAULT_TTL_S must be > 0.")
        if session_vault_max_sessions <= 0:
            raise RuntimeError("SESSION_VAULT_MAX_SESSIONS must be > 0.")

        local_api_key = os.environ.get("LOCAL_API_KEY", "").strip()

        return cls(
            api_key=api_key,
            local_api_key=local_api_key,
            model=model,
            host=host,
            port=port,
            upstream_timeout_s=upstream_timeout_s,
            protection_mode=protection_mode,
            strict_backend=strict_backend,
            strict_local_url=strict_local_url,
            strict_local_timeout_s=strict_local_timeout_s,
            masking_strategy=masking_strategy,
            session_vault_enabled=session_vault_enabled,
            session_vault_ttl_s=session_vault_ttl_s,
            session_vault_max_sessions=session_vault_max_sessions,
        )


@dataclass
class AppState:
    config: Config
    engine: MaskingEngine
    session_vault_store: "SessionVaultStore | None" = None

    def __post_init__(self) -> None:
        if self.session_vault_store is None:
            self.session_vault_store = SessionVaultStore(
                enabled=self.config.session_vault_enabled,
                ttl_s=self.config.session_vault_ttl_s,
                max_sessions=self.config.session_vault_max_sessions,
            )


@dataclass
class SessionVaultSnapshot:
    forward_map: dict[str, str] = field(default_factory=dict)
    reverse_map: dict[str, str] = field(default_factory=dict)
    alias_counters: dict[str, int] = field(default_factory=dict)
    token_forward_map: dict[int, int] = field(default_factory=dict)
    token_reverse_map: dict[int, int] = field(default_factory=dict)
    entity_metadata: dict[str, dict[str, Any]] = field(default_factory=dict)


class SessionVaultStore:
    def __init__(self, enabled: bool, ttl_s: float, max_sessions: int) -> None:
        self._enabled = enabled
        self._ttl_s = ttl_s
        self._max_sessions = max_sessions
        self._lock = threading.RLock()
        self._sessions: OrderedDict[str, dict[str, Any]] = OrderedDict()

    @property
    def enabled(self) -> bool:
        return self._enabled

    def session_count(self) -> int:
        with self._lock:
            return len(self._sessions)

    def hydrate_vault(self, session_id: str, vault: RequestVault) -> bool:
        if not self._enabled or not session_id:
            return False
        now = time.time()
        with self._lock:
            self._prune_locked(now)
            entry = self._sessions.get(session_id)
            if entry is None:
                return False
            snapshot: SessionVaultSnapshot = entry["snapshot"]
            vault.forward_map.update(snapshot.forward_map)
            vault.reverse_map.update(snapshot.reverse_map)
            vault.alias_counters.update(snapshot.alias_counters)
            vault.token_forward_map.update(snapshot.token_forward_map)
            vault.token_reverse_map.update(snapshot.token_reverse_map)
            vault.entity_metadata.update(copy.deepcopy(snapshot.entity_metadata))
            entry["updated_at"] = now
            self._sessions.move_to_end(session_id)
            return True

    def merge_from_vault(self, session_id: str, vault: RequestVault) -> None:
        if not self._enabled or not session_id:
            return
        now = time.time()
        with self._lock:
            self._prune_locked(now)
            entry = self._sessions.get(session_id)
            if entry is None:
                snapshot = SessionVaultSnapshot()
            else:
                snapshot = entry["snapshot"]
            snapshot.forward_map.update(vault.forward_map)
            snapshot.reverse_map.update(vault.reverse_map)
            snapshot.alias_counters.update(vault.alias_counters)
            snapshot.token_forward_map.update(vault.token_forward_map)
            snapshot.token_reverse_map.update(vault.token_reverse_map)
            snapshot.entity_metadata.update(copy.deepcopy(vault.entity_metadata))
            self._sessions[session_id] = {"snapshot": snapshot, "updated_at": now}
            self._sessions.move_to_end(session_id)
            while len(self._sessions) > self._max_sessions:
                self._sessions.popitem(last=False)

    def _prune_locked(self, now: float) -> None:
        stale_ids = [sid for sid, entry in self._sessions.items() if (now - float(entry["updated_at"])) > self._ttl_s]
        for session_id in stale_ids:
            self._sessions.pop(session_id, None)


class ProxyHandler(BaseHTTPRequestHandler):
    server_version = "SemanticProxy/2.0"

    def do_GET(self) -> None:
        app: AppState = self.server.app_state
        if self.path == "/healthz":
            self._write_json(
                200,
                {
                    "status": "ok",
                    "model": app.config.model,
                    "protection_mode": app.config.protection_mode,
                    "strict_backend": app.config.strict_backend,
                    "masking_strategy": app.config.masking_strategy,
                },
            )
            return
        if self.path == "/v1/masking/diagnostics":
            diagnostics = app.engine.diagnostics()
            diagnostics["session_vault_enabled"] = app.session_vault_store.enabled
            diagnostics["session_vault_active_sessions"] = app.session_vault_store.session_count()
            self._write_json(200, diagnostics)
            return
        self._write_json(404, {"error": {"message": "Not found"}})

    def do_POST(self) -> None:
        if self.path != "/v1/chat/completions":
            self._write_json(404, {"error": {"message": "Not found"}})
            return
        app: AppState = self.server.app_state
        request_id = str(uuid.uuid4())
        body = self._read_json_body()
        if body is None:
            self._write_json(400, {"error": {"message": "Invalid JSON body"}})
            return
        if body.get("stream") is True:
            self._write_json(400, {"error": {"message": "stream=true is not supported in v1"}})
            return
        result = handle_chat_completion_request(
            body,
            {k: v for k, v in self.headers.items()},
            request_id=request_id,
            config=app.config,
            engine=app.engine,
            session_vault_store=app.session_vault_store,
            upstream_sender=self._call_upstream,
        )
        self._write_json(result["status"], result["body"])

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _read_json_body(self) -> dict[str, Any] | None:
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if content_length <= 0:
            return None
        data = self.rfile.read(content_length)
        try:
            return json.loads(data.decode("utf-8"))
        except json.JSONDecodeError:
            return None

    def _call_upstream(self, payload: dict[str, Any], config: Config) -> dict[str, Any]:
        try:
            resp = requests.post(
                UPSTREAM_URL,
                headers={
                    "Authorization": f"Bearer {config.api_key}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                json=payload,
                timeout=config.upstream_timeout_s,
            )
            status = resp.status_code
            try:
                parsed = resp.json()
            except Exception:
                parsed = {"error": {"message": resp.text[:1000]}}
            if status >= 400:
                return {"ok": False, "status": status, "body": parsed}
            return {"ok": True, "status": status, "body": parsed}
        except Exception as exc:
            return {"ok": False, "status": 502, "body": {"error": {"message": f"Upstream request failed: {exc}"}}}

    def _write_json(self, status: int, body: dict[str, Any]) -> None:
        payload = json.dumps(body, ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


_server: ThreadingHTTPServer | None = None
_server_lock = threading.Lock()


def run(quiet: bool = False) -> None:
    global _server
    load_dotenv(".env", override=True)
    config = Config.from_env()
    session_vault_store = SessionVaultStore(
        enabled=config.session_vault_enabled,
        ttl_s=config.session_vault_ttl_s,
        max_sessions=config.session_vault_max_sessions,
    )
    app_state = AppState(
        config=config,
        engine=MaskingEngine(strategy=config.masking_strategy),
        session_vault_store=session_vault_store,
    )
    server = ThreadingHTTPServer((config.host, config.port), ProxyHandler)
    server.app_state = app_state
    with _server_lock:
        _server = server
    if not quiet:
        print(f"Listening on http://{config.host}:{config.port}")
    try:
        server.serve_forever()
    finally:
        with _server_lock:
            _server = None


def stop() -> None:
    global _server
    with _server_lock:
        srv = _server
        _server = None
    if srv:
        srv.shutdown()


if __name__ == "__main__":
    run()
