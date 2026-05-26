import copy
import json
import os
import re
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import requests

from env_loader import load_dotenv
from semantic_masking import IDENTIFIER_ENTITY_TYPES, MaskingEngine, RequestVault, SECRETISH_ENTITY_TYPES


UPSTREAM_URL = "https://integrate.api.nvidia.com/v1/chat/completions"
VALID_PROTECTION_MODES = {"off", "balanced", "strict"}
VALID_STRICT_BACKENDS = {"local", "reject"}
VALID_MASKING_STRATEGIES = {"token_substitution", "opaque"}
MASKING_SYSTEM_NOTE = (
    "You are operating in privacy-preserving mode. "
    "All user-supplied identifiers - variable names, constants, API keys, "
    "paths, hostnames, emails, and similar tokens - have been replaced with "
    "semantically-consistent aliases via a stable bijective mapping. "
    "These aliases are valid, well-formed identifiers. Treat them as real names "
    "and reason about the task structure and code logic normally. "
    "Do not attempt to infer or recover the original names."
)
SENSITIVITY_MARKER_RX = re.compile(
    r"\b(confidential|proprietary|internal only|do not share|private key|secret key|password|credential|api key)\b",
    re.IGNORECASE,
)


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
        if "messages" not in body or not isinstance(body["messages"], list):
            self._write_json(400, {"error": {"message": "messages must be a list"}})
            return

        if not self._authenticate(app.config):
            return

        sensitivity = self._classify_sensitivity(body["messages"], app.engine)
        route_mode = self._resolve_route_mode(app.config.protection_mode, sensitivity)
        session_id = self._session_id()

        if route_mode == "strict":
            strict_result = self._handle_strict_route(body, app.config, request_id, sensitivity)
            self._write_json(strict_result["status"], strict_result["body"])
            return

        if route_mode == "off":
            outbound_messages = body["messages"]
            vault = RequestVault(request_id=request_id)
        else:
            vault = RequestVault(request_id=request_id)
            app.session_vault_store.hydrate_vault(session_id, vault)
            t0 = time.perf_counter()
            outbound_messages = []
            messages_to_mask = self._with_masking_system_note(body["messages"])
            try:
                for message in messages_to_mask:
                    outbound_messages.append(app.engine.mask_message(message, vault))
            except RuntimeError as exc:
                self._write_json(
                    422,
                    {
                        "error": {
                            "message": f"Masking failed: {exc}",
                            "type": "masking_failed",
                            "request_id": request_id,
                            "hint": "Set TOKEN_CIPHER_MODEL_ID to a valid tokenizer model for MASKING_STRATEGY=token_substitution.",
                        }
                    },
                )
                return
            vault.timings_ms["mask_total"] = (time.perf_counter() - t0) * 1000.0
            app.session_vault_store.merge_from_vault(session_id, vault)

        outbound_payload = dict(body)
        outbound_payload["stream"] = False
        outbound_payload["model"] = body.get("model") or app.config.model
        outbound_payload["messages"] = outbound_messages

        upstream_result = self._call_upstream(outbound_payload, app.config)
        if upstream_result["ok"] is False:
            self._write_json(upstream_result["status"], upstream_result["body"])
            return

        response_body = upstream_result["body"]
        if route_mode == "balanced":
            t1 = time.perf_counter()
            app.engine.unmask_response(response_body, vault)
            vault.timings_ms["unmask_total"] = (time.perf_counter() - t1) * 1000.0
        self._write_json(upstream_result["status"], response_body)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _resolve_route_mode(self, protection_mode: str, sensitivity: dict[str, Any]) -> str:
        if protection_mode == "off":
            return "off"
        if protection_mode == "strict":
            return "strict"
        return "strict" if sensitivity["strict_recommended"] else "balanced"

    def _authenticate(self, config: Config) -> bool:
        if not config.local_api_key and not config.api_key:
            return True
        auth = self.headers.get("Authorization", "").strip()
        if not auth.startswith("Bearer "):
            self._write_json(401, {"error": {"message": "Missing or invalid Authorization header"}})
            return False
        token = auth[len("Bearer "):].strip()
        if not token:
            self._write_json(401, {"error": {"message": "Missing or invalid Authorization header"}})
            return False
        if token == config.local_api_key or token == config.api_key:
            return True
        self._write_json(401, {"error": {"message": "Invalid API key"}})
        return False

    def _session_id(self) -> str:
        session_id = self.headers.get("X-Session-ID", "").strip()
        return session_id[:256]

    def _with_masking_system_note(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        normalized = [copy.deepcopy(message) for message in messages]
        system_index = -1
        for idx, message in enumerate(normalized):
            if isinstance(message, dict) and message.get("role") == "system":
                system_index = idx
                break
        if system_index == -1:
            return [{"role": "system", "content": MASKING_SYSTEM_NOTE}, *normalized]
        system_message = normalized[system_index]
        content = system_message.get("content")
        if isinstance(content, str):
            if MASKING_SYSTEM_NOTE not in content:
                if content.strip():
                    system_message["content"] = f"{content}\n\n{MASKING_SYSTEM_NOTE}"
                else:
                    system_message["content"] = MASKING_SYSTEM_NOTE
            return normalized
        if isinstance(content, list):
            if not self._content_parts_have_masking_note(content):
                content.append({"type": "text", "text": MASKING_SYSTEM_NOTE})
            return normalized
        system_message["content"] = MASKING_SYSTEM_NOTE
        return normalized

    def _content_parts_have_masking_note(self, content_parts: list[Any]) -> bool:
        for part in content_parts:
            if isinstance(part, dict) and part.get("type") == "text" and part.get("text") == MASKING_SYSTEM_NOTE:
                return True
        return False

    def _extract_text_from_message(self, message: dict[str, Any]) -> str:
        content = message.get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts: list[str] = []
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
                    parts.append(part["text"])
            return "\n".join(parts)
        return ""

    def _classify_sensitivity(self, messages: list[dict[str, Any]], engine: MaskingEngine) -> dict[str, Any]:
        entity_counts = engine.summarize_messages_entities(messages)
        total_spans = sum(entity_counts.values())
        secretish_spans = sum(entity_counts.get(t, 0) for t in SECRETISH_ENTITY_TYPES)
        identifier_spans = sum(entity_counts.get(t, 0) for t in IDENTIFIER_ENTITY_TYPES)

        combined_text = "\n".join(self._extract_text_from_message(message) for message in messages)
        lowered = combined_text.lower()
        char_count = len(combined_text)
        tokenish_count = len(re.findall(r"\S+", combined_text))

        marker_hits = len(SENSITIVITY_MARKER_RX.findall(combined_text))
        has_code_fence = "```" in combined_text
        has_large_text = char_count >= 2200
        identifier_density = identifier_spans / max(1, tokenish_count)

        strict_score = 0
        signals: list[str] = []
        if marker_hits > 0:
            strict_score += 3
            signals.append("sensitive_markers")
        if has_large_text:
            strict_score += 2
            signals.append("large_text")
        if has_code_fence and char_count >= 900:
            strict_score += 2
            signals.append("code_fence_large")
        if total_spans >= 24:
            strict_score += 2
            signals.append("dense_sensitive_spans")
        if secretish_spans >= 8:
            strict_score += 1
            signals.append("many_secretish_spans")
        if identifier_density >= 0.08 and char_count >= 700:
            strict_score += 1
            signals.append("identifier_dense")
        if "entire prompt" in lowered or "all words" in lowered or "mask everything" in lowered:
            strict_score += 2
            signals.append("whole_prompt_signal")

        strict_recommended = strict_score >= 3
        return {
            "strict_recommended": strict_recommended,
            "strict_score": strict_score,
            "signals": signals,
            "entity_counts": entity_counts,
            "total_sensitive_spans": total_spans,
            "secretish_spans": secretish_spans,
            "identifier_spans": identifier_spans,
            "char_count": char_count,
        }

    def _handle_strict_route(
        self,
        body: dict[str, Any],
        config: Config,
        request_id: str,
        sensitivity: dict[str, Any],
    ) -> dict[str, Any]:
        if config.strict_backend == "reject":
            return {
                "status": 422,
                "body": {
                    "error": {
                        "message": "Strict mode blocked remote forwarding because request sensitivity is high. Set STRICT_BACKEND=local or STRICT_LOCAL_URL for trusted local handling.",
                        "type": "strict_mode_blocked",
                        "request_id": request_id,
                        "strict_score": sensitivity["strict_score"],
                        "signals": sensitivity["signals"],
                    }
                },
            }
        return self._call_local_strict_backend(body, config, request_id, sensitivity)

    def _call_local_strict_backend(
        self,
        body: dict[str, Any],
        config: Config,
        request_id: str,
        sensitivity: dict[str, Any],
    ) -> dict[str, Any]:
        local_url = config.strict_local_url
        if local_url:
            payload = dict(body)
            payload["stream"] = False
            payload["model"] = body.get("model") or config.model
            try:
                resp = requests.post(
                    local_url,
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                    json=payload,
                    timeout=config.strict_local_timeout_s,
                )
                parsed = resp.json()
                return {"status": resp.status_code, "body": parsed}
            except Exception as exc:
                return {
                    "status": 502,
                    "body": {
                        "error": {
                            "message": f"Strict local backend request failed: {exc}",
                            "type": "strict_local_backend_failed",
                            "request_id": request_id,
                        }
                    },
                }

        first_user_text = ""
        for message in body.get("messages", []):
            if isinstance(message, dict) and message.get("role") == "user":
                first_user_text = self._extract_text_from_message(message)[:120]
                break
        local_body = {
            "id": f"chatcmpl-strict-{request_id}",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "Strict mode handled this request locally. Configure STRICT_LOCAL_URL for full local model execution.",
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            "strict_mode": {
                "request_id": request_id,
                "strict_score": sensitivity["strict_score"],
                "signals": sensitivity["signals"],
                "preview": first_user_text,
            },
        }
        return {"status": 200, "body": local_body}

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
