import json
import os
import platform
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from semantic_masking import MaskingEngine, RequestVault


MITM_CA_CER = os.path.join(os.path.expanduser("~"), ".mitmproxy", "mitmproxy-ca-cert.cer")
DISCOVERY_PATH = Path(".agent") / "detected_providers.json"
PROVIDER_HINTS = {
    "openai": ("api.openai.com", "openai.com"),
    "anthropic": ("api.anthropic.com", "claude.ai", "anthropic.com"),
    "google": ("generativelanguage.googleapis.com", "aiplatform.googleapis.com", "googleapis.com"),
    "mistral": ("api.mistral.ai", "mistral.ai"),
    "xai": ("api.x.ai", "x.ai"),
    "nvidia": ("integrate.api.nvidia.com", "api.nvidia.com", "nvidia.com"),
    "deepseek": ("api.deepseek.com", "deepseek.com"),
    "qwen": ("dashscope.aliyuncs.com", "aliyuncs.com"),
    "cohere": ("api.cohere.ai", "cohere.com"),
    "groq": ("api.groq.com", "groq.com"),
    "azure_openai": ("openai.azure.com", "azure.com"),
    "perplexity": ("api.perplexity.ai", "perplexity.ai"),
}
PATH_HINTS = (
    "/v1/chat/completions",
    "/v1/responses",
    "/v1/completions",
    "/chat/completions",
    "/responses",
    "/completions",
    "/generate",
    "/v1beta",
)
BODY_HINT_KEYS = (
    "messages",
    "input",
    "prompt",
    "contents",
    "conversation",
    "model",
    "max_output_tokens",
    "temperature",
)

MAX_RECURSION_DEPTH = 12
@dataclass
class TransparentConfig:
    api_key: str
    model: str
    local_api_key: str = ""
    protection_mode: str = "balanced"
    strict_backend: str = "reject"
    strict_local_url: str = ""
    strict_local_timeout_s: float = 30.0
    discovery_log_path: str = str(DISCOVERY_PATH)


@dataclass
class ProviderObservation:
    provider_id: str
    host: str
    path: str
    matched_by: str
    action: str
    request_id: str
    timestamp: float = field(default_factory=time.time)


class ProviderRegistry:
    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._lock = threading.RLock()
        self._providers: dict[str, dict[str, Any]] = {}
        self._observations: list[dict[str, Any]] = []
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except Exception:
            return
        providers = data.get("providers", {})
        if isinstance(providers, dict):
            self._providers.update({str(k): dict(v) for k, v in providers.items() if isinstance(v, dict)})
        observations = data.get("observations", [])
        if isinstance(observations, list):
            self._observations.extend([dict(item) for item in observations if isinstance(item, dict)])

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"providers": self._providers, "observations": self._observations[-500:]}
        self._path.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")

    def record(self, observation: ProviderObservation) -> None:
        with self._lock:
            entry = self._providers.setdefault(
                observation.provider_id,
                {
                    "provider_id": observation.provider_id,
                    "hosts": [],
                    "paths": [],
                    "hits": 0,
                    "redirected_hits": 0,
                    "last_seen": 0.0,
                    "samples": [],
                },
            )
            if observation.host not in entry["hosts"]:
                entry["hosts"].append(observation.host)
            if observation.path not in entry["paths"]:
                entry["paths"].append(observation.path)
            entry["hits"] = int(entry.get("hits", 0)) + 1
            if observation.action == "redirected":
                entry["redirected_hits"] = int(entry.get("redirected_hits", 0)) + 1
            entry["last_seen"] = observation.timestamp
            samples = entry.setdefault("samples", [])
            if len(samples) < 20:
                samples.append(
                    {
                        "host": observation.host,
                        "path": observation.path,
                        "matched_by": observation.matched_by,
                        "action": observation.action,
                        "request_id": observation.request_id,
                        "timestamp": observation.timestamp,
                    }
                )
            self._observations.append(
                {
                    "provider_id": observation.provider_id,
                    "host": observation.host,
                    "path": observation.path,
                    "matched_by": observation.matched_by,
                    "action": observation.action,
                    "request_id": observation.request_id,
                    "timestamp": observation.timestamp,
                }
            )
            self._save()

    def summarize(self) -> list[dict[str, Any]]:
        with self._lock:
            items = list(self._providers.values())
        return sorted(items, key=lambda item: (int(item.get("redirected_hits", 0)) > 0, int(item.get("hits", 0))), reverse=True)


class TransparentState:
    def __init__(self, config: TransparentConfig, engine: MaskingEngine, session_vault_store: Any) -> None:
        self.config = config
        self.engine = engine
        self.session_vault_store = session_vault_store
        self.registry = ProviderRegistry(config.discovery_log_path)


def parse_json_body(body: bytes) -> dict[str, Any] | None:
    try:
        parsed = json.loads(body.decode("utf-8"))
    except Exception:
        return None
    return parsed if isinstance(parsed, dict) else None


def is_json_request(headers: Any) -> bool:
    content_type = ""
    if hasattr(headers, "get"):
        content_type = str(headers.get("content-type", headers.get("Content-Type", ""))).lower()
    return "application/json" in content_type or "text/json" in content_type or "application/x-ndjson" in content_type


def provider_family_for_host(host: str) -> str:
    host = host.lower().split(":", 1)[0]
    for provider_id, hints in PROVIDER_HINTS.items():
        for hint in hints:
            if host == hint or host.endswith("." + hint) or host.endswith(hint):
                return provider_id
    return "unknown"


def body_looks_llmish(body: dict[str, Any]) -> bool:
    keys = set(body.keys())
    return any(key in keys for key in BODY_HINT_KEYS) and any(
        key in keys for key in ("messages", "input", "prompt", "contents", "conversation")
    )


def body_shape_hint(body: dict[str, Any]) -> str:
    if "messages" in body and isinstance(body.get("messages"), list):
        return "chat_messages"
    if "input" in body:
        return "response_input"
    if "prompt" in body:
        return "prompt"
    if "contents" in body:
        return "contents"
    if "conversation" in body:
        return "conversation"
    return "json_llmish"


def request_target_hint(path: str) -> bool:
    lowered = path.lower()
    return any(hint in lowered for hint in PATH_HINTS)


def classify_provider(host: str, path: str, body: dict[str, Any], headers: Any) -> tuple[str, str, bool]:
    provider_id = provider_family_for_host(host)
    if provider_id != "unknown":
        return provider_id, "host_hint", True
    if request_target_hint(path):
        if body_looks_llmish(body):
            auth = ""
            if hasattr(headers, "get"):
                auth = str(headers.get("authorization", headers.get("Authorization", "")))
            if auth.lower().startswith("bearer ") or "api-key" in str(headers).lower():
                return "discovered_llm", "path+body+auth", True
            return "discovered_llm", "path+body", True
    if body_looks_llmish(body):
        return "discovered_llm", "body_shape", True
    return "unknown", "no_match", False


def response_payload(status: int, payload: dict[str, Any]) -> tuple[int, bytes, list[tuple[str, str]]]:
    data = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    return status, data, [("Content-Type", "application/json"), ("Content-Length", str(len(data)))]


def _session_id_for_flow(flow: Any, host: str, path: str) -> str:
    client = getattr(flow, "client_conn", None)
    client_host = ""
    client_port = 0
    if client is not None and hasattr(client, "address") and client.address:
        client_host, client_port = client.address[0], client.address[1]
    scheme = getattr(flow.request, "scheme", "")
    return f"{client_host}:{client_port}|{scheme}|{host}|{path}"[:256]


def _mask_json_value(value: Any, engine: MaskingEngine, vault: RequestVault, depth: int = 0) -> Any:
    if depth > MAX_RECURSION_DEPTH:
        return value
    if isinstance(value, str):
        return engine.mask_message({"content": value}, vault).get("content", value)
    if isinstance(value, list):
        return [_mask_json_value(item, engine, vault, depth + 1) for item in value]
    if isinstance(value, dict):
        return {
            key: _mask_json_value(item, engine, vault, depth + 1) if isinstance(item, (str, list, dict)) else item
            for key, item in value.items()
        }
    return value


def _unmask_text(text: str, vault: RequestVault) -> str:
    if not vault.reverse_map:
        return text
    keys = sorted(vault.reverse_map.keys(), key=len, reverse=True)
    if not keys:
        return text
    import re

    rx = re.compile("(" + "|".join(re.escape(k) for k in keys) + ")")
    return rx.sub(lambda m: vault.reverse_map.get(m.group(0), m.group(0)), text)


def _unmask_json_value(value: Any, vault: RequestVault, depth: int = 0) -> Any:
    if depth > MAX_RECURSION_DEPTH:
        return value
    if isinstance(value, str):
        return _unmask_text(value, vault)
    if isinstance(value, list):
        return [_unmask_json_value(item, vault, depth + 1) for item in value]
    if isinstance(value, dict):
        return {
            key: _unmask_json_value(item, vault, depth + 1) if isinstance(item, (str, list, dict)) else item
            for key, item in value.items()
        }
    return value


def handle_flow_request(flow: Any, state: TransparentState) -> bool:
    request = flow.request
    method = getattr(request, "method", "").upper()
    if method not in {"POST", "PUT"}:
        return False
    if not is_json_request(request.headers):
        return False

    parsed = parse_json_body(getattr(request, "content", b""))
    if parsed is None:
        return False

    host = getattr(request, "host", "")
    path = getattr(request, "path", "")
    provider_id, matched_by, should_intercept = classify_provider(host, path, parsed, request.headers)
    if not should_intercept:
        return False

    request_id = str(uuid.uuid4())
    session_id = _session_id_for_flow(flow, host, path)
    vault = RequestVault(request_id=request_id)
    state.session_vault_store.hydrate_vault(session_id, vault)
    masked_body = _mask_json_value(parsed, state.engine, vault)
    encoded = json.dumps(masked_body, ensure_ascii=True).encode("utf-8")
    flow.request.content = encoded
    if hasattr(flow.request, "headers"):
        flow.request.headers["content-length"] = str(len(encoded))
    flow.metadata["transparent_provider_id"] = provider_id
    flow.metadata["transparent_request_id"] = request_id
    flow.metadata["transparent_vault"] = vault
    flow.metadata["transparent_matched_by"] = matched_by
    flow.metadata["transparent_session_id"] = session_id
    state.registry.record(
        ProviderObservation(
            provider_id=provider_id,
            host=host,
            path=path,
            matched_by=matched_by,
            action="redirected",
            request_id=request_id,
        )
    )
    return True


class TransparentProxyManager:
    def __init__(self) -> None:
        self._process: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()

    @property
    def running(self) -> bool:
        with self._lock:
            return self._process is not None and self._process.poll() is None

    def start(self, config: TransparentConfig) -> None:
        with self._lock:
            if self._process is not None and self._process.poll() is None:
                return
            if platform.system().lower() != "windows":
                raise RuntimeError("Transparent mode is Windows-only in this build.")
            install_windows_ca()
            addon_path = os.path.abspath(__file__)
            cmd = [
                "python",
                "-m",
                "mitmdump",
                "-s",
                addon_path,
                "--mode",
                "transparent",
            ]
            env = os.environ.copy()
            env["MASKING_STRATEGY"] = os.environ.get("MASKING_STRATEGY", "token_substitution")
            env["PROTECTION_MODE"] = config.protection_mode
            env["STRICT_BACKEND"] = config.strict_backend
            env["STRICT_LOCAL_URL"] = config.strict_local_url
            env["STRICT_LOCAL_TIMEOUT_S"] = str(config.strict_local_timeout_s)
            env["TRANSPARENT_DISCOVERY_LOG"] = config.discovery_log_path
            if config.local_api_key:
                env["LOCAL_API_KEY"] = config.local_api_key
            self._process = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def stop(self) -> None:
        with self._lock:
            proc = self._process
            self._process = None
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except Exception:
                proc.kill()
        uninstall_windows_ca()


class TransparentAddon:
    def __init__(self) -> None:
        discovery_path = os.environ.get("TRANSPARENT_DISCOVERY_LOG", str(DISCOVERY_PATH))
        self._state = TransparentState(
            config=TransparentConfig(
                api_key=os.environ.get("NVIDIA_API_KEY", "").strip(),
                model=os.environ.get("NVIDIA_MODEL", "moonshotai/kimi-k2.6"),
                local_api_key=os.environ.get("LOCAL_API_KEY", "").strip(),
                protection_mode=os.environ.get("PROTECTION_MODE", "balanced").strip().lower(),
                strict_backend=os.environ.get("STRICT_BACKEND", "reject").strip().lower(),
                strict_local_url=os.environ.get("STRICT_LOCAL_URL", "").strip(),
                strict_local_timeout_s=float(os.environ.get("STRICT_LOCAL_TIMEOUT_S", "30")),
                discovery_log_path=discovery_path,
            ),
            engine=MaskingEngine(strategy=os.environ.get("MASKING_STRATEGY", "token_substitution")),
            session_vault_store=_build_session_vault_store(),
        )

    def request(self, flow: Any) -> None:
        handle_flow_request(flow, self._state)

    def response(self, flow: Any) -> None:
        vault = flow.metadata.get("transparent_vault")
        if not isinstance(vault, RequestVault):
            return
        response = flow.response
        if response is None or not hasattr(response, "headers"):
            return
        content_type = str(response.headers.get("content-type", response.headers.get("Content-Type", ""))).lower()
        if "application/json" not in content_type and "text/json" not in content_type and "application/x-ndjson" not in content_type:
            return
        raw = getattr(response, "content", b"")
        if not isinstance(raw, (bytes, bytearray)):
            return
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except Exception:
            return
        unmasked = _unmask_json_value(parsed, vault)
        encoded = json.dumps(unmasked, ensure_ascii=True).encode("utf-8")
        flow.response.content = encoded
        flow.response.headers["content-length"] = str(len(encoded))
        session_id = flow.metadata.get("transparent_session_id", "")
        if isinstance(session_id, str) and session_id:
            self._state.session_vault_store.merge_from_vault(session_id, vault)


def _build_session_vault_store() -> Any:
    class _SessionVaultStore:
        def hydrate_vault(self, *_args: Any, **_kwargs: Any) -> bool:
            return False

        def merge_from_vault(self, *_args: Any, **_kwargs: Any) -> None:
            return None

    return _SessionVaultStore()


addons = [TransparentAddon()]


def install_windows_ca() -> None:
    if platform.system().lower() != "windows":
        return
    if not os.path.isfile(MITM_CA_CER):
        return
    subprocess.run(
        ["certutil", "-addstore", "Root", MITM_CA_CER],
        check=False,
        capture_output=True,
        text=True,
    )


def uninstall_windows_ca() -> None:
    if platform.system().lower() != "windows":
        return
    if not os.path.isfile(MITM_CA_CER):
        return
    subprocess.run(
        ["certutil", "-delstore", "Root", MITM_CA_CER],
        check=False,
        capture_output=True,
        text=True,
    )
