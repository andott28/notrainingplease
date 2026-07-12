"""mitmproxy addon: intercepts AI provider API calls, masks outbound content, unmasks inbound responses.

Run via: mitmproxy -s proxy_addon.py --mode regular --listen-port 8923
"""
import json
import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    from mitmproxy import ctx
    _HAS_MITM_CTX = True
except ImportError:
    _HAS_MITM_CTX = False

try:
    from mitmproxy.proxy import layers as _proxy_layers
    _HAS_PROXY_LAYERS = True
except ImportError:
    _HAS_PROXY_LAYERS = False

try:
    from semantic_masking import MaskingEngine, RequestVault
except ImportError:
    class MaskingEngine:
        def __init__(self, strategy): self.strategy = strategy
        def mask_message(self, msg, vault): return msg
    class RequestVault:
        def __init__(self, request_id):
            self.request_id = request_id
            self.reverse_map = {}

try:
    from semantic_obfuscation import SemanticCodebook, SemanticObfuscator
except ImportError:
    SemanticCodebook = None
    SemanticObfuscator = None

CONFIG_PATH = Path(__file__).parent / "shield_config.json"
LOG_DIR = Path(__file__).parent / ".agent"
DEBUG_LOG = LOG_DIR / "addon_debug.log"
STATS_PATH = LOG_DIR / "live_stats.json"

PROVIDER_REGISTRY: dict[str, dict[str, Any]] = {
    "openai": {"id": "openai", "name": "OpenAI", "hosts": ["api.openai.com"], "paths": ["/v1/chat/completions"]},
    "anthropic": {"id": "anthropic", "name": "Anthropic", "hosts": ["api.anthropic.com"], "paths": ["/v1/messages"]},
    "google": {"id": "google", "name": "Google Gemini", "hosts": ["generativelanguage.googleapis.com"], "paths": ["/v1beta/models", "/v1/models"]},
    "opencode_zen": {"id": "opencode_zen", "name": "OpenCode Zen", "hosts": ["opencode.ai"], "paths": ["/zen/v1/responses", "/zen/v1/chat/completions"]},
    "opencode_go": {"id": "opencode_go", "name": "OpenCode Go", "hosts": ["opencode.ai"], "paths": ["/zen/go/v1/chat/completions"]},
}


def _load_config() -> dict[str, Any]:
    if not CONFIG_PATH.is_file():
        return {}
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _load_dotenv() -> None:
    dotpath = Path(__file__).parent / ".env"
    if not dotpath.is_file():
        return
    for line in dotpath.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _load_providers() -> dict[str, dict[str, Any]]:
    config = _load_config()
    providers = config.get("providers")
    if isinstance(providers, dict) and providers:
        return providers
    return dict(PROVIDER_REGISTRY)


def _load_provider_toggles() -> dict[str, bool]:
    config = _load_config()
    toggles = dict(config.get("provider_toggles", {}))
    all_ids = set(_load_providers().keys())
    for pid in all_ids:
        toggles.setdefault(pid, True)
    return toggles


def _get_enabled_providers() -> dict[str, dict[str, Any]]:
    providers = _load_providers()
    toggles = _load_provider_toggles()
    return {k: v for k, v in providers.items() if toggles.get(k, True)}


def _log(msg: str) -> None:
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        with open(DEBUG_LOG, "a", encoding="utf-8") as f:
            f.write(msg + "\n")
    except Exception:
        pass


def _write_stats(hits: int, redirections: int) -> None:
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        STATS_PATH.write_text(json.dumps({"hits": hits, "redirections": redirections}), encoding="utf-8")
    except Exception:
        pass


class ShieldAddon:
    """Intercepts AI provider API calls, masks outbound content, unmasks inbound responses."""

    def __init__(self) -> None:
        _load_dotenv()
        _log("[INIT] ShieldAddon loading...")

        self._vaults: dict[str, RequestVault] = {}
        self._hits = 0
        self._redirections = 0

        strategy = os.environ.get("MASKING_STRATEGY", "token_substitution")
        self.engine: MaskingEngine | None = None
        self.obfuscator: SemanticObfuscator | None = None

        try:
            self.engine = MaskingEngine(strategy=strategy)
            _log(f"[INIT] MaskingEngine OK, strategy={strategy}, tokenizer={'loaded' if self.engine._tokenizer else 'None'}")
        except Exception as exc:
            _log(f"[INIT] MaskingEngine FAILED: {exc}")
            self.engine = None

        if self.engine is not None and self.engine._tokenizer is not None:
            self._init_obfuscator()

        _log(f"[INIT] ShieldAddon ready, enabled_providers={list(_get_enabled_providers().keys())}")
        _write_stats(0, 0)

    def _init_obfuscator(self) -> None:
        if SemanticObfuscator is None or SemanticCodebook is None:
            return
        sem_enabled = os.environ.get("SEMANTIC_OBFUSCATION", "false").strip().lower() in {"1", "true", "yes", "on"}
        if not sem_enabled:
            return
        try:
            anchor_model = os.environ.get("SEMANTIC_OBFUSCATION_ANCHOR_MODEL", "").strip()
            level = os.environ.get("SEMANTIC_OBFUSCATION_LEVEL", "standard").strip().lower() or "standard"
            codebook_path = os.environ.get("SEMANTIC_OBFUSCATION_CODEBOOK_PATH", ".agent/semantic_codebook.json").strip()
            load_body = os.environ.get("SEMANTIC_OBFUSCATION_LOAD_ANCHOR_BODY", "true").strip().lower() in {"1", "true", "yes", "on"}
            tokenizer = self.engine.get_tokenizer() if self.engine.tokenizer_loaded() else None
            codebook = SemanticCodebook(
                tokenizer=tokenizer,
                anchor_model_id=anchor_model or "unknown",
                level=level,
                load_anchor_model_body=load_body,
                path=codebook_path,
            )
            self.obfuscator = SemanticObfuscator(codebook=codebook, tokenizer=tokenizer)
            if not codebook.ready:
                codebook.bootstrap_async()
            _log(f"[INIT] SemanticObfuscator OK, level={level}, anchor={anchor_model}")
        except Exception as exc:
            _log(f"[INIT] SemanticObfuscator FAILED: {exc}")
            self.obfuscator = None

    def _is_provider_host(self, host: str) -> bool:
        host_lower = host.lower()
        for provider in _get_enabled_providers().values():
            for h in provider.get("hosts", []):
                if h.lower() in host_lower or host_lower in h.lower():
                    return True
        return False

    def _match_provider(self, host: str, path: str) -> dict[str, Any] | None:
        host_lower = host.lower()
        path_lower = path.lower()
        for provider in _get_enabled_providers().values():
            host_match = any(h.lower() in host_lower or host_lower in h.lower() for h in provider.get("hosts", []))
            path_match = any(p.lower() in path_lower for p in provider.get("paths", []))
            if host_match and path_match:
                return provider
        return None

    def request(self, flow: Any) -> None:
        host = flow.request.host
        path = flow.request.path

        provider = self._match_provider(host, path)
        if provider is None:
            return

        self._hits += 1
        _write_stats(self._hits, self._redirections)
        _log(f"[REQ] Matched provider: {provider.get('name', '?')} — {flow.request.method} {host}{path}")

        if self.engine is None:
            _log("[REQ] SKIP: engine is None")
            return
        if not flow.request.content:
            _log(f"[REQ] SKIP: no request content (content={flow.request.content!r}, type={type(flow.request.content).__name__})")
            return

        try:
            data = json.loads(flow.request.content.decode("utf-8"))
        except Exception as exc:
            _log(f"[REQ] SKIP: JSON parse failed: {exc}")
            return

        req_id = str(uuid.uuid4())
        vault = RequestVault(request_id=req_id)

        include_system = os.environ.get("SEMANTIC_OBFUSCATION_INCLUDE_SYSTEM", "false").strip().lower() in {"1", "true", "yes", "on"}

        if "messages" in data and isinstance(data["messages"], list):
            for msg in data["messages"]:
                if not isinstance(msg, dict):
                    continue
                if "content" in msg and isinstance(msg["content"], str):
                    masked = self.engine.mask_message({"content": msg["content"]}, vault)
                    msg["content"] = masked.get("content", msg["content"])
                if self.obfuscator is not None and self.obfuscator.ready:
                    role = msg.get("role", "")
                    if include_system or role in {"user", "assistant"}:
                        encoded = self.obfuscator.encode_message(
                            {"role": role, "content": msg.get("content", "")},
                            vault,
                            include_system=include_system,
                        )
                        if isinstance(encoded.get("content"), str):
                            msg["content"] = encoded["content"]

        if "contents" in data and isinstance(data["contents"], list):
            for content_block in data["contents"]:
                if not isinstance(content_block, dict):
                    continue
                parts = content_block.get("parts")
                if not isinstance(parts, list):
                    continue
                for part in parts:
                    if not isinstance(part, dict):
                        continue
                    if "text" in part and isinstance(part["text"], str):
                        masked = self.engine.mask_message({"content": part["text"]}, vault)
                        part["text"] = masked.get("content", part["text"])

        flow.request.content = json.dumps(data).encode("utf-8")
        flow.request.headers["content-length"] = str(len(flow.request.content))

        self._vaults[req_id] = vault
        flow.metadata["shield_request_id"] = req_id
        flow.metadata["shield_is_streaming"] = data.get("stream", False)

        self._redirections += 1
        _write_stats(self._hits, self._redirections)
        _log(f"[REQ] MASKED {len(vault.reverse_map)} entities, streaming={data.get('stream', False)}")

    def _unmask_and_decode(self, body: dict, vault: RequestVault) -> None:
        if self.engine is None:
            return
        try:
            self.engine.unmask_response(body, vault)
        except Exception as exc:
            _log(f"[RES] unmask_response failed: {exc}")
        if self.obfuscator is not None and self.obfuscator.ready:
            decode_response = os.environ.get("SEMANTIC_OBFUSCATION_DECODE_RESPONSE", "false").strip().lower() in {"1", "true", "yes", "on"}
            if decode_response:
                try:
                    self.obfuscator.decode_response(body, vault)
                except Exception as exc:
                    _log(f"[RES] decode_response failed: {exc}")

    def _process_sse_line(self, line: str, vault: RequestVault) -> str:
        if not line.startswith("data: "):
            return line
        payload = line[len("data: "):]
        if payload.strip() == "[DONE]":
            return line
        try:
            chunk = json.loads(payload)
        except Exception:
            return line
        if not isinstance(chunk, dict):
            return line
        for choice in chunk.get("choices", []):
            if not isinstance(choice, dict):
                continue
            delta = choice.get("delta")
            if isinstance(delta, dict):
                content = delta.get("content")
                if isinstance(content, str) and content:
                    fake = {"choices": [{"message": {"content": content}}]}
                    self._unmask_and_decode(fake, vault)
                    delta["content"] = fake["choices"][0]["message"]["content"]
            message = choice.get("message")
            if isinstance(message, dict):
                content = message.get("content")
                if isinstance(content, str) and content:
                    fake = {"choices": [{"message": {"content": content}}]}
                    self._unmask_and_decode(fake, vault)
                    message["content"] = fake["choices"][0]["message"]["content"]
        try:
            return "data: " + json.dumps(chunk, ensure_ascii=False)
        except Exception:
            return line

    def response(self, flow: Any) -> None:
        req_id = flow.metadata.get("shield_request_id")
        if not req_id or req_id not in self._vaults:
            return
        if not flow.response or not flow.response.content:
            return
        vault = self._vaults.pop(req_id)
        _log(f"[RES] Response received, vault_entries={len(vault.reverse_map)}, streaming={flow.metadata.get('shield_is_streaming', False)}")

        raw = flow.response.content.decode("utf-8", errors="replace")

        if flow.metadata.get("shield_is_streaming", False):
            lines = raw.split("\n")
            new_lines = [self._process_sse_line(line.rstrip("\r"), vault) if line.rstrip("\r").startswith("data: ") else line for line in lines]
            new_body = "\n".join(new_lines)
            try:
                flow.response.content = new_body.encode("utf-8")
                flow.response.headers["content-length"] = str(len(flow.response.content))
            except Exception:
                pass
        else:
            try:
                decoded = json.loads(raw)
            except Exception:
                return
            if not isinstance(decoded, dict):
                return
            self._unmask_and_decode(decoded, vault)
            try:
                flow.response.content = json.dumps(decoded, ensure_ascii=False).encode("utf-8")
                flow.response.headers["content-length"] = str(len(flow.response.content))
            except Exception:
                pass

    def next_layer(self, nextlayer: Any) -> None:
        if not _HAS_PROXY_LAYERS:
            return
        current_layer = getattr(nextlayer, "layer", None)
        if current_layer is not None:
            return

        context = getattr(nextlayer, "context", None)
        if context is None:
            return

        server_addr = getattr(context.server, "address", None)
        if not server_addr or len(server_addr) < 2:
            return

        host = server_addr[0]
        if not self._is_provider_host(host):
            try:
                nextlayer.layer = _proxy_layers.TCPLayer(context, ignore=True)
                _log(f"[NEXT_LAYER] PASS-THROUGH: {host}:{server_addr[1]}")
            except Exception as exc:
                _log(f"[NEXT_LAYER] pass-through FAILED: {exc}")


_load_dotenv()

addons = [ShieldAddon()]
