import json
import os
import platform
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PROXY_PORT = 8923

def _cleanup_orphan_mitmdump() -> None:
    try:
        if platform.system().lower() != "windows":
            return
        subprocess.run(
            ["taskkill", "/f", "/im", "mitmdump.exe"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        _kill_process_on_port(PROXY_PORT)
    except Exception:
        pass


def _kill_process_on_port(port: int) -> None:
    try:
        result = subprocess.run(
            ["netstat", "-ano"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            if f":{port}" in line and "LISTENING" in line:
                parts = line.split()
                pid_str = parts[-1]
                pid = int(pid_str)
                subprocess.run(
                    ["taskkill", "/f", "/pid", str(pid)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
    except Exception:
        pass

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

MITM_CA_CER = os.path.join(os.path.expanduser("~"), ".mitmproxy", "mitmproxy-ca-cert.cer")
DISCOVERY_PATH = Path(__file__).parent / ".agent" / "detected_providers.json"
CONFIG_PATH = Path(__file__).parent / "shield_config.json"

@dataclass(frozen=True)
class ProviderDef:
    id: str
    name: str
    hosts: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()
    body_keys: tuple[str, ...] = ()

PROVIDER_REGISTRY: dict[str, ProviderDef] = {
    "openai": ProviderDef("openai", "OpenAI", ("api.openai.com",), ("/v1/chat/completions",)),
    "anthropic": ProviderDef("anthropic", "Anthropic", ("api.anthropic.com",), ("/v1/messages",)),
    "google": ProviderDef("google", "Google Gemini", ("generativelanguage.googleapis.com",), ("/v1beta/models", "/v1/models")),
    "opencode_zen": ProviderDef("opencode_zen", "OpenCode Zen", ("opencode.ai",), ("/zen/v1/responses", "/zen/v1/chat/completions")),
    "opencode_go": ProviderDef("opencode_go", "OpenCode Go", ("opencode.ai",), ("/zen/go/v1/chat/completions",)),
}

def load_config() -> dict[str, Any]:
    if not CONFIG_PATH.is_file(): return {}
    try: return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception: return {}

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

_load_dotenv()

def save_config(config: dict[str, Any]) -> None:
    CONFIG_PATH.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")

def load_provider_toggles() -> dict[str, bool]:
    return dict(load_config().get("provider_toggles", {}))

def save_provider_toggles(toggles: dict[str, bool]) -> None:
    config = load_config()
    config["provider_toggles"] = toggles
    save_config(config)

def load_user_providers() -> dict[str, ProviderDef]:
    config = load_config()
    result: dict[str, ProviderDef] = {}
    for key, entry in config.get("custom_providers", {}).items():
        if isinstance(entry, dict):
            result[key] = ProviderDef(
                id=entry.get("id", key), name=entry.get("name", key),
                hosts=tuple(entry.get("hosts", ())), paths=tuple(entry.get("paths", ())),
                body_keys=tuple(entry.get("body_keys", ()))
            )
    return result

def save_user_providers(providers: dict[str, ProviderDef]) -> None:
    config = load_config()
    config["custom_providers"] = {
        k: {"id": p.id, "name": p.name, "hosts": list(p.hosts), "paths": list(p.paths), "body_keys": list(p.body_keys)}
        for k, p in providers.items()
    }
    save_config(config)

def get_merged_registry(include_disabled: bool = False) -> dict[str, ProviderDef]:
    merged = dict(PROVIDER_REGISTRY)
    merged.update(load_user_providers())
    if not include_disabled:
        toggles = load_provider_toggles()
        merged = {k: v for k, v in merged.items() if toggles.get(k, True)}
    return merged

@dataclass
class TransparentConfig:
    api_key: str = ""
    model: str = ""
    local_api_key: str = ""
    protection_mode: str = "balanced"
    masking_strategy: str = "token_substitution"
    strict_backend: str = "reject"
    strict_local_url: str = ""
    strict_local_timeout_s: float = 30.0
    discovery_log_path: str = str(DISCOVERY_PATH)


def validate_masking_engine(strategy: str) -> str:
    try:
        engine = MaskingEngine(strategy=strategy)
    except Exception as exc:
        return f"Failed to initialise MaskingEngine (strategy={strategy!r}): {exc}"
    if strategy == "token_substitution" and engine._tokenizer is None:
        detail = engine._tokenizer_load_error or "Tokenizer could not be loaded."
        return (
            f"token_substitution strategy requires the 'transformers' package "
            f"and a downloadable tokenizer model.\n\nDetail: {detail}"
        )
    return ""


class TransparentProxyManager:
    def __init__(self) -> None:
        self._process: subprocess.Popen | None = None
        self._lock = threading.Lock()
        self.last_error: str = ""

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

            _cleanup_orphan_mitmdump()
            install_windows_ca()

            addon_path = os.path.abspath(__file__)
            mitmdump_cmd = os.path.join(os.path.dirname(sys.executable), "mitmdump.exe")
            if not os.path.exists(mitmdump_cmd):
                mitmdump_cmd = "mitmdump"

            cmd = [mitmdump_cmd, "-s", addon_path, "--mode", "local", "--listen-port", str(PROXY_PORT)]
            env = os.environ.copy()
            env["PROTECTION_MODE"] = config.protection_mode
            env["MASKING_STRATEGY"] = config.masking_strategy
            env["TRANSPARENT_DISCOVERY_LOG"] = config.discovery_log_path
            env["TRANSFORMERS_NO_ADVISORY_WARNINGS"] = "1"
            env["HF_HUB_NO_ADVISORY_WARNINGS"] = "1"
            env["HF_HUB_DISABLE_TELEMETRY"] = "1"
            env["TOKENIZERS_PARALLELISM"] = "false"
            env.pop("HTTP_PROXY", None)
            env.pop("HTTPS_PROXY", None)
            env.pop("http_proxy", None)
            env.pop("https_proxy", None)
            hf_token = os.environ.get("HF_TOKEN", "")
            if hf_token:
                env["HF_TOKEN"] = hf_token

            log_dir = Path(__file__).parent / ".agent"
            log_dir.mkdir(parents=True, exist_ok=True)
            log_path = log_dir / "mitmproxy.log"

            stderr_file = open(log_path, "a", encoding="utf-8")
            self._process = subprocess.Popen(
                cmd, env=env, stdout=subprocess.DEVNULL, stderr=stderr_file, text=True
            )

    def stop(self) -> None:
        with self._lock:
            proc = self._process
            self._process = None
        if proc and proc.poll() is None:
            proc.terminate()
            try: proc.wait(timeout=5)
            except Exception: proc.kill()
        uninstall_windows_ca()

class TransparentAddon:
    def __init__(self) -> None:
        debug_path = Path(__file__).parent / ".agent" / "addon_debug.log"
        try:
            debug_path.parent.mkdir(parents=True, exist_ok=True)
            debug_path.write_text("[INIT] TransparentAddon constructor called\n", encoding="utf-8")
        except Exception:
            pass
        strategy = os.environ.get("MASKING_STRATEGY", "token_substitution")
        try:
            self.engine = MaskingEngine(strategy=strategy)
        except Exception as exc:
            try:
                with open(debug_path, "a", encoding="utf-8") as f:
                    f.write(f"[INIT] MaskingEngine FAILED: {exc}\n")
            except Exception:
                pass
            raise
        self._vaults: dict[str, RequestVault] = {}
        self.hits = 0
        self.redirections = 0
        self.stats_path = Path(__file__).parent / ".agent" / "live_stats.json"
        self._debug_path = debug_path
        try:
            with open(debug_path, "a", encoding="utf-8") as f:
                f.write(f"[INIT] MaskingEngine OK, strategy={strategy}, tokenizer={'loaded' if self.engine._tokenizer else 'None'}\n")
        except Exception:
            pass
        self._write_stats()

    def _write_stats(self) -> None:
        try:
            self.stats_path.parent.mkdir(parents=True, exist_ok=True)
            self.stats_path.write_text(json.dumps({
                "hits": self.hits,
                "redirections": self.redirections
            }), encoding="utf-8")
        except Exception:
            pass

    def request(self, flow: Any) -> None:
        host = getattr(flow.request, "host", "").lower()
        path = getattr(flow.request, "path", "").lower()
        host_header = flow.request.headers.get("host", "").lower()
        registry = get_merged_registry()

        try:
            with open(self._debug_path, "a", encoding="utf-8") as f:
                f.write(f"[REQ] {flow.request.method} {host}{path} (Host: {host_header})\n")
        except Exception:
            pass

        matched_provider = None
        for provider in registry.values():
            host_match = any(h in host or h in host_header for h in provider.hosts)
            path_match = any(p in path for p in provider.paths)
            if host_match and path_match:
                matched_provider = provider
                break

        if matched_provider:
            self.hits += 1
            self._write_stats()

            try:
                with open(self._debug_path, "a", encoding="utf-8") as f:
                    f.write(f"[HIT] Matched provider: {matched_provider.name}\n")
            except Exception:
                pass

            if flow.request.content:
                try:
                    data = json.loads(flow.request.content.decode("utf-8"))
                    req_id = str(uuid.uuid4())
                    vault = RequestVault(request_id=req_id)

                    if "messages" in data and isinstance(data["messages"], list):
                        for msg in data["messages"]:
                            if "content" in msg and isinstance(msg["content"], str):
                                masked = self.engine.mask_message({"content": msg["content"]}, vault)
                                msg["content"] = masked.get("content", msg["content"])

                    flow.request.content = json.dumps(data).encode("utf-8")
                    flow.request.headers["content-length"] = str(len(flow.request.content))

                    self._vaults[req_id] = vault
                    flow.metadata["shield_request_id"] = req_id

                    self.redirections += 1
                    self._write_stats()

                except Exception as e:
                    print(f"[Shield] Intercept masking failure: {e}")

    def response(self, flow: Any) -> None:
        req_id = flow.metadata.get("shield_request_id")
        if req_id and req_id in self._vaults and flow.response and flow.response.content:
            try:
                vault = self._vaults.pop(req_id)
                try:
                    with open(self._debug_path, "a", encoding="utf-8") as f:
                        f.write(f"[RES] Response received, vault_entries={len(vault.reverse_map)}\n")
                except Exception:
                    pass
            except Exception:
                pass


def install_windows_ca() -> None:
    if os.path.isfile(MITM_CA_CER):
        subprocess.run(["certutil", "-addstore", "Root", MITM_CA_CER], check=False, capture_output=True)

def uninstall_windows_ca() -> None:
    if os.path.isfile(MITM_CA_CER):
        subprocess.run(["certutil", "-delstore", "Root", MITM_CA_CER], check=False, capture_output=True)

addons = [TransparentAddon()]

try:
    _dbg = Path(__file__).parent / ".agent" / "addon_debug.log"
    _dbg.parent.mkdir(parents=True, exist_ok=True)
    with open(_dbg, "a", encoding="utf-8") as _f:
        _f.write(f"[MODULE] addons list created, len={len(addons)}\n")
except Exception:
    pass
