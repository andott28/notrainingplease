"""Smoke test for the semantic_obfuscation integration with the pulled
transparent-mode (local-proxy mitmdump) architecture.

The main mode for the app, after the upstream pivot, is:

  run.py / gui.py
    -> App._toggle_shield
    -> TransparentProxyManager.start(config)        # spawns mitmdump
        -> mitmdump -s transparent_mode.py --mode local --listen-port 8923
            -> TransparentAddon().request(flow)     # intercept + mask + obfuscate
            -> TransparentAddon().response(flow)    # unmask + optional decode

These tests exercise that path against stubbed flow objects, with a stub
`MaskingEngine` that mirrors the pulled engine's `mask_message` contract,
and a stub tokenizer that lets the obfuscator's codebook be primed without
loading the real Qwen model.
"""
import json
import os
import sys
import tempfile
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class StubTokenizer:
    def __init__(self, vocab_size=200):
        self.vocab_size = vocab_size
        self._id_to_token = {i: f"tok_{i}" for i in range(vocab_size)}
        self._token_to_id = {v: k for k, v in self._id_to_token.items()}
        self.all_special_ids = [0, 1]
        self.name_or_path = "stub"

    def convert_ids_to_tokens(self, token_id):
        return self._id_to_token.get(token_id, "")

    def encode(self, text, add_special_tokens=False):
        return [self._token_to_id.get(w, 99) for w in text.split()]

    def decode(self, ids, skip_special_tokens=False, clean_up_tokenization_spaces=False):
        return " ".join(self._id_to_token.get(i, f"unk_{i}") for i in ids)


class StubMaskingEngine:
    """Mirrors the `MaskingEngine` contract used by the pulled `request` hook:
    `mask_message({"content": str}, vault) -> {"content": str}`. Tracks the
    `get_tokenizer` / `tokenizer_loaded` accessors the obfuscator relies on."""

    def __init__(self):
        self._tokenizer = None

    def mask_message(self, message, vault, entity_types=None):
        out = dict(message)
        if isinstance(out.get("content"), str):
            out["content"] = "[M] " + out["content"]
        return out

    def unmask_response(self, response_body, vault):
        # Mirror the real engine's behavior: it walks choices[*].message.content
        # and applies vault.reverse_map. Stub just removes our [M] prefix.
        for choice in response_body.get("choices", []) if isinstance(response_body, dict) else []:
            message = choice.get("message") if isinstance(choice, dict) else None
            if not isinstance(message, dict):
                continue
            content = message.get("content")
            if isinstance(content, str) and content.startswith("[M] "):
                message["content"] = content[4:]

    def get_tokenizer(self):
        return self._tokenizer

    def tokenizer_loaded(self):
        return self._tokenizer is not None


def make_obfuscator(tmp_path):
    from semantic_obfuscation import (
        CodebookRecord,
        CodebookStats,
        SemanticCodebook,
        SemanticObfuscator,
    )
    tok = StubTokenizer(vocab_size=200)
    forward = {10: 11, 20: 21, 30: 31}
    reverse = {v: k for k, v in forward.items()}
    cb = SemanticCodebook(
        tokenizer=tok, anchor_model_id="stub", level="light",
        path=os.path.join(tmp_path, "cb.json"),
    )
    cb._record = CodebookRecord(
        version=1, tokenizer_model_id="stub", anchor_model_id="stub", level="light",
        created_at=0.0, codebook_secret_salt="x",
        forward=forward, reverse=reverse, stats=CodebookStats(),
    )
    cb._bootstrapped = True
    return SemanticObfuscator(codebook=cb, tokenizer=tok), cb


class StubFlow:
    """Mirrors the relevant parts of a mitmproxy flow that
    `TransparentAddon.request` / `.response` read and write."""

    def __init__(self, host, path, body, headers=None):
        self.request = SimpleNamespace(
            method="POST",
            host=host,
            path=path,
            content=json.dumps(body).encode("utf-8"),
            headers=headers or {"content-type": "application/json"},
        )
        self.response = None
        self.metadata: dict = {}


def make_addon(tmp_path, sem_enabled=True, include_system=False, decode_response=False):
    """Construct a `TransparentAddon` instance without spawning mitmdump.
    We bypass `__init__` and wire the attributes manually, since `__init__`
    writes to a debug log and constructs the real MaskingEngine."""

    obf, cb = make_obfuscator(tmp_path)
    engine = StubMaskingEngine()
    if sem_enabled:
        # The obfuscator has its own tokenizer reference, so engine doesn't
        # need to share. We just need the engine to be present.
        pass

    from transparent_mode import TransparentAddon

    addon = TransparentAddon.__new__(TransparentAddon)
    addon.engine = engine
    addon._vaults = {}
    addon.hits = 0
    addon.redirections = 0
    addon._debug_path = os.path.join(tmp_path, "addon_debug.log")
    addon.stats_path = os.path.join(tmp_path, "live_stats.json")
    addon.obfuscator = obf if sem_enabled else None

    if include_system:
        os.environ["SEMANTIC_OBFUSCATION_INCLUDE_SYSTEM"] = "true"
    else:
        os.environ["SEMANTIC_OBFUSCATION_INCLUDE_SYSTEM"] = "false"
    if decode_response:
        os.environ["SEMANTIC_OBFUSCATION_DECODE_RESPONSE"] = "true"
    else:
        os.environ["SEMANTIC_OBFUSCATION_DECODE_RESPONSE"] = "false"

    return addon, obf


def main():
    from semantic_masking import RequestVault

    with tempfile.TemporaryDirectory() as tmp:
        print("=== addon.request masks + obfuscates detected LLM traffic ===")
        addon, _ = make_addon(tmp, sem_enabled=True, include_system=False)
        body = {
            "model": "x",
            "messages": [
                {"role": "system", "content": "tok_10"},
                {"role": "user", "content": "tok_20 tok_30"},
            ],
        }
        flow = StubFlow("api.openai.com", "/v1/chat/completions", body)
        addon.request(flow)
        sent = json.loads(flow.request.content.decode("utf-8"))
        user_msg = next(m for m in sent["messages"] if m["role"] == "user")
        sys_msg = next(m for m in sent["messages"] if m["role"] == "system")
        assert "tok_21" in user_msg["content"], f"user not obfuscated: {user_msg['content']!r}"
        assert "tok_31" in user_msg["content"], f"user not obfuscated: {user_msg['content']!r}"
        assert "tok_21" in user_msg["content"] or "[M]" in user_msg["content"], (
            f"neither mask nor obfuscation ran: {user_msg['content']!r}"
        )
        assert "tok_10" in sys_msg["content"], f"system should NOT be obfuscated by default: {sys_msg['content']!r}"
        assert "[M]" in sys_msg["content"], f"system should be masked: {sys_msg['content']!r}"
        print(f"  user-> {user_msg['content']!r}")
        print(f"  sys -> {sys_msg['content']!r}")
        assert addon.hits == 1
        assert addon.redirections == 1
        req_id = flow.metadata["shield_request_id"]
        assert req_id in addon._vaults
        print("  ok")

        print("=== addon.request skips obfuscation when obfuscator is None ===")
        addon, _ = make_addon(tmp, sem_enabled=False)
        body = {
            "model": "x",
            "messages": [{"role": "user", "content": "tok_20 tok_30"}],
        }
        flow = StubFlow("api.openai.com", "/v1/chat/completions", body)
        addon.request(flow)
        sent = json.loads(flow.request.content.decode("utf-8"))
        user_msg = sent["messages"][0]
        assert user_msg["content"] == "[M] tok_20 tok_30"
        assert "tok_21" not in user_msg["content"]
        print("  ok")

        print("=== addon.request: non-registered provider not touched ===")
        addon, _ = make_addon(tmp, sem_enabled=True)
        body = {
            "model": "x",
            "messages": [{"role": "user", "content": "tok_20"}],
        }
        flow = StubFlow("example.com", "/anything", body)
        addon.request(flow)
        assert addon.hits == 0
        assert flow.request.content == json.dumps(body).encode("utf-8")
        print("  ok")

        print("=== addon.request: GET matched but no content to mask ===")
        addon, _ = make_addon(tmp, sem_enabled=True)
        body = {"messages": [{"role": "user", "content": "tok_20"}]}
        flow = StubFlow("api.openai.com", "/v1/chat/completions", body)
        flow.request.method = "GET"
        flow.request.content = None
        addon.request(flow)
        assert addon.hits == 1
        assert addon.redirections == 0
        print("  ok")

        print("=== addon.request: include_system obfuscates system too ===")
        addon, _ = make_addon(tmp, sem_enabled=True, include_system=True)
        body = {
            "model": "x",
            "messages": [
                {"role": "system", "content": "tok_10 tok_20"},
                {"role": "user", "content": "tok_30"},
            ],
        }
        flow = StubFlow("api.openai.com", "/v1/chat/completions", body)
        addon.request(flow)
        sent = json.loads(flow.request.content.decode("utf-8"))
        sys_msg = next(m for m in sent["messages"] if m["role"] == "system")
        usr_msg = next(m for m in sent["messages"] if m["role"] == "user")
        assert "tok_11" in sys_msg["content"], f"system not obfuscated: {sys_msg['content']!r}"
        assert "tok_21" in sys_msg["content"], f"system not obfuscated: {sys_msg['content']!r}"
        assert "tok_31" in usr_msg["content"]
        print(f"  sys -> {sys_msg['content']!r}")
        print("  ok")
        os.environ["SEMANTIC_OBFUSCATION_INCLUDE_SYSTEM"] = "false"

        print("=== addon.response unmask + decode the response ===")
        addon, _ = make_addon(tmp, sem_enabled=True, decode_response=True)
        body = {
            "model": "x",
            "messages": [{"role": "user", "content": "tok_20"}],
        }
        flow = StubFlow("api.openai.com", "/v1/chat/completions", body)
        addon.request(flow)
        req_id = flow.metadata["shield_request_id"]
        response_dict = {
            "choices": [
                {"message": {"role": "assistant", "content": "[M] assistant reply with tok_21 reference"}}
            ]
        }
        flow.response = SimpleNamespace(
            headers={"content-type": "application/json", "content-length": "0"},
            content=json.dumps(response_dict).encode("utf-8"),
        )
        addon.response(flow)
        restored = json.loads(flow.response.content.decode("utf-8"))
        assistant = restored["choices"][0]["message"]["content"]
        assert "[M]" not in assistant, f"unmask did not strip [M]: {assistant!r}"
        assert "tok_21" not in assistant, f"semantic decode did not reverse obfuscation: {assistant!r}"
        assert "tok_20" in assistant, f"semantic decode should restore original token: {assistant!r}"
        assert req_id not in addon._vaults, "vault should be popped after response"
        print(f"  assistant-> {assistant!r}")
        print("  ok")

        print("=== addon.response without decode_response leaves response alone ===")
        addon, _ = make_addon(tmp, sem_enabled=True, decode_response=False)
        body = {
            "model": "x",
            "messages": [{"role": "user", "content": "tok_20"}],
        }
        flow = StubFlow("api.openai.com", "/v1/chat/completions", body)
        addon.request(flow)
        response_dict = {
            "choices": [
                {"message": {"role": "assistant", "content": "[M] assistant reply"}}
            ]
        }
        flow.response = SimpleNamespace(
            headers={"content-type": "application/json", "content-length": "0"},
            content=json.dumps(response_dict).encode("utf-8"),
        )
        addon.response(flow)
        restored = json.loads(flow.response.content.decode("utf-8"))
        assistant = restored["choices"][0]["message"]["content"]
        assert "[M]" not in assistant, "unmask should still strip [M]"
        print(f"  assistant-> {assistant!r}")
        print("  ok")

        print("=== addon.response on empty/non-JSON content is a no-op ===")
        addon, _ = make_addon(tmp, sem_enabled=True)
        body = {"messages": [{"role": "user", "content": "x"}]}
        flow = StubFlow("api.openai.com", "/v1/chat/completions", body)
        addon.request(flow)
        flow.response = SimpleNamespace(
            headers={"content-type": "text/plain", "content-length": "5"},
            content=b"hello",
        )
        addon.response(flow)
        assert flow.response.content == b"hello"
        print("  ok")

        print("=== env var passthrough in TransparentProxyManager.start ===")
        from transparent_mode import TransparentConfig, TransparentProxyManager
        cfg = TransparentConfig(
            semantic_obfuscation=True,
            semantic_obfuscation_level="aggressive",
            semantic_obfuscation_anchor_model="anchor-x",
            semantic_obfuscation_codebook_path="/tmp/cb.json",
            semantic_obfuscation_include_system=True,
            semantic_obfuscation_load_anchor_body=False,
            semantic_obfuscation_decode_response=True,
        )
        captured = {}

        class FakePopen:
            def __init__(self, cmd, env, **kwargs):
                captured["cmd"] = cmd
                captured["env"] = env

            def poll(self):
                return None

        import transparent_mode as tm
        original_popen = tm.subprocess.Popen
        tm.subprocess.Popen = FakePopen
        original_install = tm.install_windows_ca
        tm.install_windows_ca = lambda: None
        original_cleanup = tm._cleanup_orphan_mitmdump
        tm._cleanup_orphan_mitmdump = lambda: None
        try:
            mgr = TransparentProxyManager()
            try:
                mgr.start(cfg)
            except Exception:
                pass
        finally:
            tm.subprocess.Popen = original_popen
            tm.install_windows_ca = original_install
            tm._cleanup_orphan_mitmdump = original_cleanup

        env = captured.get("env", {})
        assert env.get("SEMANTIC_OBFUSCATION") == "true", env
        assert env.get("SEMANTIC_OBFUSCATION_LEVEL") == "aggressive", env
        assert env.get("SEMANTIC_OBFUSCATION_ANCHOR_MODEL") == "anchor-x", env
        assert env.get("SEMANTIC_OBFUSCATION_CODEBOOK_PATH") == "/tmp/cb.json", env
        assert env.get("SEMANTIC_OBFUSCATION_INCLUDE_SYSTEM") == "true", env
        assert env.get("SEMANTIC_OBFUSCATION_LOAD_ANCHOR_BODY") == "false", env
        assert env.get("SEMANTIC_OBFUSCATION_DECODE_RESPONSE") == "true", env
        print("  ok")

        print("=== TransparentConfig default values are backward-compatible ===")
        from transparent_mode import TransparentConfig
        c = TransparentConfig()
        assert c.semantic_obfuscation is False
        assert c.semantic_obfuscation_level == "standard"
        assert c.semantic_obfuscation_include_system is False
        assert c.semantic_obfuscation_load_anchor_body is True
        assert c.semantic_obfuscation_decode_response is False
        print("  ok")

        print("=== addon.response handles SSE streaming response ===")
        addon, _ = make_addon(tmp, sem_enabled=True, decode_response=True)
        body = {
            "model": "x",
            "messages": [{"role": "user", "content": "tok_20"}],
        }
        flow = StubFlow("api.openai.com", "/v1/chat/completions", body)
        addon.request(flow)
        req_id = flow.metadata["shield_request_id"]
        assert flow.metadata.get("shield_is_streaming") is False
        sse_lines = [
            'data: {"id":"cmpl-1","choices":[{"index":0,"delta":{"role":"assistant","content":"[M] Hello"}}]}',
            'data: {"id":"cmpl-1","choices":[{"index":0,"delta":{"content":" tok_21 world"}}]}',
            "data: [DONE]",
        ]
        sse_body = "\n".join(sse_lines)
        flow.response = SimpleNamespace(
            headers={"content-type": "text/event-stream"},
            content=sse_body.encode("utf-8"),
        )
        flow.metadata["shield_is_streaming"] = True
        addon.response(flow)
        restored = flow.response.content.decode("utf-8")
        assert "[M]" not in restored, f"SSE unmask failed: {restored!r}"
        assert "tok_21" not in restored, f"SSE decode failed: {restored!r}"
        assert "tok_20" in restored, f"SSE should restore original: {restored!r}"
        assert "[DONE]" in restored, "SSE [DONE] marker must be preserved"
        print(f"  SSE response processed: {restored[:80]}...")
        print("  ok")

        print("=== addon.request sets streaming flag ===")
        addon, _ = make_addon(tmp, sem_enabled=True)
        body = {
            "model": "x",
            "messages": [{"role": "user", "content": "tok_20"}],
            "stream": True,
        }
        flow = StubFlow("api.openai.com", "/v1/chat/completions", body)
        addon.request(flow)
        assert flow.metadata.get("shield_is_streaming") is True
        print("  ok")

        print("=== addon.request non-streaming sets flag false ===")
        addon, _ = make_addon(tmp, sem_enabled=True)
        body = {
            "model": "x",
            "messages": [{"role": "user", "content": "tok_20"}],
        }
        flow = StubFlow("api.openai.com", "/v1/chat/completions", body)
        addon.request(flow)
        assert flow.metadata.get("shield_is_streaming") is False
        print("  ok")

    print("ALL TRANSPARENT-MODE INTEGRATION SMOKE TESTS PASSED")


if __name__ == "__main__":
    main()
