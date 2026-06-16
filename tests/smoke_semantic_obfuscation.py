"""Smoke test for semantic_obfuscation without loading any real model.

This validates:
- Codebook load/save round-trip
- Token-level encode/decode round-trip
- Vault extension
- Diagnostics
- Bootstrap failure handling (no tokenizer)
"""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class StubTokenizer:
    def __init__(self, vocab_size=200):
        self.vocab_size = vocab_size
        self._cache = {}
        self._id_to_token = {i: f"tok_{i}" for i in range(vocab_size)}
        self._token_to_id = {v: k for k, v in self._id_to_token.items()}
        self.all_special_ids = [0, 1]
        self.name_or_path = "stub-tokenizer"

    def convert_ids_to_tokens(self, token_id):
        return self._id_to_token.get(token_id, "")

    def encode(self, text, add_special_tokens=False):
        ids = []
        for word in text.split():
            if word in self._token_to_id:
                ids.append(self._token_to_id[word])
            else:
                ids.append(self._token_to_id.get(f"tok_{abs(hash(word)) % (self.vocab_size - 10) + 10}", 0))
        return ids

    def decode(self, ids, skip_special_tokens=False, clean_up_tokenization_spaces=False):
        return " ".join(self._id_to_token.get(i, f"unk_{i}") for i in ids)


def main():
    from semantic_masking import RequestVault
    from semantic_obfuscation import (
        SemanticCodebook,
        SemanticObfuscator,
        _levenshtein,
        _token_shape_key,
    )

    print("=== _levenshtein ===")
    assert _levenshtein("kitten", "sitting") == 3
    assert _levenshtein("abc", "abc") == 0
    print("  ok")

    print("=== _token_shape_key ===")
    key = _token_shape_key("hello")
    assert key[1] == 1
    print("  ok")

    print("=== RequestVault has semantic fields ===")
    v = RequestVault(request_id="test")
    assert isinstance(v.semantic_forward, dict)
    assert isinstance(v.semantic_reverse, dict)
    assert v.semantic_tokens_processed == 0
    assert v.semantic_tokens_unmapped == 0
    print("  ok")

    print("=== SemanticCodebook diagnostics without bootstrap ===")
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "codebook.json")
        tok = StubTokenizer(vocab_size=200)
        cb = SemanticCodebook(
            tokenizer=tok,
            anchor_model_id="stub",
            level="light",
            path=path,
        )
        d = cb.diagnostics()
        assert d["enabled"] is True
        assert d["level"] == "light"
        assert d["codebook_loaded"] is False
        print("  ok")

    print("=== SemanticObfuscator: not ready without bootstrap ===")
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "codebook.json")
        tok = StubTokenizer(vocab_size=200)
        cb = SemanticCodebook(
            tokenizer=tok,
            anchor_model_id="stub",
            level="light",
            path=path,
        )
        obf = SemanticObfuscator(codebook=cb, tokenizer=tok)
        assert not obf.ready
        vault = RequestVault(request_id="t")
        msg = {"role": "user", "content": "hello world"}
        out = obf.encode_message(msg, vault)
        assert out == msg
        print("  ok")

    print("=== encode_message skips system messages by default ===")
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "codebook.json")
        tok = StubTokenizer(vocab_size=200)
        cb = SemanticCodebook(
            tokenizer=tok,
            anchor_model_id="stub",
            level="light",
            path=path,
        )
        obf = SemanticObfuscator(codebook=cb, tokenizer=tok)
        cb._record = type("R", (), {"forward": {10: 11}, "reverse": {11: 10}})()
        cb._bootstrapped = True
        vault = RequestVault(request_id="t")
        msg = {"role": "system", "content": "hello world"}
        out = obf.encode_message(msg, vault)
        assert out == msg
        assert vault.semantic_forward == {}
        print("  ok")

    print("=== encode_message encodes user messages when ready ===")
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "codebook.json")
        tok = StubTokenizer(vocab_size=200)
        forward = {10: 11, 20: 21, 30: 31}
        reverse = {v: k for k, v in forward.items()}
        cb = SemanticCodebook(
            tokenizer=tok,
            anchor_model_id="stub",
            level="light",
            path=path,
        )
        from semantic_obfuscation import CodebookRecord, CodebookStats
        cb._record = CodebookRecord(
            version=1,
            tokenizer_model_id="stub",
            anchor_model_id="stub",
            level="light",
            created_at=0.0,
            codebook_secret_salt="x",
            forward=forward,
            reverse=reverse,
            stats=CodebookStats(),
        )
        cb._bootstrapped = True
        obf = SemanticObfuscator(codebook=cb, tokenizer=tok)
        vault = RequestVault(request_id="t")
        msg = {"role": "user", "content": "tok_10 tok_20 tok_30"}
        out = obf.encode_message(msg, vault)
        assert "tok_10" not in out["content"]
        assert "tok_11" in out["content"]
        assert "tok_21" in out["content"]
        assert "tok_31" in out["content"]
        assert vault.semantic_forward[10] == 11
        assert vault.semantic_reverse[11] == 10
        print(f"  encoded: {out['content']!r}")

        decoded = obf._decode_text(out["content"], vault)
        print(f"  decoded: {decoded!r}")
        assert decoded == "tok_10 tok_20 tok_30", f"round-trip failed: {decoded!r}"
        print("  ok")

    print("=== encode_messages list-level ===")
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "codebook.json")
        tok = StubTokenizer(vocab_size=200)
        forward = {10: 11, 20: 21}
        reverse = {v: k for k, v in forward.items()}
        cb = SemanticCodebook(
            tokenizer=tok,
            anchor_model_id="stub",
            level="light",
            path=path,
        )
        from semantic_obfuscation import CodebookRecord, CodebookStats
        cb._record = CodebookRecord(
            version=1, tokenizer_model_id="stub", anchor_model_id="stub", level="light",
            created_at=0.0, codebook_secret_salt="x",
            forward=forward, reverse=reverse, stats=CodebookStats(),
        )
        cb._bootstrapped = True
        obf = SemanticObfuscator(codebook=cb, tokenizer=tok)
        vault = RequestVault(request_id="t")
        msgs = [
            {"role": "system", "content": "tok_10 tok_20"},
            {"role": "user", "content": "tok_10 tok_20"},
        ]
        out = obf.encode_messages(msgs, vault, include_system=False)
        assert out[0]["content"] == "tok_10 tok_20"
        assert "tok_11" in out[1]["content"]
        out2 = obf.encode_messages(msgs, vault, include_system=True)
        assert "tok_11" in out2[0]["content"]
        assert "tok_11" in out2[1]["content"]
        print("  ok")

    print("=== diagnostics includes timing samples ===")
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "codebook.json")
        tok = StubTokenizer(vocab_size=200)
        forward = {10: 11}
        reverse = {11: 10}
        cb = SemanticCodebook(
            tokenizer=tok, anchor_model_id="stub", level="light", path=path,
        )
        from semantic_obfuscation import CodebookRecord, CodebookStats
        cb._record = CodebookRecord(
            version=1, tokenizer_model_id="stub", anchor_model_id="stub", level="light",
            created_at=0.0, codebook_secret_salt="x",
            forward=forward, reverse=reverse, stats=CodebookStats(),
        )
        cb._bootstrapped = True
        obf = SemanticObfuscator(codebook=cb, tokenizer=tok)
        vault = RequestVault(request_id="t")
        for _ in range(10):
            obf.encode_message({"role": "user", "content": "tok_10"}, vault)
        d = obf.diagnostics()
        assert d["codebook_loaded"] is True
        assert d["last_encode_ms_p50"] >= 0
        assert d["last_encode_ms_p99"] >= 0
        print("  ok")

    print("=== CodebookRecord serialization round-trip ===")
    from semantic_obfuscation import CodebookRecord, CodebookStats
    rec = CodebookRecord(
        version=1,
        tokenizer_model_id="stub",
        anchor_model_id="stub",
        level="standard",
        created_at=12345.0,
        codebook_secret_salt="abc",
        forward={1: 2, 3: 4},
        reverse={2: 1, 4: 3},
        stats=CodebookStats(vocab_size=200, anchored_tokens=190, mean_cosine_similarity=0.95),
    )
    data = rec.to_dict()
    rec2 = CodebookRecord.from_dict(data)
    assert rec2.forward == rec.forward
    assert rec2.reverse == rec.reverse
    assert rec2.stats.mean_cosine_similarity == 0.95
    print("  ok")

    print("ALL SMOKE TESTS PASSED")


if __name__ == "__main__":
    main()
