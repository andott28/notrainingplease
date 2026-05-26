import builtins
import json
import hashlib
import keyword
import os
import re
from dataclasses import dataclass, field
from typing import Any


PRIORITY_ORDER = [
    "URL",
    "EMAIL",
    "WINDOWS_PATH",
    "UNIX_PATH",
    "IPV4",
    "UUID",
    "JWT",
    "HEX_TOKEN",
    "HOSTNAME",
    "SCREAMING_SNAKE",
    "snake_case",
    "camelCase",
    "PascalCase",
]

HIGH_RISK_ENTITY_TYPES = set(PRIORITY_ORDER)
IDENTIFIER_ENTITY_TYPES = {"SCREAMING_SNAKE", "snake_case", "camelCase", "PascalCase"}
SECRETISH_ENTITY_TYPES = {"JWT", "HEX_TOKEN", "EMAIL", "URL", "WINDOWS_PATH", "UNIX_PATH"}
TOKEN_CIPHER_DEFAULT_MODEL_ID = "Qwen/Qwen2.5-Coder-1.5B-Instruct"


def _build_protected_identifiers() -> set[str]:
    static_identifiers = {
        "self",
        "cls",
        "args",
        "kwargs",
        "__init__",
        "__repr__",
        "__str__",
        "__len__",
        "__call__",
        "__enter__",
        "__exit__",
        "ValueError",
        "TypeError",
        "RuntimeError",
        "KeyError",
        "IndexError",
        "AttributeError",
        "NotImplementedError",
        "StopIteration",
        "OverflowError",
        "isinstance",
        "issubclass",
        "hasattr",
        "getattr",
        "setattr",
        "delattr",
        "defaultdict",
        "OrderedDict",
        "namedtuple",
        "dataclass",
        "abstractmethod",
        "classmethod",
        "staticmethod",
        "property",
        "getElementById",
        "addEventListener",
        "querySelector",
        "querySelectorAll",
        "setTimeout",
        "setInterval",
        "clearTimeout",
        "clearInterval",
        "parseInt",
        "parseFloat",
        "isNaN",
        "isFinite",
        "Promise",
        "async",
        "await",
    }
    dynamic_identifiers = set(keyword.kwlist) | set(dir(builtins))
    return static_identifiers | dynamic_identifiers


PROTECTED_IDENTIFIERS = _build_protected_identifiers()


@dataclass
class MatchSpan:
    start: int
    end: int
    value: str
    entity_type: str
    priority: int


@dataclass
class RequestVault:
    request_id: str
    forward_map: dict[str, str] = field(default_factory=dict)
    reverse_map: dict[str, str] = field(default_factory=dict)
    entity_metadata: dict[str, dict[str, Any]] = field(default_factory=dict)
    timings_ms: dict[str, float] = field(default_factory=dict)
    alias_counters: dict[str, int] = field(default_factory=dict)
    masked_counts: dict[str, int] = field(default_factory=dict)
    token_forward_map: dict[int, int] = field(default_factory=dict)
    token_reverse_map: dict[int, int] = field(default_factory=dict)


class MaskingEngine:
    def __init__(self, strategy: str | None = None) -> None:
        self._patterns = self._build_patterns()
        self._strategy = (strategy or "opaque").strip().lower()
        self._tokenizer = None
        self._tokenizer_model_id = os.environ.get("TOKEN_CIPHER_MODEL_ID", TOKEN_CIPHER_DEFAULT_MODEL_ID).strip()
        self._tokenizer_load_error = ""
        self._tokenizer_loaded = False
        self._token_cipher_secret = "local-default-secret"
        self._token_bucket_cache: dict[tuple[int, int, int], list[int]] = {}
        self._token_class_bucket_cache: dict[tuple[int, int], list[int]] = {}
        self._token_identifier_bucket_cache: dict[tuple[int, int, int], list[int]] = {}
        self._token_identifier_class_bucket_cache: dict[tuple[int, int], list[int]] = {}
        self._token_global_candidates: list[int] = []
        self._token_identifier_global_candidates: list[int] = []
        self._token_meta: dict[int, tuple[int, int, int]] = {}
        self._token_clean_length_cache: dict[int, int] = {}
        self._token_forward_cache: dict[int, int] = {}
        self._token_reverse_cache: dict[int, int] = {}
        self._span_substitution_cache: dict[str, str] = {}
        if self._strategy == "token_substitution":
            self._ensure_tokenizer_loaded()

    def mask_message(
        self,
        message: dict[str, Any],
        vault: RequestVault,
        entity_types: set[str] | None = None,
    ) -> dict[str, Any]:
        out = dict(message)
        content = out.get("content")
        if isinstance(content, str):
            out["content"] = self._mask_text(content, vault, entity_types=entity_types)
        elif isinstance(content, list):
            new_parts = []
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
                    cp = dict(part)
                    cp["text"] = self._mask_text(cp["text"], vault, entity_types=entity_types)
                    new_parts.append(cp)
                else:
                    new_parts.append(part)
            out["content"] = new_parts
        return out

    def summarize_messages_entities(
        self,
        messages: list[dict[str, Any]],
        entity_types: set[str] | None = None,
    ) -> dict[str, int]:
        allowed = entity_types or HIGH_RISK_ENTITY_TYPES
        counts = {entity: 0 for entity in PRIORITY_ORDER}
        for message in messages:
            self._accumulate_message_entities(message, counts, allowed)
        return {entity: value for entity, value in counts.items() if value > 0}

    def diagnostics(self) -> dict[str, Any]:
        vocab_size = int(getattr(self._tokenizer, "vocab_size", 0) or 0) if self._tokenizer is not None else 0
        return {
            "tokenizer_model": self._tokenizer_model_id,
            "vocab_size": vocab_size,
            "candidate_pool_size": len(self._token_global_candidates),
            "span_substitution_cache_size": len(self._span_substitution_cache),
            "protected_identifiers_count": len(PROTECTED_IDENTIFIERS),
            "strategy": self._strategy,
            "token_identifier_global_candidates": len(self._token_identifier_global_candidates),
        }

    def unmask_response(self, response_body: dict[str, Any], vault: RequestVault) -> None:
        if not vault.reverse_map:
            return
        choices = response_body.get("choices")
        if not isinstance(choices, list):
            return
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            message = choice.get("message")
            if not isinstance(message, dict):
                continue
            content = message.get("content")
            if isinstance(content, str):
                message["content"] = self._unmask_text(content, vault)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
                        part["text"] = self._unmask_text(part["text"], vault)
            tool_calls = message.get("tool_calls")
            if isinstance(tool_calls, list):
                for tc in tool_calls:
                    if not isinstance(tc, dict):
                        continue
                    fn = tc.get("function")
                    if isinstance(fn, dict) and isinstance(fn.get("arguments"), str):
                        fn["arguments"] = self._unmask_tool_arguments(fn["arguments"], vault)

    def _accumulate_message_entities(
        self,
        message: dict[str, Any],
        counts: dict[str, int],
        allowed: set[str],
    ) -> None:
        content = message.get("content")
        if isinstance(content, str):
            for span in self._resolve_overlaps(self._scan_spans(content, allowed)):
                counts[span.entity_type] += 1
            return
        if isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
                    for span in self._resolve_overlaps(self._scan_spans(part["text"], allowed)):
                        counts[span.entity_type] += 1

    def _mask_text(
        self,
        text: str,
        vault: RequestVault,
        entity_types: set[str] | None = None,
    ) -> str:
        allowed = entity_types or HIGH_RISK_ENTITY_TYPES
        spans = self._scan_spans(text, allowed)
        accepted = self._resolve_overlaps(spans)
        if not accepted:
            return text
        result = text
        for span in sorted(accepted, key=lambda s: s.start, reverse=True):
            alias = vault.forward_map.get(span.value)
            if alias is None:
                alias = self._alias_for(span.value, span.entity_type, text, vault)
                vault.forward_map[span.value] = alias
                vault.reverse_map[alias] = span.value
                vault.entity_metadata[span.value] = {"type": span.entity_type, "alias": alias}
            vault.masked_counts[span.entity_type] = vault.masked_counts.get(span.entity_type, 0) + 1
            result = result[: span.start] + alias + result[span.end :]
        return result

    def _unmask_text(self, text: str, vault: RequestVault) -> str:
        if not vault.reverse_map:
            return text
        keys = sorted(vault.reverse_map.keys(), key=len, reverse=True)
        rx = re.compile(r"(" + "|".join(re.escape(k) for k in keys) + r")")
        return rx.sub(lambda m: vault.reverse_map[m.group(0)], text)

    def _unmask_tool_arguments(self, arguments: str, vault: RequestVault) -> str:
        try:
            parsed = json.loads(arguments)
        except Exception:
            return self._unmask_text(arguments, vault)
        hydrated = self._unmask_json_values(parsed, vault)
        return json.dumps(hydrated, ensure_ascii=True)

    def _unmask_json_values(self, value: Any, vault: RequestVault) -> Any:
        if isinstance(value, str):
            return self._unmask_text(value, vault)
        if isinstance(value, list):
            return [self._unmask_json_values(item, vault) for item in value]
        if isinstance(value, dict):
            return {k: self._unmask_json_values(v, vault) for k, v in value.items()}
        return value

    def _scan_spans(self, text: str, allowed: set[str]) -> list[MatchSpan]:
        spans: list[MatchSpan] = []
        literal_ranges = self._placeholder_literal_ranges(text)
        for idx, entity in enumerate(PRIORITY_ORDER):
            if entity not in allowed:
                continue
            rx = self._patterns[entity]
            for match in rx.finditer(text):
                if self._overlaps_ranges(match.start(), match.end(), literal_ranges):
                    continue
                value = match.group(0)
                if entity in IDENTIFIER_ENTITY_TYPES and value in PROTECTED_IDENTIFIERS:
                    continue
                spans.append(
                    MatchSpan(
                        start=match.start(),
                        end=match.end(),
                        value=value,
                        entity_type=entity,
                        priority=idx,
                    )
                )
        return spans

    def _placeholder_literal_ranges(self, text: str) -> list[tuple[int, int]]:
        ranges: list[tuple[int, int]] = []
        for match in re.finditer(r"@@[A-Z_]+_\d{4}@@", text):
            ranges.append((match.start(), match.end()))
        return ranges

    def _overlaps_ranges(self, start: int, end: int, ranges: list[tuple[int, int]]) -> bool:
        for r_start, r_end in ranges:
            if not (end <= r_start or start >= r_end):
                return True
        return False

    def _resolve_overlaps(self, spans: list[MatchSpan]) -> list[MatchSpan]:
        ordered = sorted(spans, key=lambda s: (s.start, s.priority, -(s.end - s.start)))
        accepted: list[MatchSpan] = []
        occupied: list[tuple[int, int]] = []
        for span in ordered:
            overlap = False
            for start, end in occupied:
                if not (span.end <= start or span.start >= end):
                    overlap = True
                    break
            if overlap:
                continue
            accepted.append(span)
            occupied.append((span.start, span.end))
        return accepted

    def _alias_for(self, value: str, entity_type: str, source_text: str, vault: RequestVault) -> str:
        if self._strategy == "token_substitution":
            try:
                return self._token_substitute_value(value, entity_type, source_text, vault)
            except RuntimeError as exc:
                if self._is_unrecoverable_token_substitution_error(exc):
                    raise
        placeholder_tag = self._placeholder_tag(entity_type)
        while True:
            next_id = vault.alias_counters.get(placeholder_tag, 0) + 1
            vault.alias_counters[placeholder_tag] = next_id
            alias = f"@@{placeholder_tag}_{next_id:04d}@@"
            if alias not in source_text and alias not in vault.reverse_map:
                return alias

    def _is_unrecoverable_token_substitution_error(self, exc: RuntimeError) -> bool:
        message = str(exc)
        if "requires TOKEN_CIPHER_MODEL_ID" in message:
            return True
        return False

    def _ensure_tokenizer_loaded(self) -> None:
        if self._tokenizer_loaded:
            return
        self._tokenizer_loaded = True
        model_id = self._tokenizer_model_id
        if not model_id:
            self._tokenizer = None
            return
        try:
            from transformers import AutoTokenizer

            tokenizer = AutoTokenizer.from_pretrained(model_id, use_fast=True, trust_remote_code=True)
            self._tokenizer = tokenizer
            self._token_cipher_secret = f"{model_id}-local-cipher"
            self._token_bucket_cache = {}
            self._token_class_bucket_cache = {}
            self._token_identifier_bucket_cache = {}
            self._token_identifier_class_bucket_cache = {}
            self._token_global_candidates = []
            self._token_identifier_global_candidates = []
            self._token_meta = {}
            self._token_clean_length_cache = {}
            self._token_forward_cache = {}
            self._token_reverse_cache = {}
            self._span_substitution_cache = {}
            self._tokenizer_load_error = ""
            self._build_token_buckets()
            if not self._token_global_candidates:
                self._tokenizer = None
                self._tokenizer_load_error = f"Tokenizer {model_id} did not produce usable candidates."
        except Exception as exc:
            self._tokenizer = None
            self._tokenizer_load_error = f"{type(exc).__name__}: {exc}"

    def _build_token_buckets(self) -> None:
        if self._tokenizer is None:
            return
        special_ids = set(getattr(self._tokenizer, "all_special_ids", []) or [])
        vocab_size = int(getattr(self._tokenizer, "vocab_size", 0) or 0)
        for token_id in range(vocab_size):
            if token_id in special_ids:
                continue
            token = self._tokenizer.convert_ids_to_tokens(token_id)
            if not isinstance(token, str) or not token:
                continue
            if not self._is_allowed_token(token):
                continue
            token_key = self._token_shape_key(token)
            self._token_meta[token_id] = token_key
            self._token_bucket_cache.setdefault(token_key, []).append(token_id)
            class_key = (token_key[0], token_key[1])
            self._token_class_bucket_cache.setdefault(class_key, []).append(token_id)
            self._token_global_candidates.append(token_id)
            clean = token.lstrip("▁Ġ")
            self._token_clean_length_cache[token_id] = len(clean)
            if self._is_code_identifier_token(clean):
                self._token_identifier_bucket_cache.setdefault(token_key, []).append(token_id)
                self._token_identifier_class_bucket_cache.setdefault(class_key, []).append(token_id)
                self._token_identifier_global_candidates.append(token_id)

    def _is_allowed_token(self, token: str) -> bool:
        clean = token.lstrip("▁Ġ")
        if not clean:
            return False
        if "<|" in clean or "|>" in clean:
            return False
        if any(ord(ch) < 32 for ch in clean):
            return False
        if re.search(r"[^A-Za-z0-9._\-/:\\@#'\"$%*+!?=~|&^<>(),;{}\[\]]", clean):
            return False
        return True

    def _is_code_identifier_token(self, clean_token: str) -> bool:
        if not clean_token:
            return False
        if not (clean_token[0].isalpha() or clean_token[0] == "_"):
            return False
        return all(ch.isalnum() or ch == "_" for ch in clean_token)

    def _token_shape_key(self, token: str) -> tuple[int, int, int]:
        lead_space = 1 if token.startswith("▁") or token.startswith("Ġ") else 0
        clean = token.lstrip("▁Ġ")
        if clean.isalpha():
            cls = 1
        elif clean.isdigit():
            cls = 2
        elif clean and all(ch in "._-/:\\@#" for ch in clean):
            cls = 3
        elif clean and clean.isalnum():
            cls = 4
        else:
            cls = 5
        clean_len = len(clean)
        length_bucket = clean_len if clean_len <= 16 else 16 + (clean_len // 4)
        return (lead_space, cls, length_bucket)

    def _token_substitute_value(self, value: str, entity_type: str, source_text: str, vault: RequestVault) -> str:
        cached_substituted = self._span_substitution_cache.get(value)
        if cached_substituted is not None:
            if cached_substituted in source_text or cached_substituted in vault.reverse_map:
                raise RuntimeError("Token substitution produced a colliding output span.")
            return cached_substituted
        if self._tokenizer is None:
            load_detail = self._tokenizer_load_error or "Tokenizer could not be loaded."
            raise RuntimeError(
                "MASKING_STRATEGY=token_substitution requires TOKEN_CIPHER_MODEL_ID and a loadable tokenizer. "
                f"Model={self._tokenizer_model_id}. Detail={load_detail}"
            )
        try:
            token_ids = self._tokenizer.encode(value, add_special_tokens=False)
        except Exception as exc:
            raise RuntimeError(f"Token substitution failed while encoding source value. Model={self._tokenizer_model_id}.") from exc
        if not token_ids:
            raise RuntimeError(f"Token substitution received an empty token sequence. Model={self._tokenizer_model_id}.")
        mapped_ids: list[int] = []
        for token_id in token_ids:
            source_token_len = self._token_clean_length_from_id(token_id)
            mapped_ids.append(self._map_token_id(token_id, entity_type, source_token_len, vault))
        try:
            substituted = self._tokenizer.decode(mapped_ids, skip_special_tokens=False, clean_up_tokenization_spaces=False)
        except Exception as exc:
            raise RuntimeError(
                f"Token substitution failed while decoding mapped token ids. Model={self._tokenizer_model_id}."
            ) from exc
        if not substituted:
            raise RuntimeError(f"Token substitution produced an empty string. Model={self._tokenizer_model_id}.")
        if substituted == value:
            raise RuntimeError("Token substitution produced identity output for a sensitive span.")
        if substituted in source_text or substituted in vault.reverse_map:
            raise RuntimeError("Token substitution produced a colliding output span.")
        self._span_substitution_cache[value] = substituted
        return substituted

    def _map_token_id(self, source_id: int, entity_type: str, source_token_len: int, vault: RequestVault) -> int:
        global_existing = self._token_forward_cache.get(source_id)
        if global_existing is not None:
            vault.token_forward_map[source_id] = global_existing
            vault.token_reverse_map[global_existing] = source_id
            return global_existing

        existing = vault.token_forward_map.get(source_id)
        if existing is not None:
            return existing

        global_candidates = self._global_candidates_for_entity(entity_type)
        candidates = self._candidate_token_ids(source_id, entity_type)
        if not candidates:
            raise RuntimeError(f"Token substitution has no candidate token ids for mapping. Model={self._tokenizer_model_id}.")
        try:
            return self._select_deterministic_candidate(source_id, candidates, vault, source_token_len)
        except RuntimeError:
            if candidates is not global_candidates:
                return self._select_deterministic_candidate(source_id, global_candidates, vault, source_token_len)
            raise

    def _filter_candidates_by_length_and_collision(
        self,
        source_id: int,
        candidates: list[int],
        vault: RequestVault,
        source_token_len: int,
    ) -> list[int]:
        filtered: list[int] = []
        for candidate_id in candidates:
            if candidate_id == source_id:
                continue
            if candidate_id in vault.token_reverse_map:
                continue
            if candidate_id in self._token_reverse_cache and self._token_reverse_cache[candidate_id] != source_id:
                continue
            candidate_len = self._token_clean_length_from_id(candidate_id)
            if not self._is_length_compatible(source_token_len, candidate_len):
                continue
            filtered.append(candidate_id)
        return filtered

    def _select_deterministic_candidate(
        self, source_id: int, candidates: list[int], vault: RequestVault, source_token_len: int
    ) -> int:
        if not candidates:
            raise RuntimeError(f"Empty candidate list. Model={self._tokenizer_model_id}.")
        filtered = self._filter_candidates_by_length_and_collision(source_id, candidates, vault, source_token_len)
        if not filtered:
            filtered = [cid for cid in candidates if cid != source_id and cid not in vault.token_reverse_map]
        if not filtered:
            raise RuntimeError(
                f"Token substitution found no non-colliding candidates. Model={self._tokenizer_model_id}."
            )
        seed = self._hash_to_int(f"{self._token_cipher_secret}:{source_id}")
        start = seed % len(filtered)
        chosen = filtered[start]
        if chosen in self._token_reverse_cache and self._token_reverse_cache[chosen] != source_id:
            attempts = 0
            while attempts < len(filtered):
                candidate = filtered[(start + attempts) % len(filtered)]
                owner = self._token_reverse_cache.get(candidate)
                if owner is None or owner == source_id:
                    chosen = candidate
                    break
                attempts += 1
            else:
                raise RuntimeError(
                    f"Token substitution found no globally non-colliding candidate. Model={self._tokenizer_model_id}."
                )
        self._token_forward_cache[source_id] = chosen
        self._token_reverse_cache[chosen] = source_id
        vault.token_forward_map[source_id] = chosen
        vault.token_reverse_map[chosen] = source_id
        return chosen

    def _candidate_token_ids(self, source_id: int, entity_type: str) -> list[int]:
        meta = self._token_meta.get(source_id)
        if entity_type in IDENTIFIER_ENTITY_TYPES:
            if meta is None:
                return self._token_identifier_global_candidates or self._token_global_candidates
            identifier_candidates = self._token_identifier_bucket_cache.get(meta)
            if identifier_candidates and len(identifier_candidates) >= 8:
                return identifier_candidates
            identifier_class_candidates = self._token_identifier_class_bucket_cache.get((meta[0], meta[1]))
            if identifier_class_candidates:
                return identifier_class_candidates
            if identifier_candidates:
                return identifier_candidates
            if self._token_identifier_global_candidates:
                return self._token_identifier_global_candidates
            return self._token_global_candidates
        if meta is None:
            return self._token_global_candidates
        candidates = self._token_bucket_cache.get(meta)
        if candidates and len(candidates) >= 8:
            return candidates
        class_candidates = self._token_class_bucket_cache.get((meta[0], meta[1]))
        if class_candidates:
            return class_candidates
        if candidates:
            return candidates
        return self._token_global_candidates

    def _global_candidates_for_entity(self, entity_type: str) -> list[int]:
        if entity_type in IDENTIFIER_ENTITY_TYPES and self._token_identifier_global_candidates:
            return self._token_identifier_global_candidates
        return self._token_global_candidates

    def _token_clean_length_from_id(self, token_id: int) -> int:
        cached = self._token_clean_length_cache.get(token_id)
        if cached is not None:
            return cached
        if token_id in self._token_meta:
            cached_len = self._token_meta[token_id][2]
            if cached_len <= 16:
                return cached_len
        if self._tokenizer is None:
            return 0
        token = self._tokenizer.convert_ids_to_tokens(token_id)
        if not isinstance(token, str) or not token:
            return 0
        clean_len = len(token.lstrip("▁Ġ"))
        self._token_clean_length_cache[token_id] = clean_len
        return clean_len

    def _is_length_compatible(self, source_len: int, candidate_len: int) -> bool:
        if source_len <= 2:
            return candidate_len == source_len
        if source_len <= 6:
            return abs(candidate_len - source_len) <= 2
        if source_len == 0:
            return candidate_len == 0
        ratio = candidate_len / float(source_len)
        return 0.5 <= ratio <= 1.5

    def _hash_to_int(self, data: str) -> int:
        digest = hashlib.sha256(data.encode("utf-8")).digest()
        return int.from_bytes(digest[:8], byteorder="big", signed=False)

    def _placeholder_tag(self, entity_type: str) -> str:
        if entity_type == "URL":
            return "URL"
        if entity_type == "EMAIL":
            return "EMAIL"
        if entity_type == "WINDOWS_PATH":
            return "PATH_WIN"
        if entity_type == "UNIX_PATH":
            return "PATH_UNIX"
        if entity_type == "IPV4":
            return "IPV4"
        if entity_type == "HOSTNAME":
            return "HOST"
        if entity_type == "UUID":
            return "UUID"
        if entity_type == "JWT":
            return "JWT"
        if entity_type == "HEX_TOKEN":
            return "HEX"
        return "ID"

    def _build_patterns(self) -> dict[str, re.Pattern[str]]:
        return {
            "URL": re.compile(r"\bhttps?://[^\s<>()\"']+"),
            "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
            "WINDOWS_PATH": re.compile(r"(?:(?<=\s)|^)[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n ]+\\)*[^\\/:*?\"<>|\r\n ]+"),
            "UNIX_PATH": re.compile(r"(?:(?<=\s)|^)/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+"),
            "IPV4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
            "HOSTNAME": re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,}\b"),
            "UUID": re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"),
            "JWT": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
            "HEX_TOKEN": re.compile(r"\b[a-fA-F0-9]{32,}\b"),
            "SCREAMING_SNAKE": re.compile(r"\b[A-Z][A-Z0-9]+(?:_[A-Z0-9]+)+\b"),
            "snake_case": re.compile(r"\b[a-z][a-z0-9]+(?:_[a-z0-9]+)+\b"),
            "camelCase": re.compile(r"\b[a-z]+(?:[A-Z][a-z0-9]+)+\b"),
            "PascalCase": re.compile(r"\b[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]+)+\b"),
        }
