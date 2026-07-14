import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from semantic_masking import PROTECTED_IDENTIFIERS, RequestVault


VALID_SEMANTIC_LEVELS = {"light", "standard", "aggressive"}


def _token_shape_key(token: str) -> tuple[int, int, int]:
    lead_space = 1 if token.startswith(" ") else 0
    if not token:
        return (lead_space, 0, 0)
    stripped = token.lstrip()
    if not stripped:
        return (lead_space, 0, 0)
    if stripped.isalpha():
        cls = 1
    elif stripped.isdigit():
        cls = 2
    elif all(ch in "._-/:\\@#" for ch in stripped):
        cls = 3
    elif stripped.isalnum():
        cls = 4
    else:
        cls = 5
    length_bucket = len(stripped) if len(stripped) <= 16 else 16 + (len(stripped) // 4)
    return (lead_space, cls, length_bucket)


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    if len(a) > len(b):
        a, b = b, a
    previous = list(range(len(a) + 1))
    for i, ch_b in enumerate(b, start=1):
        current = [i] + [0] * len(a)
        for j, ch_a in enumerate(a, start=1):
            insert_cost = current[j - 1] + 1
            delete_cost = previous[j] + 1
            replace_cost = previous[j - 1] + (0 if ch_a == ch_b else 1)
            current[j] = min(insert_cost, delete_cost, replace_cost)
        previous = current
    return previous[-1]


def _hash_to_int(data: str) -> int:
    digest = hashlib.sha256(data.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], byteorder="big", signed=False)


DEFAULT_CODEBOOK_PATH = os.path.join(".agent", "semantic_codebook.json")


@dataclass
class CodebookStats:
    vocab_size: int = 0
    anchored_tokens: int = 0
    skipped_protected: int = 0
    skipped_visual_collision: int = 0
    fallback_class: str = "alphanumeric"
    mean_cosine_similarity: float = 0.0
    mean_levenshtein_distance: float = 0.0


@dataclass
class CodebookRecord:
    version: int
    tokenizer_model_id: str
    anchor_model_id: str
    level: str
    created_at: float
    codebook_secret_salt: str
    forward: dict[int, int]
    reverse: dict[int, int]
    stats: CodebookStats

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "tokenizer_model_id": self.tokenizer_model_id,
            "anchor_model_id": self.anchor_model_id,
            "level": self.level,
            "created_at": self.created_at,
            "codebook_secret_salt": self.codebook_secret_salt,
            "forward": {str(k): v for k, v in self.forward.items()},
            "reverse": {str(k): v for k, v in self.reverse.items()},
            "stats": {
                "vocab_size": self.stats.vocab_size,
                "anchored_tokens": self.stats.anchored_tokens,
                "skipped_protected": self.stats.skipped_protected,
                "skipped_visual_collision": self.stats.skipped_visual_collision,
                "fallback_class": self.stats.fallback_class,
                "mean_cosine_similarity": self.stats.mean_cosine_similarity,
                "mean_levenshtein_distance": self.stats.mean_levenshtein_distance,
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CodebookRecord":
        stats = data.get("stats", {}) or {}
        return cls(
            version=int(data.get("version", 1)),
            tokenizer_model_id=str(data.get("tokenizer_model_id", "")),
            anchor_model_id=str(data.get("anchor_model_id", "")),
            level=str(data.get("level", "standard")),
            created_at=float(data.get("created_at", 0.0)),
            codebook_secret_salt=str(data.get("codebook_secret_salt", "")),
            forward={int(k): int(v) for k, v in (data.get("forward") or {}).items()},
            reverse={int(k): int(v) for k, v in (data.get("reverse") or {}).items()},
            stats=CodebookStats(
                vocab_size=int(stats.get("vocab_size", 0)),
                anchored_tokens=int(stats.get("anchored_tokens", 0)),
                skipped_protected=int(stats.get("skipped_protected", 0)),
                skipped_visual_collision=int(stats.get("skipped_visual_collision", 0)),
                fallback_class=str(stats.get("fallback_class", "alphanumeric")),
                mean_cosine_similarity=float(stats.get("mean_cosine_similarity", 0.0)),
                mean_levenshtein_distance=float(stats.get("mean_levenshtein_distance", 0.0)),
            ),
        )


class _AnchorEmbedder:
    def __init__(self, model_id: str, load_model_body: bool) -> None:
        self.model_id = model_id
        self._load_model_body = load_model_body
        self._tokenizer = None
        self._embedding_matrix: Any = None
        self._backend = "uninitialized"
        self._load_error = ""

    def load(self) -> None:
        if self._backend != "uninitialized":
            return
        if self.model_id and self.model_id not in ("unknown", ""):
            try:
                from transformers import AutoTokenizer
                self._tokenizer = AutoTokenizer.from_pretrained(self.model_id, use_fast=True, trust_remote_code=True)
            except Exception as exc:
                self._load_error = f"tokenizer load failed: {type(exc).__name__}: {exc}"
            if self._load_model_body and self._tokenizer is not None:
                try:
                    from transformers import AutoModel
                    model = AutoModel.from_pretrained(self.model_id, trust_remote_code=True)
                    self._embedding_matrix = model.get_input_embeddings().weight.detach().cpu()
                    del model
                    self._backend = "model_body"
                    return
                except Exception as exc:
                    self._load_error = f"model body load failed: {type(exc).__name__}: {exc}"
        try:
            from sentence_transformers import SentenceTransformer
            encoder = SentenceTransformer("all-MiniLM-L6-v2")
            self._sentence_encoder = encoder
            self._backend = "sentence_transformer"
            os.environ["HF_HUB_OFFLINE"] = "1"
        except Exception as exc:
            self._load_error += f" | sentence-transformer load failed: {type(exc).__name__}: {exc}"
            self._backend = "fallback_shape_only"

    def embed_tokens(self, token_strings: list[str]) -> Any:
        if self._backend == "model_body" and self._embedding_matrix is not None:
            return self._embedding_matrix
        if self._backend == "sentence_transformer" and hasattr(self, "_sentence_encoder"):
            unique_strings = list(dict.fromkeys(token_strings))
            if not unique_strings:
                return None
            vectors = self._sentence_encoder.encode(unique_strings, convert_to_numpy=True, show_progress_bar=False)
            index = {s: i for i, s in enumerate(unique_strings)}
            return vectors, index
        return None

    def backend(self) -> str:
        return self._backend

    def error(self) -> str:
        return self._load_error


class SemanticCodebook:
    def __init__(
        self,
        tokenizer: Any,
        anchor_model_id: str,
        level: str = "standard",
        load_anchor_model_body: bool = True,
        path: str = DEFAULT_CODEBOOK_PATH,
        secret_salt: str | None = None,
    ) -> None:
        if level not in VALID_SEMANTIC_LEVELS:
            level = "standard"
        self._tokenizer = tokenizer
        self._anchor_model_id = anchor_model_id
        self._level = level
        self._load_anchor_model_body = load_anchor_model_body
        self._path = path
        self._secret_salt = secret_salt or hashlib.sha256(os.urandom(32)).hexdigest()[:16]
        self._record: CodebookRecord | None = None
        self._lock = threading.RLock()
        self._bootstrap_error = ""
        self._bootstrapped = False
        self._bootstrap_in_progress = False
        self._bootstrap_stats: CodebookStats = CodebookStats()
        self._last_load_path = ""

    @property
    def level(self) -> str:
        return self._level

    @property
    def path(self) -> str:
        return self._path

    @property
    def anchor_model_id(self) -> str:
        return self._anchor_model_id

    @property
    def record(self) -> CodebookRecord | None:
        return self._record

    @property
    def ready(self) -> bool:
        return self._bootstrapped and self._record is not None

    @property
    def bootstrap_error(self) -> str:
        return self._bootstrap_error

    def diagnostics(self) -> dict[str, Any]:
        with self._lock:
            stats = self._record.stats if self._record is not None else self._bootstrap_stats
            return {
                "enabled": True,
                "level": self._level,
                "anchor_model_id": self._anchor_model_id,
                "codebook_path": self._path,
                "codebook_loaded": self._bootstrapped,
                "codebook_size_bytes": self._file_size(),
                "vocab_size": stats.vocab_size,
                "anchored_tokens": stats.anchored_tokens,
                "skipped_protected": stats.skipped_protected,
                "skipped_visual_collision": stats.skipped_visual_collision,
                "fallback_class": stats.fallback_class,
                "mean_cosine_similarity": stats.mean_cosine_similarity,
                "mean_levenshtein_distance": stats.mean_levenshtein_distance,
                "bootstrap_error": self._bootstrap_error,
            }

    def _file_size(self) -> int:
        try:
            return os.path.getsize(self._path) if os.path.isfile(self._path) else 0
        except OSError:
            return 0

    def _level_to_neighbor_count(self) -> int:
        if self._level == "light":
            return 4
        if self._level == "aggressive":
            return 32
        return 12

    def _level_to_visual_distance(self) -> int:
        if self._level == "light":
            return 1
        if self._level == "aggressive":
            return 3
        return 2

    def bootstrap(self) -> bool:
        with self._lock:
            if self._bootstrapped:
                return True
            if self._bootstrap_in_progress:
                return False
            self._bootstrap_in_progress = True
        try:
            existing = self._try_load_existing()
            if existing is not None:
                with self._lock:
                    self._record = existing
                    self._bootstrapped = True
                return True
            record = self._build_record()
            with self._lock:
                if record is None:
                    self._bootstrapped = False
                    return False
                self._record = record
                self._bootstrapped = True
                self._bootstrap_stats = record.stats
            self._persist(record)
            return True
        finally:
            with self._lock:
                self._bootstrap_in_progress = False

    def bootstrap_async(self) -> threading.Thread:
        thread = threading.Thread(target=self.bootstrap, name="semantic-codebook-bootstrap", daemon=True)
        thread.start()
        return thread

    def _try_load_existing(self) -> CodebookRecord | None:
        if not self._path or not os.path.isfile(self._path):
            return None
        try:
            with open(self._path, "r", encoding="utf-8") as fp:
                data = json.load(fp)
        except (OSError, json.JSONDecodeError) as exc:
            self._bootstrap_error = f"existing codebook unreadable: {type(exc).__name__}: {exc}"
            return None
        try:
            record = CodebookRecord.from_dict(data)
        except Exception as exc:
            self._bootstrap_error = f"existing codebook malformed: {type(exc).__name__}: {exc}"
            return None
        if record.tokenizer_model_id != self._tokenizer_name():
            self._bootstrap_error = (
                f"existing codebook tokenizer mismatch "
                f"(have={record.tokenizer_model_id}, want={self._tokenizer_name()})"
            )
            return None
        if record.anchor_model_id != self._anchor_model_id:
            self._bootstrap_error = (
                f"existing codebook anchor model mismatch "
                f"(have={record.anchor_model_id}, want={self._anchor_model_id})"
            )
            return None
        if record.level != self._level:
            self._bootstrap_error = (
                f"existing codebook level mismatch (have={record.level}, want={self._level})"
            )
            return None
        self._last_load_path = self._path
        return record

    def _tokenizer_name(self) -> str:
        name = getattr(self._tokenizer, "name_or_path", "") or ""
        return str(name)

    def _build_shape_index(self, vocab_size: int, special_ids: set[int]) -> dict[tuple[int,int], list[int]]:
        index: dict[tuple[int,int], list[int]] = {}
        for token_id in range(vocab_size):
            if token_id in special_ids:
                continue
            token = self._safe_token_str(token_id)
            if not token or self._is_protected_token(token):
                continue
            key = _token_shape_key(token)
            group_key = (key[0], key[1])
            bucket = key[2]
            candidates = index.get(group_key)
            if candidates is None:
                index[group_key] = [(bucket, token_id)]
            else:
                candidates.append((bucket, token_id))
        result: dict[tuple[int,int], list[int]] = {}
        for group_key, items in index.items():
            items.sort(key=lambda x: x[0])
            result[group_key] = [tid for _, tid in items]
        return result

    def _lookup_candidates(self, shape_index: dict[tuple[int,int], list[int]], token_id: int, source_token: str, vocab_size: int, special_ids: set[int], max_candidates: int = 20) -> list[int]:
        source_key = _token_shape_key(source_token)
        group_key = (source_key[0], source_key[1])
        source_bucket = source_key[2]
        candidates = shape_index.get(group_key, [])
        if not candidates:
            return []
        result: list[int] = []
        for cand_id in candidates:
            if len(result) >= max_candidates:
                break
            if cand_id == token_id or cand_id in special_ids:
                continue
            cand_token = self._safe_token_str(cand_id)
            if not cand_token or cand_token == source_token:
                continue
            if self._is_protected_token(cand_token):
                continue
            cand_bucket = _token_shape_key(cand_token)[2]
            if abs(cand_bucket - source_bucket) <= 2:
                result.append(cand_id)
        return result

    def _build_record(self) -> CodebookRecord | None:
        if self._tokenizer is None:
            self._bootstrap_error = "tokenizer unavailable"
            return None
        tokenizer_model_id = self._tokenizer_name() or "unknown-tokenizer"
        vocab_size = int(getattr(self._tokenizer, "vocab_size", 0) or 0)
        if vocab_size <= 0:
            self._bootstrap_error = "tokenizer vocab size is zero"
            return None
        special_ids = set(getattr(self._tokenizer, "all_special_ids", []) or [])
        anchor = _AnchorEmbedder(self._anchor_model_id, self._load_anchor_model_body)
        anchor.load()
        backend = anchor.backend()
        if backend in ("failed", "uninitialized"):
            self._bootstrap_error = f"anchor embedder unavailable: {anchor.error()}"
            return None
        use_real_embedding = backend == "model_body"
        vectors_or_matrix = anchor.embed_tokens([]) if use_real_embedding else anchor.embed_tokens([])
        cosines: list[float] = []
        distances: list[int] = []
        forward: dict[int, int] = {}
        reverse: dict[int, int] = {}
        anchored = 0
        skipped_protected = 0
        skipped_visual = 0
        min_visual = self._level_to_visual_distance()
        top_k = self._level_to_neighbor_count()
        all_tokens: list[str] = [self._safe_token_str(i) for i in range(vocab_size)]
        token_shapes: list[tuple[int,int,int]] = [_token_shape_key(t) if t else (0,0,0) for t in all_tokens]
        is_obfuscatable: list[bool] = [
            bool(t) and t not in special_ids and not self._is_protected_token(t)
            for t in all_tokens
        ]
        shape_index = self._build_shape_index(vocab_size, special_ids)
        if backend == "sentence_transformer":
            unique_tokens = list(dict.fromkeys(all_tokens))
            encoder_vecs, encoder_index = anchor.embed_tokens(unique_tokens)
            vec_map = {s: encoder_vecs[encoder_index[s]] for s in unique_tokens}
        for token_id in range(vocab_size):
            if not is_obfuscatable[token_id]:
                if all_tokens[token_id] and all_tokens[token_id].strip() and all_tokens[token_id] in PROTECTED_IDENTIFIERS:
                    skipped_protected += 1
                continue
            source_token = all_tokens[token_id]
            if use_real_embedding:
                source_vec = vectors_or_matrix[token_id]
                source_key = token_shapes[token_id]
                group_key = (source_key[0], source_key[1])
                source_bucket = source_key[2]
                raw_candidates = shape_index.get(group_key, [])
                scored: list[tuple[float, int]] = []
                checked = 0
                for cand_id in raw_candidates:
                    if checked >= 20:
                        break
                    if cand_id == token_id or not is_obfuscatable[cand_id]:
                        continue
                    cand_token = all_tokens[cand_id]
                    if not cand_token or cand_token == source_token:
                        continue
                    cand_bucket = token_shapes[cand_id][2]
                    if abs(cand_bucket - source_bucket) > 1:
                        continue
                    checked += 1
                    if _levenshtein(source_token, cand_token) < min_visual:
                        continue
                    cand_vec = vectors_or_matrix[cand_id]
                    sim = self._cosine(source_vec, cand_vec)
                    if sim <= 0.0:
                        continue
                    scored.append((sim, cand_id))
                if not scored:
                    skipped_visual += 1
                    continue
                scored.sort(key=lambda x: x[0], reverse=True)
                top = scored[:top_k]
                idx = _hash_to_int(f"{self._secret_salt}:{token_id}") % len(top)
                chosen_sim, chosen_id = top[idx]
                forward[token_id] = chosen_id
                reverse[chosen_id] = token_id
                cosines.append(chosen_sim)
                cand_token = all_tokens[chosen_id]
                if cand_token:
                    distances.append(_levenshtein(source_token, cand_token))
                anchored += 1
                continue
            if backend == "sentence_transformer":
                source_vec = vec_map.get(source_token)
                if source_vec is None:
                    continue
                source_key = token_shapes[token_id]
                group_key = (source_key[0], source_key[1])
                source_bucket = source_key[2]
                raw_candidates = shape_index.get(group_key, [])
                scored = []
                checked = 0
                for cand_id in raw_candidates:
                    if checked >= 20:
                        break
                    if cand_id == token_id or not is_obfuscatable[cand_id]:
                        continue
                    cand_token = all_tokens[cand_id]
                    if not cand_token or cand_token == source_token:
                        continue
                    cand_bucket = token_shapes[cand_id][2]
                    if abs(cand_bucket - source_bucket) > 1:
                        continue
                    checked += 1
                    if _levenshtein(source_token, cand_token) < min_visual:
                        continue
                    cand_vec = vec_map.get(cand_token)
                    if cand_vec is None:
                        continue
                    sim = self._cosine(source_vec, cand_vec)
                    if sim <= 0.0:
                        continue
                    scored.append((sim, cand_id))
                if not scored:
                    skipped_visual += 1
                    continue
                scored.sort(key=lambda x: x[0], reverse=True)
                top = scored[:top_k]
                idx = _hash_to_int(f"{self._secret_salt}:{token_id}") % len(top)
                chosen_sim, chosen_id = top[idx]
                forward[token_id] = chosen_id
                reverse[chosen_id] = token_id
                cosines.append(chosen_sim)
                cand_token = all_tokens[chosen_id]
                if cand_token:
                    distances.append(_levenshtein(source_token, cand_token))
                anchored += 1
                continue
            source_key = token_shapes[token_id]
            group_key = (source_key[0], source_key[1])
            source_bucket = source_key[2]
            raw_candidates = shape_index.get(group_key, [])
            scored = []
            checked = 0
            for cand_id in raw_candidates:
                if checked >= 20:
                    break
                if cand_id == token_id or not is_obfuscatable[cand_id]:
                    continue
                cand_token = all_tokens[cand_id]
                if not cand_token or cand_token == source_token:
                    continue
                cand_bucket = token_shapes[cand_id][2]
                if abs(cand_bucket - source_bucket) > 1:
                    continue
                checked += 1
                if _levenshtein(source_token, cand_token) < min_visual:
                    continue
                scored.append((cand_id, cand_token))
            if not scored:
                skipped_visual += 1
                continue
            idx = _hash_to_int(f"{self._secret_salt}:{token_id}") % len(scored)
            chosen_id, chosen_token = scored[idx]
            forward[token_id] = chosen_id
            reverse[chosen_id] = token_id
            cosines.append(0.5)
            distances.append(_levenshtein(source_token, chosen_token))
            anchored += 1
        if anchored == 0:
            self._bootstrap_error = "codebook generation produced no anchors"
            return None
        stats = CodebookStats(
            vocab_size=vocab_size,
            anchored_tokens=anchored,
            skipped_protected=skipped_protected,
            skipped_visual_collision=skipped_visual,
            fallback_class=("model_body" if use_real_embedding else backend),
            mean_cosine_similarity=(sum(cosines) / len(cosines)) if cosines else 0.0,
            mean_levenshtein_distance=(sum(distances) / len(distances)) if distances else 0.0,
        )
        return CodebookRecord(
            version=1,
            tokenizer_model_id=tokenizer_model_id,
            anchor_model_id=self._anchor_model_id,
            level=self._level,
            created_at=time.time(),
            codebook_secret_salt=self._secret_salt,
            forward=forward,
            reverse=reverse,
            stats=stats,
        )

    def _safe_token_str(self, token_id: int) -> str:
        try:
            token = self._tokenizer.convert_ids_to_tokens(token_id)
        except Exception:
            return ""
        if not isinstance(token, str):
            return ""
        return token

    def _is_protected_token(self, token: str) -> bool:
        clean = token.strip()
        if not clean:
            return True
        if clean in PROTECTED_IDENTIFIERS:
            return True
        return False

    def _candidate_token_ids(
        self,
        token_id: int,
        vocab_size: int,
        special_ids: set[int],
        source_token: str,
    ) -> list[int]:
        source_key = _token_shape_key(source_token)
        candidates: list[int] = []
        for cand_id in range(vocab_size):
            if cand_id == token_id or cand_id in special_ids:
                continue
            cand_token = self._safe_token_str(cand_id)
            if not cand_token:
                continue
            cand_key = _token_shape_key(cand_token)
            if cand_key[0] != source_key[0]:
                continue
            if cand_key[1] != source_key[1]:
                continue
            if abs(cand_key[2] - source_key[2]) > 4:
                continue
            candidates.append(cand_id)
        return candidates

    @staticmethod
    def _cosine(a: Any, b: Any) -> float:
        try:
            import numpy as np
            a_np = np.asarray(a, dtype=np.float64)
            b_np = np.asarray(b, dtype=np.float64)
            dot = np.dot(a_np, b_np)
            na = np.dot(a_np, a_np)
            nb = np.dot(b_np, b_np)
            if na == 0.0 or nb == 0.0:
                return 0.0
            return float(dot / (np.sqrt(na) * np.sqrt(nb)))
        except Exception:
            return 0.0

    def _persist(self, record: CodebookRecord) -> None:
        if not self._path:
            return
        try:
            path = Path(self._path)
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(path.suffix + ".tmp")
            with open(tmp, "w", encoding="utf-8") as fp:
                json.dump(record.to_dict(), fp, ensure_ascii=True)
            os.replace(tmp, path)
        except OSError as exc:
            self._bootstrap_error = f"codebook persist failed: {type(exc).__name__}: {exc}"


@dataclass
class SemanticObfuscationResult:
    encoded: str
    forward: dict[int, int] = field(default_factory=dict)
    reverse: dict[int, int] = field(default_factory=dict)
    encode_ms: float = 0.0
    tokens_processed: int = 0
    tokens_unmapped: int = 0


class SemanticObfuscator:
    def __init__(
        self,
        codebook: SemanticCodebook,
        tokenizer: Any,
    ) -> None:
        self._codebook = codebook
        self._tokenizer = tokenizer
        self._encode_ms_p50: float = 0.0
        self._encode_ms_p99: float = 0.0
        self._encode_ms_max: float = 0.0
        self._decode_ms_p50: float = 0.0
        self._decode_ms_p99: float = 0.0
        self._decode_ms_max: float = 0.0
        self._samples: list[float] = []
        self._decode_samples: list[float] = []

    @property
    def ready(self) -> bool:
        return self._codebook.ready

    @property
    def codebook(self) -> SemanticCodebook:
        return self._codebook

    def diagnostics(self) -> dict[str, Any]:
        cb = self._codebook.diagnostics()
        cb["last_encode_ms_p50"] = self._encode_ms_p50
        cb["last_encode_ms_p99"] = self._encode_ms_p99
        cb["last_decode_ms_p50"] = self._decode_ms_p50
        cb["last_decode_ms_p99"] = self._decode_ms_p99
        return cb

    def encode_message(
        self,
        message: dict[str, Any],
        vault: RequestVault,
        include_system: bool = False,
    ) -> dict[str, Any]:
        if not self.ready:
            return message
        role = message.get("role", "")
        if role == "system" and not include_system:
            return message
        out = dict(message)
        content = out.get("content")
        if isinstance(content, str):
            result = self._encode_text(content)
            out["content"] = result.encoded
            self._merge_into_vault(vault, result)
        elif isinstance(content, list):
            new_parts = []
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
                    cp = dict(part)
                    result = self._encode_text(cp["text"])
                    cp["text"] = result.encoded
                    new_parts.append(cp)
                    self._merge_into_vault(vault, result)
                else:
                    new_parts.append(part)
            out["content"] = new_parts
        return out

    def encode_messages(
        self,
        messages: list[dict[str, Any]],
        vault: RequestVault,
        include_system: bool = False,
    ) -> list[dict[str, Any]]:
        if not self.ready:
            return messages
        encoded: list[dict[str, Any]] = []
        for message in messages:
            encoded.append(self.encode_message(message, vault, include_system=include_system))
        return encoded

    def decode_response(self, response_body: dict[str, Any], vault: RequestVault) -> None:
        if not vault.semantic_reverse:
            return
        choices = response_body.get("choices")
        if not isinstance(choices, list):
            return
        t0 = time.perf_counter()
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            message = choice.get("message")
            if not isinstance(message, dict):
                continue
            content = message.get("content")
            if isinstance(content, str):
                message["content"] = self._decode_text(content, vault)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
                        part["text"] = self._decode_text(part["text"], vault)
            tool_calls = message.get("tool_calls")
            if isinstance(tool_calls, list):
                for tc in tool_calls:
                    if not isinstance(tc, dict):
                        continue
                    fn = tc.get("function")
                    if isinstance(fn, dict) and isinstance(fn.get("arguments"), str):
                        fn["arguments"] = self._decode_text(fn["arguments"], vault)
        elapsed = (time.perf_counter() - t0) * 1000.0
        self._record_decode(elapsed)
        vault.timings_ms["semantic_decode_total"] = elapsed

    def _merge_into_vault(self, vault: RequestVault, result: SemanticObfuscationResult) -> None:
        if not result.forward:
            return
        vault.semantic_forward.update(result.forward)
        vault.semantic_reverse.update(result.reverse)
        vault.timings_ms["semantic_encode_total"] = (
            vault.timings_ms.get("semantic_encode_total", 0.0) + result.encode_ms
        )
        vault.semantic_tokens_processed = (
            vault.semantic_tokens_processed + result.tokens_processed
        )
        vault.semantic_tokens_unmapped = (
            vault.semantic_tokens_unmapped + result.tokens_unmapped
        )

    def _encode_text(self, text: str) -> SemanticObfuscationResult:
        t0 = time.perf_counter()
        if not text:
            return SemanticObfuscationResult(encoded=text, encode_ms=0.0)
        if self._tokenizer is None or not self.ready:
            return SemanticObfuscationResult(encoded=text, encode_ms=0.0)
        try:
            token_ids = self._tokenizer.encode(text, add_special_tokens=False)
        except Exception:
            return SemanticObfuscationResult(encoded=text, encode_ms=0.0)
        if not token_ids:
            return SemanticObfuscationResult(encoded=text, encode_ms=0.0)
        forward: dict[int, int] = {}
        reverse: dict[int, int] = {}
        mapped: list[int] = []
        unmapped = 0
        for tid in token_ids:
            surrogate = self._codebook.record.forward.get(tid) if self._codebook.record is not None else None
            if surrogate is None:
                mapped.append(tid)
                unmapped += 1
                continue
            if surrogate in reverse.values() and reverse.get(surrogate) != tid:
                mapped.append(tid)
                unmapped += 1
                continue
            forward[tid] = surrogate
            reverse[surrogate] = tid
            mapped.append(surrogate)
        try:
            encoded = self._tokenizer.decode(mapped, skip_special_tokens=False, clean_up_tokenization_spaces=False)
        except Exception:
            return SemanticObfuscationResult(encoded=text, encode_ms=(time.perf_counter() - t0) * 1000.0)
        elapsed = (time.perf_counter() - t0) * 1000.0
        self._record_encode(elapsed)
        return SemanticObfuscationResult(
            encoded=encoded,
            forward=forward,
            reverse=reverse,
            encode_ms=elapsed,
            tokens_processed=len(token_ids),
            tokens_unmapped=unmapped,
        )

    def _decode_text(self, text: str, vault: RequestVault) -> str:
        if not text or not vault.semantic_reverse:
            return text
        if self._tokenizer is None:
            return text
        try:
            token_ids = self._tokenizer.encode(text, add_special_tokens=False)
        except Exception:
            return text
        if not token_ids:
            return text
        mapped: list[int] = []
        changed = False
        for tid in token_ids:
            original = vault.semantic_reverse.get(tid)
            if original is None:
                mapped.append(tid)
                continue
            mapped.append(original)
            changed = True
        if not changed:
            return text
        try:
            return self._tokenizer.decode(mapped, skip_special_tokens=False, clean_up_tokenization_spaces=False)
        except Exception:
            return text

    def _record_encode(self, ms: float) -> None:
        self._samples.append(ms)
        if len(self._samples) > 500:
            self._samples = self._samples[-500:]
        sorted_samples = sorted(self._samples)
        n = len(sorted_samples)
        self._encode_ms_p50 = sorted_samples[n // 2]
        self._encode_ms_p99 = sorted_samples[max(0, int(n * 0.99) - 1)]
        self._encode_ms_max = sorted_samples[-1]

    def _record_decode(self, ms: float) -> None:
        self._decode_samples.append(ms)
        if len(self._decode_samples) > 500:
            self._decode_samples = self._decode_samples[-500:]
        sorted_samples = sorted(self._decode_samples)
        n = len(sorted_samples)
        self._decode_ms_p50 = sorted_samples[n // 2]
        self._decode_ms_p99 = sorted_samples[max(0, int(n * 0.99) - 1)]
