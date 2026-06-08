import copy
import json
import re
import time
import uuid
from typing import Any, Callable

from semantic_masking import IDENTIFIER_ENTITY_TYPES, MaskingEngine, RequestVault, SECRETISH_ENTITY_TYPES


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


def with_masking_system_note(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
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
        if not _content_parts_have_masking_note(content):
            content.append({"type": "text", "text": MASKING_SYSTEM_NOTE})
        return normalized
    system_message["content"] = MASKING_SYSTEM_NOTE
    return normalized


def _content_parts_have_masking_note(content_parts: list[Any]) -> bool:
    for part in content_parts:
        if isinstance(part, dict) and part.get("type") == "text" and part.get("text") == MASKING_SYSTEM_NOTE:
            return True
    return False


def extract_text_from_message(message: dict[str, Any]) -> str:
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


def classify_sensitivity(messages: list[dict[str, Any]], engine: MaskingEngine) -> dict[str, Any]:
    entity_counts = engine.summarize_messages_entities(messages)
    total_spans = sum(entity_counts.values())
    secretish_spans = sum(entity_counts.get(t, 0) for t in SECRETISH_ENTITY_TYPES)
    identifier_spans = sum(entity_counts.get(t, 0) for t in IDENTIFIER_ENTITY_TYPES)

    combined_text = "\n".join(extract_text_from_message(message) for message in messages)
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


def resolve_route_mode(protection_mode: str, sensitivity: dict[str, Any]) -> str:
    if protection_mode == "off":
        return "off"
    if protection_mode == "strict":
        return "strict"
    return "strict" if sensitivity["strict_recommended"] else "balanced"


def authenticate_request(headers: dict[str, str], local_api_key: str, api_key: str) -> tuple[bool, dict[str, Any] | None]:
    if not local_api_key and not api_key:
        return True, None
    auth = headers.get("Authorization", "").strip()
    if not auth.startswith("Bearer "):
        return False, {"error": {"message": "Missing or invalid Authorization header"}}
    token = auth[len("Bearer "):].strip()
    if not token:
        return False, {"error": {"message": "Missing or invalid Authorization header"}}
    if token == local_api_key or token == api_key:
        return True, None
    return False, {"error": {"message": "Invalid API key"}}


def session_id_from_headers(headers: dict[str, str]) -> str:
    return headers.get("X-Session-ID", "").strip()[:256]


def handle_chat_completion_request(
    body: dict[str, Any],
    headers: dict[str, str],
    *,
    request_id: str,
    config: Any,
    engine: MaskingEngine,
    session_vault_store: Any,
    upstream_sender: Callable[[dict[str, Any], Any], dict[str, Any]],
) -> dict[str, Any]:
    if "messages" not in body or not isinstance(body["messages"], list):
        return {"status": 400, "body": {"error": {"message": "messages must be a list"}}}

    ok, auth_error = authenticate_request(headers, getattr(config, "local_api_key", ""), getattr(config, "api_key", ""))
    if not ok:
        return {"status": 401, "body": auth_error}

    sensitivity = classify_sensitivity(body["messages"], engine)
    route_mode = resolve_route_mode(config.protection_mode, sensitivity)
    session_id = session_id_from_headers(headers)
    vault = RequestVault(request_id=request_id)

    if route_mode != "off":
        session_vault_store.hydrate_vault(session_id, vault)
        t0 = time.perf_counter()
        outbound_messages = []
        messages_to_mask = with_masking_system_note(body["messages"])
        try:
            for message in messages_to_mask:
                outbound_messages.append(engine.mask_message(message, vault))
        except RuntimeError as exc:
            return {
                "status": 422,
                "body": {
                    "error": {
                        "message": f"Masking failed: {exc}",
                        "type": "masking_failed",
                        "request_id": request_id,
                        "hint": "Set TOKEN_CIPHER_MODEL_ID to a valid tokenizer model for MASKING_STRATEGY=token_substitution.",
                    }
                },
            }
        vault.timings_ms["mask_total"] = (time.perf_counter() - t0) * 1000.0
        session_vault_store.merge_from_vault(session_id, vault)
    else:
        outbound_messages = body["messages"]

    outbound_payload = dict(body)
    outbound_payload["stream"] = False
    outbound_payload["model"] = body.get("model") or config.model
    outbound_payload["messages"] = outbound_messages

    if route_mode == "strict":
        strict_result = handle_strict_route(body, config, request_id, sensitivity, upstream_sender)
        return strict_result

    upstream_result = upstream_sender(outbound_payload, config)
    if upstream_result["ok"] is False:
        return {"status": upstream_result["status"], "body": upstream_result["body"]}

    response_body = upstream_result["body"]
    if route_mode == "balanced":
        t1 = time.perf_counter()
        engine.unmask_response(response_body, vault)
        vault.timings_ms["unmask_total"] = (time.perf_counter() - t1) * 1000.0
    return {"status": upstream_result["status"], "body": response_body}


def handle_strict_route(
    body: dict[str, Any],
    config: Any,
    request_id: str,
    sensitivity: dict[str, Any],
    upstream_sender: Callable[[dict[str, Any], Any], dict[str, Any]],
) -> dict[str, Any]:
    if getattr(config, "strict_backend", "reject") == "reject":
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
    local_url = getattr(config, "strict_local_url", "")
    if local_url:
        payload = dict(body)
        payload["stream"] = False
        payload["model"] = body.get("model") or config.model
        return upstream_sender(payload, config, strict_url=local_url, strict_timeout_s=config.strict_local_timeout_s)
    first_user_text = ""
    for message in body.get("messages", []):
        if isinstance(message, dict) and message.get("role") == "user":
            first_user_text = extract_text_from_message(message)[:120]
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

