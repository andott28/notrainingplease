# Mask Proxy

 A local proxy that intercepts AI chat requests, automatically detects sensitive data (API keys, URLs, emails, paths, UUIDs, identifiers), and blocks or masks it depending on mode.

## How it works

```
Your app (Cursor, ChatGPT, IDE, etc.)
  → POST http://localhost:8787/v1/chat/completions
    Authorization: Bearer sk-local-xxxx
    {"messages": [{"role":"user","content":"My token is sk-abc123"}]}

Mask Proxy
  → detects "sk-abc123" as a sensitive value
  → replaces it with a masked alias
  → forwards to NVIDIA API with your real API key
  → receives the model response
  → restores all original values in the response
  → returns the clean response to your app
```

The masking engine uses a HuggingFace tokenizer to perform deterministic token substitutions, ensuring:
- **Round-trip fidelity**: every masked value is restored exactly after unmasking
- **Protected identifiers**: Python/JS keywords and builtins are never masked
- **Length-aware substitutions**: replacement tokens stay within compatible length bounds

## Requirements

- **Python 3.10+** (uses `dict[str, str]` type hints and the `|` union syntax)
- **requests** — HTTP calls to upstream API
- **transformers** — Tokenizer for masking strategies
- **Tkinter** (included with Python on Windows)

Optional (for code snippets in documentation):
- **openai** — OpenAI Python client library

## Installation

```bash
git clone https://github.com/andott28/notrainingplease.git
cd notrainingplease
pip install -r requirements.txt
```

## Quick Start

**Windows users:** Double-click `run.bat` to launch the shield UI.

**Command line:**
```bash
python run.py
```

If you prefer the GUI directly:
```bash
python gui.py
```

### Setup

1. Open the app.
2. Click **Enable Shield**.
3. Let the shield intercept detected LLM traffic system-wide.

### Controls

- **Enable Shield** — Starts system-wide transparent interception.
- **Disable Shield** — Stops interception and restores normal egress.
- **Refresh Providers** — Reloads the intercepted provider registry.

## Transparent Mode

Transparent mode is Windows-only in this build. It launches `mitmdump` in transparent mode, loads the local interception addon, and best-effort installs the mitmproxy root CA into the Windows trust store so HTTPS LLM calls can be inspected.

Detected provider traffic is redirected through the proxy and logged to `.agent/detected_providers.json`. The GUI includes a live provider viewer and a detail pane so you can inspect hosts, paths, match reasons, and recent samples.

## Protection Modes

The proxy supports three protection modes, configured via the `.env` file:

| Mode | Behavior | Use Case |
|------|----------|----------|
| **balanced** (default) | Masks sensitive data before sending upstream, unmaskes the response. Automatically switches to strict mode if high-sensitivity signals are detected (markers like "confidential", large code blocks, dense sensitive spans). | **Recommended for most users.** Balances security with convenience—sensitive requests are blocked, routine requests flow through with masking. |
| **strict** | Rejects any request containing detected sensitive data by default. Can be configured to forward to a local model instead via `STRICT_LOCAL_URL`. | For maximum privacy, when you want to guarantee no sensitive data reaches the remote provider. |
| **off** | Passes all requests through without masking or checking. | Testing and debugging only. |

**Configure in `.env`:**
```env
PROTECTION_MODE=balanced
```

## Masking Strategies

| Strategy | Behavior | Pros | Cons |
|----------|----------|------|------|
| **token_substitution** (default) | Encodes sensitive values to token IDs, maps each to a deterministic hash-based substitute, decodes back to text. Preserves approximate length and shape. | Seamless—model sees natural-looking identifiers. Undetectable masking. | Requires tokenizer model download. |
| **opaque** | Replaces sensitive values with placeholder aliases (`@@ID_0001@@`, `@@URL_0001@@`, etc.). | Fast, no dependencies. Clear visual markers. | Model knows data is masked. |

**Configure in `.env`:**
```env
MASKING_STRATEGY=token_substitution
```

## Semantic Obfuscation

An additional, **orthogonal** protection mode. It re-encodes the prompt at the **token level** using a persisted, per-deployment random codebook, so the upstream model still sees a semantically equivalent sequence of token IDs while the raw surface form becomes unreadable to humans and to plaintext log scrapers.

This is **not** entity masking (which only swaps identifiers) and **not** synonym replacement (which keeps words readable). It is a whole-sentence token-stream substitution. The mapping is bijective and keyed on the tokenizer's own embedding space, so the model receives a stream that lands in nearly the same point in semantic space as the original — same reasoning, same answer, but the prompt looks scrambled to a human reader.

**Configure in `.env`:**
```env
SEMANTIC_OBFUSCATION=false
SEMANTIC_OBFUSCATION_LEVEL=standard   # light | standard | aggressive
SEMANTIC_OBFUSCATION_ANCHOR_MODEL=   # defaults to TOKEN_CIPHER_MODEL_ID
SEMANTIC_OBFUSCATION_CODEBOOK_PATH=.agent/semantic_codebook.json
SEMANTIC_OBFUSCATION_INCLUDE_SYSTEM=false
SEMANTIC_OBFUSCATION_LOAD_ANCHOR_BODY=true
SEMANTIC_OBFUSCATION_DECODE_RESPONSE=false
```

**How it works:**

1. On first startup, the obfuscator loads the embedding matrix of the anchor model (or a smaller fallback embedder if `LOAD_ANCHOR_BODY=false`) and builds a one-to-one mapping from each vocab token to a near-cosine-similar token of the same syntactic class but visually different surface form.
2. The mapping is deterministic (salted hash → same source always picks the same surrogate) and persisted to `.agent/semantic_codebook.json` so it stays stable across restarts.
3. On every intercepted request, each `user` / `assistant` message is re-tokenized, the source token IDs are replaced with their surrogate IDs, and the resulting token sequence is decoded back to text. The system message is left intact (so any system note the upstream sees stays readable) unless `INCLUDE_SYSTEM=true`.
4. The mapping is stored per-request in the `RequestVault`, so the same prompt produces the same obfuscation across the request.
5. On the response, the existing `unmask_response` pass restores the entity-masking aliases, and an optional `DECODE_RESPONSE=true` pass also reverses the semantic obfuscation in the model's reply.

**Knobs:**

- `LEVEL` trades readability for behavior stability: `light` is the closest to source (highest cosine), `aggressive` is the most scrambled. `standard` is the default and is calibrated for typical chat traffic.
- `LOAD_ANCHOR_BODY=false` skips the model body download (~3 GB) and uses a smaller fallback embedder. This weakens the cosine-similarity guarantee.
- `DECODE_RESPONSE=true` also reverses the encoding on the model's response. **Off by default.** Response decoding can introduce false-positive substitutions on common English tokens whose ID happens to equal one of the prompt's surrogate IDs. Enable only if you have measured the tradeoff in your own traffic.

**Important limit:** nothing here prevents the upstream provider from training on the obfuscated stream after re-tokenizing it. The obfuscation makes the *raw surface* harder to learn from, but the token IDs themselves are normal vocab IDs and a determined provider can reconstruct the same embedding-space stream. This is a fundamental limit of any client-side scrambling approach.

## Configuration Reference

See `.env.example` for all available options:

```env
# NVIDIA API credentials
NVIDIA_API_KEY=your_real_nvidia_api_key
NVIDIA_MODEL=qwen/qwen3-coder-480b-a35b-instruct

# Proxy server
PROXY_HOST=127.0.0.1
PROXY_PORT=8787

# Upstream timeout
UPSTREAM_TIMEOUT_S=120

# Protection and masking
PROTECTION_MODE=balanced
STRICT_BACKEND=reject
STRICT_LOCAL_URL=
STRICT_LOCAL_TIMEOUT_S=30
MASKING_STRATEGY=token_substitution

# Tokenizer for token_substitution strategy
TOKEN_CIPHER_MODEL_ID=Qwen/Qwen2.5-Coder-1.5B-Instruct

# Session caching (maintains masking consistency across requests)
SESSION_VAULT_ENABLED=true
SESSION_VAULT_TTL_S=86400
SESSION_VAULT_MAX_SESSIONS=1000
```

## API Endpoints

- `GET /healthz` — Health check. Returns proxy status, model, and protection settings.
- `GET /v1/masking/diagnostics` — Engine diagnostics (vocab size, candidate pool, protected identifiers, etc.)
- `POST /v1/chat/completions` — Masked chat completion endpoint (OpenAI-compatible)

## Project Structure

```
run.bat                  ← double-click to launch (Windows)
gui.py                   ← Tkinter GUI for easy setup
transparent_mode.py      ← transparent proxy and provider detection
semantic_masking.py      ← masking engine
semantic_obfuscation.py  ← token-level semantic obfuscation engine
shield_config.example.json ← example custom provider config
.env.example             ← configuration reference
requirements.txt         ← Python dependencies
LICENSE                  ← MIT license
```

## Custom Providers

The shield auto-detects 17 built-in LLM providers with toggle switches. Click any provider to enable/disable detection. To add a custom provider, click "+" and enter just a Name and Host — that's it.

Provider toggle states and custom providers are saved to `shield_config.json`.

## License

MIT
