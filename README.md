# Mask Proxy

A transparent local proxy that intercepts AI chat requests, automatically detects and masks sensitive data (API keys, URLs, emails, paths, UUIDs, identifiers) before forwarding to the upstream provider, then unmaskes the response.

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

**Windows users:** Double-click `run.bat` to launch the GUI.

**Command line:**
```bash
python gui.py
```

### Setup

1. Select your **provider** (currently NVIDIA)
2. Paste your **NVIDIA API Key**
3. Click **Start**

The proxy generates a local API key and listens on `http://localhost:8787/v1`.

### Use with OpenAI Client

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8787/v1",
    api_key="sk-local-xxxx",  # shown in the GUI
)

completion = client.chat.completions.create(
    model="qwen/qwen3-coder-480b-a35b-instruct",
    messages=[{"role": "user", "content": "My password is secret123"}],
)

print(completion.choices[0].message.content)
# The proxy masks "secret123" before it reaches NVIDIA and unmaskes the response.
```

### Controls

- **Stop** — Stops the proxy
- **Change API Key** — Stops the proxy and returns to setup screen (key is saved to `.env` for next launch)

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
proxy.py                 ← HTTP proxy server
semantic_masking.py      ← masking engine
env_loader.py            ← .env file loader
.env.example             ← configuration reference
requirements.txt         ← Python dependencies
LICENSE                  ← MIT license
```

## License

MIT
