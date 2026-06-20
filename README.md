# Mask Proxy

A local privacy firewall that intercepts ALL outbound traffic to AI providers, cryptographically masks sensitive identifiers before sending to the cloud, and unmaskes on response. Works seamlessly regardless of which app generates the traffic (Go binaries, Python, Electron, CLI tools, etc.).

## How It Works

```
Your app (Cursor, ChatGPT, IDE, CLI, etc.)
  → ANY HTTP/HTTPS request to a known AI provider
    Authorization: Bearer sk-local-xxxx
    {"messages": [{"role":"user","content":"My token is sk-abc123"}]}

Mask Proxy (WinDivert driver-level capture)
  → detects provider by Host header / IP
  → masks sensitive data (API keys, paths, emails, UUIDs, etc.)
  → optionally applies semantic obfuscation (every token replaced)
  → forwards to upstream API with your real API key
  → receives the model response
  → restores all original values in the response
  → returns the clean response to your app
```

Two masking layers run in sequence:

1. **Entity masking** (`semantic_masking.py`) — regex-based detection of sensitive identifiers (paths, emails, API keys, UUIDs, variable names). Detected values are replaced with `[M] tok_N` placeholders using the Qwen tokenizer.

2. **Semantic obfuscation** (`semantic_obfuscation.py`) — every token in the message is replaced with a semantically similar token from a persisted codebook. The AI still understands the message (similar embedding space), but the raw text is unreadable to humans and log scrapers.

## Requirements

- **Python 3.10+**
- **Windows** (WinDivert driver-level capture)
- **mitmproxy >= 10.0** — proxy engine
- **transformers >= 4.30** — Qwen tokenizer
- **sentence-transformers** (optional) — better anchor embeddings for codebook
- **Tkinter** (included with Python on Windows) — GUI

## Installation

```bash
git clone https://github.com/andott28/notrainingplease.git
cd notrainingplease
pip install -r requirements.txt
```

## Quick Start

### 1. Configure `.env`

Copy `.env.example` to `.env` and fill in your API keys:

```env
NVIDIA_API_KEY=your_nvidia_api_key
HF_TOKEN=your_huggingface_token  # optional, for tokenizer download

# Masking
MASKING_STRATEGY=token_substitution
TOKEN_CIPHER_MODEL_ID=Qwen/Qwen2.5-Coder-1.5B-Instruct

# Semantic obfuscation (optional, replaces every token)
SEMANTIC_OBFUSCATION=true
SEMANTIC_OBFUSCATION_LEVEL=standard
SEMANTIC_OBFUSCATION_LOAD_ANCHOR_BODY=false
SEMANTIC_OBFUSCATION_DECODE_RESPONSE=true

# Proxy
PROXY_HOST=127.0.0.1
PROXY_PORT=8923
```

### 2. Launch

**Windows:** Double-click `run.bat`

**Command line:**
```bash
python run.py
```

### 3. Enable Shield

Click **Enable Shield** in the GUI. The proxy intercepts all traffic at the WinDivert driver level — no app restart needed, no system proxy configuration required.

## Architecture

### Traffic Interception

The proxy uses `mitmproxy_rs` with WinDivert (`--mode local`) to capture packets at the network driver level. This means:

- Works for ANY app (Go binaries, Python, Electron, CLI tools)
- No system proxy configuration needed
- No app cooperation required
- Intercepts both HTTP and HTTPS traffic

The addon (`transparent_mode.py`) registers known AI provider hostnames/IPs and redirects matching traffic through the proxy for masking.

### Entity Masking (`semantic_masking.py`)

- Regex patterns detect sensitive identifiers: file paths, emails, API keys, UUIDs, variable names, JWTs, etc.
- Detected values are tokenized using the Qwen tokenizer
- Each token is mapped to a deterministic substitute using `RequestVault`
- Protected identifiers (Python/JS keywords, builtins) are never masked
- The `[M]` marker prefix signals that masking was applied

### Semantic Obfuscation (`semantic_obfuscation.py`)

- On first startup, builds a codebook mapping every vocabulary token to a semantically similar replacement
- Uses cosine similarity from anchor embeddings to find replacements
- Three anchor backends: (1) model body embeddings, (2) sentence-transformers, (3) shape-only fallback
- Codebook is persisted to `.agent/semantic_codebook.json` and reused across restarts
- Three levels: `light` (4 neighbors), `standard` (12), `aggressive` (32)

### Response Unmasking

- On the response path, the proxy reverses both layers
- Entity masking placeholders are restored to original values
- If `DECODE_RESPONSE=true`, semantic obfuscation is also reversed

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `NVIDIA_API_KEY` | — | Your NVIDIA API key |
| `HF_TOKEN` | — | HuggingFace token (for tokenizer download) |
| `PROXY_HOST` | `127.0.0.1` | Proxy bind address |
| `PROXY_PORT` | `8923` | Proxy port |
| `MASKING_STRATEGY` | `token_substitution` | `token_substitution` or `opaque` |
| `TOKEN_CIPHER_MODEL_ID` | `Qwen/Qwen2.5-Coder-1.5B-Instruct` | Tokenizer model |
| `SEMANTIC_OBFUSCATION` | `false` | Enable every-token obfuscation |
| `SEMANTIC_OBFUSCATION_LEVEL` | `standard` | `light`, `standard`, or `aggressive` |
| `SEMANTIC_OBFUSCATION_ANCHOR_MODEL` | same as tokenizer | Anchor model for embeddings |
| `SEMANTIC_OBFUSCATION_LOAD_ANCHOR_BODY` | `true` | Download model body (~3GB) |
| `SEMANTIC_OBFUSCATION_DECODE_RESPONSE` | `false` | Reverse obfuscation on response |
| `SEMANTIC_OBFUSCATION_INCLUDE_SYSTEM` | `false` | Obfuscate system messages too |
| `SEMANTIC_OBFUSCATION_CODEBOOK_PATH` | `.agent/semantic_codebook.json` | Codebook storage path |

## First Startup

On first launch with `SEMANTIC_OBFUSCATION=true`:

1. The Qwen tokenizer is loaded from cache (or downloaded if not present)
2. The codebook bootstrap runs in a background thread (up to 30s)
3. During bootstrap, obfuscation is disabled — only entity masking runs
4. Once the codebook is built, it's saved to disk and reused on subsequent startups
5. Subsequent startups load the cached codebook instantly

To pre-generate the codebook before first launch:
```bash
python test_codebook.py
```

## Troubleshooting

### Proxy blocks all traffic / "Connect Timeout"

- Check that port 8923 is not in use: `netstat -ano | findstr 8923`
- Run as Administrator (WinDivert requires elevated privileges)
- Check `.agent/addon_debug.log` for addon lifecycle events

### Tokenizer download hangs

The addon sets `HF_HUB_OFFLINE=1` to prevent circular dependency when running under WinDivert. If the tokenizer isn't cached:

1. Temporarily run with `--mode regular` to download the tokenizer
2. Or manually: `python -c "from transformers import AutoTokenizer; AutoTokenizer.from_pretrained('Qwen/Qwen2.5-Coder-1.5B-Instruct')"`

### Codebook bootstrap is slow

First-time codebook generation processes 151K+ tokens. With `LOAD_ANCHOR_BODY=false` (shape-only fallback), it completes in ~30s. With a model body or sentence-transformers, it may take longer but produces better quality mappings.

### Semantic obfuscation not working

Check diagnostics:
```bash
python -c "
import sys; sys.path.insert(0, '.')
from semantic_obfuscation import SemanticCodebook
# Check .agent/semantic_codebook.json exists and is valid JSON
import json
print(json.dumps(json.load(open('.agent/semantic_codebook.json'))['stats'], indent=2))
"
```

## Project Structure

```
run.bat                   ← double-click to launch (Windows)
run.py                    ← entry point
gui.py                    ← Tkinter GUI
transparent_mode.py       ← mitmproxy addon + provider registry
semantic_masking.py       ← entity masking engine (regex + Qwen tokenizer)
semantic_obfuscation.py   ← every-token semantic obfuscation engine
test_codebook.py          ← standalone codebook bootstrap test
requirements.txt          ← Python dependencies
.env.example              ← configuration reference
.agent/
  addon_debug.log         ← addon lifecycle debug log
  semantic_codebook.json  ← persisted codebook (auto-generated)
  live_stats.json         ← live hit/redirection counts
tests/
  smoke_semantic_obfuscation.py  ← obfuscator unit tests
  smoke_integration.py           ← addon + obfuscator integration tests
```

## License

MIT
