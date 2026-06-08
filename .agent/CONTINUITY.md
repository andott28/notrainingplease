[PLANS]
- Add a Windows transparent-capture path alongside the existing localhost OpenAI-compatible proxy.
- Reuse a shared chat-completion pipeline so both explicit clients and intercepted flows go through the same masking logic.

[DECISIONS]
- Transparent mode is Windows-only in v1.
- HTTPS inspection is enabled via the mitmproxy root CA.
- Supported transparent interception scope is OpenAI-compatible chat-style JSON requests on known LLM provider hosts.

[PROGRESS]
- Extracted shared request-processing logic into `intercept_core.py`.
- Added `transparent_mode.py` with a mitmproxy addon, provider allowlist, and a launcher/manager.
- Wired the GUI to start/stop transparent mode and added best-effort CA trust hooks.
- Added `mitmproxy` to dependencies.

[DISCOVERIES]
- The existing app was only an explicit localhost proxy before this change.
- The repo had no tests; verification is currently limited to compile-time and smoke checks.

[OUTCOMES]
- `python -m py_compile intercept_core.py proxy.py gui.py transparent_mode.py semantic_masking.py env_loader.py` passes.
- Targeted smoke check confirmed shared request handling and provider matching behavior.
