[PLANS]
- Test end-to-end after --mode local switch.

[DECISIONS]
- Windows local traffic interception: switched from --mode transparent (deprecated/broken) to --mode local (mitmproxy's WinDivert-based helper).
- --mode wireguard is not applicable (remote clients only, cannot intercept same-machine traffic).
- system proxy + HTTPS_PROXY env vars removed: --mode local captures ALL traffic at the packet level, no per-app config needed.
- run.bat auto-elevates via UAC (needed for mitmproxy helper + CA trust).
- mitmproxy/CA cert auto-installed via requirements.txt + venv isolation.
- Semantic obfuscation is an orthogonal mode that composes AFTER entity masking in `TransparentAddon.request` and AFTER unmasking in `TransparentAddon.response`. It does not replace or alter existing masking behavior.
- Response decoding (DECODE_RESPONSE) is OFF by default to avoid false-positive substitutions on common English tokens whose ID collides with a prompt surrogate. User can opt in via env var.
- System messages are left intact by default; SEMANTIC_OBFUSCATION_INCLUDE_SYSTEM is opt-in to keep any future system note readable.
- Anchor embedding model defaults to TOKEN_CIPHER_MODEL_ID; user can override to a smaller model via SEMANTIC_OBFUSCATION_LOAD_ANCHOR_BODY=false.
- Codebook is persisted to `.agent/semantic_codebook.json` (matches existing `.agent/` convention).

[PROGRESS]
- Added OpenCode Zen and OpenCode Go to provider registry.
- Fixed mitmdump command to use venv's sys.executable (was using global python).
- Switched from regular proxy mode to --mode local (packet-level interception on Windows).
- Added _cleanup_orphan_mitmdump() to kill stale processes on start.
- Added window-close handler to stop proxy on app exit (no orphan processes).
- Made DISCOVERY_PATH absolute (was relative -- working directory mismatch risk).
- Made error popup centered, copyable, with monospace font.
- Added stderr capture to .agent/mitmproxy.log for debugging addon errors.
- Replaced messagebox with custom Toplevel dialog (selectable/copyable text).
- Implemented semantic obfuscation layer (`semantic_obfuscation.py`) with `SemanticCodebook` (persistent random codebook in vocab+embedding space) and `SemanticObfuscator` (token-level encode + optional decode).
- Added `RequestVault.semantic_forward` / `semantic_reverse` / `semantic_tokens_processed` / `semantic_tokens_unmapped` fields, plus `MaskingEngine.get_tokenizer()` and `tokenizer_loaded()` accessors.
- Wired obfuscator into `TransparentAddon.__init__` (constructs from env), `.request` (after mask_message per message), and `.response` (calls `engine.unmask_response` and optionally `obfuscator.decode_response`).
- Extended `TransparentConfig` with 7 new fields and propagated them as env vars in `TransparentProxyManager.start`.
- Updated `gui.py` `_async_start_shield` to read SEMANTIC_OBFUSCATION* from env and pass to `TransparentConfig`.
- Added 7 new env vars (SEMANTIC_OBFUSCATION*) to `.env.example` and a "Semantic Obfuscation" section to README.md.
- Two smoke tests in `tests/`: `smoke_semantic_obfuscation.py` (unit-level) and `smoke_integration.py` (integration with pulled `TransparentAddon` flow). Both pass on the pulled code.

[DISCOVERIES]
- mitmproxy 12.2.3 --mode transparent is deprecated on Windows and fails with WinDivert access error.
- mitmproxy_rs bundles wireguard and local redirect modules natively.
- --mode local uses a privileged helper subprocess via mitmproxy_rs.local + WinDivert.
- OpenCode (bun/Node.js) does not respect Windows system proxy settings or HTTPS_PROXY env var at the OS level — requires packet-level interception.
- The pulled `TransparentAddon.response` hook previously only popped the vault without unmasking the response; this work also adds the missing `engine.unmask_response` call to make round-trip masking functional.

[OUTCOMES]
- `python -m py_compile gui.py transparent_mode.py semantic_masking.py semantic_obfuscation.py run.py` passes.
- `python tests/smoke_semantic_obfuscation.py` passes (unit tests for codebook, encode/decode, vault, diagnostics, serialization).
- `python tests/smoke_integration.py` passes (request hook masks+obfuscates, response hook unmask+decode, env var passthrough, no regression for non-registered providers / non-POST methods).
- `TransparentConfig` defaults remain backward-compatible: `semantic_obfuscation=False` means existing users see no behavior change.
- Key remaining unknowns:
  1) Does --mode local actually succeed on this Win11 build? (WinDivert + helper process)
  2) Does the addon request hook fire for intercepted traffic?
  3. Does classify_provider() correctly match real LLM API traffic?
