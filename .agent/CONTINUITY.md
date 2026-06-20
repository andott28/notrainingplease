[PLANS]
- Test end-to-end with semantic obfuscation enabled (proxy start, send request, verify obfuscation + unmasking).
- User should run `python test_codebook.py` to pre-generate the codebook before first shield launch.

[DECISIONS]
- Windows local traffic interception: switched from --mode transparent (deprecated/broken) to --mode local (mitmproxy's WinDivert-based helper).
- --mode wireguard is not applicable (remote clients only, cannot intercept same-machine traffic).
- system proxy + HTTPS_PROXY env vars removed: --mode local captures ALL traffic at the packet level, no per-app config needed.
- run.bat auto-elevates via UAC (needed for mitmproxy helper + CA trust).
- Semantic obfuscation is an orthogonal mode that composes AFTER entity masking.
- Response decoding (DECODE_RESPONSE) is OFF by default to avoid false-positive substitutions.
- Codebook bootstrap uses shape-key index + capped candidates (50) + length filter (±1) + 30s timeout to avoid blocking startup.
- HF_HUB_OFFLINE=1 set in addon env and _ensure_tokenizer_loaded to prevent circular dependency under WinDivert.
- First-time codebook generation runs in background thread; obfuscation disabled until codebook ready.

[PROGRESS]
- Fixed O(N²) candidate lookup: pre-build shape-key index, cap at 50 candidates, length filter ±1.
- Added HF_HUB_OFFLINE=1 to prevent tokenizer download deadlock under WinDivert.
- Added 30s bootstrap timeout to prevent blocking startup.
- Rewrote _build_record to use pre-computed token arrays (no repeated convert_ids_to_tokens).
- Added test_codebook.py standalone diagnostic tool (--diagnose flag).
- Rewrote README.md with current architecture, configuration, and troubleshooting.
- All 20 smoke tests pass (10 unit + 10 integration).
- Committed and pushed: a7f7921.

[DISCOVERIES]
- mitmproxy 12.2.3 --mode transparent is deprecated on Windows and fails with WinDivert access error.
- mitmproxy_rs bundles wireguard and local redirect modules natively.
- --mode local uses a privileged helper subprocess via mitmproxy_rs.local + WinDivert.
- OpenCode (bun/Node.js) does not respect Windows system proxy settings or HTTPS_PROXY env var at the OS level — requires packet-level interception.
- AutoTokenizer.from_pretrained() makes HTTP HEAD requests even when tokenizer is cached (update checks). Under --mode local this causes circular deadlock. Fixed by setting HF_HUB_OFFLINE=1.
- _candidate_token_ids was O(N²) for 151K vocab. Fixed with shape-key index + candidate cap.
- Sentence-transformers not installed; falls back to shape-only anchor (no embedding model needed).

[OUTCOMES]
- python tests/smoke_semantic_obfuscation.py passes (10 unit tests).
- python tests/smoke_integration.py passes (10 integration tests).
- Committed and pushed to main: a7f7921.
- Key remaining: test actual proxy interception with semantic obfuscation end-to-end.
