[PLANS]
- Test end-to-end after --mode local switch.

[DECISIONS]
- Windows local traffic interception: switched from --mode transparent (deprecated/broken) to --mode local (mitmproxy's WinDivert-based helper).
- --mode wireguard is not applicable (remote clients only, cannot intercept same-machine traffic).
- system proxy + HTTPS_PROXY env vars removed: --mode local captures ALL traffic at the packet level, no per-app config needed.
- run.bat auto-elevates via UAC (needed for mitmproxy helper + CA trust).
- mitmproxy/CA cert auto-installed via requirements.txt + venv isolation.

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

[DISCOVERIES]
- mitmproxy 12.2.3 --mode transparent is deprecated on Windows and fails with WinDivert access error.
- mitmproxy_rs bundles wireguard and local redirect modules natively.
- --mode local uses a privileged helper subprocess via mitmproxy_rs.local + WinDivert.
- OpenCode (bun/Node.js) does not respect Windows system proxy settings or HTTPS_PROXY env var at the OS level — requires packet-level interception.

[OUTCOMES]
- `python -m py_compile gui.py transparent_mode.py semantic_masking.py run.py` passes.
- Key remaining unknowns:
  1) Does --mode local actually succeed on this Win11 build? (WinDivert + helper process)
  2) Does the addon request hook fire for intercepted traffic?
  3. Does classify_provider() correctly match real LLM API traffic?
