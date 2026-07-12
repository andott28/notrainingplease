# LLM Shield — Architecture & Decisions

## Architecture
- **Docker-containerized mitmproxy** in regular proxy mode (`--mode regular`)
- Host-side system proxy toggle (Windows registry) for clean on/off
- mitmproxy CA certificate managed per-cycle (install on start, remove on stop)
- Container isolated from host: zero residue when stopped

## Key Files
- `proxy_addon.py` — mitmproxy addon: intercepts AI provider calls, masks/unmasks content
- `semantic_masking.py` — entity detection + token substitution engine
- `semantic_obfuscation.py` — semantic-level obfuscation with codebook
- `toggle_proxy.py` — host-side utility: system proxy ON/OFF + CA management
- `start.py` — orchestrator: build image, start container, configure host
- `start.bat` / `stop.bat` — batch entry points
- `docker-compose.yml` — container service definition

## Design Decisions
- **`--mode regular` over `--mode local`**: Regular proxy mode avoids WinDivert (kernel packet interception) which is fragile on Windows, requires admin, and modifies system state. Regular mode is standard HTTP/HTTPS proxy — apps must be configured to use it.
- **Dandbox isolation**: Proxy runs in Docker container. When stopped, container is removed — zero system residue.
- **System proxy toggle**: The only host change is Windows system proxy setting (reversible via registry). Cleared on stop.
- **CA certificate per-cycle**: Added to Windows Root store on start, removed on stop. Clean cycle.
- **Provider whitelisting via config**: `shield_config.json#provider_toggles` controls which AI providers are intercepted. Non-provider traffic passes through via `next_layer` TCPLayer(ignore=True).
- **Semantic obfuscation optional**: Disabled by default (`SEMANTIC_OBFUSCATION=false`). Token substitution masking is always active.

## Toggle Behavior
- **ON**: `start.bat` → Docker container starts → CA installed → system proxy set → all HTTP/HTTPS traffic routed through container → AI traffic masked/unmasked
- **OFF**: `stop.bat` → system proxy cleared → CA removed → container stopped and removed → zero artifacts
