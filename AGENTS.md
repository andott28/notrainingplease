## 1. Context & Search
- **Recency:** For time-sensitive tasks, explicitly state the current timestamp (`date -Is`).
- **Search Policy:** Use web search only to check live APIs or active advisories. Prioritize official vendor documentation. Cross-check >= 2 sources for safety-critical details.

## 2. Security & Operations
- **Access:** Read-only exploration by default. Dry-run remote API writes first. Never execute destructive commands.
- **Secrets:** Never print, request, or expose credentials. Avoid broad environment or SSH directory dumps. Redact output tokens.
- **Containers (Mandatory):** Never install packages on the host. Use containerized environments by default. Follow existing Dockerfile/compose workflows or create a minimal one.

## 3. Code Discipline & Verification
- **Scope:** Apply the smallest safe change addressing the root cause. Adhere to single responsibility; prefer modifying existing files over creating new ones. Do not build speculative features or broad, silent error-trapping fallbacks.
- **Verification:** Run project formatting, linting, and tests post-edit. Document the precise impact and remaining trade-offs to complete a task.

## 4. State Continuity
Maintain `.agent/CONTINUITY.md` as the canonical workspace briefing. Read it first each turn; update it only on meaningful delta changes.
- **Structure:** Categorize via `[PLANS]`, `[DECISIONS]`, `[PROGRESS]`, `[DISCOVERIES]`, and `[OUTCOMES]`.
- **Rules:** High-signal facts only (no raw logs/transcripts). Label unknowns as `UNCONFIRMED`. Explicitly supersede old history; compress aging items into `[MILESTONE]` bullets to eliminate bloat.