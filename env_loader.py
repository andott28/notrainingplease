from pathlib import Path
import os


def load_dotenv(path: str = ".env", override: bool = False) -> dict[str, str]:
    p = Path(path)
    loaded: dict[str, str] = {}
    if not p.exists():
        return loaded
    for raw in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"'")
        if key and (override or key not in os.environ):
            os.environ[key] = value
            loaded[key] = value
    return loaded
