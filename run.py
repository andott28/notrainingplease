import os
import subprocess
import sys


def ensure_deps() -> None:
    req_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")
    if not os.path.isfile(req_path):
        return
    missing = []
    for pkg in ("mitmproxy", "transformers"):
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"Installing missing dependencies ({', '.join(missing)}) into virtual environment...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", req_path])


def main() -> None:
    root = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, root)
    ensure_deps()
    from gui import App

    App().run()


if __name__ == "__main__":
    main()
