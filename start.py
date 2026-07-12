"""LLM Shield proxy launcher. Builds and runs the container, configures host proxy.

Usage:
    python start.py              # Start proxy (build image if needed, set system proxy)
    python start.py --no-proxy   # Start proxy without setting system proxy
    python start.py --build      # Force rebuild Docker image
"""
import argparse
import atexit
import os
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

CONTAINER_NAME = "llm-shield"
PROXY_PORT = 8923
CA_CONTAINER_PATH = "/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem"
CA_HOST_PATH = os.path.join(ROOT, ".agent", "ca-cert.pem")


def _log(msg: str) -> None:
    print(f"[LLM Shield] {msg}", flush=True)


def _docker_compose_cmd() -> list[str]:
    result = subprocess.run(["docker", "compose", "version"], capture_output=True, text=True, timeout=10)
    if result.returncode == 0:
        return ["docker", "compose"]
    return ["docker-compose"]


def _container_running() -> bool:
    result = subprocess.run(
        ["docker", "ps", "-q", "-f", f"name={CONTAINER_NAME}"],
        capture_output=True, text=True, timeout=10,
    )
    return bool(result.stdout.strip())


def _stop_existing_container() -> None:
    if _container_running():
        _log("Stopping existing container...")
        subprocess.run(["docker", "stop", CONTAINER_NAME], capture_output=True, timeout=15)
    subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True, timeout=10)


def _build_image() -> bool:
    _log("Building Docker image...")
    result = subprocess.run(
        ["docker", "build", "-t", "llm-shield:latest", "."],
        cwd=ROOT, timeout=600,
    )
    if result.returncode != 0:
        _log("Docker build failed.")
        return False
    _log("Docker image built successfully.")
    return True


def _start_container() -> bool:
    compose = _docker_compose_cmd()
    _log("Starting container via docker compose...")
    result = subprocess.run(
        [*compose, "up", "-d"],
        cwd=ROOT, timeout=60,
    )
    if result.returncode != 0:
        _log("Container start failed.")
        return False
    _log(f"Container started on port {PROXY_PORT}")
    return True


def _wait_for_proxy(timeout: float = 30.0) -> bool:
    import socket
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", PROXY_PORT), timeout=2):
                _log("Proxy is accepting connections.")
                return True
        except (ConnectionRefusedError, OSError):
            time.sleep(0.5)
    _log(f"Proxy did not become ready within {timeout}s.")
    return False


def _extract_ca_from_container() -> bool:
    _log("Extracting CA certificate from container...")
    os.makedirs(os.path.dirname(CA_HOST_PATH), exist_ok=True)
    result = subprocess.run(
        ["docker", "cp", f"{CONTAINER_NAME}:{CA_CONTAINER_PATH}", CA_HOST_PATH],
        capture_output=True, text=True, timeout=15,
    )
    if result.returncode != 0 or not os.path.isfile(CA_HOST_PATH):
        _log("Failed to extract CA certificate. Generating local CA...")
        result = subprocess.run(
            ["docker", "exec", CONTAINER_NAME, "mitmproxy-ca", "--help"],
            capture_output=True, text=True, timeout=10,
        )
        subprocess.run(
            ["docker", "exec", CONTAINER_NAME, "mitmproxy-ca", "--noninteractive"],
            capture_output=True, text=True, timeout=30,
        )
        result = subprocess.run(
            ["docker", "cp", f"{CONTAINER_NAME}:{CA_CONTAINER_PATH}", CA_HOST_PATH],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0 or not os.path.isfile(CA_HOST_PATH):
            alt_path = os.path.join(ROOT, ".agent", "mitmproxy-ca-cert.pem")
            subprocess.run(
                ["docker", "cp", f"{CONTAINER_NAME}:/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem", alt_path],
                capture_output=True, text=True, timeout=15,
            )
            if os.path.isfile(alt_path):
                shutil.move(alt_path, CA_HOST_PATH)
            else:
                _log("Could not find CA certificate in container.")
                return False
    _log(f"CA certificate saved to {CA_HOST_PATH}")
    return True


def _install_ca() -> None:
    if not os.path.isfile(CA_HOST_PATH):
        _log("No CA certificate to install.")
        return
    import subprocess as sp
    result = sp.run(
        ["certutil", "-addstore", "Root", CA_HOST_PATH],
        capture_output=True, text=True, timeout=15,
    )
    if result.returncode == 0:
        _log("CA certificate installed to Windows Root store.")
    else:
        _log(f"CA install failed: {result.stderr.strip()[:120]}")


def _set_system_proxy() -> None:
    if os.name != "nt":
        _log("Non-Windows: set HTTP_PROXY=http://127.0.0.1:8923 manually")
        return
    import winreg
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"http=127.0.0.1:{PROXY_PORT};https=127.0.0.1:{PROXY_PORT}")
    winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>")
    winreg.CloseKey(key)
    _log(f"System proxy set → 127.0.0.1:{PROXY_PORT}")


def _clear_system_proxy() -> None:
    if os.name != "nt":
        return
    import winreg
    try:
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        winreg.DeleteValue(key, "ProxyServer")
        winreg.DeleteValue(key, "ProxyOverride")
        winreg.CloseKey(key)
    except FileNotFoundError:
        pass


def _uninstall_ca() -> None:
    if not os.path.isfile(CA_HOST_PATH):
        return
    import subprocess as sp
    filename = os.path.basename(CA_HOST_PATH)
    sp.run(["certutil", "-delstore", "Root", filename], capture_output=True, timeout=15)


def _cleanup() -> None:
    _log("Shutting down...")
    _clear_system_proxy()
    _uninstall_ca()
    compose = _docker_compose_cmd()
    subprocess.run([*compose, "down"], cwd=ROOT, capture_output=True, timeout=30)
    _log("Proxy stopped.")


def main() -> None:
    parser = argparse.ArgumentParser(description="LLM Shield proxy launcher")
    parser.add_argument("--build", action="store_true", help="Force rebuild Docker image")
    parser.add_argument("--no-proxy", action="store_true", help="Start proxy without setting system proxy")
    args = parser.parse_args()

    if args.build:
        if not _build_image():
            sys.exit(1)

    _stop_existing_container()

    if not _container_running():
        if not _start_container():
            sys.exit(1)

    if not _wait_for_proxy():
        _cleanup()
        sys.exit(1)

    _extract_ca_from_container()

    atexit.register(_cleanup)

    if not args.no_proxy:
        _install_ca()
        _set_system_proxy()

    _log(f"LLM Shield is RUNNING on port {PROXY_PORT}")
    _log("Press Ctrl+C to stop.")

    try:
        while _container_running():
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        _cleanup()


if __name__ == "__main__":
    main()
