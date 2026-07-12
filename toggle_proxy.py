"""Host-side proxy toggle: set/clear Windows system proxy + manage mitmproxy CA certificate.

Usage:
    python toggle_proxy.py on [--ca PATH_TO_CA_CERT]
    python toggle_proxy.py off
    python toggle_proxy.py status
"""
import argparse
import os
import subprocess
import sys

INTERNET_SETTINGS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


def _check_admin() -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _set_system_proxy(host: str, port: int) -> None:
    if os.name != "nt":
        print("[toggle] Non-Windows: skipping system proxy set (set HTTP_PROXY env var instead)")
        return
    import winreg
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"http={host}:{port};https={host}:{port}")
    winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>")
    winreg.CloseKey(key)
    print(f"[toggle] System proxy set → {host}:{port}")


def _clear_system_proxy() -> None:
    if os.name != "nt":
        print("[toggle] Non-Windows: skipping system proxy clear")
        return
    import winreg
    try:
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        try:
            winreg.DeleteValue(key, "ProxyServer")
        except FileNotFoundError:
            pass
        try:
            winreg.DeleteValue(key, "ProxyOverride")
        except FileNotFoundError:
            pass
        winreg.CloseKey(key)
    except FileNotFoundError:
        pass
    print("[toggle] System proxy cleared")


def _get_proxy_status() -> dict:
    if os.name != "nt":
        return {"enabled": False, "server": "", "platform": "non-windows"}
    import winreg
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_READ)
        enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
        server, _ = winreg.QueryValueEx(key, "ProxyServer")
        winreg.CloseKey(key)
        return {"enabled": bool(enabled), "server": str(server), "platform": "windows"}
    except FileNotFoundError:
        return {"enabled": False, "server": "", "platform": "windows"}


def _install_ca(cert_path: str) -> None:
    if not os.path.isfile(cert_path):
        print(f"[toggle] CA certificate not found: {cert_path}")
        return
    if os.name != "nt":
        print("[toggle] Non-Windows: skipping CA install")
        return
    result = subprocess.run(
        ["certutil", "-addstore", "Root", cert_path],
        capture_output=True, text=True, timeout=15,
    )
    if result.returncode == 0:
        print(f"[toggle] CA certificate installed to Windows Root store")
    else:
        print(f"[toggle] CA install failed: {result.stderr.strip()}")


def _uninstall_ca(cert_path: str) -> None:
    if not os.path.isfile(cert_path):
        return
    if os.name != "nt":
        print("[toggle] Non-Windows: skipping CA uninstall")
        return
    filename = os.path.basename(cert_path)
    result = subprocess.run(
        ["certutil", "-delstore", "Root", filename],
        capture_output=True, text=True, timeout=15,
    )
    if result.returncode == 0:
        print(f"[toggle] CA certificate removed from Windows Root store")
    else:
        print(f"[toggle] CA removal failed (may already be removed): {result.stderr.strip()[:100]}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Toggle LLM Shield system proxy")
    sub = parser.add_subparsers(dest="command")

    on_cmd = sub.add_parser("on", help="Enable proxy")
    on_cmd.add_argument("--ca", type=str, default="", help="Path to mitmproxy CA .pem file")
    on_cmd.add_argument("--host", type=str, default="127.0.0.1")
    on_cmd.add_argument("--port", type=int, default=8923)

    sub.add_parser("off", help="Disable proxy")
    sub.add_parser("status", help="Show proxy status")

    args = parser.parse_args()

    if args.command == "on":
        _set_system_proxy(args.host, args.port)
        if args.ca:
            _install_ca(args.ca)
    elif args.command == "off":
        _clear_system_proxy()
        cert_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".agent", "ca-cert.pem")
        if os.path.isfile(cert_path):
            _uninstall_ca(cert_path)
    elif args.command == "status":
        status = _get_proxy_status()
        print(f"Proxy: {'ON' if status['enabled'] else 'OFF'}")
        if status["server"]:
            print(f"Server: {status['server']}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
