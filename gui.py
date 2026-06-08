import os
import sys
import json
import threading
import tkinter as tk
from tkinter import ttk, messagebox
import uuid
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import transparent_mode


ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")


class App:
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("LLM Shield")
        self.root.geometry("900x600")
        self.root.resizable(False, False)

        self._transparent_manager = transparent_mode.TransparentProxyManager()
        self._provider_cache: dict[str, dict[str, object]] = {}
        self._shield_enabled = tk.BooleanVar(value=False)

        self._build_setup()
        self._build_running()
        self._show_setup()

    def _build_setup(self) -> None:
        f = ttk.Frame(self.root, padding=20)
        self._setup_frame = f

        ttk.Label(f, text="LLM Shield", font=("Segoe UI", 16, "bold")).pack(anchor="w")
        ttk.Label(f, text="").pack()

        ttk.Label(f, text="Shield Mode").pack(anchor="w")
        ttk.Label(f, text="Transparent interception and redirect layer for detected LLM traffic.").pack(anchor="w")
        ttk.Label(f, text="").pack()

        self._shield_toggle_btn = ttk.Button(f, text="Enable Shield", command=self._toggle_shield)
        self._shield_toggle_btn.pack(anchor="w")
        ttk.Label(f, text="").pack()

        ttk.Label(f, text="Status").pack(anchor="w")
        self._setup_status_var = tk.StringVar(value="Shield is off.")
        ttk.Label(f, textvariable=self._setup_status_var).pack(anchor="w")

    def _build_running(self) -> None:
        f = ttk.Frame(self.root, padding=20)
        self._running_frame = f

        ttk.Label(f, text="LLM Shield", font=("Segoe UI", 16, "bold")).pack(anchor="w")
        ttk.Label(f, text="").pack()

        ttk.Label(f, text="Shield control").pack(anchor="w")
        self._shield_status_var = tk.StringVar(value="Disabled")
        ttk.Label(f, textvariable=self._shield_status_var, foreground="green").pack(anchor="w")
        ttk.Label(f, text="").pack()

        ttk.Label(f, text="Detected providers").pack(anchor="w")
        providers_split = ttk.Panedwindow(f, orient="horizontal")
        providers_split.pack(anchor="w", fill="both", expand=True)

        provider_list_frame = ttk.Frame(providers_split)
        provider_detail_frame = ttk.Frame(providers_split)
        providers_split.add(provider_list_frame, weight=1)
        providers_split.add(provider_detail_frame, weight=2)

        self._provider_tree = ttk.Treeview(provider_list_frame, columns=("hits", "redirected"), show="headings", selectmode="browse", height=10)
        self._provider_tree.heading("hits", text="Hits")
        self._provider_tree.heading("redirected", text="Redirected")
        self._provider_tree.column("hits", width=70, anchor="center")
        self._provider_tree.column("redirected", width=90, anchor="center")
        self._provider_tree.pack(side="left", fill="both", expand=True)
        provider_tree_scroll = ttk.Scrollbar(provider_list_frame, orient="vertical", command=self._provider_tree.yview)
        provider_tree_scroll.pack(side="right", fill="y")
        self._provider_tree.config(yscrollcommand=provider_tree_scroll.set)
        self._provider_tree.bind("<<TreeviewSelect>>", self._on_provider_select)

        ttk.Label(provider_detail_frame, text="Provider details").pack(anchor="w")
        self._provider_detail_text = tk.Text(provider_detail_frame, height=12, width=60, wrap="word")
        self._provider_detail_text.pack(fill="both", expand=True)
        self._provider_detail_text.config(state="disabled")
        ttk.Label(f, text="").pack()

        btn_frame = ttk.Frame(f)
        btn_frame.pack(anchor="w")
        self._toggle_shield_btn = ttk.Button(btn_frame, text="Toggle Shield", command=self._toggle_shield)
        self._toggle_shield_btn.pack(side="left")
        self._refresh_btn = ttk.Button(btn_frame, text="Refresh Providers", command=self._refresh_providers)
        self._refresh_btn.pack(side="left", padx=(10, 0))

        self._status_var = tk.StringVar(value="Shield is disabled.")
        ttk.Label(f, textvariable=self._status_var, foreground="green").pack(anchor="w")

    def _show_setup(self) -> None:
        self._running_frame.pack_forget()
        self._setup_frame.pack(fill="both", expand=True)

    def _show_running(self) -> None:
        self._setup_frame.pack_forget()
        self._running_frame.pack(fill="both", expand=True)
        self._refresh_providers()

    def _toggle_shield(self) -> None:
        if self._transparent_manager.running:
            self._transparent_manager.stop()
            self._shield_enabled.set(False)
            self._status_var.set("Shield is disabled.")
            self._setup_status_var.set("Shield is off.")
            self._shield_status_var.set("Disabled")
            self._shield_toggle_btn.config(text="Enable Shield")
            return
        config = transparent_mode.TransparentConfig(
            api_key="",
            model=os.environ.get("NVIDIA_MODEL", "moonshotai/kimi-k2.6"),
            local_api_key=os.environ.get("LOCAL_API_KEY", "").strip(),
            protection_mode=os.environ.get("PROTECTION_MODE", "balanced"),
            strict_backend=os.environ.get("STRICT_BACKEND", "reject"),
            strict_local_url=os.environ.get("STRICT_LOCAL_URL", ""),
            strict_local_timeout_s=float(os.environ.get("STRICT_LOCAL_TIMEOUT_S", "30")),
        )
        self._transparent_manager.start(config)
        self._shield_enabled.set(True)
        self._status_var.set("Shield is enabled.")
        self._setup_status_var.set("Shield is on.")
        self._shield_status_var.set("Enabled")
        self._shield_toggle_btn.config(text="Disable Shield")
        self._show_running()

    def _poll_providers(self) -> None:
        if not self._transparent_manager.running:
            return
        self._refresh_providers()
        self.root.after(2000, self._poll_providers)

    def _refresh_providers(self) -> None:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".agent", "detected_providers.json")
        providers = {}
        if os.path.isfile(path):
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                providers = data.get("providers", {})
            except Exception as exc:
                providers = {"__error__": {"provider_id": "__error__", "error": str(exc)}}

        for item in self._provider_tree.get_children():
            self._provider_tree.delete(item)

        if isinstance(providers, dict) and providers:
            for provider_id, info in sorted(
                providers.items(),
                key=lambda item: (int(item[1].get("redirected_hits", 0)), int(item[1].get("hits", 0))),
                reverse=True,
            ):
                self._provider_tree.insert("", "end", iid=provider_id, values=(int(info.get("hits", 0)), int(info.get("redirected_hits", 0))))
            current = self._provider_tree.selection()
            if not current:
                first = self._provider_tree.get_children()
                if first:
                    self._provider_tree.selection_set(first[0])
                    self._provider_tree.focus(first[0])
                    self._show_provider_details(first[0], providers)
        else:
            self._provider_tree.insert("", "end", iid="__empty__", values=(0, 0))
            self._show_provider_details(None, providers)

        self._provider_cache = providers

    def _on_provider_select(self, event: object = None) -> None:
        selection = self._provider_tree.selection()
        if not selection:
            return
        self._show_provider_details(selection[0], getattr(self, "_provider_cache", {}))

    def _show_provider_details(self, provider_id: str | None, providers: dict[str, dict[str, object]]) -> None:
        details = []
        if not provider_id or provider_id not in providers:
            details.append("No provider selected.")
        else:
            info = providers[provider_id]
            details.append(f"Provider: {provider_id}")
            details.append(f"Hits: {info.get('hits', 0)}")
            details.append(f"Redirected: {info.get('redirected_hits', 0)}")
            last_seen = info.get("last_seen", 0)
            try:
                details.append(f"Last seen: {datetime.fromtimestamp(float(last_seen)).isoformat(sep=' ', timespec='seconds')}")
            except Exception:
                details.append(f"Last seen: {last_seen}")
            details.append("")
            details.append("Hosts:")
            for host in info.get("hosts", []):
                details.append(f"  - {host}")
            details.append("")
            details.append("Paths:")
            for path in info.get("paths", []):
                details.append(f"  - {path}")
            details.append("")
            details.append("Recent samples:")
            samples = info.get("samples", [])
            if samples:
                for sample in samples[-5:]:
                    details.append(
                        f"  - {sample.get('host', '')}{sample.get('path', '')} | {sample.get('matched_by', '')} | {sample.get('action', '')}"
                    )
            else:
                details.append("  - None")
        self._provider_detail_text.config(state="normal")
        self._provider_detail_text.delete("1.0", "end")
        self._provider_detail_text.insert("1.0", "\n".join(details))
        self._provider_detail_text.config(state="disabled")

    def run(self) -> None:
        self.root.mainloop()


if __name__ == "__main__":
    App().run()
