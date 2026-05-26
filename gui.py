import os
import sys
import threading
import tkinter as tk
from tkinter import ttk
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import proxy


ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")


def _load_saved_key() -> str:
    if not os.path.isfile(ENV_PATH):
        return ""
    with open(ENV_PATH, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line.startswith("NVIDIA_API_KEY="):
                raw = line.split("=", 1)[1].strip().strip("\"'")
                if raw:
                    return raw
    return ""


def _save_key(key: str) -> None:
    lines = []
    found = False
    if os.path.isfile(ENV_PATH):
        with open(ENV_PATH, encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith("NVIDIA_API_KEY="):
                    lines.append(f"NVIDIA_API_KEY={key}\n")
                    found = True
                else:
                    lines.append(line)
    if not found:
        lines.append(f"NVIDIA_API_KEY={key}\n")
    with open(ENV_PATH, "w", encoding="utf-8") as f:
        f.writelines(lines)


class App:
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("Mask Proxy")
        self.root.geometry("540x440")
        self.root.resizable(False, False)

        self._proxy_thread: threading.Thread | None = None

        self._build_setup()
        self._build_running()
        self._show_setup()

    def _build_setup(self) -> None:
        f = ttk.Frame(self.root, padding=20)
        self._setup_frame = f

        ttk.Label(f, text="Mask Proxy", font=("Segoe UI", 16, "bold")).pack(anchor="w")
        ttk.Label(f, text="").pack()

        ttk.Label(f, text="Provider").pack(anchor="w")
        self._provider_var = tk.StringVar(value="nvidia")
        ttk.Combobox(f, textvariable=self._provider_var, values=["nvidia"], state="readonly", width=30).pack(anchor="w", fill="x")
        ttk.Label(f, text="").pack()

        ttk.Label(f, text="API Key").pack(anchor="w")
        key_row = ttk.Frame(f)
        key_row.pack(anchor="w", fill="x")
        self._api_key_var = tk.StringVar(value=_load_saved_key())
        self._api_key_visible = tk.BooleanVar(value=False)
        self._api_key_entry = ttk.Entry(key_row, textvariable=self._api_key_var, show="*", width=40)
        self._api_key_entry.pack(side="left", fill="x", expand=True)
        self._toggle_key_btn = ttk.Button(key_row, text="\U0001f441", width=3, command=self._toggle_key_visibility)
        self._toggle_key_btn.pack(side="left", padx=(4, 0))
        if not self._api_key_var.get():
            self._api_key_entry.insert(0, "nvapi-...")
            self._api_key_entry.config(foreground="gray")
            self._api_key_entry.bind("<FocusIn>", self._on_key_focus, "+")
        ttk.Label(f, text="").pack()

        self._start_btn = ttk.Button(f, text="Start", command=self._start)
        self._start_btn.pack(anchor="w")

        self._error_var = tk.StringVar()
        ttk.Label(f, textvariable=self._error_var, foreground="red").pack(anchor="w")

    def _on_key_focus(self, event: object = None) -> None:
        if self._api_key_var.get() == "nvapi-...":
            self._api_key_var.set("")
            self._api_key_entry.config(foreground="black")

    def _toggle_key_visibility(self) -> None:
        self._api_key_visible.set(not self._api_key_visible.get())
        self._api_key_entry.config(show="" if self._api_key_visible.get() else "*")

    def _build_running(self) -> None:
        f = ttk.Frame(self.root, padding=20)
        self._running_frame = f

        ttk.Label(f, text="Mask Proxy", font=("Segoe UI", 16, "bold")).pack(anchor="w")
        ttk.Label(f, text="").pack()

        ttk.Label(f, text="Local API Key").pack(anchor="w")
        self._local_key_var = tk.StringVar()
        local_key_entry = ttk.Entry(f, textvariable=self._local_key_var, width=50, state="readonly")
        local_key_entry.pack(anchor="w", fill="x")
        ttk.Label(f, text="").pack()

        ttk.Label(f, text="Code snippet").pack(anchor="w")
        self._snippet_text = tk.Text(f, height=8, width=60, wrap="none")
        self._snippet_text.pack(anchor="w", fill="both")
        ttk.Label(f, text="").pack()

        btn_frame = ttk.Frame(f)
        btn_frame.pack(anchor="w")
        self._stop_btn = ttk.Button(btn_frame, text="Stop", command=self._stop)
        self._stop_btn.pack(side="left")
        self._change_key_btn = ttk.Button(btn_frame, text="Change API Key", command=self._change_key)
        self._change_key_btn.pack(side="left", padx=(10, 0))

        self._status_var = tk.StringVar(value="Proxy running on 127.0.0.1:8787")
        ttk.Label(f, textvariable=self._status_var, foreground="green").pack(anchor="w")

    def _show_setup(self) -> None:
        self._running_frame.pack_forget()
        self._setup_frame.pack(fill="both", expand=True)

    def _show_running(self) -> None:
        self._setup_frame.pack_forget()
        self._running_frame.pack(fill="both", expand=True)

    def _start(self) -> None:
        api_key = self._api_key_var.get().strip()
        if not api_key or api_key == "nvapi-...":
            self._error_var.set("Enter your NVIDIA API key.")
            return
        self._error_var.set("")
        _save_key(api_key)

        local_token = "sk-local-" + uuid.uuid4().hex[:12]
        os.environ["NVIDIA_API_KEY"] = api_key
        os.environ["LOCAL_API_KEY"] = local_token

        self._local_key_var.set(local_token)
        snippet = (
            "from openai import OpenAI\n\n"
            "client = OpenAI(\n"
            '    base_url="http://localhost:8787/v1",\n'
            f'    api_key="{local_token}",\n'
            ")\n"
        )
        self._snippet_text.delete("1.0", "end")
        self._snippet_text.insert("1.0", snippet)

        self._proxy_thread = threading.Thread(target=lambda: proxy.run(quiet=True), daemon=True)
        self._proxy_thread.start()

        self._show_running()

    def _stop(self) -> None:
        proxy.stop()
        self._show_setup()

    def _change_key(self) -> None:
        proxy.stop()
        self._show_setup()
        self._api_key_entry.focus()

    def run(self) -> None:
        self.root.mainloop()


if __name__ == "__main__":
    App().run()
