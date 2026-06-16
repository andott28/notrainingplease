import json
import os
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import ttk, messagebox
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import transparent_mode

BG, BG_LIGHT, BG_HOVER = "#1a1b26", "#24283b", "#2f3347"
FG, FG_DIM, ACCENT, ACCENT_DIM = "#c0caf5", "#565f89", "#9ece6a", "#3d5941"
TOGGLE_ON, TOGGLE_OFF, DOT_ON, DOT_OFF = "#9ece6a", "#3b3f57", "#9ece6a", "#565f89"

def draw_shield(canvas: tk.Canvas, cx: int, cy: int, size: int, color: str) -> None:
    s = size
    top, bot, mid = cy - s * 0.45, cy + s * 0.45, cy + s * 0.05
    left, right = cx - s * 0.38, cx + s * 0.38
    canvas.delete("shield")
    points = [cx, top, right, top + s * 0.18, right, mid, cx, bot, left, mid, left, top + s * 0.18]
    canvas.create_polygon(points, fill=color, outline="", tags="shield")

def draw_toggle(canvas: tk.Canvas, x: int, y: int, on: bool) -> None:
    canvas.delete("toggle")
    w, h = 40, 20
    r = h // 2
    color = TOGGLE_ON if on else TOGGLE_OFF
    canvas.create_arc(x, y, x + h, y + h, start=90, extent=180, fill=color, outline="", tags="toggle")
    canvas.create_arc(x + w - h, y, x + w, y + h, start=270, extent=180, fill=color, outline="", tags="toggle")
    canvas.create_rectangle(x + r, y, x + w - r, y + h, fill=color, outline="", tags="toggle")
    knob_x = x + w - r if on else x + r
    canvas.create_oval(knob_x - 7, y + 3, knob_x + 7, y + h - 3, fill="#c0caf5", outline="", tags="toggle")

class App:
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("LLM Shield")
        self.root.geometry("520x640")
        self.root.resizable(False, False)
        self.root.configure(bg=BG)

        self._manager = transparent_mode.TransparentProxyManager()
        self._shield_on = tk.BooleanVar(value=False)
        self._toggles: dict[str, tk.BooleanVar] = {}
        self._build_ui()
        self._load_toggles()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _on_close(self) -> None:
        if self._shield_on.get():
            self._stop_shield()
        self.root.destroy()

    def _build_ui(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", background=BG, foreground=FG, fieldbackground=BG_LIGHT)
        style.configure("TFrame", background=BG)
        style.configure("Title.TLabel", font=("Segoe UI", 18, "bold"), background=BG, foreground=FG)
        style.configure("Sub.TLabel", font=("Segoe UI", 10), background=BG, foreground=FG_DIM)
        style.configure("Status.TLabel", font=("Segoe UI", 11), background=BG, foreground=ACCENT)
        style.configure("Provider.TLabel", font=("Segoe UI", 11), background=BG_LIGHT, foreground=FG)
        style.configure("Dim.TLabel", font=("Segoe UI", 9), background=BG, foreground=FG_DIM)
        style.configure("Add.TButton", font=("Segoe UI", 12, "bold"), foreground=ACCENT, background=BG_LIGHT)
        style.configure("ShieldOff.TButton", font=("Segoe UI", 12, "bold"), foreground=FG, background=BG_HOVER)
        style.configure("Shield.TButton", font=("Segoe UI", 12, "bold"), foreground=FG, background=ACCENT_DIM)

        top = ttk.Frame(self.root)
        top.pack(fill="x", padx=20, pady=(16, 0))

        self._shield_canvas = tk.Canvas(top, width=48, height=48, bg=BG, highlightthickness=0)
        self._shield_canvas.pack(side="left")
        draw_shield(self._shield_canvas, 24, 24, 48, FG_DIM)

        title_frame = ttk.Frame(top)
        title_frame.pack(side="left", padx=(10, 0), fill="x", expand=True)
        ttk.Label(title_frame, text="LLM Shield", style="Title.TLabel").pack(anchor="w")
        self._status_label = ttk.Label(title_frame, text="Shield off", style="Sub.TLabel")
        self._status_label.pack(anchor="w")

        self.telemetry_frame = ttk.Frame(title_frame)
        self.telemetry_frame.pack(anchor="w", pady=(4, 0))

        self._hits_label = ttk.Label(self.telemetry_frame, text="Hits: 0", font=("Segoe UI", 9, "bold"), foreground=FG)
        self._hits_label.pack(side="left", padx=(0, 10))

        self._redir_label = ttk.Label(self.telemetry_frame, text="Masked Redirections: 0", font=("Segoe UI", 9, "bold"), foreground=ACCENT)
        self._redir_label.pack(side="left")

        self._shield_btn = ttk.Button(top, text="Enable", style="ShieldOff.TButton", command=self._toggle_shield, width=10)
        self._shield_btn.pack(side="right")

        sep = tk.Frame(self.root, height=1, bg=FG_DIM)
        sep.pack(fill="x", padx=20, pady=(12, 0))

        prov_header = ttk.Frame(self.root)
        prov_header.pack(fill="x", padx=20, pady=(12, 0))
        ttk.Label(prov_header, text="Active Providers", style="Sub.TLabel", font=("Segoe UI", 10, "bold")).pack(side="left")
        ttk.Button(prov_header, text="+", style="Add.TButton", width=3, command=self._add_provider_dialog).pack(side="right")

        list_frame = tk.Frame(self.root, bg=BG_LIGHT, highlightthickness=1, highlightbackground=FG_DIM)
        list_frame.pack(fill="both", expand=True, padx=20, pady=(8, 16))

        canvas = tk.Canvas(list_frame, bg=BG_LIGHT, highlightthickness=0)
        scrollbar = tk.Scrollbar(list_frame, orient="vertical", command=canvas.yview)
        self._provider_frame = tk.Frame(canvas, bg=BG_LIGHT)

        self._provider_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self._provider_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.stats_file = Path(__file__).parent / ".agent" / "live_stats.json"
        self._poll_telemetry_metrics()

    def _load_toggles(self) -> None:
        saved = transparent_mode.load_provider_toggles()
        all_providers = transparent_mode.get_merged_registry(include_disabled=True)
        for pid in all_providers:
            if pid not in self._toggles:
                self._toggles[pid] = tk.BooleanVar(value=saved.get(pid, True))
        self._rebuild_provider_list()

    def _rebuild_provider_list(self) -> None:
        for w in self._provider_frame.winfo_children(): w.destroy()
        all_providers = transparent_mode.get_merged_registry(include_disabled=True)
        
        for pid, pdef in all_providers.items():
            row = tk.Frame(self._provider_frame, bg=BG_LIGHT)
            row.pack(fill="x", padx=4, pady=2)

            lbl = ttk.Label(row, text=pdef.name, style="Provider.TLabel")
            lbl.pack(side="left", padx=10, pady=8)

            tc = tk.Canvas(row, width=40, height=20, bg=BG_LIGHT, highlightthickness=0, cursor="hand2")
            tc.pack(side="right", padx=10, pady=8)
            is_on = self._toggles[pid].get()
            draw_toggle(tc, 0, 0, is_on)

            def make_click_callback(p_id=pid, canvas_obj=tc):
                return lambda e: self._on_toggle_click(p_id, canvas_obj)

            tc.bind("<Button-1>", make_click_callback())

    def _on_toggle_click(self, pid: str, canvas: tk.Canvas) -> None:
        new_val = not self._toggles[pid].get()
        self._toggles[pid].set(new_val)
        draw_toggle(canvas, 0, 0, new_val)
        toggles = {k: v.get() for k, v in self._toggles.items()}
        transparent_mode.save_provider_toggles(toggles)

    def _toggle_shield(self) -> None:
        if self._shield_on.get():
            self._stop_shield()
        else:
            self._shield_btn.config(state="disabled")
            threading.Thread(target=self._async_start_shield, daemon=True).start()

    def _async_start_shield(self) -> None:
        strategy = os.environ.get("MASKING_STRATEGY", "token_substitution")
        validation_error = transparent_mode.validate_masking_engine(strategy)
        if validation_error:
            self.root.after(0, lambda: messagebox.showerror("Masking Engine Error", validation_error))
            self.root.after(0, lambda: self._shield_btn.config(state="normal"))
            return
        sem_enabled = os.environ.get("SEMANTIC_OBFUSCATION", "false").strip().lower() in {
            "1", "true", "yes", "on",
        }
        sem_level = os.environ.get("SEMANTIC_OBFUSCATION_LEVEL", "standard").strip().lower() or "standard"
        sem_anchor = os.environ.get("SEMANTIC_OBFUSCATION_ANCHOR_MODEL", "").strip()
        sem_codebook_path = os.environ.get(
            "SEMANTIC_OBFUSCATION_CODEBOOK_PATH", ".agent/semantic_codebook.json"
        ).strip()
        sem_include_system = os.environ.get("SEMANTIC_OBFUSCATION_INCLUDE_SYSTEM", "false").strip().lower() in {
            "1", "true", "yes", "on",
        }
        sem_load_body = os.environ.get("SEMANTIC_OBFUSCATION_LOAD_ANCHOR_BODY", "true").strip().lower() in {
            "1", "true", "yes", "on",
        }
        sem_decode_response = os.environ.get("SEMANTIC_OBFUSCATION_DECODE_RESPONSE", "false").strip().lower() in {
            "1", "true", "yes", "on",
        }
        config = transparent_mode.TransparentConfig(
            protection_mode="balanced",
            masking_strategy=strategy,
            semantic_obfuscation=sem_enabled,
            semantic_obfuscation_level=sem_level,
            semantic_obfuscation_anchor_model=sem_anchor,
            semantic_obfuscation_codebook_path=sem_codebook_path,
            semantic_obfuscation_include_system=sem_include_system,
            semantic_obfuscation_load_anchor_body=sem_load_body,
            semantic_obfuscation_decode_response=sem_decode_response,
        )
        try:
            self._manager.start(config)
            time.sleep(1.5)  # Let mitmdump bind cleanly backgrounded
            if self._manager.running:
                self.root.after(0, self._sync_start_success)
            else:
                self.root.after(0, lambda: messagebox.showerror("Error", "Proxy process crashed."))
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", str(e)))

    def _sync_start_success(self) -> None:
        self._shield_on.set(True)
        self._shield_btn.config(text="Disable", style="Shield.TButton", state="normal")
        self._status_label.config(text="Shield active", style="Status.TLabel")
        draw_shield(self._shield_canvas, 24, 24, 48, ACCENT)

    def _stop_shield(self) -> None:
        self._manager.stop()
        self._shield_on.set(False)
        self._shield_btn.config(text="Enable", style="ShieldOff.TButton")
        self._status_label.config(text="Shield off", style="Sub.TLabel")
        draw_shield(self._shield_canvas, 24, 24, 48, FG_DIM)

    def _poll_telemetry_metrics(self) -> None:
        if self._shield_on.get() and self.stats_file.is_file():
            try:
                stats = json.loads(self.stats_file.read_text(encoding="utf-8"))
                hits = stats.get("hits", 0)
                redirections = stats.get("redirections", 0)
                self._hits_label.config(text=f"Hits: {hits}")
                self._redir_label.config(text=f"Masked Redirections: {redirections}")
            except Exception:
                pass
        else:
            if not self._shield_on.get():
                self._hits_label.config(text="Hits: 0")
                self._redir_label.config(text="Masked Redirections: 0")
                if self.stats_file.is_file():
                    try: self.stats_file.unlink()
                    except Exception: pass
        self.root.after(500, self._poll_telemetry_metrics)

    def _add_provider_dialog(self) -> None:
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Domain Filter")
        dialog.geometry("360x180")
        dialog.configure(bg=BG)
        dialog.grab_set()

        ttk.Label(dialog, text="Filter Label", style="Sub.TLabel").pack(anchor="w", padx=20, pady=(10,2))
        name_ent = tk.Entry(dialog, bg=BG_LIGHT, fg=FG, insertbackground=FG, relief="flat")
        name_ent.pack(fill="x", padx=20)

        ttk.Label(dialog, text="Target URL Host Domain", style="Sub.TLabel").pack(anchor="w", padx=20, pady=(10,2))
        host_ent = tk.Entry(dialog, bg=BG_LIGHT, fg=FG, insertbackground=FG, relief="flat")
        host_ent.pack(fill="x", padx=20)

        def append_provider():
            n, h = name_ent.get().strip(), host_ent.get().strip()
            if n and h:
                pid = n.lower().replace(" ", "_")
                p_dict = transparent_mode.load_user_providers()
                p_dict[pid] = transparent_mode.ProviderDef(id=pid, name=n, hosts=(h,), paths=("/chat",))
                transparent_mode.save_user_providers(p_dict)
                self._toggles[pid] = tk.BooleanVar(value=True)
                self._load_toggles()
                dialog.destroy()

        tk.Button(dialog, text="Add Filter", bg=ACCENT_DIM, fg=FG, command=append_provider, relief="flat").pack(pady=15)

    def run(self) -> None:
        self.root.mainloop()

if __name__ == "__main__":
    App().run()