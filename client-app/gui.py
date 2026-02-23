"""
PKI Secure Update Client – Tkinter GUI
=======================================
Provides a user-facing interface that delegates all security-sensitive
operations to updater.py (UpdateClient class).

UI features:
  - Installed version / latest version display
  - "Check for Updates" button
  - "Download & Install" button (enabled only when update available)
  - "Open Install Folder" button
  - Scrollable real-time log panel
  - Popup notifications for update available / success / failure
"""

import os
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk
from urllib.error import HTTPError, URLError

from updater import UpdateClient, UpdateError

# ---------------------------------------------------------------------------
# Configuration – edit these to match your environment
# ---------------------------------------------------------------------------
SERVER_BASE   = "http://192.168.56.103:9000"
CA_CERT_PATH  = Path("./ca_cert.pem")       # Trust anchor – NEVER download from server
DOWNLOADS_DIR = Path("./downloads")
INSTALL_DIR   = Path("./installed")
STATE_PATH    = Path("./client_state.json")
# ---------------------------------------------------------------------------

PALETTE = {
    "bg":       "#1e1e2e",
    "surface":  "#2a2a3e",
    "accent":   "#7c3aed",
    "accent2":  "#10b981",
    "danger":   "#ef4444",
    "text":     "#e2e8f0",
    "subtext":  "#94a3b8",
    "logbg":    "#12121c",
}


class UpdateClientApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PKI Secure Update Client v2.0")
        self.geometry("720x500")
        self.resizable(False, False)
        self.configure(bg=PALETTE["bg"])

        # Bootstrap UpdateClient
        for d in (DOWNLOADS_DIR, INSTALL_DIR):
            d.mkdir(parents=True, exist_ok=True)

        self.client = UpdateClient(
            server_base   = SERVER_BASE,
            ca_cert_path  = CA_CERT_PATH,
            downloads_dir = DOWNLOADS_DIR,
            install_dir   = INSTALL_DIR,
            state_path    = STATE_PATH,
        )

        self._latest_release = None
        self._build_ui()
        self._refresh_version_labels()

        # Auto-check on launch
        self._async(self._do_check)

    # ── UI construction ──────────────────────────────────────────────────

    def _build_ui(self):
        # Header
        header = tk.Frame(self, bg=PALETTE["accent"], height=48)
        header.pack(fill="x")
        tk.Label(
            header,
            text="🔐  PKI Secure Update Client",
            bg=PALETTE["accent"],
            fg="white",
            font=("Segoe UI", 14, "bold"),
            pady=10,
        ).pack(side="left", padx=16)

        # Info panel
        info = tk.Frame(self, bg=PALETTE["bg"], pady=12, padx=20)
        info.pack(fill="x")

        self._installed_var = tk.StringVar(value="Installed: –")
        self._latest_var    = tk.StringVar(value="Latest on server: –")
        self._status_var    = tk.StringVar(value="Idle")

        tk.Label(
            info, textvariable=self._installed_var,
            bg=PALETTE["bg"], fg=PALETTE["text"],
            font=("Segoe UI", 11),
        ).pack(anchor="w")
        tk.Label(
            info, textvariable=self._latest_var,
            bg=PALETTE["bg"], fg=PALETTE["subtext"],
            font=("Segoe UI", 10),
        ).pack(anchor="w", pady=(2, 0))

        # Status badge
        self._status_label = tk.Label(
            info, textvariable=self._status_var,
            bg=PALETTE["surface"], fg=PALETTE["text"],
            font=("Segoe UI", 9),
            padx=10, pady=4,
            relief="flat",
        )
        self._status_label.pack(anchor="w", pady=(8, 0))

        # Buttons
        btn_row = tk.Frame(self, bg=PALETTE["bg"], padx=20, pady=8)
        btn_row.pack(fill="x")

        self._check_btn = self._make_btn(
            btn_row, "🔍  Check for Updates",
            PALETTE["accent"], self._on_check
        )
        self._check_btn.pack(side="left")

        self._install_btn = self._make_btn(
            btn_row, "⬇️  Download & Install",
            PALETTE["accent2"], self._on_install, state="disabled"
        )
        self._install_btn.pack(side="left", padx=(10, 0))

        self._folder_btn = self._make_btn(
            btn_row, "📂  Open Install Folder",
            PALETTE["surface"], self._on_open_folder,
            fg=PALETTE["text"]
        )
        self._folder_btn.pack(side="left", padx=(10, 0))

        # Log panel
        log_frame = tk.LabelFrame(
            self, text=" Activity Log ",
            bg=PALETTE["bg"], fg=PALETTE["subtext"],
            font=("Segoe UI", 9),
            padx=10, pady=6,
        )
        log_frame.pack(fill="both", expand=True, padx=20, pady=(4, 16))

        self._log = tk.Text(
            log_frame,
            bg=PALETTE["logbg"], fg=PALETTE["text"],
            font=("Consolas", 9),
            wrap="word",
            state="disabled",
            relief="flat",
            height=14,
        )
        scroll = ttk.Scrollbar(log_frame, command=self._log.yview)
        self._log["yscrollcommand"] = scroll.set
        scroll.pack(side="right", fill="y")
        self._log.pack(fill="both", expand=True)

        # Tag colours
        self._log.tag_config("ok",    foreground="#10b981")
        self._log.tag_config("err",   foreground="#ef4444")
        self._log.tag_config("warn",  foreground="#f59e0b")
        self._log.tag_config("info",  foreground="#94a3b8")

    def _make_btn(self, parent, text, bg, cmd, state="normal", fg="white"):
        return tk.Button(
            parent, text=text, bg=bg, fg=fg,
            font=("Segoe UI", 9, "bold"),
            relief="flat", padx=14, pady=7,
            cursor="hand2", command=cmd, state=state,
        )

    # ── Helpers ──────────────────────────────────────────────────────────

    def _log_line(self, msg: str, tag: str = "info"):
        ts = time.strftime("%H:%M:%S")
        self._log.configure(state="normal")
        self._log.insert("end", f"[{ts}] {msg}\n", tag)
        self._log.see("end")
        self._log.configure(state="disabled")

    def _set_status(self, msg: str, colour: str = PALETTE["text"]):
        self._status_var.set(msg)
        self._status_label.configure(fg=colour)
        self._log_line(msg)

    def _refresh_version_labels(self):
        iv = self.client.installed_version or "None"
        self._installed_var.set(f"Installed version: {iv}")

    def _async(self, fn, *args):
        threading.Thread(target=fn, args=args, daemon=True).start()

    # ── Button callbacks ──────────────────────────────────────────────────

    def _on_check(self):
        self._check_btn.configure(state="disabled")
        self._set_status("Checking for updates…", PALETTE["subtext"])
        self._async(self._do_check)

    def _on_install(self):
        self._install_btn.configure(state="disabled")
        self._check_btn.configure(state="disabled")
        self._set_status("Starting download & install…", PALETTE["subtext"])
        self._async(self._do_install)

    def _on_open_folder(self):
        path = INSTALL_DIR.resolve()
        path.mkdir(parents=True, exist_ok=True)
        if os.name == "nt":
            os.startfile(str(path))
        else:
            os.system(f'xdg-open "{path}" >/dev/null 2>&1 &')

    # ── Background workers ────────────────────────────────────────────────

    def _do_check(self):
        try:
            available, release = self.client.check()
        except (HTTPError, URLError) as e:
            self.after(0, self._set_status, f"Server not reachable: {e}", PALETTE["danger"])
            self.after(0, self._check_btn.configure, {"state": "normal"})
            return
        except Exception as e:
            self.after(0, self._set_status, f"Check error: {e}", PALETTE["danger"])
            self.after(0, self._check_btn.configure, {"state": "normal"})
            return

        self._latest_release = release

        def update_ui():
            self._check_btn.configure(state="normal")
            if release:
                self._latest_var.set(f"Latest on server: {release['version']}")
            else:
                self._latest_var.set("Latest on server: None")

            if available and release:
                self._install_btn.configure(state="normal")
                self._set_status(
                    f"Update available: {release['version']}", PALETTE["accent2"]
                )
                messagebox.showinfo(
                    "Update Available",
                    f"New version available: {release['version']}\n"
                    "Click 'Download & Install' to update.",
                )
            else:
                self._install_btn.configure(state="disabled")
                self._set_status("You are up to date.", PALETTE["accent2"])

        self.after(0, update_ui)

    def _do_install(self):
        if not self._latest_release:
            self.after(
                0, self._set_status,
                "No release info cached – run 'Check for Updates' first.",
                PALETTE["danger"],
            )
            self.after(0, self._check_btn.configure, {"state": "normal"})
            return

        def progress(msg: str):
            tag = "ok" if any(
                kw in msg.lower() for kw in ("ok", "success", "extracted", "installed")
            ) else "info"
            self.after(0, self._log_line, msg, tag)
            self.after(0, self._set_status, msg)

        try:
            install_path = self.client.download_and_install(
                self._latest_release, on_progress=progress
            )
        except UpdateError as e:
            def on_fail():
                self._set_status(f"Install FAILED: {e}", PALETTE["danger"])
                self._log_line(str(e), "err")
                self._check_btn.configure(state="normal")
                messagebox.showerror("Install Failed", str(e))
            self.after(0, on_fail)
            return
        except Exception as e:
            def on_unexpected():
                self._set_status(f"Unexpected error: {e}", PALETTE["danger"])
                self._log_line(str(e), "err")
                self._check_btn.configure(state="normal")
                messagebox.showerror("Unexpected Error", str(e))
            self.after(0, on_unexpected)
            return

        version = self._latest_release["version"]

        def on_success():
            self._refresh_version_labels()
            self._install_btn.configure(state="disabled")
            self._check_btn.configure(state="normal")
            self._set_status(
                f"Successfully installed {version}", PALETTE["accent2"]
            )
            self._log_line(f"Installed to: {install_path}", "ok")
            messagebox.showinfo(
                "Installed Successfully",
                f"Version {version} installed.\nLocation: {install_path}",
            )
        self.after(0, on_success)


def main():
    app = UpdateClientApp()
    app.mainloop()


if __name__ == "__main__":
    main()
