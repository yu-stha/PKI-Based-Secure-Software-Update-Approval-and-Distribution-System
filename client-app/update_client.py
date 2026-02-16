import base64
import hashlib
import json
import os
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from pathlib import Path
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


# ====== CONFIG (edit these) ======
SERVER_BASE = "http://192.168.56.103:9000"
MANIFEST_URL = f"{SERVER_BASE}/manifest.json"
# Put a copy of the trusted company cert on the client (the cert, NOT the private key)
COMPANY_CERT_PATH = Path("./company_cert.pem")

# Where updates are stored/extracted
DOWNLOADS_DIR = Path("./downloads")
INSTALL_DIR = Path("./installed")
STATE_PATH = Path("./client_state.json")
# ================================


def load_state() -> dict:
    if STATE_PATH.exists():
        try:
            return json.loads(STATE_PATH.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def save_state(state: dict) -> None:
    STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")


def http_get_json(url: str, timeout=8) -> dict:
    req = Request(url, headers={"User-Agent": "PKI-Update-Client/1.0"})
    with urlopen(req, timeout=timeout) as r:
        data = r.read()
    return json.loads(data.decode("utf-8"))


def download_file(url: str, dest: Path, timeout=20) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = Request(url, headers={"User-Agent": "PKI-Update-Client/1.0"})
    with urlopen(req, timeout=timeout) as r, open(dest, "wb") as f:
        while True:
            chunk = r.read(1024 * 1024)
            if not chunk:
                break
            f.write(chunk)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_company_cert() -> x509.Certificate:
    if not COMPANY_CERT_PATH.exists():
        raise FileNotFoundError(
            f"Missing {COMPANY_CERT_PATH}. Put company_cert.pem next to the app."
        )
    return x509.load_pem_x509_certificate(COMPANY_CERT_PATH.read_bytes())


def verify_signature_over_hash(company_cert: x509.Certificate, signature_b64: str, sha256_hex: str) -> None:
    pub = company_cert.public_key()
    if not isinstance(pub, rsa.RSAPublicKey):
        raise ValueError("Only RSA company certificates are supported in this lab client")

    sig_raw = base64.b64decode(signature_b64.strip())
    data = sha256_hex.encode("utf-8")  # must match what publisher signed

    pub.verify(
        sig_raw,
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )


def get_latest_release(manifest: dict) -> dict | None:
    latest = manifest.get("latest")
    if not latest:
        return None
    for r in manifest.get("releases", []):
        if r.get("version") == latest:
            return r
    return None


def is_newer(current: str | None, latest: str) -> bool:
    # Simple rule for lab: if version string differs, treat as newer
    return (current or "") != latest


class UpdateClientGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("PKI Update Client (Lab)")
        self.root.geometry("640x320")
        self.root.resizable(False, False)

        self.state = load_state()
        self.current_version = self.state.get("installed_version")

        self.status_var = tk.StringVar(value="Ready")
        self.version_var = tk.StringVar(value=f"Installed version: {self.current_version or 'None'}")
        self.latest_var = tk.StringVar(value="Latest on server: (unknown)")

        self._build_ui()

        # Start background check on open
        self.set_status("Checking for updates on launch...")
        threading.Thread(target=self.check_updates, daemon=True).start()

    def _build_ui(self):
        frame = ttk.Frame(self.root, padding=16)
        frame.pack(fill="both", expand=True)

        title = ttk.Label(frame, text="PKI Secure Update Client", font=("Segoe UI", 16))
        title.pack(anchor="w")

        ttk.Label(frame, textvariable=self.version_var).pack(anchor="w", pady=(12, 0))
        ttk.Label(frame, textvariable=self.latest_var).pack(anchor="w", pady=(4, 0))

        ttk.Separator(frame).pack(fill="x", pady=14)

        btns = ttk.Frame(frame)
        btns.pack(fill="x")

        self.check_btn = ttk.Button(btns, text="Check for updates", command=self.on_check_clicked)
        self.check_btn.pack(side="left")

        self.install_btn = ttk.Button(btns, text="Download and install latest", command=self.on_install_clicked)
        self.install_btn.pack(side="left", padx=(10, 0))
        self.install_btn.state(["disabled"])

        self.open_btn = ttk.Button(btns, text="Open install folder", command=self.on_open_folder)
        self.open_btn.pack(side="left", padx=(10, 0))

        ttk.Separator(frame).pack(fill="x", pady=14)

        log_frame = ttk.LabelFrame(frame, text="Log")
        log_frame.pack(fill="both", expand=True)

        self.log = tk.Text(log_frame, height=7, wrap="word")
        self.log.pack(fill="both", expand=True, padx=8, pady=8)
        self.log.configure(state="disabled")

        ttk.Label(frame, textvariable=self.status_var).pack(anchor="w", pady=(10, 0))

    def log_line(self, msg: str):
        self.log.configure(state="normal")
        self.log.insert("end", f"[{time.strftime('%H:%M:%S')}] {msg}\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def set_status(self, msg: str):
        self.status_var.set(msg)
        self.log_line(msg)

    def on_check_clicked(self):
        self.set_status("Manual update check started...")
        threading.Thread(target=self.check_updates, daemon=True).start()

    def on_install_clicked(self):
        self.set_status("Starting download and install...")
        threading.Thread(target=self.download_and_install_latest, daemon=True).start()

    def on_open_folder(self):
        path = INSTALL_DIR.resolve()
        path.mkdir(parents=True, exist_ok=True)
        if os.name == "nt":
            os.startfile(str(path))
        else:
            # linux/kali
            os.system(f'xdg-open "{path}" >/dev/null 2>&1 &')

    def check_updates(self):
        try:
            manifest = http_get_json(MANIFEST_URL)
            latest_release = get_latest_release(manifest)

            if not latest_release:
                self.latest_var.set("Latest on server: None")
                self.install_btn.state(["disabled"])
                self.set_status("No releases on server.")
                return

            latest_version = latest_release.get("version")
            self.latest_var.set(f"Latest on server: {latest_version}")

            if is_newer(self.current_version, latest_version):
                self.install_btn.state(["!disabled"])
                self.set_status(f"Update available: {latest_version}")
                messagebox.showinfo("Update available", f"New update found: {latest_version}\nClick Download and install.")
            else:
                self.install_btn.state(["disabled"])
                self.set_status("You are up to date.")
        except (HTTPError, URLError) as e:
            self.install_btn.state(["disabled"])
            self.set_status(f"Server not reachable: {e}")
        except Exception as e:
            self.install_btn.state(["disabled"])
            self.set_status(f"Error checking updates: {e}")

    def download_and_install_latest(self):
        try:
            manifest = http_get_json(MANIFEST_URL)
            latest = get_latest_release(manifest)
            if not latest:
                self.set_status("No releases to install.")
                return

            latest_version = latest["version"]
            filename = latest["filename"]
            expected_sha = latest["sha256"]

            # These exist only after you upgraded the server to store them
            signature_b64 = latest.get("signature_b64")
            if not signature_b64:
                raise ValueError("Manifest missing signature_b64. Publish again using signature-enabled server.")

            download_url = f"{SERVER_BASE}/updates/{latest_version}/{filename}"
            zip_path = DOWNLOADS_DIR / latest_version / filename

            self.set_status(f"Downloading: {download_url}")
            download_file(download_url, zip_path)

            self.set_status("Verifying SHA256...")
            actual_sha = sha256_file(zip_path)
            if actual_sha.lower() != expected_sha.lower():
                raise ValueError(f"SHA256 mismatch: expected={expected_sha} actual={actual_sha}")

            self.set_status("Verifying signature using company cert...")
            cert = load_company_cert()
            verify_signature_over_hash(cert, signature_b64, actual_sha)

            self.set_status("Extracting update...")
            target_dir = INSTALL_DIR / latest_version
            target_dir.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(zip_path, "r") as z:
                z.extractall(target_dir)

            # mark installed
            self.current_version = latest_version
            self.version_var.set(f"Installed version: {self.current_version}")
            self.state["installed_version"] = self.current_version
            save_state(self.state)

            self.install_btn.state(["disabled"])
            self.set_status(f"Installed successfully: {latest_version}")
            messagebox.showinfo("Installed", f"Update installed: {latest_version}\nLocation: {target_dir}")

        except Exception as e:
            self.set_status(f"Install failed: {e}")
            messagebox.showerror("Install failed", str(e))


def main():
    DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)

    root = tk.Tk()
    UpdateClientGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
