import tkinter as tk
from tkinter import messagebox
import threading
import time

APP_NAME = "PKI Secure Updater (Client)"

def check_updates(background=False):
    # TODO: replace with real server request later
    time.sleep(1)  # simulate network delay

    update_available = False  # change to True to test popup
    version = "v2.0"

    def show_result():
        if update_available:
            if messagebox.askyesno("Update Available", f"Update {version} is available.\nUpdate now?"):
                messagebox.showinfo("Updating", "Downloading and installing update...")
                # TODO: download + verify + install + run
                messagebox.showinfo("Done", "Update installed successfully.")
            else:
                messagebox.showinfo("Cancelled", "Update cancelled.")
        else:
            if not background:
                messagebox.showinfo("No Updates", "No updates available.")

    root.after(0, show_result)

def check_updates_thread(background=False):
    threading.Thread(target=check_updates, args=(background,), daemon=True).start()

root = tk.Tk()
root.title(APP_NAME)
root.geometry("420x180")

title = tk.Label(root, text=APP_NAME, font=("Arial", 14))
title.pack(pady=15)

btn = tk.Button(root, text="Check for Updates", width=20, command=lambda: check_updates_thread(background=False))
btn.pack(pady=10)

status = tk.Label(root, text="Status: Ready")
status.pack(pady=10)

# Background check on startup (silent)
check_updates_thread(background=True)

root.mainloop()
