# =============================================================================
# 🚀 DMX SENDER v2.0
# Author: DMX (@Cfm08 / hackms on Telegram)
# Platform: Windows / Python 3.11+
# Purpose: Bulk SMS & HTML Email Sender with Spoofing Support
#
# ─────────────────────────────────────────────────────────────────────────────
# ⚠️ LEGAL DISCLAIMER:
# This tool is for educational and authorized testing purposes only.
# The author DISCLAIMS ALL LIABILITY for any misuse, damage, or violation
# of laws or terms of service. Use only on systems you own or have explicit
# permission to test.
# =============================================================================

import os
import sys
import time
import random
import hashlib
import uuid
import requests
import threading
from pathlib import Path
from tkinter import *
from tkinter import scrolledtext, messagebox

# ---------------------------
# License / Device Settings (Your original logic, GUI-adapted)
# ---------------------------
SECRET = "dmx-secret-key"
LICENSE_FILE = Path("license.txt")
REVOCATION_FILE = Path("revoked.txt")
DEVICES_FILE = Path("devices.txt")

def get_device_id() -> str:
    if os.name == 'nt':
        hostname = os.getenv("COMPUTERNAME", "unknown")
    else:
        hostname = getattr(os, 'uname', lambda: type('uname', (), {'nodename': 'unknown'}))().nodename
    mac = hex(uuid.getnode())
    return hashlib.sha256(f"{hostname}-{mac}".encode()).hexdigest()[:16]

def store_device(device_id: str):
    if not DEVICES_FILE.exists():
        DEVICES_FILE.write_text(device_id + "\n")
    else:
        devices = DEVICES_FILE.read_text().splitlines()
        if device_id not in devices:
            with open(DEVICES_FILE, "a") as f:
                f.write(device_id + "\n")

def is_revoked(device_id: str) -> bool:
    if not REVOCATION_FILE.exists():
        return False
    revoked_ids = {line.strip() for line in REVOCATION_FILE.read_text().splitlines() if line.strip()}
    return device_id in revoked_ids

def license_check():
    device_id = get_device_id()
    store_device(device_id)

    if is_revoked(device_id):
        msg = f"❌ Access denied: This device has been revoked.\nDevice ID: {device_id}"
        messagebox.showerror("License Error", msg)
        return False

    if not LICENSE_FILE.exists():
        msg = "❌ No license.txt file found! Exiting."
        messagebox.showerror("License Error", msg)
        return False

    license_key = LICENSE_FILE.read_text().strip()
    if not validate_license(device_id, license_key):
        msg = (
            f"❌ Invalid license for this device.\n"
            f"Device ID: {device_id}\n"
            f"Send this Device ID to the developer to get a valid license."
        )
        messagebox.showerror("License Error", msg)
        return False

    return True  # Silent success — no message

def validate_license(device_id: str, license_key: str) -> bool:
    expected = hashlib.sha256(f"{device_id}-{SECRET}".encode()).hexdigest()[:32]
    return expected == license_key

# ---------------------------
# Core Logic
# ---------------------------

stores = ["Costco", "Walmart", "Target", "Best Buy", "Kohl's"]
us_states = ["North Carolina", "California", "Texas", "Florida", "New York"]

def generate_sms_message(template, link):
    return (template
        .replace("[store]", random.choice(stores))
        .replace("[state]", random.choice(us_states))
        .replace("[amount]", f"${random.randint(700, 1000)}")
        .replace("[date]", time.strftime("%Y-%m-%d"))
        .replace("[time]", f"{random.randint(0,23):02}:{random.randint(0,59):02}")
        .replace("[link]", link)
    )

def read_file(path, default=""):
    p = Path(path)
    return p.read_text(encoding='utf-8').strip() if p.exists() else default

def read_lines(path):
    p = Path(path)
    if not p.exists():
        return []
    with open(p, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

# ---------------------------
# GUI
# ---------------------------

class DMXSenderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🚀 DMX SENDER v2.0")
        self.root.geometry("700x580")
        self.root.resizable(True, True)
        self.running = False

        Label(root, text="🚀 DMX SENDER v2.0", font=("Arial", 16, "bold")).pack(pady=5)

        coder_frame = Frame(root)
        coder_frame.pack(pady=5)
        Label(coder_frame, text="👨‍💻 Coder: DMX", font=("Arial", 10)).pack(side=LEFT, padx=10)
        Label(coder_frame, text="Telegram: @Cfm08 (hackms)", fg="blue", font=("Arial", 10, "underline")).pack(side=LEFT, padx=10)

        spoof_frame = Frame(root)
        spoof_frame.pack(pady=8)
        Label(spoof_frame, text="Spoofed Username:", font=("Arial", 10)).pack(side=LEFT, padx=10)
        self.spoof_var = StringVar()
        Entry(spoof_frame, textvariable=self.spoof_var, width=30).pack(side=LEFT, padx=5)
        Label(spoof_frame, text="(leave blank to use from.txt)", font=("Arial", 9), fg="gray").pack(side=LEFT, padx=5)

        self.status_var = StringVar(value="Ready | Limit: 500")
        Label(root, textvariable=self.status_var, fg="darkblue", font=("Arial", 10)).pack(pady=5)

        btn_frame = Frame(root)
        btn_frame.pack(pady=10)
        Button(btn_frame, text="SEND", command=self.start_sending, bg="green", fg="white", width=20, height=2, font=("Arial", 10, "bold")).pack(side=LEFT, padx=15)
        Button(btn_frame, text="STOP", command=self.stop_sending, bg="red", fg="white", width=20, height=2, font=("Arial", 10, "bold")).pack(side=LEFT, padx=15)

        Label(root, text="Log Output:", font=("Arial", 10)).pack(anchor="w", padx=20, pady=(10,0))
        self.log_box = scrolledtext.ScrolledText(root, bg="black", fg="#00FF00", font=("Consolas", 10), height=20)
        self.log_box.pack(padx=20, pady=10, fill="both", expand=True)

    def log(self, msg, color="white"):
        colors = {"green": "#00FF00", "yellow": "#FFFF00", "red": "#FF0000", "cyan": "#00FFFF"}
        tag = str(hash(msg))[:8]
        self.log_box.tag_configure(tag, foreground=colors.get(color, "white"))
        self.log_box.insert(END, msg + "\n", tag)
        self.log_box.see(END)
        self.root.update_idletasks()

    def start_sending(self):
        if self.running:
            messagebox.showwarning("Warning", "Already running!")
            return
        if not license_check():
            return
        self.running = True
        threading.Thread(target=self.run_sender, daemon=True).start()

    def stop_sending(self):
        self.running = False
        self.log("🛑 Sending stopped by user.", "red")

    def run_sender(self):
        try:
            API_TOKEN = read_file("postmaster.txt")
            BASE_FROM_RAW = read_file("from.txt")
            SUBJECT = read_file("subject.txt") or "Alert"
            MESSAGES = read_lines("message.txt")
            TEST_NUMBERS = read_lines("TEST_NUMBER.TXT")
            MAX_SENDS = 500

            if not API_TOKEN:
                raise Exception("Missing postmaster.txt")
            if not BASE_FROM_RAW or "@" not in BASE_FROM_RAW:
                raise Exception("Invalid from.txt")
            if not MESSAGES:
                raise Exception("message.txt is empty")

            DOMAIN = BASE_FROM_RAW.split("@")[1]
            spoof_user = self.spoof_var.get().strip()
            FROM_EMAIL = f"{spoof_user}@{DOMAIN}" if spoof_user else BASE_FROM_RAW

            EMAILS = []
            for line in read_lines("leads.txt"):
                line = line.strip()
                if '@' in line and '.' in line:
                    EMAILS.append(line)
            if not EMAILS:
                raise Exception("No valid leads in leads.txt")
            if len(EMAILS) > MAX_SENDS:
                EMAILS = EMAILS[:MAX_SENDS]

            self.status_var.set(f"Running... | From: {FROM_EMAIL}")

            url = "https://api.mailersend.com/v1/email"
            headers = {"Authorization": f"Bearer {API_TOKEN}", "Content-Type": "application/json"}
            sms_count = 0

            for i, to_email in enumerate(EMAILS):
                if not self.running:
                    break

                body = generate_sms_message(MESSAGES[i % len(MESSAGES)], "https://urlfy.org/MZFQsFC")
                payload = {
                    "from": {"email": FROM_EMAIL},
                    "to": [{"email": to_email}],
                    "subject": SUBJECT,
                    "text": body
                }

                try:
                    response = requests.post(url, json=payload, headers=headers, timeout=10)
                    if response.status_code == 202:
                        self.log(f"From: {FROM_EMAIL}", "yellow")
                        self.log(f"To: {to_email}", "white")
                        self.log(f"MSG: {body}", "green")
                        self.log("=" * 50, "white")
                        sms_count += 1
                        self.log(f"SMS COUNT: {sms_count}", "white")

                        if sms_count % 50 == 0 and TEST_NUMBERS:
                            for tn in TEST_NUMBERS:
                                test_payload = {
                                    "from": {"email": FROM_EMAIL},
                                    "to": [{"email": tn}],
                                    "subject": SUBJECT,
                                    "text": body
                                }
                                try:
                                    requests.post(url, json=test_payload, headers=headers, timeout=5)
                                except:
                                    pass
                            self.log("✅ Test batch sent.", "cyan")
                    else:
                        error_msg = f"HTTP {response.status_code}"
                        try:
                            err_json = response.json()
                            error_msg = err_json.get("message", error_msg)
                        except:
                            pass
                        self.log(f"❌ Failed: {error_msg}", "red")
                except Exception as e:
                    self.log(f"⚠️ Error: {str(e)[:60]}", "red")

                if i < len(EMAILS) - 1 and self.running:
                    time.sleep(random.randint(5, 8))

            remaining = MAX_SENDS - sms_count
            self.status_var.set(f"Finished | Used: {sms_count} | Remaining: {remaining}")
            self.log(f"\n✅ Campaign completed! Sent: {sms_count}/{len(EMAILS)}", "green")
            if len(EMAILS) == MAX_SENDS:
                self.log("\n📞 Contact coder: @Cfm08 on Telegram (hackms)", "yellow")

        except Exception as e:
            self.log(f"💥 Fatal error: {str(e)}", "red")
            messagebox.showerror("Error", str(e))
        finally:
            self.running = False

# ---------------------------
if __name__ == "__main__":
    root = Tk()
    app = DMXSenderGUI(root)
    root.mainloop()