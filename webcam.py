import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import os, webbrowser, hashlib, time, subprocess, smtplib, platform, random, ssl, html
from email.mime.text import MIMEText

# =========================
# Paths & Globals
# =========================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "logs.txt")
CONFIG_FILE = os.path.join(BASE_DIR, "config.dat")     # stores hashed password (sha256)
CRED_FILE = os.path.join(BASE_DIR, "cred.dat")         # stores sender email + app password
USER_FILE = os.path.join(BASE_DIR, "user.dat")         # stores recovery email
INFO_FILE = os.path.join(BASE_DIR, "project_info.html")
SETTINGS_FILE = os.path.join(BASE_DIR, "settings.dat") # stores cooldown time (minutes)

DEFAULT_SENDER = "navadheer6730@gmail.com"

failed_attempts = 0
max_attempts = 3
lockout = False
lockout_end = 0
attempts_label = None
cooldown_minutes = 5  # default, will be loaded from file

# Ensure base dir exists (helpful if running from temp dirs)
os.makedirs(BASE_DIR, exist_ok=True)

# =========================
# Settings
# =========================
def load_settings():
    global cooldown_minutes
    if not os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            f.write("5")
        cooldown_minutes = 5
    else:
        try:
            with open(SETTINGS_FILE, encoding="utf-8") as f:
                cooldown_minutes = int(f.read().strip())
        except Exception:
            cooldown_minutes = 5

# =========================
# Helpers
# =========================
def log_action(action):
    with open(LOG_FILE, "a", encoding="utf-8") as log:
        log.write(f"{action} - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

def hash_password(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def load_config():
    if not os.path.exists(CONFIG_FILE):
        return None
    with open(CONFIG_FILE, encoding="utf-8") as f:
        return f.read().strip()

def save_config(password):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        f.write(hash_password(password))

def load_sender_credentials():
    if not os.path.exists(CRED_FILE):
        return None, None
    with open(CRED_FILE, encoding="utf-8") as f:
        lines = f.read().splitlines()
        return (lines[0] if lines else None,
                lines[1] if len(lines) > 1 else None)

def save_sender_credentials(email, app_pass):
    with open(CRED_FILE, "w", encoding="utf-8") as f:
        f.write(email.strip() + "\n" + app_pass.strip())

def save_user_email(email):
    with open(USER_FILE, "w", encoding="utf-8") as f:
        f.write(email.strip())

def load_user_email():
    return open(USER_FILE, encoding="utf-8").read().strip() if os.path.exists(USER_FILE) else None

# =========================
# Email
# =========================
def _smtp_send(sender_email, sender_pass, msg):
    ctx = ssl.create_default_context()
    last_err = None
    # Try STARTTLS 587 first
    try:
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=60) as server:
            server.ehlo()
            server.starttls(context=ctx)
            server.ehlo()
            server.login(sender_email, sender_pass)
            server.send_message(msg)
        return
    except Exception as e:
        last_err = e
    # Fallback SSL 465
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=60, context=ctx) as server:
            server.login(sender_email, sender_pass)
            server.send_message(msg)
        return
    except Exception as e:
        raise RuntimeError(f"587 STARTTLS failed: {last_err}; 465 SSL failed: {e}")

def send_email_alert():
    owner_email = load_user_email()
    sender_email, sender_pass = load_sender_credentials()
    if not sender_email or not sender_pass or not owner_email:
        messagebox.showerror("Email Error", "Sender or recovery email not set.")
        return

    msg = MIMEText(
        "⚠️ SECURITY ALERT ⚠️\n\n"
        "Someone entered the wrong password 3 times and is now locked out.\n"
        f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}"
    )
    msg["Subject"] = "Security Alert – User Locked Out"
    msg["From"] = sender_email
    msg["To"] = owner_email

    try:
        _smtp_send(sender_email, sender_pass, msg)
        log_action("Alert email sent to recovery email")
    except Exception as e:
        log_action(f"Email send failed: {e}")

# =========================
# Auth / Setup
# =========================
def first_time_setup():
    """Runs on first launch: sets default password and asks for Gmail App Password + recovery email"""
    default_pw = "nani@29"
    app_pass = simpledialog.askstring(
        "Sender App Password",
        f"Enter Gmail App Password for {DEFAULT_SENDER}:",
        show="*"
    )
    recovery_email = simpledialog.askstring("Recovery Email", "Enter your email for password resets:")

    if app_pass and recovery_email:
        save_config(default_pw)
        save_sender_credentials(DEFAULT_SENDER, app_pass)
        save_user_email(recovery_email)
        messagebox.showinfo(
            "Success",
            f"Setup complete.\nDefault password is: {default_pw}\nRecovery email set: {recovery_email}"
        )
        return True
    else:
        messagebox.showerror("Error", "Setup failed. App password + recovery email required.")
        return False

def update_attempts_label():
    global lockout, lockout_end
    if attempts_label:
        if lockout:
            remaining = int(lockout_end - time.time())
            if remaining > 0:
                m, s = divmod(remaining, 60)
                attempts_label.config(text=f"🔒 Locked out for {m:02d}:{s:02d}")
            else:
                attempts_label.config(text="Attempts left: 3")
        else:
            remaining = max_attempts - failed_attempts
            attempts_label.config(text=f"Attempts left: {remaining}")

def check_password():
    global failed_attempts, lockout, lockout_end
    if lockout:
        remaining = int(lockout_end - time.time())
        if remaining > 0:
            messagebox.showwarning("Locked", f"⚠️ Access locked. Wait {remaining//60}m {remaining%60}s.")
            return False
        else:
            # cooldown finished
            lockout = False
            failed_attempts = 0
            update_attempts_label()

    stored = load_config()
    if stored is None:
        return first_time_setup()
    else:
        pw = simpledialog.askstring("Password", "Enter password:", show="*")
        if not pw:
            return False
        if hash_password(pw) == stored:
            failed_attempts = 0
            update_attempts_label()
            return True
        else:
            failed_attempts += 1
            update_attempts_label()
            if failed_attempts >= max_attempts:
                lockout = True
                lockout_end = time.time() + cooldown_minutes * 60
                update_attempts_label()
                messagebox.showerror("Locked", f"⚠️ Wrong password 3 times. Locked for {cooldown_minutes} minutes.")
                send_email_alert()
            else:
                messagebox.showerror("Error", "Incorrect password!")
            return False

def change_password():
    if not check_password():
        return
    stored = load_config()
    if not stored:
        messagebox.showerror("Error", "No password set.")
        return
    current = simpledialog.askstring("Change Password", "Enter current password:", show="*")
    if not current:
        return
    if hash_password(current) == stored:
        new = simpledialog.askstring("Change Password", "Enter new password:", show="*")
        confirm = simpledialog.askstring("Change Password", "Confirm new password:", show="*")
        if new and confirm and new == confirm:
            save_config(new)
            messagebox.showinfo("Success", "Password changed!")
        else:
            messagebox.showerror("Error", "Passwords do not match.")
    else:
        messagebox.showerror("Error", "Incorrect password.")


# =========================
# Camera Controls (Windows)
# =========================
def update_status_label(status):
    if status == "Enabled":
        status_label.config(text="🟢 Enabled ", fg="lime")
    elif status == "Disabled":
        status_label.config(text="🔴 Disabled", fg="red")
    else:
        status_label.config(text="⚪ Unknown", fg="gray")

def disable_camera():
    if not check_password():
        return
    try:
        cmd = [
            "powershell", "Start-Process", "reg",
            "-ArgumentList",
            "'add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam "
            "/v Value /t REG_SZ /d Deny /f'",
            "-Verb", "runAs"
        ]
        subprocess.run(cmd, check=True)
        log_action("Camera Disabled")
        messagebox.showinfo("Success", "Camera disabled.")
        update_status_label("Disabled")
    except Exception as e:
        messagebox.showerror("Error", f"Failed:\n{e}")

def enable_camera():
    if not check_password():
        return
    try:
        cmd = [
            "powershell", "Start-Process", "reg",
            "-ArgumentList",
            "'add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam "
            "/v Value /t REG_SZ /d Allow /f'",
            "-Verb", "runAs"
        ]
        subprocess.run(cmd, check=True)
        log_action("Camera Enabled")
        messagebox.showinfo("Success", "Camera enabled.")
        update_status_label("Enabled")
    except Exception as e:
        messagebox.showerror("Error", f"Failed:\n{e}")

def check_status(show_popup=True):
    try:
        result = subprocess.check_output(
            r'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v Value',
            shell=True
        ).decode(errors="ignore")
        status = "Disabled" if "Deny" in result else "Enabled" if "Allow" in result else "Unknown"
        if show_popup:
            messagebox.showinfo("Camera Status", f"Camera is {status}")
        update_status_label(status)
        return status
    except Exception as e:
        if show_popup:
            messagebox.showerror("Error", f"Unable to check:\n{e}")
        update_status_label("Unknown")
        return "Unknown"

def refresh_status():
    update_attempts_label()
    try:
        root.after(1000, refresh_status)
    except tk.TclError:
        # window closed
        pass

# =========================
# Misc
# =========================
def view_logs():
    if os.path.exists(LOG_FILE):
        if platform.system() == "Windows":
            os.startfile(LOG_FILE)
        elif platform.system() == "Darwin":
            subprocess.call(["open", LOG_FILE])
        else:
            subprocess.call(["xdg-open", LOG_FILE])
    else:
        messagebox.showinfo("Logs", "No logs available.")

def project_info():
    """
    Generates the project info HTML file and opens it.
    Also includes a 'Source Code' section showing this script's contents (HTML-escaped).
    """
    # Attempt to read this script's source for embedding
    try:
        with open(__file__, "r", encoding="utf-8") as sf:
            raw_source = sf.read()
            source_html = html.escape(raw_source)
    except Exception:
        source_html = "Source code not available."

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Project Information</title>
  <style>
    body {{ font-family: Arial, sans-serif; background-color: #f7f7f7; margin: 0; padding: 0; }}
    .container {{ width: 90%; max-width: 1100px; background: #fff; margin: 30px auto; padding: 30px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); border-radius: 10px; }}
    .header {{ display: flex; justify-content: space-between; align-items: center; gap: 20px; flex-wrap:wrap; }}
    h1 {{ margin: 0; font-size: 28px; color: #333; }}
    .header img {{ width: 100px; height: auto; }}
    p {{ margin-top: 15px; font-size: 16px; color: #444; line-height: 1.5; }}
    h2 {{ margin-top: 30px; font-size: 22px; color: #222; border-bottom: 2px solid #ccc; padding-bottom: 5px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
    table, th, td {{ border: 1px solid #ddd; }}
    th {{ background-color: #f2f2f2; padding: 10px; text-align: left; font-weight: bold; }}
    td {{ padding: 10px; text-align: left; }}
    pre.code-block {{ background:#0d0d0d; color:#e6e6e6; padding: 15px; overflow:auto; max-height:600px; border-radius:6px; white-space:pre-wrap; word-wrap:break-word; }}
    .small {{ font-size:12px; color:#666; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Project Information</h1>
      <img src="https://cdn-icons-png.flaticon.com/512/921/921079.png" alt="Boy with laptop">
    </div>

    <p>
      This project was developed by <b>Our Team </b> as part of a Cyber Security Internship.
      This project is designed to <b>Secure the Organizations in Real World</b> from Cyber Frauds performed by Hackers.
    </p>

    <h2>Project Details</h2>
    <table>
      <tr><th>Project Detail</th><th>Value</th></tr>
      <tr><td>Project Name</td><td>Web Cam Security from Spyware</td></tr>
      <tr><td>Project Description</td><td>Implementing Physical Security Policy on Web Cam in Devices to prevent Spyware Activities</td></tr>
      <tr><td>Project Start Date</td><td>01-May-2025</td></tr>
      <tr><td>Project End Date</td><td>01-June-2025</td></tr>
      <tr><td>Project Status</td><td>Completed</td></tr>
    </table>

    <h2>Developer Details</h2>
    <table>
      <tr><th>Name</th><th>Emp ID</th><th>Email</th></tr>
      <tr><td>Komali Kadiyala</td><td>23C08#ST#IS#7781</td><td>komalikadiyala17@gmail.com</td></tr>
      <tr><td>K Venkata Navadheer</td><td>23C08#ST#IS#7784</td><td>navadheer2004@gmail.com</td></tr>
      <tr><td>Motupalli Sasanth</td><td>23C08#ST#IS#7786</td><td>motupalli021@gmail.com</td></tr>
      <tr><td>Vanipenta Chaitanya</td><td>23C08#ST#IS#7775</td><td>munnareddy8208@gmail.com</td></tr>
      <tr><td>G.Rama Krishna Prasad</td><td>23C08#ST#IS#7779</td><td>ramu4012y@gmail.com</td></tr>
    </table>

    <h2>Company Details</h2>
    <table>
      <tr><th>Company</th><th>Value</th></tr>
      <tr><td>Name</td><td>Supraja Technologies</td></tr>
      <tr><td>Email</td><td>contact@suprajatechnologies.com</td></tr>
    </table>

    <h2>Notes & Usage</h2>
    <p class="small">This application is intended to be run on Windows. Camera enable/disable uses Windows registry commands requiring administrative privileges (UAC). Email sending requires a working Gmail SMTP App Password for the sender account.</p>

    <h2>Source Code (this script)</h2>
    <pre class="code-block">{source_html}</pre>
  </div>
</body>
</html>
"""
    with open(INFO_FILE, "w", encoding="utf-8") as f:
        f.write(html_content)
    webbrowser.open(INFO_FILE)

# =========================
# GUI
# =========================
root = tk.Tk()
root.title("Webcam Spyware Security")
root.geometry("600x720")
root.resizable(False, False)

style = ttk.Style()
try:
    style.theme_use("clam")
except Exception:
    pass  # fallback to default if clam not available

# Premium styles
style.configure("TButton", font=("Segoe UI", 12, "bold"), padding=12, background="#4CAF50", foreground="white")
style.map("TButton", background=[("active", "#45a049")])
style.configure("Header.TLabel", font=("Segoe UI", 20, "bold"), foreground="#FFD700")
style.configure("Status.TLabel", font=("Segoe UI", 14, "italic"))
style.configure("Attempts.TLabel", font=("Segoe UI", 12), foreground="#BDBDBD")
style.configure("Theme.TButton", font=("Segoe UI", 10), padding=5)

def apply_dark():
    root.configure(bg="#121212")
    header.configure(bg="#1f1f1f")
    title_label.configure(background="#1f1f1f", foreground="#FFD700")
    status_frame.configure(bg="#121212")
    status_label.configure(background="#121212", foreground="white")
    attempts_label.configure(background="#121212", foreground="#BDBDBD")
    theme_frame.configure(bg="#121212")
    style.configure("TButton", background="#333333", foreground="white")
    style.map("TButton", background=[("active", "#444444")], foreground=[("active", "white")])
    style.configure("Theme.TButton", background="#1f1f1f", foreground="white")
    style.map("Theme.TButton", background=[("active", "#2f2f2f")])

def apply_light():
    root.configure(bg="#f0f0f0")
    header.configure(bg="#e0e0e0")
    title_label.configure(background="#e0e0e0", foreground="#333333")
    status_frame.configure(bg="#f0f0f0")
    status_label.configure(background="#f0f0f0", foreground="black")
    attempts_label.configure(background="#f0f0f0", foreground="#333333")
    theme_frame.configure(bg="#f0f0f0")
    style.configure("TButton", background="#ffffff", foreground="black")
    style.map("TButton", background=[("active", "#dddddd")], foreground=[("active", "black")])
    style.configure("Theme.TButton", background="#e0e0e0", foreground="black")
    style.map("Theme.TButton", background=[("active", "#d0d0d0")])

header = tk.Frame(root, bg="#1f1f1f", height=60)
header.pack(fill="x")

title_label = ttk.Label(
    header,
    text="📷 Webcam Spyware Security",
    style="Header.TLabel"
)
title_label.pack(pady=15)

status_frame = tk.Frame(root, bg="#121212")
status_frame.pack(pady=15)
tk.Label(status_frame, text="Camera Status: ", font=("Segoe UI", 14, "bold"), bg="#121212", fg="white").grid(row=0, column=0)
status_label = tk.Label(status_frame, text="⚪ Unknown", font=("Segoe UI", 14, "italic"), bg="#121212", fg="gray")
status_label.grid(row=0, column=1, padx=10)

main_frame = tk.Frame(root, bg="#121212")
main_frame.pack(pady=10, padx=20, fill="x")

btn_enable = ttk.Button(main_frame, text="Enable Camera", style="TButton",
                       command=enable_camera, width=30)
btn_enable.pack(pady=8, fill="x")

btn_disable = ttk.Button(main_frame, text="Disable Camera", style="TButton",
                        command=disable_camera, width=30)
btn_disable.pack(pady=8, fill="x")

btn_logs = ttk.Button(main_frame, text="View Logs", style="TButton",
                     command=view_logs, width=30)
btn_logs.pack(pady=8, fill="x")

btn_info = ttk.Button(main_frame, text="Project Info", style="TButton",
                     command=project_info, width=30)
btn_info.pack(pady=8, fill="x")

btn_change_pw = ttk.Button(main_frame, text="Change Password", style="TButton",
                          command=change_password, width=30)
btn_change_pw.pack(pady=8, fill="x")


attempts_label = ttk.Label(root, text="Attempts left: 3", style="Attempts.TLabel")
attempts_label.pack(pady=15)

theme_frame = tk.Frame(root, bg="#121212")
theme_frame.pack(pady=10)
ttk.Button(theme_frame, text="🌙 Dark", command=apply_dark, style="Theme.TButton").grid(row=0, column=1, padx=5)
ttk.Button(theme_frame, text="☀️ Light", command=apply_light, style="Theme.TButton").grid(row=0, column=2, padx=5)

# =========================
# Bootstrap
# =========================
apply_dark()
load_settings()
# Do not show a popup on startup; just try to determine status silently
try:
    check_status(show_popup=False)
except Exception:
    pass
refresh_status()
root.mainloop()