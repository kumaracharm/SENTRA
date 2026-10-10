import sys
import os
import json
import uuid
import webbrowser
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

import tkinter as tk
from tkinter import ttk, messagebox

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
LOGS_FILE = DATA_DIR / "logs.json"

API_URL = "http://localhost:8000/api"

class LogShieldSimulator(tk.Tk):
    """Tkinter Controlled Security Event Simulator for LogShield Testing."""

    def __init__(self):
        super().__init__()

        self.title("LogShield Controlled Security Event Simulator (Testing Tool)")
        self.geometry("700x560")
        self.configure(bg="#181b20")
        self.resizable(True, True)

        # Style configuration
        self.style = ttk.Style()
        self.style.theme_use("clam")
        
        # Configure colors
        self.style.configure(".", background="#181b20", foreground="#e2e8f0", font=("Segoe UI", 10))
        self.style.configure("TLabel", background="#181b20", foreground="#94a3b8")
        self.style.configure("Header.TLabel", background="#181b20", foreground="#e2e8f0", font=("Segoe UI", 13, "bold"))
        self.style.configure("SubHeader.TLabel", background="#181b20", foreground="#64748b", font=("Segoe UI", 9))
        self.style.configure("Status.TLabel", background="#1e2229", foreground="#10b981", font=("Segoe UI", 10, "bold"))

        self.build_ui()
        self.update_log_count()

    def build_ui(self):
        # Header Container
        header_frame = tk.Frame(self, bg="#1e2229", bd=1, relief="solid")
        header_frame.pack(fill="x", padx=15, pady=15)

        title_label = ttk.Label(header_frame, text="🛡️ LOGSHIELD CONTROLLED SECURITY EVENT SIMULATOR", style="Header.TLabel")
        title_label.pack(anchor="w", padx=15, pady=(12, 2))
        
        sub_label = ttk.Label(
            header_frame,
            text="Controlled Security Event Generator • Synthetic Scenario Testing • Pipeline Verification Tool",
            style="SubHeader.TLabel"
        )
        sub_label.pack(anchor="w", padx=15, pady=(0, 12))

        # Main Layout: Buttons on Left, Log Console on Right
        content_frame = tk.Frame(self, bg="#181b20")
        content_frame.pack(fill="both", expand=True, padx=15, pady=5)

        # Left Controls Frame
        btn_frame = tk.Frame(content_frame, bg="#1e2229", bd=1, relief="solid")
        btn_frame.pack(side="left", fill="y", padx=(0, 10), ipadx=10, ipady=10)

        control_title = tk.Label(
            btn_frame,
            text="SCENARIO GENERATORS",
            font=("Segoe UI", 9, "bold"),
            bg="#1e2229",
            fg="#94a3b8"
        )
        control_title.pack(anchor="w", padx=10, pady=(10, 8))

        # Standard scenario buttons
        buttons = [
            ("🟢 Normal Activity", self.gen_normal_activity, "#10b981"),
            ("🟡 Suspicious Login", self.gen_suspicious_login, "#f59e0b"),
            ("🔴 Account Takeover", self.gen_account_takeover, "#ef4444"),
            ("⚡ Privilege Escalation", self.gen_privilege_escalation, "#ec4899"),
            ("📦 Sensitive Access", self.gen_sensitive_access, "#8b5cf6"),
        ]

        for text, cmd, color in buttons:
            btn = tk.Button(
                btn_frame,
                text=text,
                command=cmd,
                font=("Segoe UI", 9, "bold"),
                bg="#252b36",
                fg=color,
                activebackground=color,
                activeforeground="#ffffff",
                bd=1,
                relief="groove",
                anchor="w",
                cursor="hand2",
                padx=8,
                pady=4
            )
            btn.pack(fill="x", padx=10, pady=2)

        # Advanced Benchmark Scenarios Section
        adv_title = tk.Label(
            btn_frame,
            text="BENCHMARK SCENARIOS (L1-L4)",
            font=("Segoe UI", 8, "bold"),
            bg="#1e2229",
            fg="#94a3b8"
        )
        adv_title.pack(anchor="w", padx=10, pady=(8, 4))

        self.scenario_var = tk.StringVar(value="gradual_drift")
        scenario_combo = ttk.Combobox(
            btn_frame,
            textvariable=self.scenario_var,
            values=[
                "normal",
                "brute_force",
                "privilege_escalation",
                "data_exfil",
                "gradual_drift",
                "baseline_poison",
                "incomplete_telemetry",
                "conflicting_evidence",
                "novel_sequence",
            ],
            state="readonly",
            font=("Segoe UI", 9),
        )
        scenario_combo.pack(fill="x", padx=10, pady=2)

        run_adv_btn = tk.Button(
            btn_frame,
            text="▶ Run Selected Scenario",
            command=self.run_selected_scenario,
            font=("Segoe UI", 9, "bold"),
            bg="#1e3a5f",
            fg="#38bdf8",
            activebackground="#0284c7",
            activeforeground="#ffffff",
            bd=1,
            relief="groove",
            cursor="hand2",
            padx=8,
            pady=4,
        )
        run_adv_btn.pack(fill="x", padx=10, pady=4)

        # Bottom Utilities
        util_frame = tk.Frame(btn_frame, bg="#1e2229")
        util_frame.pack(fill="x", padx=10, pady=(8, 0))

        clear_btn = tk.Button(
            util_frame,
            text="🗑️ Clear Logs",
            command=self.clear_logs,
            font=("Segoe UI", 9, "bold"),
            bg="#252b36",
            fg="#64748b",
            activebackground="#64748b",
            activeforeground="#ffffff",
            bd=1,
            relief="groove",
            cursor="hand2",
            padx=6,
            pady=4,
        )
        clear_btn.pack(side="left", fill="x", expand=True, padx=(0, 2))

        dash_btn = tk.Button(
            util_frame,
            text="🌐 Dashboard",
            command=self.open_dashboard,
            font=("Segoe UI", 9, "bold"),
            bg="#252b36",
            fg="#3b82f6",
            activebackground="#3b82f6",
            activeforeground="#ffffff",
            bd=1,
            relief="groove",
            cursor="hand2",
            padx=6,
            pady=4,
        )
        dash_btn.pack(side="right", fill="x", expand=True, padx=(2, 0))

        # Right Status Console Frame
        console_frame = tk.Frame(content_frame, bg="#1e2229", bd=1, relief="solid")
        console_frame.pack(side="right", fill="both", expand=True)

        status_header = tk.Frame(console_frame, bg="#252b36")
        status_header.pack(fill="x")

        tk.Label(
            status_header,
            text="EVENT LOG ACTIVITY CONSOLE",
            font=("Segoe UI", 9, "bold"),
            bg="#252b36",
            fg="#94a3b8"
        ).pack(side="left", padx=10, pady=6)

        self.log_count_lbl = tk.Label(
            status_header,
            text="Total Logs: 0",
            font=("Segoe UI", 9, "bold"),
            bg="#252b36",
            fg="#10b981"
        )
        self.log_count_lbl.pack(side="right", padx=10, pady=6)

        # Console Text Box
        self.console_text = tk.Text(
            console_frame,
            bg="#121417",
            fg="#10b981",
            insertbackground="#ffffff",
            font=("Consolas", 9),
            bd=0,
            padx=10,
            pady=10
        )
        self.console_text.pack(fill="both", expand=True)
        
        # Scrollbar for console
        scrollbar = ttk.Scrollbar(self.console_text, command=self.console_text.yview)
        scrollbar.pack(side="right", fill="y")
        self.console_text.config(yscrollcommand=scrollbar.set)

        self.log_to_console("Simulator initialized. Ready to generate synthetic log events.")

    def log_to_console(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.console_text.insert(tk.END, f"[{ts}] {msg}\n")
        self.console_text.see(tk.END)

    def read_current_logs(self):
        if not LOGS_FILE.exists():
            return []
        try:
            with open(LOGS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def write_logs(self, new_events: list, append: bool = True):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        current = self.read_current_logs() if append else []
        combined = current + new_events

        with open(LOGS_FILE, "w", encoding="utf-8") as f:
            json.dump(combined, f, indent=2)

        self.update_log_count()

        # Attempt to notify backend API if running
        try:
            req = urllib.request.Request(
                f"{API_URL}/upload",
                data=json.dumps(combined).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            urllib.request.urlopen(req, timeout=1)
        except Exception:
            pass  # Backend polling will read logs.json directly

    def update_log_count(self):
        logs = self.read_current_logs()
        self.log_count_lbl.config(text=f"Total Logs: {len(logs)}")

    def run_selected_scenario(self):
        scenario_name = self.scenario_var.get()
        try:
            from backend.scenario_runner import ScenarioRunner
            runner = ScenarioRunner()
            result = runner.run(scenario_name)
            if result.get("error"):
                self.log_to_console(f"ERROR: {result.get('error')}")
                return
            events = result.get("events", [])
            self.write_logs(events, append=True)
            self.log_to_console(f"BENCHMARK: Generated {len(events)} events for scenario '{scenario_name}'.")
            self.log_to_console(f"  Description: {result.get('description', '')}")
        except Exception as e:
            self.log_to_console(f"ERROR running scenario: {e}")

    # SCENARIOS
    def gen_normal_activity(self):
        now_iso = datetime.now(timezone.utc).isoformat()
        events = [
            {
                "id": f"evt-{uuid.uuid4().hex[:8]}",
                "timestamp": now_iso,
                "hour": 9,
                "user": "jdoe",
                "source_ip": "192.168.1.45",
                "event_type": "login_success",
                "resource": "/auth/login",
                "details": "User jdoe logged in successfully"
            },
            {
                "id": f"evt-{uuid.uuid4().hex[:8]}",
                "timestamp": now_iso,
                "hour": 10,
                "user": "jdoe",
                "source_ip": "192.168.1.45",
                "event_type": "file_access",
                "resource": "/docs/quarterly_report.pdf",
                "details": "Opened quarterly report document"
            },
            {
                "id": f"evt-{uuid.uuid4().hex[:8]}",
                "timestamp": now_iso,
                "hour": 11,
                "user": "mworker",
                "source_ip": "192.168.1.52",
                "event_type": "login_success",
                "resource": "/auth/login",
                "details": "User mworker authenticated"
            },
            {
                "id": f"evt-{uuid.uuid4().hex[:8]}",
                "timestamp": now_iso,
                "hour": 14,
                "user": "mworker",
                "source_ip": "192.168.1.52",
                "event_type": "data_transfer",
                "resource": "/export/billing_csv",
                "details": "Standard data export performed"
            }
        ]
        self.write_logs(events, append=True)
        self.log_to_console("SUCCESS: Generated 4 standard business activity log events.")

    def gen_suspicious_login(self):
        now_iso = datetime.now(timezone.utc).isoformat()
        target_ip = "198.51.100.44"
        events = [
            {
                "id": f"evt-{uuid.uuid4().hex[:8]}",
                "timestamp": now_iso,
                "hour": 3,
                "user": "admin",
                "source_ip": target_ip,
                "event_type": "login_failed",
                "resource": "/admin/login",
                "details": "Invalid password attempt (off-hours)"
            },
            {
                "id": f"evt-{uuid.uuid4().hex[:8]}",
                "timestamp": now_iso,
                "hour": 3,
                "user": "admin",
                "source_ip": target_ip,
                "event_type": "login_failed",
                "resource": "/admin/login",
                "details": "Invalid password attempt (off-hours)"
            },
            {
                "id": f"evt-{uuid.uuid4().hex[:8]}",
                "timestamp": now_iso,
                "hour": 3,
                "user": "admin",
                "source_ip": target_ip,
                "event_type": "login_failed",
                "resource": "/admin/login",
                "details": "Invalid password attempt (off-hours)"
            },
            {
                "id": f"evt-{uuid.uuid4().hex[:8]}",
                "timestamp": now_iso,
                "hour": 3,
                "user": "admin",
                "source_ip": target_ip,
                "event_type": "unusual_request",
                "resource": "/admin/api/v1/keys",
                "details": "Unauthenticated API probe detected"
            }
        ]
        self.write_logs(events, append=True)
        self.log_to_console("ALERT: Generated Suspicious Off-Hours Login Attempt events.")

    def gen_account_takeover(self):
        now_iso = datetime.now(timezone.utc).isoformat()
        target_ip = "203.0.113.88"
        user = "admin"
        events = [
            {
                "id": f"evt-{uuid.uuid4().hex[:8]}",
                "timestamp": now_iso,
                "hour": 2,
                "user": user,
                "source_ip": target_ip,
                "event_type": "login_failed",
                "resource": "/portal/login",
                "details": "Failed password check"
            },
            {
                "id": f"evt-{uuid.uuid4().hex[:8]}",
                "timestamp": now_iso,
                "hour": 2,
                "user": user,
                "source_ip": target_ip,
                "event_type": "login_failed",
                "resource": "/portal/login",
                "details": "Failed password check"
            },
            {
                "id": f"evt-{uuid.uuid4().hex[:8]}",
                "timestamp": now_iso,
                "hour": 2,
                "user": user,
                "source_ip": target_ip,
                "event_type": "login_failed",
                "resource": "/portal/login",
                "details": "Failed password check"
            },
            {
                "id": f"evt-{uuid.uuid4().hex[:8]}",
                "timestamp": now_iso,
                "hour": 2,
                "user": user,
                "source_ip": target_ip,
                "event_type": "login_success",
                "resource": "/portal/login",
                "details": "Successful login after 3 failed attempts (Brute force success)"
            },
            {
                "id": f"evt-{uuid.uuid4().hex[:8]}",
                "timestamp": now_iso,
                "hour": 2,
                "user": user,
                "source_ip": target_ip,
                "event_type": "privilege_change",
                "resource": "/admin/roles/grant_super_admin",
                "details": "User elevated privileges to Super Admin"
            },
            {
                "id": f"evt-{uuid.uuid4().hex[:8]}",
                "timestamp": now_iso,
                "hour": 2,
                "user": user,
                "source_ip": target_ip,
                "event_type": "sensitive_resource_access",
                "resource": "/vault/customer_ssn_db",
                "details": "Accessed encrypted customer database credentials"
            }
        ]
        self.write_logs(events, append=True)
        self.log_to_console("CRITICAL: Generated Complete Account Takeover & Exfiltration Attack Chain.")

    def gen_privilege_escalation(self):
        now_iso = datetime.now(timezone.utc).isoformat()
        user = "dev_user"
        ip = "10.0.4.12"
        events = [
            {
                "id": f"evt-{uuid.uuid4().hex[:8]}",
                "timestamp": now_iso,
                "hour": 14,
                "user": user,
                "source_ip": ip,
                "event_type": "login_success",
                "resource": "/dev/login",
                "details": "Developer workstation session initiated"
            },
            {
                "id": f"evt-{uuid.uuid4().hex[:8]}",
                "timestamp": now_iso,
                "hour": 14,
                "user": user,
                "source_ip": ip,
                "event_type": "unusual_request",
                "resource": "/api/internal/sudo_check",
                "details": "Internal privilege boundary probe"
            },
            {
                "id": f"evt-{uuid.uuid4().hex[:8]}",
                "timestamp": now_iso,
                "hour": 15,
                "user": user,
                "source_ip": ip,
                "event_type": "privilege_change",
                "resource": "/system/group/wheel",
                "details": "Account added to privileged wheel group"
            },
            {
                "id": f"evt-{uuid.uuid4().hex[:8]}",
                "timestamp": now_iso,
                "hour": 15,
                "user": user,
                "source_ip": ip,
                "event_type": "sensitive_resource_access",
                "resource": "/etc/shadow",
                "details": "Direct file read on system password shadow file"
            }
        ]
        self.write_logs(events, append=True)
        self.log_to_console("HIGH: Generated Privilege Escalation Attack Chain.")

    def gen_sensitive_access(self):
        now_iso = datetime.now(timezone.utc).isoformat()
        user = "analyst1"
        ip = "192.168.1.110"
        events = [
            {
                "id": f"evt-{uuid.uuid4().hex[:8]}",
                "timestamp": now_iso,
                "hour": 11,
                "user": user,
                "source_ip": ip,
                "event_type": "login_success",
                "resource": "/auth/login",
                "details": "Standard analyst login"
            },
            {
                "id": f"evt-{uuid.uuid4().hex[:8]}",
                "timestamp": now_iso,
                "hour": 11,
                "user": user,
                "source_ip": ip,
                "event_type": "sensitive_resource_access",
                "resource": "/db/payroll_records",
                "details": "Accessed Restricted HR Payroll Records Database"
            },
            {
                "id": f"evt-{uuid.uuid4().hex[:8]}",
                "timestamp": now_iso,
                "hour": 11,
                "user": user,
                "source_ip": ip,
                "event_type": "sensitive_resource_access",
                "resource": "/db/executive_compensation",
                "details": "Accessed Executive Compensation Database"
            },
            {
                "id": f"evt-{uuid.uuid4().hex[:8]}",
                "timestamp": now_iso,
                "hour": 11,
                "user": user,
                "source_ip": ip,
                "event_type": "data_transfer",
                "resource": "/export/bulk_dl",
                "details": "Exported 5,000 records via HTTPS"
            }
        ]
        self.write_logs(events, append=True)
        self.log_to_console("WARNING: Generated Unauthorized Sensitive Data Access events.")

    def clear_logs(self):
        self.write_logs([], append=False)
        self.log_to_console("CLEARED: All synthetic log events cleared from logs.json.")

    def open_dashboard(self):
        url = "http://localhost:8000"
        webbrowser.open(url)
        self.log_to_console(f"Opened Live Dashboard in default browser: {url}")


if __name__ == "__main__":
    app = LogShieldSimulator()
    app.mainloop()
