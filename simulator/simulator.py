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

# Ensure logshield directory is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

WORKSPACE_ROOT = BASE_DIR.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

DATA_DIR = BASE_DIR / "data"
LOGS_FILE = DATA_DIR / "logs.json"
API_URL = "http://localhost:8000/api"

class CyberButton(tk.Frame):
    """Custom Apple/Cybersecurity-styled borderless hover button."""
    def __init__(self, parent, text, command, fg="#f8fafc", bg="#131b2e", hover_bg="#1e293b", accent_color="#06b6d4", font=None, **kwargs):
        super().__init__(parent, bg=accent_color, bd=0, highlightthickness=0, **kwargs)
        self.command = command
        self.bg = bg
        self.hover_bg = hover_bg
        self.fg = fg
        self.accent_color = accent_color
        
        self.inner = tk.Frame(self, bg=bg, bd=0)
        self.inner.pack(fill="both", expand=True, padx=1, pady=1)
        
        self.label = tk.Label(
            self.inner,
            text=text,
            fg=fg,
            bg=bg,
            font=font or ("Segoe UI", 9, "bold"),
            anchor="w",
            padx=12,
            pady=8,
            cursor="hand2"
        )
        self.label.pack(fill="both", expand=True)
        
        self.label.bind("<Enter>", self._on_enter)
        self.label.bind("<Leave>", self._on_leave)
        self.label.bind("<Button-1>", self._on_click)

    def _on_enter(self, e):
        self.inner.config(bg=self.hover_bg)
        self.label.config(bg=self.hover_bg)

    def _on_leave(self, e):
        self.inner.config(bg=self.bg)
        self.label.config(bg=self.bg)

    def _on_click(self, e):
        if self.command:
            self.command()


class LogShieldSimulator(tk.Tk):
    """macOS-inspired Cybersecurity Event Simulator for SENTRA / LogShield."""

    def __init__(self):
        super().__init__()

        self.title("SENTRA — Security Event Simulation Suite")
        self.geometry("900x650")
        self.minsize(820, 580)
        self.configure(bg="#070a12")

        # Color Palette - Cybersecurity Dark Mode
        self.C_BG = "#070a12"
        self.C_CARD = "#0f172a"
        self.C_CARD_HEADER = "#1e293b"
        self.C_BORDER = "#1e293b"
        self.C_TEXT = "#f8fafc"
        self.C_MUTED = "#64748b"
        self.C_SUBTEXT = "#94a3b8"
        
        self.C_CYAN = "#06b6d4"        # Neon Cyan
        self.C_EMERALD = "#10b981"     # Emerald Green
        self.C_AMBER = "#f59e0b"       # Amber Gold
        self.C_ROSE = "#f43f5e"        # Rose Crimson
        self.C_VIOLET = "#a855f7"      # Electric Violet
        self.C_BLUE = "#3b82f6"        # Apple Blue

        # Font configuration
        self.F_FAMILY = "-apple-system" if sys.platform == "darwin" else "Segoe UI"
        self.F_HEADER = (self.F_FAMILY, 12, "bold")
        self.F_SUB = (self.F_FAMILY, 8)
        self.F_BTN = (self.F_FAMILY, 9, "bold")
        self.F_MONO = ("JetBrains Mono", 9) if sys.platform != "darwin" else ("Menlo", 10)

        # ttk combobox styling
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TCombobox", fieldbackground="#131b2e", background="#1e293b", foreground="#f8fafc", borderwidth=0)

        self.build_ui()
        self.check_backend_status()
        self.update_log_count()

    def build_ui(self):
        # 1. macOS Top Window Bar
        mac_bar = tk.Frame(self, bg="#0d1322", height=38, bd=0)
        mac_bar.pack(fill="x", side="top")

        # macOS Red / Yellow / Green Window Controls
        dots_frame = tk.Frame(mac_bar, bg="#0d1322")
        dots_frame.pack(side="left", padx=14, pady=10)

        tk.Label(dots_frame, text="🔴", font=("Segoe UI", 7), bg="#0d1322", fg="#ff5f56").pack(side="left", padx=2)
        tk.Label(dots_frame, text="🟡", font=("Segoe UI", 7), bg="#0d1322", fg="#ffbd2e").pack(side="left", padx=2)
        tk.Label(dots_frame, text="🟢", font=("Segoe UI", 7), bg="#0d1322", fg="#27c93f").pack(side="left", padx=2)

        tk.Label(
            mac_bar,
            text="SENTRA // SECURITY TELEMETRY SIMULATION SUITE",
            font=(self.F_FAMILY, 9, "bold"),
            bg="#0d1322",
            fg=self.C_CYAN
        ).pack(side="left", padx=10)

        # Status Badge Pill
        self.status_badge = tk.Label(
            mac_bar,
            text="● CONNECTING",
            font=(self.F_FAMILY, 8, "bold"),
            bg="#1e293b",
            fg=self.C_SUBTEXT,
            padx=10,
            pady=3
        )
        self.status_badge.pack(side="right", padx=14, pady=6)

        # 2. Subheader Banner
        sub_banner = tk.Frame(self, bg="#0f172a", bd=1, relief="flat", highlightbackground="#1e293b", highlightthickness=1)
        sub_banner.pack(fill="x", padx=14, pady=(10, 10))

        tk.Label(
            sub_banner,
            text="🛡️ Controlled Security Telemetry Stream Generator",
            font=self.F_HEADER,
            bg="#0f172a",
            fg=self.C_TEXT
        ).pack(anchor="w", padx=14, pady=(10, 2))

        tk.Label(
            sub_banner,
            text="Simulate realistic attack scenarios, privilege changes, and multi-stage exfiltration chains into SENTRA detection pipeline.",
            font=self.F_SUB,
            bg="#0f172a",
            fg=self.C_SUBTEXT
        ).pack(anchor="w", padx=14, pady=(0, 10))

        # 3. Main Content Layout (Left Controls 330px, Right Console)
        content_frame = tk.Frame(self, bg=self.C_BG)
        content_frame.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        # Left Controls Frame
        controls_card = tk.Frame(content_frame, bg="#0f172a", bd=1, relief="flat", highlightbackground="#1e293b", highlightthickness=1)
        controls_card.pack(side="left", fill="y", padx=(0, 10), ipadx=6, ipady=6)

        tk.Label(
            controls_card,
            text="THREAT SCENARIO INJECTORS",
            font=(self.F_FAMILY, 8, "bold"),
            bg="#0f172a",
            fg=self.C_CYAN
        ).pack(anchor="w", padx=12, pady=(12, 8))

        scenarios = [
            ("🟢 Standard Business Activity", self.gen_normal_activity, self.C_EMERALD, self.C_EMERALD),
            ("🟡 Off-Hours Suspicious Probe", self.gen_suspicious_login, self.C_AMBER, self.C_AMBER),
            ("🔴 Account Takeover & Exfil", self.gen_account_takeover, self.C_ROSE, self.C_ROSE),
            ("⚡ Privilege Escalation Chain", self.gen_privilege_escalation, self.C_VIOLET, self.C_VIOLET),
            ("📦 Restricted Vault Access", self.gen_sensitive_access, self.C_CYAN, self.C_CYAN),
        ]

        for text, cmd, fg_color, border_color in scenarios:
            CyberButton(
                controls_card,
                text=text,
                command=cmd,
                fg=fg_color,
                bg="#131b2e",
                hover_bg="#1c2842",
                accent_color=border_color,
                font=self.F_BTN
            ).pack(fill="x", padx=12, pady=4)

        # Benchmark Scenarios
        tk.Label(
            controls_card,
            text="BENCHMARK EVALUATION (L1 - L4)",
            font=(self.F_FAMILY, 8, "bold"),
            bg="#0f172a",
            fg=self.C_MUTED
        ).pack(anchor="w", padx=12, pady=(14, 4))

        self.scenario_var = tk.StringVar(value="gradual_drift")
        scenario_combo = ttk.Combobox(
            controls_card,
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
            font=(self.F_FAMILY, 9),
        )
        scenario_combo.pack(fill="x", padx=12, pady=4)

        CyberButton(
            controls_card,
            text="▶ Inject Benchmark Scenario",
            command=self.run_selected_scenario,
            fg="#ffffff",
            bg="#0284c7",
            hover_bg="#0369a1",
            accent_color="#38bdf8",
            font=self.F_BTN
        ).pack(fill="x", padx=12, pady=(4, 12))

        # Bottom Quick Tools
        util_frame = tk.Frame(controls_card, bg="#0f172a")
        util_frame.pack(fill="x", padx=12, pady=(8, 8), side="bottom")

        CyberButton(
            util_frame,
            text="🗑️ Clear Store",
            command=self.clear_logs,
            fg=self.C_MUTED,
            bg="#131b2e",
            hover_bg="#1e293b",
            accent_color="#334155",
            font=self.F_BTN
        ).pack(side="left", fill="x", expand=True, padx=(0, 3))

        CyberButton(
            util_frame,
            text="🌐 Dashboard",
            command=self.open_dashboard,
            fg=self.C_BLUE,
            bg="#131b2e",
            hover_bg="#1e293b",
            accent_color=self.C_BLUE,
            font=self.F_BTN
        ).pack(side="right", fill="x", expand=True, padx=(3, 0))

        # Right Console Frame
        console_card = tk.Frame(content_frame, bg="#0f172a", bd=1, relief="flat", highlightbackground="#1e293b", highlightthickness=1)
        console_card.pack(side="right", fill="both", expand=True)

        console_header = tk.Frame(console_card, bg="#1e293b")
        console_header.pack(fill="x")

        tk.Label(
            console_header,
            text="REAL-TIME TELEMETRY CONSOLE",
            font=(self.F_FAMILY, 8, "bold"),
            bg="#1e293b",
            fg=self.C_SUBTEXT
        ).pack(side="left", padx=12, pady=8)

        self.log_count_lbl = tk.Label(
            console_header,
            text="Active Records: 0",
            font=(self.F_FAMILY, 9, "bold"),
            bg="#1e293b",
            fg=self.C_EMERALD
        )
        self.log_count_lbl.pack(side="right", padx=12, pady=8)

        # Console Text Box
        self.console_text = tk.Text(
            console_card,
            bg="#090d16",
            fg="#38bdf8",
            insertbackground="#ffffff",
            font=self.F_MONO,
            bd=0,
            padx=14,
            pady=14,
            wrap="word"
        )
        self.console_text.pack(fill="both", expand=True)
        
        scrollbar = ttk.Scrollbar(self.console_text, command=self.console_text.yview)
        scrollbar.pack(side="right", fill="y")
        self.console_text.config(yscrollcommand=scrollbar.set)

        self.log_to_console("SENTRA Telemetry Streamer active. Select an injection scenario.")

    def log_to_console(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.console_text.insert(tk.END, f"[{ts}] {msg}\n")
        self.console_text.see(tk.END)

    def check_backend_status(self):
        """Safely check if LogShield FastAPI backend is active."""
        try:
            req = urllib.request.Request(f"{API_URL}/health")
            with urllib.request.urlopen(req, timeout=1) as resp:
                if resp.status == 200:
                    self.status_badge.config(text="● SERVER ONLINE", fg=self.C_EMERALD, bg="#064e3b")
                    return
        except Exception:
            pass
        self.status_badge.config(text="● STANDBY (LOCAL STORE)", fg=self.C_AMBER, bg="#451a03")

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

        try:
            req = urllib.request.Request(
                f"{API_URL}/upload",
                data=json.dumps(combined).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            urllib.request.urlopen(req, timeout=1)
            self.check_backend_status()
        except Exception:
            pass

    def update_log_count(self):
        logs = self.read_current_logs()
        self.log_count_lbl.config(text=f"Active Records: {len(logs)}")

    def run_selected_scenario(self):
        scenario_name = self.scenario_var.get()
        try:
            try:
                from backend.scenario_runner import ScenarioRunner
            except ImportError:
                from logshield.backend.scenario_runner import ScenarioRunner

            runner = ScenarioRunner()
            result = runner.run(scenario_name)
            if result.get("error"):
                self.log_to_console(f"ERROR: {result.get('error')}")
                return
            events = result.get("events", [])
            self.write_logs(events, append=True)
            self.log_to_console(f"BENCHMARK: Generated {len(events)} events for scenario '{scenario_name}'.")
            self.log_to_console(f"  Info: {result.get('description', '')}")
        except Exception as e:
            self.log_to_console(f"NOTICE: Benchmark Scenario Engine: {e}")

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
            }
        ]
        self.write_logs(events, append=True)
        self.log_to_console("SUCCESS: Injected standard operational business logs.")

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
                "event_type": "unusual_request",
                "resource": "/admin/api/v1/keys",
                "details": "Unauthenticated API probe detected"
            }
        ]
        self.write_logs(events, append=True)
        self.log_to_console("ALERT: Injected Suspicious Off-Hours Probe Telemetry.")

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
                "event_type": "login_success",
                "resource": "/portal/login",
                "details": "Successful login after failed attempts"
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
                "details": "Accessed encrypted database credentials"
            }
        ]
        self.write_logs(events, append=True)
        self.log_to_console("CRITICAL: Injected Account Takeover & Exfiltration Attack Chain.")

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
        self.log_to_console("HIGH: Injected Privilege Escalation Attack Chain.")

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
                "event_type": "sensitive_resource_access",
                "resource": "/db/payroll_records",
                "details": "Accessed Restricted HR Payroll Database"
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
        self.log_to_console("WARNING: Injected Restricted Vault Data Access Telemetry.")

    def clear_logs(self):
        self.write_logs([], append=False)
        self.log_to_console("CLEARED: Telemetry log store cleared.")

    def open_dashboard(self):
        url = "http://localhost:8000"
        webbrowser.open(url)
        self.log_to_console(f"Opened SENTRA Dashboard in browser: {url}")


if __name__ == "__main__":
    app = LogShieldSimulator()
    app.mainloop()
