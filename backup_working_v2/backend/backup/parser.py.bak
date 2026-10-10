import json
import csv
import io
import re
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

VALID_EVENT_TYPES = {
    "login_failed",
    "login_success",
    "privilege_change",
    "sensitive_resource_access",
    "file_access",
    "unusual_request",
    "data_transfer"
}

def parse_timestamp(ts_val: Any) -> tuple[str, int]:
    """Parse various timestamp formats and return (iso_string, hour_of_day)."""
    if not ts_val:
        now = datetime.now(timezone.utc)
        return now.isoformat(), now.hour

    if isinstance(ts_val, (int, float)):
        try:
            dt = datetime.fromtimestamp(ts_val, tz=timezone.utc)
            return dt.isoformat(), dt.hour
        except Exception:
            pass

    ts_str = str(ts_val).strip()
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.isoformat(), dt.hour
    except Exception:
        pass

    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S",
        "%b %d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(ts_str[:19], fmt).replace(tzinfo=timezone.utc)
            return dt.isoformat(), dt.hour
        except Exception:
            continue

    now = datetime.now(timezone.utc)
    return now.isoformat(), now.hour


def normalize_event_type(raw_type: Any) -> str:
    """Normalize event type to standard set or 'unusual_request' if unrecognized."""
    if not raw_type:
        return "unusual_request"
    
    clean_type = str(raw_type).strip().lower().replace(" ", "_").replace("-", "_")
    
    if clean_type in VALID_EVENT_TYPES:
        return clean_type
    
    aliases = {
        "failed_login": "login_failed",
        "login_failure": "login_failed",
        "auth_failed": "login_failed",
        "authentication_failure": "login_failed",
        "invalid_password": "login_failed",
        "access_denied": "login_failed",
        "401": "login_failed",
        "403": "login_failed",
        
        "successful_login": "login_success",
        "login_ok": "login_success",
        "auth_success": "login_success",
        "authenticated": "login_success",
        "200_login": "login_success",
        "session_start": "login_success",
        
        "priv_esc": "privilege_change",
        "privilege_escalation": "privilege_change",
        "role_change": "privilege_change",
        "sudo": "privilege_change",
        "admin_grant": "privilege_change",
        "chmod": "privilege_change",
        
        "sensitive_access": "sensitive_resource_access",
        "vault_access": "sensitive_resource_access",
        "secret_read": "sensitive_resource_access",
        "key_access": "sensitive_resource_access",
        
        "exfiltration": "data_transfer",
        "file_download": "data_transfer",
        "data_export": "data_transfer",
        "download": "data_transfer",
        
        "file_read": "file_access",
        "read": "file_access",
        "file_open": "file_access",
        
        "suspicious_req": "unusual_request",
        "probe": "unusual_request",
        "scan": "unusual_request"
    }
    
    return aliases.get(clean_type, "unusual_request")


def normalize_log_event(raw_event: Dict[str, Any], index: int = 0) -> Dict[str, Any]:
    """Ensure a single event dictionary has all required standard fields."""
    if not isinstance(raw_event, dict):
        raw_event = {"details": str(raw_event)}

    evt_id = str(raw_event.get("id") or raw_event.get("event_id") or f"evt-{uuid.uuid4().hex[:8]}")
    ts_raw = raw_event.get("timestamp") or raw_event.get("time") or raw_event.get("datetime") or raw_event.get("date")
    iso_ts, hour = parse_timestamp(ts_raw)

    user = str(
        raw_event.get("user") or 
        raw_event.get("username") or 
        raw_event.get("account") or 
        raw_event.get("usr") or 
        "unknown"
    ).strip()
    
    source_ip = str(
        raw_event.get("source_ip") or 
        raw_event.get("ip") or 
        raw_event.get("client_ip") or 
        raw_event.get("src_ip") or 
        raw_event.get("remote_addr") or 
        "127.0.0.1"
    ).strip()
    
    raw_type = raw_event.get("event_type") or raw_event.get("type") or raw_event.get("action") or raw_event.get("status")
    event_type = normalize_event_type(raw_type)

    resource = str(
        raw_event.get("resource") or 
        raw_event.get("target") or 
        raw_event.get("path") or 
        raw_event.get("uri") or 
        raw_event.get("url") or 
        "/"
    ).strip()
    
    details = str(
        raw_event.get("details") or 
        raw_event.get("message") or 
        raw_event.get("description") or 
        raw_event.get("msg") or 
        f"Event {event_type}"
    ).strip()

    return {
        "id": evt_id,
        "timestamp": iso_ts,
        "hour": hour,
        "user": user,
        "source_ip": source_ip,
        "event_type": event_type,
        "resource": resource,
        "details": details
    }


class BaseLogParser(ABC):
    """Abstract Base Class for modular log parsers."""
    
    @abstractmethod
    def can_parse(self, content: str, filename: str = "") -> bool:
        """Check if this parser handles the given content or file type."""
        pass

    @abstractmethod
    def parse(self, content: str) -> List[Dict[str, Any]]:
        """Parse raw content into normalized log events."""
        pass


class JSONLogParser(BaseLogParser):
    """Parser for JSON array, JSON object, and JSON Lines (JSONL) log formats."""

    def can_parse(self, content: str, filename: str = "") -> bool:
        clean = content.strip()
        if filename.lower().endswith((".json", ".jsonl")):
            return True
        return clean.startswith("[") or clean.startswith("{")

    def parse(self, content: str) -> List[Dict[str, Any]]:
        content_str = content.strip()
        if not content_str:
            return []

        parsed = None
        # Try full JSON parse
        try:
            parsed = json.loads(content_str)
        except Exception:
            # Fallback to line-delimited JSON (JSONL)
            parsed = []
            for line in content_str.splitlines():
                line = line.strip()
                if line and (line.startswith("{") or line.startswith("[")):
                    try:
                        parsed.append(json.loads(line))
                    except Exception:
                        continue

        if parsed is None:
            return []

        if isinstance(parsed, dict):
            if "logs" in parsed and isinstance(parsed["logs"], list):
                parsed = parsed["logs"]
            elif "events" in parsed and isinstance(parsed["events"], list):
                parsed = parsed["events"]
            else:
                parsed = [parsed]

        if not isinstance(parsed, list):
            return []

        normalized = []
        for idx, item in enumerate(parsed):
            if item:
                normalized.append(normalize_log_event(item, idx))

        return normalized


class CSVLogParser(BaseLogParser):
    """Parser for CSV log files with flexible column headers."""

    def can_parse(self, content: str, filename: str = "") -> bool:
        if filename.lower().endswith(".csv"):
            return True
        lines = [line.strip() for line in content.splitlines() if line.strip()]
        if lines and "," in lines[0] and not lines[0].startswith("{"):
            return True
        return False

    def parse(self, content: str) -> List[Dict[str, Any]]:
        content_str = content.strip()
        if not content_str:
            return []

        stream = io.StringIO(content_str)
        reader = csv.DictReader(stream)
        
        normalized = []
        for idx, row in enumerate(reader):
            if row:
                normalized.append(normalize_log_event(dict(row), idx))

        return normalized


class SyslogParser(BaseLogParser):
    """Parser for standard Syslog (RFC 3164 / Auth / Web access text logs)."""

    SYSLOG_PATTERN = re.compile(
        r'^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<process>[\w\-\/\.]+)(?:\[\d+\])?:?\s+(?P<message>.*)$'
    )

    def can_parse(self, content: str, filename: str = "") -> bool:
        if filename.lower().endswith((".log", ".txt")):
            return True
        lines = [line.strip() for line in content.splitlines() if line.strip()]
        if lines and self.SYSLOG_PATTERN.match(lines[0]):
            return True
        return False

    def parse(self, content: str) -> List[Dict[str, Any]]:
        normalized = []
        for idx, line in enumerate(content.splitlines()):
            line_str = line.strip()
            if not line_str:
                continue

            match = self.SYSLOG_PATTERN.match(line_str)
            if match:
                gd = match.groupdict()
                msg = gd.get("message", "")
                
                # Extract IP if present in message
                ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', msg)
                source_ip = ip_match.group(0) if ip_match else "127.0.0.1"

                # Extract user if present in message
                user_match = re.search(r'\buser\s+([\w\.\-]+)|\bfor\s+([\w\.\-]+)', msg, re.IGNORECASE)
                user = (user_match.group(1) or user_match.group(2)) if user_match else "system"

                # Extract event type from text patterns
                event_type = "unusual_request"
                msg_lower = msg.lower()
                if "failed" in msg_lower or "invalid" in msg_lower or "denied" in msg_lower:
                    event_type = "login_failed"
                elif "accepted" in msg_lower or "session opened" in msg_lower or "success" in msg_lower:
                    event_type = "login_success"
                elif "sudo" in msg_lower or "privilege" in msg_lower or "command as root" in msg_lower:
                    event_type = "privilege_change"

                raw_event = {
                    "timestamp": gd.get("timestamp"),
                    "user": user,
                    "source_ip": source_ip,
                    "event_type": event_type,
                    "resource": gd.get("process", "/syslog"),
                    "details": msg
                }
                normalized.append(normalize_log_event(raw_event, idx))
            else:
                raw_event = {
                    "details": line_str,
                    "event_type": "unusual_request"
                }
                normalized.append(normalize_log_event(raw_event, idx))

        return normalized


class LogParserManager:
    """Central registry and dispatcher for extensible log format parsing."""

    def __init__(self):
        self.parsers: List[BaseLogParser] = [
            JSONLogParser(),
            CSVLogParser(),
            SyslogParser()
        ]

    def register_parser(self, parser: BaseLogParser):
        """Allows adding new log format parsers dynamically."""
        self.parsers.insert(0, parser)

    def parse(self, content: str | bytes, filename: str = "") -> List[Dict[str, Any]]:
        if isinstance(content, (bytes, bytearray)):
            content = content.decode("utf-8", errors="ignore")

        if not content or not content.strip():
            return []

        for parser in self.parsers:
            if parser.can_parse(content, filename):
                try:
                    events = parser.parse(content)
                    if events:
                        return events
                except Exception:
                    continue

        try:
            return JSONLogParser().parse(content)
        except Exception:
            pass

        try:
            return CSVLogParser().parse(content)
        except Exception:
            pass

        return SyslogParser().parse(content)


parser_manager = LogParserManager()

def parse_json_logs(json_content: str | bytes | list | dict) -> List[Dict[str, Any]]:
    if isinstance(json_content, (list, dict)):
        json_content = json.dumps(json_content)
    return JSONLogParser().parse(str(json_content))

def parse_csv_logs(csv_content: str | bytes) -> List[Dict[str, Any]]:
    return CSVLogParser().parse(str(csv_content))

def parse_logs(content: str | bytes, filename: str = "") -> List[Dict[str, Any]]:
    return parser_manager.parse(content, filename)

