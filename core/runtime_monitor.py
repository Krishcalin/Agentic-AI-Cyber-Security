"""Runtime Agent Monitor — real-time session monitoring with anomaly detection.

Tracks agent behavior in real-time and detects anomalies:
- Action frequency spikes (sudden burst of file reads or network requests)
- Behavioral drift (agent deviating from established patterns)
- Sensitive resource access sequences
- Session-level risk scoring with progressive alerts
- Time-series analysis for long-running sessions

Integrates with PolicyEngine for enforcement and ChainDetector for
multi-step attack detection.
"""

from __future__ import annotations

import time
from collections import Counter, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

log = structlog.get_logger("runtime_monitor")


# ── Data Models ───────────────────────────────────────────────────────────

class AlertLevel(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AnomalyType(str, Enum):
    FREQUENCY_SPIKE = "frequency_spike"
    BEHAVIORAL_DRIFT = "behavioral_drift"
    SENSITIVE_ACCESS = "sensitive_access"
    UNUSUAL_SEQUENCE = "unusual_sequence"
    RATE_ANOMALY = "rate_anomaly"
    PRIVILEGE_ANOMALY = "privilege_anomaly"
    NETWORK_ANOMALY = "network_anomaly"


@dataclass
class MonitoredAction:
    """A recorded agent action for monitoring."""
    action_type: str
    target: str
    tool_name: str
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0


@dataclass
class Alert:
    """A generated alert from the monitor."""
    alert_id: str
    level: AlertLevel
    anomaly_type: AnomalyType
    title: str
    description: str
    session_id: str
    timestamp: float = field(default_factory=time.time)
    related_actions: list[MonitoredAction] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "level": self.level.value,
            "anomaly_type": self.anomaly_type.value,
            "title": self.title,
            "description": self.description,
            "session_id": self.session_id,
            "timestamp": self.timestamp,
            "related_actions_count": len(self.related_actions),
        }


@dataclass
class SessionProfile:
    """Behavioral profile for a session — tracks normal patterns."""
    session_id: str
    start_time: float = field(default_factory=time.time)
    action_counts: Counter = field(default_factory=Counter)
    action_rate_history: list[float] = field(default_factory=list)  # Actions per minute
    tool_usage: Counter = field(default_factory=Counter)
    sensitive_accesses: int = 0
    network_requests: int = 0
    total_actions: int = 0
    risk_score: float = 0.0
    alerts: list[Alert] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        return time.time() - self.start_time

    @property
    def actions_per_minute(self) -> float:
        dur = self.duration_seconds
        if dur < 1:
            return 0.0
        return (self.total_actions / dur) * 60

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "duration_seconds": round(self.duration_seconds, 1),
            "total_actions": self.total_actions,
            "actions_per_minute": round(self.actions_per_minute, 1),
            "risk_score": round(self.risk_score, 2),
            "alert_count": len(self.alerts),
            "sensitive_accesses": self.sensitive_accesses,
            "network_requests": self.network_requests,
            "top_tools": dict(self.tool_usage.most_common(5)),
            "top_action_types": dict(self.action_counts.most_common(5)),
        }


# ── Sensitive Patterns ────────────────────────────────────────────────────

SENSITIVE_FILE_PATTERNS = [
    r"\.env", r"\.aws", r"\.ssh", r"\.gnupg", r"\.kube",
    r"credential", r"password", r"secret", r"token", r"\.key$",
    r"/etc/shadow", r"/etc/passwd", r"\.pem$", r"\.p12$",
    r"id_rsa", r"wallet\.dat", r"\.netrc", r"\.pgpass",
]

SUSPICIOUS_NETWORK_PATTERNS = [
    r"ngrok", r"requestbin", r"hookbin", r"burpcollaborator",
    r"interact\.sh", r"pipedream", r"canarytokens", r"webhook\.site",
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # Raw IP addresses
]

PRIVILEGE_PATTERNS = [
    r"sudo", r"su\s+-", r"runas", r"chmod\s+[47]", r"chown\s+root",
    r"net\s+localgroup\s+admin", r"Add-LocalGroupMember",
    r"setuid", r"setgid", r"pkexec",
]


# ── Runtime Monitor ───────────────────────────────────────────────────────

class RuntimeMonitor:
    """Real-time agent session monitor with anomaly detection.

    Usage:
        monitor = RuntimeMonitor()

        # Record actions as they happen
        alert = monitor.record("sess1", "file_read", "/home/user/.env", "read_file")
        if alert:
            print(f"ALERT: {alert.title}")

        # Get session status
        profile = monitor.get_session_profile("sess1")
        print(profile.risk_score)

        # Get all alerts
        alerts = monitor.get_alerts("sess1")
    """

    # Thresholds for anomaly detection
    FREQUENCY_WINDOW_SECONDS = 30
    FREQUENCY_SPIKE_THRESHOLD = 15  # Actions in window
    SENSITIVE_ACCESS_WARN_THRESHOLD = 3
    SENSITIVE_ACCESS_CRITICAL_THRESHOLD = 5
    NETWORK_BURST_THRESHOLD = 10  # Requests in 30 seconds
    RISK_SCORE_WARN = 50.0
    RISK_SCORE_CRITICAL = 80.0

    # Risk score weights
    RISK_WEIGHTS = {
        "sensitive_file": 10.0,
        "network_request": 3.0,
        "suspicious_network": 15.0,
        "command_execution": 2.0,
        "privilege_action": 20.0,
        "frequency_spike": 10.0,
    }

    def __init__(self, max_history: int = 10000) -> None:
        self._sessions: dict[str, SessionProfile] = {}
        self._action_windows: dict[str, deque] = {}  # session -> recent action timestamps
        self._max_history = max_history
        self._alert_counter = 0

    def record(
        self,
        session_id: str,
        action_type: str,
        target: str,
        tool_name: str,
        metadata: dict[str, Any] | None = None,
    ) -> Alert | None:
        """Record an agent action and check for anomalies.

        Returns an Alert if anomaly is detected, None otherwise.
        """
        now = time.time()

        # Initialize session if needed
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionProfile(session_id=session_id)
            self._action_windows[session_id] = deque(maxlen=self._max_history)

        profile = self._sessions[session_id]
        window = self._action_windows[session_id]

        # Create monitored action
        action = MonitoredAction(
            action_type=action_type,
            target=target,
            tool_name=tool_name,
            timestamp=now,
            metadata=metadata or {},
        )

        # Update profile stats
        profile.total_actions += 1
        profile.action_counts[action_type] += 1
        profile.tool_usage[tool_name] += 1
        window.append(action)

        # Run anomaly checks
        alerts = []

        # 1. Frequency spike detection
        freq_alert = self._check_frequency_spike(session_id, profile, window, now)
        if freq_alert:
            alerts.append(freq_alert)

        # 2. Sensitive file access
        sens_alert = self._check_sensitive_access(session_id, profile, action)
        if sens_alert:
            alerts.append(sens_alert)

        # 3. Network anomaly
        net_alert = self._check_network_anomaly(session_id, profile, action, window, now)
        if net_alert:
            alerts.append(net_alert)

        # 4. Privilege escalation patterns
        priv_alert = self._check_privilege_anomaly(session_id, profile, action)
        if priv_alert:
            alerts.append(priv_alert)

        # 5. Overall risk score check
        self._update_risk_score(profile, action)
        risk_alert = self._check_risk_threshold(session_id, profile)
        if risk_alert:
            alerts.append(risk_alert)

        # Store alerts and return the most severe one
        profile.alerts.extend(alerts)
        if alerts:
            # Return highest severity alert
            severity_order = {AlertLevel.CRITICAL: 0, AlertLevel.WARNING: 1, AlertLevel.INFO: 2}
            alerts.sort(key=lambda a: severity_order.get(a.level, 3))
            return alerts[0]

        return None

    def get_session_profile(self, session_id: str) -> SessionProfile | None:
        """Get the behavioral profile for a session."""
        return self._sessions.get(session_id)

    def get_alerts(self, session_id: str, level: str | None = None) -> list[Alert]:
        """Get alerts for a session, optionally filtered by level."""
        profile = self._sessions.get(session_id)
        if not profile:
            return []

        alerts = profile.alerts
        if level:
            try:
                alert_level = AlertLevel(level)
                alerts = [a for a in alerts if a.level == alert_level]
            except ValueError:
                pass

        return alerts

    def get_all_sessions(self) -> list[dict[str, Any]]:
        """Get summary of all monitored sessions."""
        return [profile.to_dict() for profile in self._sessions.values()]

    def end_session(self, session_id: str) -> SessionProfile | None:
        """End monitoring for a session and return final profile."""
        profile = self._sessions.pop(session_id, None)
        self._action_windows.pop(session_id, None)
        return profile

    def reset(self) -> None:
        """Reset all monitoring state."""
        self._sessions.clear()
        self._action_windows.clear()
        self._alert_counter = 0

    # ── Anomaly Detection Methods ─────────────────────────────────────

    def _check_frequency_spike(
        self,
        session_id: str,
        profile: SessionProfile,
        window: deque,
        now: float,
    ) -> Alert | None:
        """Detect unusual action frequency spikes."""
        cutoff = now - self.FREQUENCY_WINDOW_SECONDS
        recent_count = sum(1 for a in window if a.timestamp > cutoff)

        if recent_count >= self.FREQUENCY_SPIKE_THRESHOLD:
            # Check if this was already alerted recently
            recent_alerts = [
                a for a in profile.alerts
                if a.anomaly_type == AnomalyType.FREQUENCY_SPIKE
                and now - a.timestamp < 60  # Suppress for 60 seconds
            ]
            if recent_alerts:
                return None

            self._alert_counter += 1
            return Alert(
                alert_id=f"ALERT-{self._alert_counter:06d}",
                level=AlertLevel.WARNING,
                anomaly_type=AnomalyType.FREQUENCY_SPIKE,
                title="Action Frequency Spike",
                description=f"{recent_count} actions in last {self.FREQUENCY_WINDOW_SECONDS}s "
                            f"(threshold: {self.FREQUENCY_SPIKE_THRESHOLD})",
                session_id=session_id,
                related_actions=[a for a in window if a.timestamp > cutoff],
            )

        return None

    def _check_sensitive_access(
        self,
        session_id: str,
        profile: SessionProfile,
        action: MonitoredAction,
    ) -> Alert | None:
        """Detect sensitive file/resource access."""
        import re

        if action.action_type not in ("file_read", "file_write", "read_file", "write_file"):
            return None

        is_sensitive = any(
            re.search(pat, action.target, re.IGNORECASE) for pat in SENSITIVE_FILE_PATTERNS
        )

        if not is_sensitive:
            return None

        profile.sensitive_accesses += 1
        action.risk_score = self.RISK_WEIGHTS["sensitive_file"]

        if profile.sensitive_accesses >= self.SENSITIVE_ACCESS_CRITICAL_THRESHOLD:
            self._alert_counter += 1
            return Alert(
                alert_id=f"ALERT-{self._alert_counter:06d}",
                level=AlertLevel.CRITICAL,
                anomaly_type=AnomalyType.SENSITIVE_ACCESS,
                title="Excessive Sensitive File Access",
                description=f"Agent has accessed {profile.sensitive_accesses} sensitive files "
                            f"this session (latest: {action.target})",
                session_id=session_id,
                related_actions=[action],
            )
        elif profile.sensitive_accesses >= self.SENSITIVE_ACCESS_WARN_THRESHOLD:
            self._alert_counter += 1
            return Alert(
                alert_id=f"ALERT-{self._alert_counter:06d}",
                level=AlertLevel.WARNING,
                anomaly_type=AnomalyType.SENSITIVE_ACCESS,
                title="Sensitive File Access Pattern",
                description=f"Agent has accessed {profile.sensitive_accesses} sensitive files "
                            f"(latest: {action.target})",
                session_id=session_id,
                related_actions=[action],
            )

        return None

    def _check_network_anomaly(
        self,
        session_id: str,
        profile: SessionProfile,
        action: MonitoredAction,
        window: deque,
        now: float,
    ) -> Alert | None:
        """Detect network-related anomalies."""
        import re

        if action.action_type not in ("network", "fetch_url", "web_fetch", "http_request"):
            return None

        profile.network_requests += 1

        # Check for suspicious network targets
        is_suspicious = any(
            re.search(pat, action.target, re.IGNORECASE) for pat in SUSPICIOUS_NETWORK_PATTERNS
        )

        if is_suspicious:
            action.risk_score = self.RISK_WEIGHTS["suspicious_network"]
            self._alert_counter += 1
            return Alert(
                alert_id=f"ALERT-{self._alert_counter:06d}",
                level=AlertLevel.CRITICAL,
                anomaly_type=AnomalyType.NETWORK_ANOMALY,
                title="Suspicious Network Target",
                description=f"Agent connecting to suspicious endpoint: {action.target[:100]}",
                session_id=session_id,
                related_actions=[action],
            )

        # Check for network burst
        cutoff = now - self.FREQUENCY_WINDOW_SECONDS
        recent_net = sum(
            1 for a in window
            if a.timestamp > cutoff
            and a.action_type in ("network", "fetch_url", "web_fetch", "http_request")
        )

        if recent_net >= self.NETWORK_BURST_THRESHOLD:
            self._alert_counter += 1
            return Alert(
                alert_id=f"ALERT-{self._alert_counter:06d}",
                level=AlertLevel.WARNING,
                anomaly_type=AnomalyType.NETWORK_ANOMALY,
                title="Network Request Burst",
                description=f"{recent_net} network requests in last {self.FREQUENCY_WINDOW_SECONDS}s",
                session_id=session_id,
                related_actions=[action],
            )

        return None

    def _check_privilege_anomaly(
        self,
        session_id: str,
        profile: SessionProfile,
        action: MonitoredAction,
    ) -> Alert | None:
        """Detect privilege escalation attempts."""
        import re

        if action.action_type not in ("command", "execute_command", "permission"):
            return None

        is_privilege = any(
            re.search(pat, action.target, re.IGNORECASE) for pat in PRIVILEGE_PATTERNS
        )

        if is_privilege:
            action.risk_score = self.RISK_WEIGHTS["privilege_action"]
            self._alert_counter += 1
            return Alert(
                alert_id=f"ALERT-{self._alert_counter:06d}",
                level=AlertLevel.CRITICAL,
                anomaly_type=AnomalyType.PRIVILEGE_ANOMALY,
                title="Privilege Escalation Pattern",
                description=f"Agent attempting privilege operation: {action.target[:100]}",
                session_id=session_id,
                related_actions=[action],
            )

        return None

    def _update_risk_score(self, profile: SessionProfile, action: MonitoredAction) -> None:
        """Update session risk score based on action."""
        # Base risk from action type
        type_risks = {
            "command": self.RISK_WEIGHTS["command_execution"],
            "execute_command": self.RISK_WEIGHTS["command_execution"],
            "network": self.RISK_WEIGHTS["network_request"],
            "fetch_url": self.RISK_WEIGHTS["network_request"],
        }
        base_risk = type_risks.get(action.action_type, 0.5)

        # Add action-specific risk
        total_risk = base_risk + action.risk_score

        # Decay existing risk slightly (older actions matter less)
        profile.risk_score = profile.risk_score * 0.98 + total_risk

    def _check_risk_threshold(
        self,
        session_id: str,
        profile: SessionProfile,
    ) -> Alert | None:
        """Check if session risk score has crossed thresholds."""
        # Only alert once per threshold crossing
        if profile.risk_score >= self.RISK_SCORE_CRITICAL:
            recent_critical = [
                a for a in profile.alerts
                if a.anomaly_type == AnomalyType.BEHAVIORAL_DRIFT
                and a.level == AlertLevel.CRITICAL
                and time.time() - a.timestamp < 300
            ]
            if not recent_critical:
                self._alert_counter += 1
                return Alert(
                    alert_id=f"ALERT-{self._alert_counter:06d}",
                    level=AlertLevel.CRITICAL,
                    anomaly_type=AnomalyType.BEHAVIORAL_DRIFT,
                    title="Session Risk Score Critical",
                    description=f"Session risk score {profile.risk_score:.1f} exceeds critical "
                                f"threshold ({self.RISK_SCORE_CRITICAL})",
                    session_id=session_id,
                    metadata={"risk_score": profile.risk_score},
                )

        elif profile.risk_score >= self.RISK_SCORE_WARN:
            recent_warn = [
                a for a in profile.alerts
                if a.anomaly_type == AnomalyType.BEHAVIORAL_DRIFT
                and a.level == AlertLevel.WARNING
                and time.time() - a.timestamp < 300
            ]
            if not recent_warn:
                self._alert_counter += 1
                return Alert(
                    alert_id=f"ALERT-{self._alert_counter:06d}",
                    level=AlertLevel.WARNING,
                    anomaly_type=AnomalyType.BEHAVIORAL_DRIFT,
                    title="Session Risk Score Elevated",
                    description=f"Session risk score {profile.risk_score:.1f} exceeds warning "
                                f"threshold ({self.RISK_SCORE_WARN})",
                    session_id=session_id,
                    metadata={"risk_score": profile.risk_score},
                )

        return None
