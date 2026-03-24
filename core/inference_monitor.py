"""Inference Monitor — detects model extraction and cost harvesting attacks.

Monitors AI inference API usage patterns to detect:
- Model extraction: systematic queries to reconstruct model (AML.T0024.002)
- Training data extraction: membership inference attacks (AML.T0024.000)
- Cost harvesting: excessive compute to inflict costs (AML.T0034)
- Denial of service: flooding inference endpoint (AML.T0029)
- Model inversion: recovering sensitive training data (AML.T0024.001)
"""

from __future__ import annotations

import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any

import structlog

log = structlog.get_logger("inference_monitor")


@dataclass
class InferenceRequest:
    """A recorded inference API request."""
    request_id: str
    source_ip: str
    model_id: str
    input_tokens: int
    output_tokens: int
    timestamp: float = field(default_factory=time.time)
    input_hash: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class InferenceAlert:
    """An alert from the inference monitor."""
    alert_id: str
    category: str
    risk: str
    title: str
    description: str
    atlas_technique: str
    source_ip: str
    request_count: int
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "category": self.category,
            "risk": self.risk,
            "title": self.title,
            "description": self.description,
            "atlas_technique": self.atlas_technique,
            "source_ip": self.source_ip,
            "request_count": self.request_count,
        }


@dataclass
class InferenceProfile:
    """Usage profile for a source IP / API key."""
    source_id: str
    total_requests: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    unique_inputs: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    model_ids: set = field(default_factory=set)
    alerts: list[InferenceAlert] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        return max(self.last_seen - self.first_seen, 1)

    @property
    def requests_per_minute(self) -> float:
        return (self.total_requests / self.duration_seconds) * 60

    @property
    def avg_input_tokens(self) -> float:
        return self.total_input_tokens / max(self.total_requests, 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "total_requests": self.total_requests,
            "total_tokens": self.total_input_tokens + self.total_output_tokens,
            "requests_per_minute": round(self.requests_per_minute, 1),
            "unique_inputs": self.unique_inputs,
            "models_accessed": len(self.model_ids),
            "alert_count": len(self.alerts),
        }


# ── Thresholds ────────────────────────────────────────────────────────────

class Thresholds:
    """Configurable detection thresholds."""
    # Model extraction
    EXTRACTION_RPM = 60          # Requests/min suggesting extraction
    EXTRACTION_UNIQUE_RATIO = 0.9  # High unique input ratio
    EXTRACTION_MIN_REQUESTS = 100  # Minimum requests before alerting

    # Cost harvesting
    COST_TOKENS_PER_MIN = 100_000  # Token/min rate suggesting cost attack
    COST_MAX_INPUT_TOKENS = 50_000  # Single request input token limit

    # DoS
    DOS_RPM = 200                # Requests/min suggesting DoS
    DOS_BURST_WINDOW = 10        # Seconds for burst detection
    DOS_BURST_COUNT = 50         # Requests in burst window

    # Data extraction
    DATA_EXTRACTION_OUTPUT_RATIO = 5.0  # Output/input token ratio
    DATA_EXTRACTION_LONG_OUTPUTS = 10_000  # Single response token threshold


# ── Inference Monitor ─────────────────────────────────────────────────────

class InferenceMonitor:
    """Monitors AI inference API usage for attack patterns.

    Usage:
        monitor = InferenceMonitor()

        # Record each API request
        alert = monitor.record_request(
            request_id="req_123",
            source_ip="10.0.0.5",
            model_id="gpt-4",
            input_tokens=500,
            output_tokens=200,
        )
        if alert:
            print(f"ALERT: {alert.title}")

        # Get source profile
        profile = monitor.get_profile("10.0.0.5")

        # Get all alerts
        alerts = monitor.get_alerts()
    """

    def __init__(self, thresholds: Thresholds | None = None) -> None:
        self.thresholds = thresholds or Thresholds()
        self._profiles: dict[str, InferenceProfile] = {}
        self._request_windows: dict[str, deque] = {}
        self._input_hashes: dict[str, set] = {}
        self._alert_counter = 0
        self._all_alerts: list[InferenceAlert] = []

    def _next_alert_id(self) -> str:
        self._alert_counter += 1
        return f"INF-{self._alert_counter:04d}"

    def record_request(
        self,
        request_id: str,
        source_ip: str,
        model_id: str,
        input_tokens: int,
        output_tokens: int,
        input_hash: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> InferenceAlert | None:
        """Record an inference request and check for anomalies."""
        now = time.time()

        # Initialize profile
        if source_ip not in self._profiles:
            self._profiles[source_ip] = InferenceProfile(source_id=source_ip)
            self._request_windows[source_ip] = deque(maxlen=10000)
            self._input_hashes[source_ip] = set()

        profile = self._profiles[source_ip]
        window = self._request_windows[source_ip]

        # Update profile
        profile.total_requests += 1
        profile.total_input_tokens += input_tokens
        profile.total_output_tokens += output_tokens
        profile.last_seen = now
        profile.model_ids.add(model_id)

        if input_hash:
            self._input_hashes[source_ip].add(input_hash)
            profile.unique_inputs = len(self._input_hashes[source_ip])

        # Record in window
        req = InferenceRequest(
            request_id=request_id, source_ip=source_ip, model_id=model_id,
            input_tokens=input_tokens, output_tokens=output_tokens,
            timestamp=now, input_hash=input_hash, metadata=metadata or {},
        )
        window.append(req)

        # Run detection checks
        alerts = []
        alerts.extend(self._check_model_extraction(source_ip, profile, window, now))
        alerts.extend(self._check_cost_harvesting(source_ip, profile, window, now, input_tokens))
        alerts.extend(self._check_dos(source_ip, profile, window, now))
        alerts.extend(self._check_data_extraction(source_ip, profile, req))

        # Store and return most severe
        for alert in alerts:
            profile.alerts.append(alert)
            self._all_alerts.append(alert)

        if alerts:
            risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            alerts.sort(key=lambda a: risk_order.get(a.risk, 4))
            return alerts[0]

        return None

    def get_profile(self, source_ip: str) -> InferenceProfile | None:
        return self._profiles.get(source_ip)

    def get_all_profiles(self) -> list[dict[str, Any]]:
        return [p.to_dict() for p in self._profiles.values()]

    def get_alerts(self, source_ip: str | None = None) -> list[InferenceAlert]:
        if source_ip:
            profile = self._profiles.get(source_ip)
            return profile.alerts if profile else []
        return list(self._all_alerts)

    def reset(self) -> None:
        self._profiles.clear()
        self._request_windows.clear()
        self._input_hashes.clear()
        self._all_alerts.clear()
        self._alert_counter = 0

    # ── Detection Methods ─────────────────────────────────────────────

    def _check_model_extraction(
        self, source_ip: str, profile: InferenceProfile,
        window: deque, now: float,
    ) -> list[InferenceAlert]:
        """Detect model extraction attacks (systematic querying)."""
        alerts = []

        if profile.total_requests < self.thresholds.EXTRACTION_MIN_REQUESTS:
            return alerts

        # Check request rate
        rpm = self._calculate_rpm(window, now)
        if rpm >= self.thresholds.EXTRACTION_RPM:
            # Check unique input ratio (high = systematic probing)
            unique_ratio = profile.unique_inputs / max(profile.total_requests, 1)
            if unique_ratio >= self.thresholds.EXTRACTION_UNIQUE_RATIO:
                # Suppress if already alerted recently
                if not self._has_recent_alert(profile, "model_extraction", 300):
                    alerts.append(InferenceAlert(
                        alert_id=self._next_alert_id(),
                        category="model_extraction",
                        risk="critical",
                        title="Possible model extraction attack",
                        description=f"Source {source_ip} sending {rpm:.0f} req/min with "
                                   f"{unique_ratio:.0%} unique inputs ({profile.total_requests} total). "
                                   f"Pattern consistent with systematic model querying.",
                        atlas_technique="AML.T0024.002",
                        source_ip=source_ip,
                        request_count=profile.total_requests,
                    ))

        return alerts

    def _check_cost_harvesting(
        self, source_ip: str, profile: InferenceProfile,
        window: deque, now: float, current_input_tokens: int,
    ) -> list[InferenceAlert]:
        """Detect cost harvesting attacks (excessive compute)."""
        alerts = []

        # Check single request with huge input
        if current_input_tokens >= self.thresholds.COST_MAX_INPUT_TOKENS:
            alerts.append(InferenceAlert(
                alert_id=self._next_alert_id(),
                category="cost_harvesting",
                risk="high",
                title="Extremely large input — possible cost harvesting",
                description=f"Single request with {current_input_tokens:,} input tokens "
                           f"from {source_ip}. May be attempting to inflate compute costs.",
                atlas_technique="AML.T0034",
                source_ip=source_ip,
                request_count=1,
                metadata={"input_tokens": current_input_tokens},
            ))

        # Check sustained high token rate
        recent_tokens = self._calculate_tokens_per_minute(window, now)
        if recent_tokens >= self.thresholds.COST_TOKENS_PER_MIN:
            if not self._has_recent_alert(profile, "cost_harvesting", 300):
                alerts.append(InferenceAlert(
                    alert_id=self._next_alert_id(),
                    category="cost_harvesting",
                    risk="high",
                    title="Sustained high token rate — cost harvesting",
                    description=f"Source {source_ip} consuming {recent_tokens:,.0f} tokens/min. "
                               f"Total: {profile.total_input_tokens + profile.total_output_tokens:,} tokens.",
                    atlas_technique="AML.T0034",
                    source_ip=source_ip,
                    request_count=profile.total_requests,
                ))

        return alerts

    def _check_dos(
        self, source_ip: str, profile: InferenceProfile,
        window: deque, now: float,
    ) -> list[InferenceAlert]:
        """Detect denial of service attacks."""
        alerts = []

        # Check sustained high rate
        rpm = self._calculate_rpm(window, now)
        if rpm >= self.thresholds.DOS_RPM:
            if not self._has_recent_alert(profile, "denial_of_service", 60):
                alerts.append(InferenceAlert(
                    alert_id=self._next_alert_id(),
                    category="denial_of_service",
                    risk="critical",
                    title="Denial of ML service attack",
                    description=f"Source {source_ip} sending {rpm:.0f} req/min — "
                               f"exceeds DoS threshold ({self.thresholds.DOS_RPM}).",
                    atlas_technique="AML.T0029",
                    source_ip=source_ip,
                    request_count=profile.total_requests,
                ))

        # Check burst
        burst_cutoff = now - self.thresholds.DOS_BURST_WINDOW
        burst_count = sum(1 for r in window if r.timestamp > burst_cutoff)
        if burst_count >= self.thresholds.DOS_BURST_COUNT:
            if not self._has_recent_alert(profile, "burst", 30):
                alerts.append(InferenceAlert(
                    alert_id=self._next_alert_id(),
                    category="burst",
                    risk="high",
                    title="Request burst detected",
                    description=f"{burst_count} requests in {self.thresholds.DOS_BURST_WINDOW}s "
                               f"from {source_ip}.",
                    atlas_technique="AML.T0029",
                    source_ip=source_ip,
                    request_count=burst_count,
                ))

        return alerts

    def _check_data_extraction(
        self, source_ip: str, profile: InferenceProfile,
        req: InferenceRequest,
    ) -> list[InferenceAlert]:
        """Detect training data extraction attempts."""
        alerts = []

        # Very long outputs relative to input (data extraction indicator)
        if req.input_tokens > 0:
            ratio = req.output_tokens / req.input_tokens
            if ratio >= self.thresholds.DATA_EXTRACTION_OUTPUT_RATIO and \
               req.output_tokens >= self.thresholds.DATA_EXTRACTION_LONG_OUTPUTS:
                alerts.append(InferenceAlert(
                    alert_id=self._next_alert_id(),
                    category="data_extraction",
                    risk="high",
                    title="Possible training data extraction",
                    description=f"Output/input ratio of {ratio:.1f}x with {req.output_tokens:,} "
                               f"output tokens. May be extracting memorized training data.",
                    atlas_technique="AML.T0024.000",
                    source_ip=source_ip,
                    request_count=1,
                    metadata={"ratio": ratio, "output_tokens": req.output_tokens},
                ))

        return alerts

    # ── Helpers ────────────────────────────────────────────────────────

    def _calculate_rpm(self, window: deque, now: float) -> float:
        """Calculate requests per minute from recent window."""
        cutoff = now - 60
        recent = sum(1 for r in window if r.timestamp > cutoff)
        return recent  # Already per minute

    def _calculate_tokens_per_minute(self, window: deque, now: float) -> float:
        """Calculate tokens per minute from recent window."""
        cutoff = now - 60
        total = sum(r.input_tokens + r.output_tokens for r in window if r.timestamp > cutoff)
        return total

    def _has_recent_alert(self, profile: InferenceProfile, category: str, seconds: float) -> bool:
        """Check if there's a recent alert of this category."""
        now = time.time()
        return any(
            a.category == category
            for a in profile.alerts[-10:]  # Check last 10
        )
