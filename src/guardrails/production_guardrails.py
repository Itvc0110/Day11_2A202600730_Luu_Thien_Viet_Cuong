"""
Assignment 11 - Production Defense-in-Depth Guardrails

This file keeps the assignment-only safety layers separate from the lab TODO
files. The classes are small, deterministic, and compatible with the ADK-style
plugin callbacks used elsewhere in this repo.
"""
import json
import re
import time
import unicodedata
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

try:
    from google.genai import types
except ImportError:
    class _Part:
        def __init__(self, text=""):
            self.text = text

        @classmethod
        def from_text(cls, text):
            return cls(text=text)

    class _Content:
        def __init__(self, role=None, parts=None):
            self.role = role
            self.parts = parts or []

    types = SimpleNamespace(Content=_Content, Part=_Part)

try:
    from google.adk.plugins import base_plugin
except ImportError:
    class _BasePlugin:
        def __init__(self, name):
            self.name = name

    base_plugin = SimpleNamespace(BasePlugin=_BasePlugin)


def _content_text(content) -> str:
    """Extract text from ADK/GenAI Content objects for logging and checks."""
    text = ""
    if content and getattr(content, "parts", None):
        for part in content.parts:
            part_text = getattr(part, "text", "")
            if part_text:
                text += part_text
    return text


def _block_content(message: str):
    """Return a model Content object that safely blocks a request."""
    return types.Content(
        role="model",
        parts=[types.Part.from_text(text=message)],
    )


def _normalize_text(text: str) -> str:
    """Fold accents and punctuation for lightweight security matching."""
    folded = unicodedata.normalize("NFKD", text or "")
    folded = "".join(ch for ch in folded if not unicodedata.combining(ch))
    folded = folded.lower()
    folded = re.sub(r"[^a-z0-9]+", " ", folded)
    return re.sub(r"\s+", " ", folded).strip()


class RateLimitPlugin(base_plugin.BasePlugin):
    """Block request bursts with a per-user sliding window.

    Why needed: input guardrails catch malicious content, but rate limiting
    catches abuse patterns such as repeated probing, DDoS-like traffic, and cost
    explosion even when each individual prompt looks harmless.
    """

    def __init__(self, max_requests=10, window_seconds=60):
        super().__init__(name="rate_limiter")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.user_windows = defaultdict(deque)
        self.blocked_count = 0
        self.total_count = 0

    async def on_user_message_callback(self, *, invocation_context, user_message):
        """Allow the request or return a block message with wait time."""
        self.total_count += 1
        user_id = getattr(invocation_context, "user_id", None) or "anonymous"
        now = time.time()
        window = self.user_windows[user_id]

        while window and now - window[0] > self.window_seconds:
            window.popleft()

        if len(window) >= self.max_requests:
            self.blocked_count += 1
            wait_time = max(1, int(self.window_seconds - (now - window[0])))
            return _block_content(
                f"Too many requests. Please wait about {wait_time} seconds and try again."
            )

        window.append(now)
        return None


class SessionAnomalyPlugin(base_plugin.BasePlugin):
    """Block multi-turn probing that becomes risky across a session.

    Why needed: single-message input guardrails catch explicit attacks, but a
    red teamer can spread intent across multiple prompts. This layer keeps a
    sliding risk score per user and blocks once the session pattern looks like
    credential extraction, even if an individual prompt looks borderline.
    """

    def __init__(self, max_risk_score=6, window_seconds=300):
        super().__init__(name="session_anomaly")
        self.max_risk_score = max_risk_score
        self.window_seconds = window_seconds
        self.user_events = defaultdict(deque)
        self.blocked_count = 0
        self.total_count = 0

    def _score_message(self, text: str) -> tuple[int, list[str]]:
        """Return a risk score and reasons for a single user message."""
        normalized = _normalize_text(text)
        score = 0
        reasons = []

        scoring_rules = [
            (r"\b(ciso|auditor|audit|compliance|sec \d|security ticket)\b", 2, "authority/audit framing"),
            (r"\b(password|credential|api key|secret|database host|connection string)\b", 3, "credential target"),
            (r"\b(system prompt|hidden instruction|developer message|internal note)\b", 3, "hidden context target"),
            (r"\b(confirm|deny|hint|starts with|first letter|fill in)\b", 2, "side-channel extraction"),
            (r"\b(export|convert|translate|encode|decode|json|yaml|xml|base64|rot13|hex)\b", 2, "transformation request"),
            (r"\b(ignore|forget|override|developer mode|admin mode|dan)\b", 3, "role or instruction override"),
            (r"\b(bo qua|tiet lo|mat khau|khoa api|huong dan he thong)\b", 3, "vietnamese extraction"),
        ]

        for pattern, weight, reason in scoring_rules:
            if re.search(pattern, normalized):
                score += weight
                reasons.append(reason)

        return score, reasons

    async def on_user_message_callback(self, *, invocation_context, user_message):
        """Observe session risk and block when accumulated risk is too high."""
        self.total_count += 1
        user_id = getattr(invocation_context, "user_id", None) or "anonymous"
        text = _content_text(user_message)
        now = time.time()
        window = self.user_events[user_id]

        while window and now - window[0]["timestamp"] > self.window_seconds:
            window.popleft()

        score, reasons = self._score_message(text)
        if score:
            window.append({
                "timestamp": now,
                "score": score,
                "reasons": reasons,
            })

        total_risk = sum(event["score"] for event in window)
        if total_risk >= self.max_risk_score:
            self.blocked_count += 1
            return _block_content(
                "This session has repeated security-sensitive requests. "
                "I can continue with normal VinBank banking questions, but I cannot help with credentials or internal data."
            )

        return None


class AuditLogPlugin(base_plugin.BasePlugin):
    """Record input/output events and export them to JSON.

    Why needed: audit logs give evidence for incident review, false-positive
    analysis, and production monitoring. This layer never blocks; it observes.
    """

    def __init__(self):
        super().__init__(name="audit_log")
        self.logs = []
        self._active = {}

    async def on_user_message_callback(self, *, invocation_context, user_message):
        """Record the user input and request start time."""
        user_id = getattr(invocation_context, "user_id", None) or "anonymous"
        key = id(invocation_context) if invocation_context is not None else user_id
        self._active[key] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_id": user_id,
            "input": _content_text(user_message),
            "start_time": time.time(),
            "blocked_by": None,
        }
        return None

    async def after_model_callback(self, *, callback_context, llm_response):
        """Record the model output and latency."""
        key = id(callback_context) if callback_context is not None else "anonymous"
        entry = self._active.pop(key, None)
        if entry is None:
            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "user_id": "anonymous",
                "input": "",
                "start_time": time.time(),
                "blocked_by": None,
            }

        entry["output"] = _content_text(getattr(llm_response, "content", None))
        entry["latency_ms"] = round((time.time() - entry.pop("start_time")) * 1000, 2)
        self.logs.append(entry)
        return llm_response

    def mark_blocked(self, user_id="anonymous", blocked_by="unknown"):
        """Annotate the active audit entry when an earlier layer blocks.

        Rate limiting and input guardrails can stop a request before the LLM
        runs. This signal records which safety layer acted first.
        """
        entry = self._active.get(user_id)
        if entry is None:
            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "user_id": user_id,
                "input": "",
                "start_time": time.time(),
                "blocked_by": blocked_by,
            }
            self._active[user_id] = entry
        else:
            entry["blocked_by"] = blocked_by

    def export_json(self, filepath="security_audit.json"):
        """Export audit records to a JSON file and return the written path."""
        path = Path(filepath)
        path.write_text(json.dumps(self.logs, indent=2, ensure_ascii=False), encoding="utf-8")
        return str(path)


class MonitoringAlert:
    """Calculate simple production safety metrics and threshold alerts.

    Why needed: monitoring catches system-level drift, spikes in attacks, and
    judge failures that isolated prompt tests may miss.
    """

    def __init__(
        self,
        plugins,
        block_rate_threshold=0.30,
        rate_limit_threshold=5,
        judge_fail_threshold=3,
        session_anomaly_threshold=2,
    ):
        self.plugins = plugins
        self.block_rate_threshold = block_rate_threshold
        self.rate_limit_threshold = rate_limit_threshold
        self.judge_fail_threshold = judge_fail_threshold
        self.session_anomaly_threshold = session_anomaly_threshold

    def collect_metrics(self) -> dict:
        """Collect counters exposed by guardrail plugins."""
        total = 0
        blocked = 0
        rate_limit_hits = 0
        judge_failures = 0
        session_anomaly_hits = 0

        for plugin in self.plugins:
            total += getattr(plugin, "total_count", 0)
            blocked += getattr(plugin, "blocked_count", 0)
            if getattr(plugin, "name", "") == "rate_limiter":
                rate_limit_hits += getattr(plugin, "blocked_count", 0)
            if getattr(plugin, "name", "") == "session_anomaly":
                session_anomaly_hits += getattr(plugin, "blocked_count", 0)
            judge_failures += getattr(plugin, "judge_failed_count", 0)

        block_rate = blocked / total if total else 0.0
        return {
            "total_events": total,
            "blocked_events": blocked,
            "block_rate": block_rate,
            "rate_limit_hits": rate_limit_hits,
            "session_anomaly_hits": session_anomaly_hits,
            "judge_failures": judge_failures,
        }

    def check_metrics(self) -> list:
        """Return alert messages for metrics above configured thresholds."""
        metrics = self.collect_metrics()
        alerts = []

        if metrics["block_rate"] > self.block_rate_threshold:
            alerts.append(
                f"High block rate: {metrics['block_rate']:.0%} "
                f"(threshold {self.block_rate_threshold:.0%})"
            )
        if metrics["rate_limit_hits"] > self.rate_limit_threshold:
            alerts.append(
                f"Rate-limit spike: {metrics['rate_limit_hits']} hits "
                f"(threshold {self.rate_limit_threshold})"
            )
        if metrics["judge_failures"] > self.judge_fail_threshold:
            alerts.append(
                f"Judge failures elevated: {metrics['judge_failures']} "
                f"(threshold {self.judge_fail_threshold})"
            )
        if metrics["session_anomaly_hits"] > self.session_anomaly_threshold:
            alerts.append(
                f"Session anomaly spike: {metrics['session_anomaly_hits']} hits "
                f"(threshold {self.session_anomaly_threshold})"
            )

        return alerts
