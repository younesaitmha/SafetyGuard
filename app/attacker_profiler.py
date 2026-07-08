from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from typing import Dict, List, Tuple

from .sqlite_store import get_state_store

logger = logging.getLogger("attacker_profiler")


class AttackerProfile:
    """Tracks attack patterns by (IP, subject) tuple."""

    def __init__(self, client_id: str, subject: str, max_history: int = 100):
        self.client_id = client_id
        self.subject = subject
        self.first_seen = time.time()
        self.last_seen = time.time()
        self.refusal_count = 0
        self.refusal_reasons: deque[str] = deque(maxlen=max_history)
        self.injection_attempts = 0
        self.jailbreak_attempts = 0
        self.escalation_attempts = 0
        self.tool_abuse_attempts = 0

    def record_refusal(self, reason_codes: List[str]) -> None:
        self.refusal_count += 1
        self.last_seen = time.time()
        for code in reason_codes:
            self.refusal_reasons.append(code)
            if "INJECTION" in code or "JAILBREAK" in code:
                self.injection_attempts += 1
            if "JAILBREAK" in code:
                self.jailbreak_attempts += 1
            if "ESCALATION" in code or "PRIVILEGE" in code:
                self.escalation_attempts += 1
            if "TOOL" in code:
                self.tool_abuse_attempts += 1

    def is_suspicious(self) -> bool:
        """Return True if profile exhibits attack patterns."""
        # 5+ refusals in < 5 minutes
        if self.refusal_count >= 5 and (time.time() - self.first_seen) < 300:
            return True
        # 3+ jailbreak attempts
        if self.jailbreak_attempts >= 3:
            return True
        # 2+ escalation attempts
        if self.escalation_attempts >= 2:
            return True
        # 5+ tool abuse attempts
        if self.tool_abuse_attempts >= 5:
            return True
        return False

    def get_reason_cluster(self) -> str:
        """Return most common refusal reason."""
        if not self.refusal_reasons:
            return "unknown"
        reason_counts: Dict[str, int] = defaultdict(int)
        for reason in self.refusal_reasons:
            reason_counts[reason] += 1
        return max(reason_counts, key=reason_counts.get)

    def to_dict(self) -> Dict:
        return {
            "client_id": self.client_id,
            "subject": self.subject,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "refusal_count": self.refusal_count,
            "refusal_reasons": list(self.refusal_reasons),
            "injection_attempts": self.injection_attempts,
            "jailbreak_attempts": self.jailbreak_attempts,
            "escalation_attempts": self.escalation_attempts,
            "tool_abuse_attempts": self.tool_abuse_attempts,
        }

    @classmethod
    def from_dict(cls, payload: Dict) -> "AttackerProfile":
        profile = cls(
            client_id=str(payload.get("client_id", "unknown")),
            subject=str(payload.get("subject", "unknown")),
        )
        profile.first_seen = float(payload.get("first_seen", time.time()))
        profile.last_seen = float(payload.get("last_seen", time.time()))
        profile.refusal_count = int(payload.get("refusal_count", 0))
        profile.injection_attempts = int(payload.get("injection_attempts", 0))
        profile.jailbreak_attempts = int(payload.get("jailbreak_attempts", 0))
        profile.escalation_attempts = int(payload.get("escalation_attempts", 0))
        profile.tool_abuse_attempts = int(payload.get("tool_abuse_attempts", 0))
        for reason in payload.get("refusal_reasons", []):
            profile.refusal_reasons.append(str(reason))
        return profile


class AttackerProfiler:
    """Maintains profiles of suspicious clients."""
    
    def __init__(self, max_profiles: int = 10000):
        self._profiles: Dict[Tuple[str, str], AttackerProfile] = {}
        self._max_profiles = max_profiles
        self._store = get_state_store()

    def _key(self, client_id: str, subject: str) -> str:
        return f"{client_id}::{subject}"

    def _load_profile(self, client_id: str, subject: str) -> AttackerProfile | None:
        key = (client_id, subject)
        if key in self._profiles:
            return self._profiles[key]
        if not self._store:
            return None
        payload = self._store.get_json("attacker_profile", self._key(client_id, subject))
        if not payload:
            return None
        profile = AttackerProfile.from_dict(payload)
        self._profiles[key] = profile
        return profile

    def _save_profile(self, profile: AttackerProfile) -> None:
        key = (profile.client_id, profile.subject)
        self._profiles[key] = profile
        if self._store:
            self._store.put_json("attacker_profile", self._key(profile.client_id, profile.subject), profile.to_dict())

    def record_refusal(self, client_id: str, subject: str, reason_codes: List[str]) -> None:
        """Record a policy refusal."""
        key = (client_id, subject)
        profile = self._load_profile(client_id, subject)

        if not profile:
            if len(self._profiles) >= self._max_profiles:
                # Evict oldest profile
                oldest_key = min(self._profiles.keys(), key=lambda k: self._profiles[k].first_seen)
                del self._profiles[oldest_key]
            profile = AttackerProfile(client_id, subject)

        profile.record_refusal(reason_codes)
        self._save_profile(profile)
        
        if profile.is_suspicious():
            reason_cluster = profile.get_reason_cluster()
            logger.warning(
                "attacker_profile_alert client_id=%s subject=%s refusal_count=%d "
                "jailbreak_attempts=%d escalation_attempts=%d reason_cluster=%s",
                client_id,
                subject,
                profile.refusal_count,
                profile.jailbreak_attempts,
                profile.escalation_attempts,
                reason_cluster,
            )

    def get_profile(self, client_id: str, subject: str) -> AttackerProfile | None:
        """Retrieve profile if exists."""
        return self._load_profile(client_id, subject)

    def is_suspicious_client(self, client_id: str, subject: str) -> bool:
        """Check if client is in suspicious profile."""
        profile = self.get_profile(client_id, subject)
        return profile.is_suspicious() if profile else False

    def get_adaptive_rate_limit_multiplier(self, client_id: str, subject: str) -> float:
        """Return rate limit window multiplier for this client."""
        profile = self.get_profile(client_id, subject)
        if not profile:
            return 1.0

        multiplier = 1.0
        if profile.jailbreak_attempts >= 3:
            multiplier *= 5.0
        if profile.escalation_attempts >= 2:
            multiplier *= 3.0
        if profile.injection_attempts >= 5:
            multiplier *= 2.0

        return min(multiplier, 20.0)  # Cap at 20x

    def recent_alerts(self, limit: int = 100) -> List[Dict]:
        """Return list of suspicious profiles."""
        suspicious = [p for p in self._profiles.values() if p.is_suspicious()]
        suspicious.sort(key=lambda p: p.last_seen, reverse=True)
        return [
            {
                "client_id": p.client_id,
                "subject": p.subject,
                "refusal_count": p.refusal_count,
                "jailbreak_attempts": p.jailbreak_attempts,
                "escalation_attempts": p.escalation_attempts,
                "tool_abuse_attempts": p.tool_abuse_attempts,
                "last_seen": p.last_seen,
                "reason_cluster": p.get_reason_cluster(),
            }
            for p in suspicious[:limit]
        ]
