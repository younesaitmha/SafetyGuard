import time
from collections import defaultdict, deque

from .sqlite_store import get_state_store


class InMemoryRateLimiter:
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits = defaultdict(deque)
        self._cooldown_until = defaultdict(float)  # NEW: cooldown tracking
        self._store = get_state_store()

    def allow(
        self,
        key: str,
        severity_score: int = 0,
        injection_attempt_count: int = 0,
        profile_multiplier: float = 1.0,
    ) -> tuple[bool, str]:
        """
        Check if request allowed. NEW: Adaptive rate limiting based on risk.
        
        Args:
            key: Rate limit key (e.g., client_ip+subject)
            severity_score: Input scan score (0-100); higher = stricter limits
            injection_attempt_count: Cumulative injection attempts in session
            
        Returns:
            (allowed, reason) tuple
        """
        now = time.time()

        # Check permanent cooldown
        if self._store:
            cooldown = self._store.get_cooldown(key)
            if now < cooldown:
                return False, "cooldown_active"
            self._store.prune_hits(key, now - self.window_seconds)
            current_hits = self._store.count_hits(key, now - self.window_seconds)
        else:
            if now < self._cooldown_until.get(key, 0):
                return False, "cooldown_active"
            bucket = self._hits[key]
            while bucket and now - bucket[0] > self.window_seconds:
                bucket.popleft()
            current_hits = len(bucket)

        # Adaptive limits based on risk signals
        effective_max = self.max_requests
        if severity_score >= 80:
            effective_max = max(1, self.max_requests // 10)  # 10x stricter
        elif severity_score >= 50:
            effective_max = max(1, self.max_requests // 5)   # 5x stricter
        elif severity_score >= 30:
            effective_max = max(1, self.max_requests // 2)   # 2x stricter

        if profile_multiplier > 1.0:
            effective_max = max(1, int(effective_max / profile_multiplier))
        
        # Additional multiplier for repeated injection attempts
        if injection_attempt_count >= 3:
            # Apply 1-hour cooldown for aggressive attackers
            if self._store:
                self._store.set_cooldown(key, now + 3600)
            else:
                self._cooldown_until[key] = now + 3600
            return False, "aggressive_attacker_cooldown"
        elif injection_attempt_count >= 2:
            effective_max = max(1, effective_max // 2)

        if current_hits >= effective_max:
            return False, "rate_limit_exceeded"

        if self._store:
            self._store.add_hit(key, now)
        else:
            self._hits[key].append(now)
        return True, "allowed"

