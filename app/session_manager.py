from __future__ import annotations

import time
import uuid

from .sqlite_store import get_state_store
from .models import CanonicalRequestEnvelope, SessionState


class InMemorySessionManager:
    def __init__(self):
        self._sessions: dict[str, SessionState] = {}
        self._store = get_state_store()

    def _save(self, session: SessionState) -> None:
        self._sessions[session.session_id] = session
        if self._store:
            self._store.put_json("session", session.session_id, session.model_dump())

    def _load(self, session_id: str) -> SessionState | None:
        if session_id in self._sessions:
            return self._sessions[session_id]
        if not self._store:
            return None
        payload = self._store.get_json("session", session_id)
        if not payload:
            return None
        try:
            session = SessionState.model_validate(payload)
            self._sessions[session.session_id] = session
            return session
        except Exception:
            return None

    def get_or_create_session(
        self,
        session_id: str | None,
        subject: str,
        tenant_id: str | None,
    ) -> SessionState:
        if session_id:
            session = self._load(session_id)
        else:
            session = None

        if session:
            session.last_seen_at = time.time()
            self._save(session)
            return session

        new_session_id = session_id or str(uuid.uuid4())
        session = SessionState(
            session_id=new_session_id,
            subject=subject,
            tenant_id=tenant_id,
            created_at=time.time(),
            last_seen_at=time.time(),
        )
        self._save(session)
        return session

    def update_from_request(self, session_state: SessionState, envelope: CanonicalRequestEnvelope) -> None:
        session_state.request_count += 1
        session_state.total_message_count += len(envelope.messages)
        session_state.total_attachment_count += len(envelope.attachments)
        session_state.last_seen_at = time.time()
        self._save(session_state)

    def append_risk_score(self, session_id: str, score: int, state_name: str) -> None:
        session = self._load(session_id)
        if not session:
            return
        session.risk_history.append(score)
        session.state = state_name  # type: ignore[assignment]
        self._save(session)

    def record_refusal(self, session_id: str) -> None:
        session = self._load(session_id)
        if session:
            session.refusal_count += 1
            self._save(session)

    def record_tool_request(self, session_id: str) -> None:
        session = self._load(session_id)
        if session:
            session.tool_request_count += 1
            self._save(session)

    def record_injection_attempt(
        self,
        session_id: str,
        deterministic_score: int,
    ) -> None:
        """Record an injection attempt for multi-turn escalation tracking."""
        session = self._load(session_id)
        if not session:
            return

        session.injection_attempt_count += 1

        # Detect escalation: high-severity attempt (score >= 60) triggers flag
        if session.injection_attempt_count >= 2 and deterministic_score >= 60:
            session.escalation_pattern_count += 1
        self._save(session)

    def get_escalation_status(self, session_id: str) -> bool:
        """Check if escalation pattern has been detected."""
        session = self._load(session_id)
        if not session:
            return False
        return session.escalation_pattern_count > 0

    def get_injection_attempt_count(self, session_id: str) -> int:
        """Get cumulative injection attempts for rate limiting multiplier."""
        session = self._load(session_id)
        if not session:
            return 0
        return session.injection_attempt_count
