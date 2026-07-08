from __future__ import annotations

from .models import CanonicalRequestEnvelope, SessionRiskAssessment, SessionState


class SessionRiskEngine:
    def assess(
        self,
        envelope: CanonicalRequestEnvelope,
        session_state: SessionState,
    ) -> SessionRiskAssessment:
        score = 0
        reasons: list[str] = []
        features = {
            "request_count": session_state.request_count,
            "refusal_count": session_state.refusal_count,
            "tool_request_count": session_state.tool_request_count,
            "injection_attempt_count": session_state.injection_attempt_count,
            "escalation_pattern_count": session_state.escalation_pattern_count,
            "risk_history_length": len(session_state.risk_history),
        }

        if session_state.refusal_count >= 3:
            score += 40
            reasons.append("multiple_prior_refusals")

        if session_state.tool_request_count >= 5:
            score += 20
            reasons.append("high_tool_request_volume")

        if session_state.request_count >= 20:
            score += 15
            reasons.append("high_session_request_volume")

        if session_state.injection_attempt_count >= 2:
            score += 20
            reasons.append("cumulative_injection_attempts")

        if session_state.escalation_pattern_count >= 1:
            score += 25
            reasons.append("escalation_pattern_detected")

        if envelope.input_scan and envelope.input_scan.score >= 70:
            score += 20
            reasons.append("high_current_input_risk")

        if any(m.has_control_chars for m in envelope.messages):
            score += 10
            reasons.append("control_chars_present")

        if envelope.request_facts.get("has_system_messages"):
            score += 15
            reasons.append("user_supplied_system_message")

        if envelope.request_facts.get("has_developer_messages"):
            score += 15
            reasons.append("user_supplied_developer_message")

        if score >= 80:
            state = "blocked"
        elif score >= 50:
            state = "restricted"
        elif score >= 20:
            state = "elevated"
        else:
            state = "normal"

        return SessionRiskAssessment(
            score=min(score, 100),
            state=state,  # type: ignore[arg-type]
            reasons=reasons,
            features=features,
        )
