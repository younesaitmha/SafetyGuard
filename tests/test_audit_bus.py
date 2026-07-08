from app.audit_bus import AuditBus
from app.models import CanonicalRequestEnvelope, NormalizedMessage, PromptPackage, SecurityContext


def _envelope() -> CanonicalRequestEnvelope:
    return CanonicalRequestEnvelope(
        trace_id="trace-1",
        session_id="session-1",
        user_id="user-1",
        source={},
        messages=[
            NormalizedMessage(
                role="user",
                source_label="untrusted",
                content="hello",
                content_length=5,
            )
        ],
        security_context=SecurityContext(
            subject="user-1",
            user_id="user-1",
            issuer="issuer",
            audience="aud",
            claims={},
        ),
    )


def test_audit_bus_emits_prompt_pii_residual_alert_when_hybrid_check_fails() -> None:
    env = _envelope()
    env.prompt_package = PromptPackage(
        mode="guarded",
        prompt_text="x",
        metadata={
            "hybrid_pii_check_passed": False,
            "pii_regex_residual_match_count": 2,
            "pii_regex_residual_patterns": ["api_key_assignment"],
            "llm_pii_signal_detected": True,
            "pii_redaction_count": 3,
        },
    )

    bus = AuditBus()
    bus.emit_for_envelope(env)
    events = bus.recent_events(10)

    assert any(e.event_type == "prompt_pii_residual_alert" for e in events)


def test_audit_bus_does_not_emit_prompt_pii_residual_alert_when_check_passes() -> None:
    env = _envelope()
    env.prompt_package = PromptPackage(
        mode="guarded",
        prompt_text="x",
        metadata={
            "hybrid_pii_check_passed": True,
            "pii_regex_residual_match_count": 0,
            "pii_regex_residual_patterns": [],
            "llm_pii_signal_detected": True,
            "pii_redaction_count": 3,
        },
    )

    bus = AuditBus()
    bus.emit_for_envelope(env)
    events = bus.recent_events(10)

    assert not any(e.event_type == "prompt_pii_residual_alert" for e in events)
