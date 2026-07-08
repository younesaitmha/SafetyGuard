from app.models import (
    CanonicalRequestEnvelope,
    ContentClassification,
    DLPScanResult,
    InputScanResult,
    NormalizedMessage,
    SecurityContext,
    SessionRiskAssessment,
)
from app.policy_service import PolicyService


def make_envelope() -> CanonicalRequestEnvelope:
    env = CanonicalRequestEnvelope(
        trace_id="trace",
        user_id="u1",
        source={},
        messages=[
            NormalizedMessage(
                role="user",
                content="hello",
                source_label="untrusted",
                content_length=5,
            )
        ],
        attachments=[],
        metadata={},
        security_context=SecurityContext(
            subject="u1",
            user_id="u1",
            permissions=["llm:chat"],
            issuer="issuer",
            audience="aud",
            claims={},
        ),
    )
    env.input_scan = InputScanResult(score=0, labels=[], signals=[], summary={})
    env.dlp_scan = DLPScanResult(score=0, labels=[], matches=[], summary={})
    env.session_risk = SessionRiskAssessment(score=0, state="normal", reasons=[], features={})
    env.content_classification = ContentClassification(
        label="benign",
        confidence=0.9,
        reasons=[],
        features={},
    )
    return env


def test_policy_default_allow():
    env = make_envelope()
    service = PolicyService()

    decision = service.evaluate(env)

    assert decision.action in {"allow", "allow_with_restrictions"}


def test_policy_denies_secret_exfiltration():
    env = make_envelope()
    env.input_scan = InputScanResult(score=30, labels=["secret_exfiltration"], signals=[], summary={})
    service = PolicyService()

    decision = service.evaluate(env)

    assert decision.action == "deny"
    assert "SECRET_EXFILTRATION_ATTEMPT" in decision.reason_codes


def test_policy_denies_moderation_bypass():
    env = make_envelope()
    env.input_scan = InputScanResult(score=35, labels=["moderation_bypass"], signals=[], summary={})
    service = PolicyService()

    decision = service.evaluate(env)

    assert decision.action == "deny"
    assert "MODERATION_BYPASS_ATTEMPT_DETECTED" in decision.reason_codes


def test_policy_restricts_hateful_or_discriminatory_content():
    env = make_envelope()
    env.input_scan = InputScanResult(score=25, labels=["hate_content"], signals=[], summary={})
    service = PolicyService()

    decision = service.evaluate(env)

    assert decision.action == "allow_with_restrictions"
    assert "HATEFUL_CONTENT_DETECTED" in decision.reason_codes
