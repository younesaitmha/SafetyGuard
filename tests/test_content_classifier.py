from app.content_classifier import ContentClassifier
from app.models import (
    CanonicalRequestEnvelope,
    ContentClassification,
    LLMGuardAnalysis,
    DLPScanResult,
    InputScanResult,
    NormalizedMessage,
    SecurityContext,
    SessionRiskAssessment,
)


def base_envelope() -> CanonicalRequestEnvelope:
    return CanonicalRequestEnvelope(
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
            issuer="issuer",
            audience="aud",
            claims={},
        ),
    )


def test_classifier_benign():
    env = base_envelope()
    env.input_scan = InputScanResult(score=0, labels=[], signals=[], summary={})
    env.dlp_scan = DLPScanResult(score=0, labels=[], matches=[], summary={})
    env.session_risk = SessionRiskAssessment(score=0, state="normal", reasons=[], features={})

    result = ContentClassifier().classify(env)

    assert result.label == "benign"


def test_classifier_prompt_injection():
    env = base_envelope()
    env.input_scan = InputScanResult(score=25, labels=["prompt_injection"], signals=[], summary={})
    env.dlp_scan = DLPScanResult(score=0, labels=[], matches=[], summary={})
    env.session_risk = SessionRiskAssessment(score=0, state="normal", reasons=[], features={})

    result = ContentClassifier().classify(env)

    assert result.label == "prompt_injection"


def test_classifier_sensitive_submission():
    env = base_envelope()
    env.input_scan = InputScanResult(score=0, labels=[], signals=[], summary={})
    env.dlp_scan = DLPScanResult(score=20, labels=["secret"], matches=[], summary={})
    env.session_risk = SessionRiskAssessment(score=0, state="normal", reasons=[], features={})

    result = ContentClassifier().classify(env)

    assert result.label == "sensitive_data_submission"


def test_classifier_reclassifies_llm_exfiltration_to_sensitive_submission_when_no_exfil_signal():
    env = base_envelope()
    env.input_scan = InputScanResult(score=0, labels=[], signals=[], summary={})
    env.dlp_scan = DLPScanResult(score=30, labels=["pii", "secret"], matches=[], summary={})
    env.session_risk = SessionRiskAssessment(score=0, state="normal", reasons=[], features={})
    env.llm_input_guard = LLMGuardAnalysis(
        label="secret_exfiltration_intent",
        confidence=0.9,
        risk_score=85,
        reasons=["Contains API key"],
        recommended_action="deny",
        raw_response={"label": "secret_exfiltration_intent"},
    )

    result = ContentClassifier().classify(env)

    assert result.label == "sensitive_data_submission"
    assert "secret_submission_without_exfiltration_request" in result.reasons


def test_classifier_downgrades_llm_only_jailbreak_without_deterministic_signals():
    env = base_envelope()
    env.input_scan = InputScanResult(score=0, labels=[], signals=[], summary={})
    env.dlp_scan = DLPScanResult(score=0, labels=[], matches=[], summary={})
    env.session_risk = SessionRiskAssessment(score=0, state="normal", reasons=[], features={})
    env.llm_input_guard = LLMGuardAnalysis(
        label="jailbreak_attempt",
        confidence=0.9,
        risk_score=85,
        reasons=["model_detected_jailbreak"],
        recommended_action="deny",
        raw_response={"label": "jailbreak_attempt"},
    )

    result = ContentClassifier().classify(env)

    assert result.label == "suspicious"
    assert "llm_guard_unconfirmed_by_deterministic_signals" in result.reasons
