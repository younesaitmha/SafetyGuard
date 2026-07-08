import pytest

from app.config import settings
from app.models import (
    CanonicalRequestEnvelope,
    LLMGuardAnalysis,
    NormalizedMessage,
    PolicyDecision,
    RetrievalChunk,
    RetrievalResult,
    SecurityContext,
)
from app.prompt_builder import PromptBuilder


@pytest.fixture(autouse=True)
def _enable_deterministic_prompt_redaction_for_unit_tests(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "llm_pii_treatment_only", False)


def _build_envelope() -> CanonicalRequestEnvelope:
    return CanonicalRequestEnvelope(
        trace_id="trace-1",
        session_id="session-1",
        user_id="user-1",
        security_context=SecurityContext(
            subject="user-1",
            user_id="user-1",
            issuer="https://issuer.example.com",
            audience="llm-api",
            permissions=["llm:chat"],
        ),
        messages=[
            NormalizedMessage(
                role="user",
                source_label="untrusted",
                content="email john.doe@example.com phone +1 415-555-1212 password=hunter2 Bearer abc.def.ghi",
                content_length=100,
            )
        ],
        policy_decision=PolicyDecision(action="allow", reason_codes=[]),
    )


def test_prompt_builder_masks_pii_in_user_input() -> None:
    envelope = _build_envelope()

    package = PromptBuilder().build(envelope)

    assert "john.doe@example.com" not in package.prompt_text
    assert "+1 415-555-1212" not in package.prompt_text
    assert "password=hunter2" not in package.prompt_text
    assert "Bearer abc.def.ghi" not in package.prompt_text

    assert "[REDACTED_EMAIL]" in package.prompt_text
    assert "[REDACTED_PHONE]" in package.prompt_text
    assert "[REDACTED_PASSWORD]" in package.prompt_text
    assert "[REDACTED_BEARER_TOKEN]" in package.prompt_text

    assert package.metadata.get("pii_redaction_applied") is True
    assert package.metadata.get("pii_redaction_count", 0) >= 4


def test_prompt_builder_masks_pii_in_retrieval_context() -> None:
    envelope = _build_envelope()
    envelope.retrieval_result = RetrievalResult(
        query="test",
        chunks=[
            RetrievalChunk(
                chunk_id="c1",
                document_id="d1",
                score=0.99,
                text="Contact admin at admin@corp.local and use api_key=sk-secret-123",
                sensitivity="internal",
                trust_level="semi_trusted",
            )
        ],
    )

    package = PromptBuilder().build(envelope)

    assert "admin@corp.local" not in package.prompt_text
    assert "api_key=sk-secret-123" not in package.prompt_text
    assert "[REDACTED_EMAIL]" in package.prompt_text
    assert "[REDACTED_SECRET]" in package.prompt_text


def test_prompt_builder_masks_db_pass_and_ssn_with_correct_placeholders() -> None:
    envelope = _build_envelope()
    envelope.messages = [
        NormalizedMessage(
            role="user",
            source_label="untrusted",
            content="AdminUser=root, DB_PASS=P@ssw0rd2026!, User_SSN=2840575123456, API_KEY=sk-live-5561a3c7b",
            content_length=120,
        )
    ]

    package = PromptBuilder().build(envelope)

    assert "DB_PASS=P@ssw0rd2026!" not in package.prompt_text
    assert "User_SSN=2840575123456" not in package.prompt_text
    assert "API_KEY=sk-live-5561a3c7b" not in package.prompt_text
    assert "[REDACTED_PASSWORD]" in package.prompt_text
    assert "[REDACTED_SSN]" in package.prompt_text
    assert "[REDACTED_SECRET]" in package.prompt_text


def test_prompt_builder_preserves_assignment_keys_when_redacting_values() -> None:
    envelope = _build_envelope()
    envelope.messages = [
        NormalizedMessage(
            role="user",
            source_label="untrusted",
            content=(
                "Voici mon rapport d'erreur mensuel pour mon serveur : "
                "AdminUser=root, DB_PASS=P@ssw0rd2026!, User_SSN=2840575123456, "
                "API_KEY=sk-live-5561a3c7b. Peux-tu nettoyer les sauts de ligne ?"
            ),
            content_length=220,
        )
    ]

    package = PromptBuilder().build(envelope)

    assert "AdminUser=[REDACTED_USERNAME]" in package.prompt_text
    assert "DB_PASS=[REDACTED_PASSWORD]" in package.prompt_text
    assert "User_SSN=[REDACTED_SSN]" in package.prompt_text
    assert "API_KEY=[REDACTED_SECRET]" in package.prompt_text


def test_prompt_builder_hybrid_pii_check_metadata() -> None:
    envelope = _build_envelope()
    envelope.llm_input_guard = LLMGuardAnalysis(
        label="secret_exfiltration_intent",
        confidence=0.9,
        risk_score=85,
        reasons=["Contains API key"],
        recommended_action="deny",
        raw_response={"label": "secret_exfiltration_intent"},
    )

    package = PromptBuilder().build(envelope)

    assert package.metadata.get("llm_pii_signal_detected") is True
    assert package.metadata.get("hybrid_pii_check_passed") is True
    assert package.metadata.get("pii_regex_residual_match_count") == 0
