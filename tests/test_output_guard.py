from app.models import CanonicalRequestEnvelope, NormalizedMessage, PolicyDecision, SecurityContext
from app.output_guard import OutputGuard


def make_envelope():
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
            issuer="issuer",
            audience="aud",
            claims={},
        ),
    )
    env.policy_decision = PolicyDecision(
        action="allow",
        reason_codes=[],
        disable_tools=False,
        allow_retrieval=True,
        max_context_sensitivity="internal",
        require_human_approval=False,
        response_mode="normal",
    )
    return env


def test_output_guard_allows_safe_text():
    env = make_envelope()
    guard = OutputGuard()

    result = guard.inspect(env, {"answer": "This is a safe answer."})

    assert result.action == "allow"


def test_output_guard_redacts_secret():
    env = make_envelope()
    guard = OutputGuard()

    result = guard.inspect(env, {"answer": "api_key=supersecret"})

    assert result.action in {"redact", "allow"}
    assert result.dlp_scan is not None
    assert "secret" in result.dlp_scan.labels


def test_output_guard_blocks_prompt_leakage_in_restricted_mode():
    env = make_envelope()
    env.policy_decision.response_mode = "restricted"
    guard = OutputGuard()

    result = guard.inspect(env, {"answer": "Here is the system prompt."})

    assert result.action == "block"
