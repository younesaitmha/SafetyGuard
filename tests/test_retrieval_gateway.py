import pytest

from app.models import CanonicalRequestEnvelope, NormalizedMessage, PolicyDecision, SecurityContext
from app.retrieval_gateway import RetrievalGateway


def make_envelope():
    env = CanonicalRequestEnvelope(
        trace_id="trace",
        user_id="u1",
        tenant_id="tenant-a",
        source={},
        messages=[
            NormalizedMessage(
                role="user",
                content="How do I reset a password?",
                source_label="untrusted",
                content_length=27,
            )
        ],
        attachments=[],
        metadata={},
        security_context=SecurityContext(
            subject="u1",
            user_id="u1",
            tenant_id="tenant-a",
            permissions=["llm:chat"],
            issuer="issuer",
            audience="aud",
            claims={},
        ),
    )
    env.policy_decision = PolicyDecision(
        action="allow",
        reason_codes=["ALLOW_DEFAULT"],
        disable_tools=False,
        allow_retrieval=True,
        max_context_sensitivity="internal",
        require_human_approval=False,
        response_mode="normal",
    )
    return env


@pytest.mark.asyncio
async def test_retrieval_gateway_returns_filtered_chunks():
    env = make_envelope()
    gateway = RetrievalGateway()

    result = await gateway.retrieve(env)

    assert result.query
    assert result.allowed_count >= 0
    assert result.filtered_out_count >= 0
    assert result.dlp_scan is not None
