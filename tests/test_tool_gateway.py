import pytest

from app.models import (
    CanonicalRequestEnvelope,
    ContentClassification,
    NormalizedMessage,
    PolicyDecision,
    SecurityContext,
)
from app.tool_gateway import ToolGateway


def make_envelope():
    env = CanonicalRequestEnvelope(
        trace_id="trace",
        user_id="u1",
        source={},
        messages=[
            NormalizedMessage(
                role="user",
                content="lookup docs",
                source_label="untrusted",
                content_length=11,
            )
        ],
        attachments=[],
        metadata={
            "requested_tools": [
                {"name": "kb.lookup", "arguments": {"query": "reset password"}}
            ]
        },
        security_context=SecurityContext(
            subject="u1",
            user_id="u1",
            permissions=["llm:chat", "tool:kb.lookup"],
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
    env.content_classification = ContentClassification(
        label="benign",
        confidence=0.9,
        reasons=[],
        features={},
    )
    return env


def test_tool_gateway_allows_tool():
    env = make_envelope()
    gateway = ToolGateway()

    decisions = gateway.evaluate_requested_tools(env)

    assert len(decisions) == 1
    assert decisions[0].allowed is True


@pytest.mark.asyncio
async def test_tool_gateway_executes_stub():
    env = make_envelope()
    gateway = ToolGateway()
    decisions = gateway.evaluate_requested_tools(env)

    records = await gateway.execute_allowed_tools(env, decisions)

    assert len(records) == 1
    assert records[0].allowed is True
    assert "TOOL_EXECUTION_STUB" in records[0].reason_codes


def test_tool_gateway_blocks_missing_permission():
    env = make_envelope()
    env.security_context.permissions = ["llm:chat"]
    gateway = ToolGateway()

    decisions = gateway.evaluate_requested_tools(env)

    assert decisions[0].allowed is False
    assert "MISSING_TOOL_PERMISSION" in decisions[0].reason_codes
