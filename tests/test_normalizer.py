from app.models import ChatMessage, ChatRequest, SecurityContext
from app.normalizer import build_canonical_request_envelope


def test_build_canonical_request_envelope_basic():
    body = ChatRequest(
        session_id="sess-1",
        user_id="user-1",
        messages=[
            ChatMessage(role="user", content="Hello\r\nworld"),
            ChatMessage(role="assistant", content="Previous answer"),
        ],
        metadata={"k": "v"},
    )

    security_context = SecurityContext(
        subject="user-1",
        user_id="user-1",
        tenant_id="tenant-a",
        roles=["user"],
        permissions=["llm:chat"],
        issuer="issuer",
        audience="aud",
        claims={},
    )

    envelope = build_canonical_request_envelope(
        trace_id="trace-1",
        body=body,
        security_context=security_context,
        source={"channel": "api"},
    )

    assert envelope.trace_id == "trace-1"
    assert envelope.session_id == "sess-1"
    assert envelope.user_id == "user-1"
    assert envelope.messages[0].content == "Hello\nworld"
    assert envelope.messages[0].source_label == "untrusted"
    assert envelope.messages[1].source_label == "semi_trusted"
    assert envelope.request_facts["message_count"] == 2


def test_normalizer_removes_control_chars():
    body = ChatRequest(
        messages=[ChatMessage(role="user", content="abc\x00def\x07ghi")]
    )

    security_context = SecurityContext(
        subject="user-1",
        user_id="user-1",
        issuer="issuer",
        audience="aud",
        claims={},
    )

    envelope = build_canonical_request_envelope(
        trace_id="trace-2",
        body=body,
        security_context=security_context,
        source={},
    )

    assert envelope.messages[0].content == "abcdefghi"
    assert envelope.messages[0].has_control_chars is True
