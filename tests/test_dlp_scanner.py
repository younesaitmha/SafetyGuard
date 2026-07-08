from app.dlp_scanner import DLPScanner
from app.models import CanonicalRequestEnvelope, NormalizedMessage, SecurityContext


def make_envelope(text: str) -> CanonicalRequestEnvelope:
    return CanonicalRequestEnvelope(
        trace_id="trace-dlp",
        user_id="user-1",
        source={},
        messages=[
            NormalizedMessage(
                role="user",
                content=text,
                source_label="untrusted",
                content_length=len(text),
            )
        ],
        attachments=[],
        metadata={},
        security_context=SecurityContext(
            subject="user-1",
            user_id="user-1",
            issuer="issuer",
            audience="aud",
            claims={},
        ),
    )


def test_dlp_scanner_detects_email_and_secret():
    scanner = DLPScanner()
    envelope = make_envelope("email alice@example.com api_key=supersecret")

    result = scanner.scan(envelope)

    assert "pii" in result.labels
    assert "secret" in result.labels
    assert result.summary["match_count"] >= 2


def test_dlp_scanner_detects_private_key():
    scanner = DLPScanner()
    envelope = make_envelope("-----BEGIN PRIVATE KEY-----")

    result = scanner.scan(envelope)

    assert "secret" in result.labels
    assert result.score >= 30
