from __future__ import annotations

import re
import uuid

from .models import (
    CanonicalRequestEnvelope,
    ChatRequest,
    NormalizedAttachment,
    NormalizedMessage,
    SecurityContext,
)

CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")

# NEW: Metadata injection patterns
METADATA_INJECTION_PATTERNS = [
    r"<script",
    r"javascript:",
    r"onerror\s*=",
    r"onload\s*=",
    r"eval\s*\(",
    r"__import__",
    r"import\s+os",
    r"system\s*\(",
]


def _normalize_text(text: str) -> tuple[str, bool]:
    has_control_chars = bool(CONTROL_CHAR_RE.search(text))
    normalized = CONTROL_CHAR_RE.sub("", text)
    normalized = normalized.replace("\r\n", "\n").replace("\r", "\n").strip()
    return normalized, has_control_chars


def _source_label_for_role(role: str) -> str:
    if role in {"system", "developer"}:
        return "trusted"
    if role == "assistant":
        return "semi_trusted"
    return "untrusted"


def _has_metadata_injection(text: str | None) -> bool:
    """NEW: Check if text contains metadata injection patterns."""
    if not text:
        return False
    text_lower = text.lower()
    return any(re.search(pattern, text_lower) for pattern in METADATA_INJECTION_PATTERNS)


def build_canonical_request_envelope(
    trace_id: str,
    body: ChatRequest,
    security_context: SecurityContext,
    source: dict,
) -> CanonicalRequestEnvelope:
    normalized_messages = []
    for msg in body.messages:
        content, has_control_chars = _normalize_text(msg.content)
        normalized_messages.append(
            NormalizedMessage(
                role=msg.role,
                content=content,
                source_label=_source_label_for_role(msg.role),  # type: ignore[arg-type]
                content_length=len(content),
                has_control_chars=has_control_chars,
                encoding_hints=[],
            )
        )

    normalized_attachments = []
    metadata_injection_count = 0
    for att in body.attachments:
        # NEW: Check metadata for injection patterns
        has_metadata_injection = (
            _has_metadata_injection(att.name)
            or _has_metadata_injection(att.content_type)
            or _has_metadata_injection(att.uri)
        )
        if has_metadata_injection:
            metadata_injection_count += 1
        
        normalized_attachments.append(
            NormalizedAttachment(
                name=att.name,
                content_type=att.content_type,
                size_bytes=att.size_bytes,
                uri=att.uri,
                source_label="untrusted",
                source=att.source,
                content=att.content,
            )
        )

    return CanonicalRequestEnvelope(
        trace_id=trace_id or str(uuid.uuid4()),
        session_id=body.session_id,
        user_id=body.user_id or security_context.user_id,
        tenant_id=security_context.tenant_id,
        source=source,
        messages=normalized_messages,
        attachments=normalized_attachments,
        metadata=body.metadata,
        security_context=security_context,
        request_facts={
            "message_count": len(normalized_messages),
            "attachment_count": len(normalized_attachments),
            "has_system_messages": any(m.role == "system" for m in normalized_messages),
            "has_developer_messages": any(m.role == "developer" for m in normalized_messages),
            "metadata_injection_detected": metadata_injection_count > 0,
            "metadata_injection_count": metadata_injection_count,
        },
    )
