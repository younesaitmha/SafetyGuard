from __future__ import annotations

import json
import logging
from typing import List

from .models import AuditEvent, CanonicalRequestEnvelope

logger = logging.getLogger("audit_bus")


class AuditBus:
    def __init__(self):
        self._events: List[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self._events.append(event)
        logger.info(json.dumps(event.model_dump(), ensure_ascii=False))

    def emit_for_envelope(self, envelope: CanonicalRequestEnvelope) -> None:
        base = {
            "trace_id": envelope.trace_id,
            "session_id": envelope.session_id,
            "subject": envelope.security_context.subject,
            "tenant_id": envelope.security_context.tenant_id,
        }

        if envelope.policy_decision and envelope.policy_decision.action in {"deny", "challenge"}:
            self.emit(
                AuditEvent(
                    event_type="policy_decision",
                    severity="high",
                    details={
                        "action": envelope.policy_decision.action,
                        "reason_codes": envelope.policy_decision.reason_codes,
                    },
                    **base,
                )
            )

        if envelope.input_scan and envelope.input_scan.score >= 50:
            self.emit(
                AuditEvent(
                    event_type="high_risk_input_scan",
                    severity="high",
                    details={
                        "score": envelope.input_scan.score,
                        "labels": envelope.input_scan.labels,
                        "summary": envelope.input_scan.summary,
                    },
                    **base,
                )
            )

        if envelope.dlp_scan and envelope.dlp_scan.score >= 20:
            self.emit(
                AuditEvent(
                    event_type="dlp_detection",
                    severity="high" if envelope.dlp_scan.score >= 40 else "medium",
                    details={
                        "score": envelope.dlp_scan.score,
                        "labels": envelope.dlp_scan.labels,
                        "summary": envelope.dlp_scan.summary,
                    },
                    **base,
                )
            )

        blocked_tools = [t for t in envelope.tool_decisions if not t.allowed]
        if blocked_tools:
            self.emit(
                AuditEvent(
                    event_type="tool_blocked",
                    severity="medium",
                    details={
                        "blocked_tools": [t.model_dump() for t in blocked_tools],
                    },
                    **base,
                )
            )

        if envelope.output_guard and envelope.output_guard.action in {"redact", "block"}:
            self.emit(
                AuditEvent(
                    event_type="output_guard_action",
                    severity="high" if envelope.output_guard.action == "block" else "medium",
                    details=envelope.output_guard.model_dump(),
                    **base,
                )
            )

        if envelope.prompt_package:
            metadata = envelope.prompt_package.metadata or {}
            hybrid_passed = metadata.get("hybrid_pii_check_passed", True)
            residual_count = int(metadata.get("pii_regex_residual_match_count", 0) or 0)
            if not hybrid_passed or residual_count > 0:
                self.emit(
                    AuditEvent(
                        event_type="prompt_pii_residual_alert",
                        severity="high" if residual_count > 0 else "medium",
                        details={
                            "hybrid_pii_check_passed": bool(hybrid_passed),
                            "pii_regex_residual_match_count": residual_count,
                            "pii_regex_residual_patterns": metadata.get("pii_regex_residual_patterns", []),
                            "llm_pii_signal_detected": bool(metadata.get("llm_pii_signal_detected", False)),
                            "pii_redaction_count": int(metadata.get("pii_redaction_count", 0) or 0),
                        },
                        **base,
                    )
                )

    def recent_events(self, limit: int = 100) -> List[AuditEvent]:
        return self._events[-limit:]
