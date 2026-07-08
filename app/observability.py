from __future__ import annotations

import json
import logging
import time
from collections import defaultdict
from typing import Dict

from .models import CanonicalRequestEnvelope, DecisionLogRecord

logger = logging.getLogger("observability")


class UpstreamMetrics:
    def __init__(self):
        self._counters: dict[str, int] = defaultdict(int)

    def record_success(self) -> None:
        self._counters["upstream_success"] += 1

    def record_failure(self, error_type: str, fail_open: bool) -> None:
        self._counters["upstream_failure"] += 1
        self._counters[f"upstream_failure_type:{error_type}"] += 1
        mode = "fail_open" if fail_open else "fail_closed"
        self._counters[f"upstream_failure_mode:{mode}"] += 1

    def snapshot(self) -> Dict[str, int]:
        return dict(self._counters)


class RequestTimer:
    def __init__(self):
        self._start = time.perf_counter()
        self._marks: Dict[str, float] = {}

    def mark(self, name: str) -> None:
        self._marks[name] = (time.perf_counter() - self._start) * 1000.0

    def snapshot(self) -> Dict[str, float]:
        return {k: round(v, 2) for k, v in self._marks.items()}


class DecisionLogger:
    def log(
        self,
        envelope: CanonicalRequestEnvelope,
        timings_ms: Dict[str, float],
        outcome: Dict[str, object],
    ) -> DecisionLogRecord:
        record = DecisionLogRecord(
            trace_id=envelope.trace_id,
            session_id=envelope.session_id,
            subject=envelope.security_context.subject,
            tenant_id=envelope.security_context.tenant_id,
            request_summary={
                "message_count": len(envelope.messages),
                "attachment_count": len(envelope.attachments),
                "requested_tool_count": len(envelope.metadata.get("requested_tools", [])),
                "retrieval_allowed": envelope.policy_decision.allow_retrieval if envelope.policy_decision else False,
            },
            decisions={
                "session_risk": envelope.session_risk.model_dump() if envelope.session_risk else None,
                "input_scan": envelope.input_scan.model_dump() if envelope.input_scan else None,
                "dlp_scan": envelope.dlp_scan.model_dump() if envelope.dlp_scan else None,
                "llm_input_guard": envelope.llm_input_guard.model_dump() if envelope.llm_input_guard else None,
                "content_classification": envelope.content_classification.model_dump() if envelope.content_classification else None,
                "policy_decision": envelope.policy_decision.model_dump() if envelope.policy_decision else None,
                "retrieval_summary": envelope.retrieval_result.model_dump() if envelope.retrieval_result else None,
                "tool_decisions": [t.model_dump() for t in envelope.tool_decisions],
                "llm_output_guard": envelope.llm_output_guard.model_dump() if envelope.llm_output_guard else None,
                "output_guard": envelope.output_guard.model_dump() if envelope.output_guard else None,
            },
            timings_ms=timings_ms,
            outcome=outcome,
        )
        logger.info(json.dumps(record.model_dump(), ensure_ascii=False))
        return record
