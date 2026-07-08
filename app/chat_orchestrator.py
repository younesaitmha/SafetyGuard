from __future__ import annotations

from dataclasses import dataclass

from fastapi import Request

from .chat_pipeline import (
    Forwarder,
    PipelineContext,
    PreflightAndNormalizeStep,
    RetrievalAndPromptStep,
    SessionPolicyStep,
    UpstreamAndOutputStep,
)
from .interfaces import OrchestratorServicesProtocol
from .models import ChatRequest, ChatResponse, SecurityContext
from .observability import RequestTimer


@dataclass
class OrchestratorServices:
    rate_limiter: object
    session_manager: object
    risk_engine: object
    input_scanner: object
    dlp_scanner: object
    llm_guard: object
    content_classifier: object
    policy_engine: object
    retrieval_gateway: object
    tool_gateway: object
    prompt_builder: object
    output_guard: object
    attacker_profiler: object
    audit_bus: object
    decision_logger: object
    settings: object


class ChatOrchestrator:
    def __init__(self, services: OrchestratorServicesProtocol):
        self.s = services
        self._pipeline = PreflightAndNormalizeStep()
        self._pipeline.set_next(SessionPolicyStep()).set_next(RetrievalAndPromptStep()).set_next(UpstreamAndOutputStep())

    async def execute(
        self,
        request: Request,
        body: ChatRequest,
        authorization: str | None,
        security_context: SecurityContext,
        trace_id: str,
        forward_fn: Forwarder,
    ) -> ChatResponse:
        context = PipelineContext(
            request=request,
            body=body,
            authorization=authorization,
            security_context=security_context,
            trace_id=trace_id,
            forward_fn=forward_fn,
            services=self.s,
            timer=RequestTimer(),
        )
        await self._pipeline.run(context)
        if context.response is None:
            raise RuntimeError("chat_pipeline_missing_response")
        return context.response
