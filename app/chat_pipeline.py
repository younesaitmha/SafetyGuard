from __future__ import annotations

import logging
import inspect
from dataclasses import dataclass
from typing import Awaitable, Callable

from fastapi import HTTPException, Request, status

from .error_handlers import (
    ChallengeHandler,
    DenyHandler,
    ErrorHandlerContext,
    OutputBlockedHandler,
    OutputRedactHandler,
    PromptBudgetExceededHandler,
    RateLimitHandler,
)
from .interfaces import OrchestratorServicesProtocol
from .models import CanonicalRequestEnvelope, ChatRequest, ChatResponse, SecurityContext, SessionState
from .normalizer import build_canonical_request_envelope
from .observability import RequestTimer
from .security import get_client_identifier

Forwarder = Callable[[dict, str, str | None], Awaitable[dict]]


@dataclass
class PipelineContext:
    request: Request
    body: ChatRequest
    authorization: str | None
    security_context: SecurityContext
    trace_id: str
    forward_fn: Forwarder
    services: OrchestratorServicesProtocol
    timer: RequestTimer
    client_id: str | None = None
    rate_limit_key: str | None = None
    envelope: CanonicalRequestEnvelope | None = None
    session_state: SessionState | None = None
    upstream_response: dict | None = None
    output_text: str = ""
    client_response: dict | None = None
    response: ChatResponse | None = None


class PipelineStep:
    def __init__(self) -> None:
        self._next: PipelineStep | None = None

    def set_next(self, next_step: PipelineStep) -> PipelineStep:
        self._next = next_step
        return next_step

    async def run(self, context: PipelineContext) -> None:
        await self.handle(context)
        if self._next is not None:
            await self._next.run(context)

    async def handle(self, context: PipelineContext) -> None:
        raise NotImplementedError


class PreflightAndNormalizeStep(PipelineStep):
    async def handle(self, context: PipelineContext) -> None:
        content_length = context.request.headers.get("content-length")
        if content_length and int(content_length) > context.services.settings.max_request_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="Request too large",
            )

        context.timer.mark("identity")
        context.client_id = get_client_identifier(context.request)
        context.rate_limit_key = f"{context.client_id}:{context.security_context.subject}"
        source = {
            "channel": "api",
            "client_id": context.client_id,
            "user_agent": context.request.headers.get("user-agent"),
            "remote_addr": context.client_id,
        }
        context.envelope = build_canonical_request_envelope(
            trace_id=context.trace_id,
            body=context.body,
            security_context=context.security_context,
            source=source,
        )
        context.timer.mark("normalize")


class SessionPolicyStep(PipelineStep):
    async def handle(self, context: PipelineContext) -> None:
        assert context.envelope is not None
        session_state = context.services.session_manager.get_or_create_session(
            session_id=context.envelope.session_id,
            subject=context.security_context.subject,
            tenant_id=context.security_context.tenant_id,
        )
        context.session_state = session_state
        context.envelope.session_id = session_state.session_id
        context.services.session_manager.update_from_request(session_state, context.envelope)

        context.envelope.input_scan = context.services.input_scanner.scan(context.envelope)
        injection_attempt_count = context.services.session_manager.get_injection_attempt_count(session_state.session_id)
        profile_multiplier = context.services.attacker_profiler.get_adaptive_rate_limit_multiplier(
            context.client_id,
            context.security_context.subject,
        )
        allowed, reason = context.services.rate_limiter.allow(
            key=context.rate_limit_key,
            severity_score=context.envelope.input_scan.score if context.envelope.input_scan else 0,
            injection_attempt_count=injection_attempt_count,
            profile_multiplier=profile_multiplier,
        )
        if not allowed:
            handler = RateLimitHandler(reason)
            handler.create_exception(
                ErrorHandlerContext(
                    trace_id=context.trace_id,
                    session_id=session_state.session_id,
                    reason_codes=[reason],
                )
            )
        context.timer.mark("rate_limit")
        context.timer.mark("input_scan")

        context.envelope.session_state = session_state
        context.envelope.session_risk = context.services.risk_engine.assess(
            envelope=context.envelope,
            session_state=session_state,
        )
        context.services.session_manager.append_risk_score(
            session_id=session_state.session_id,
            score=context.envelope.session_risk.score,
            state_name=context.envelope.session_risk.state,
        )
        context.timer.mark("session_risk")

        context.envelope.dlp_scan = context.services.dlp_scanner.scan(context.envelope)
        context.timer.mark("dlp_scan")

        context.envelope.llm_input_guard = await context.services.llm_guard.analyze_input(context.envelope)
        context.timer.mark("llm_input_guard")

        context.envelope.content_classification = context.services.content_classifier.classify(context.envelope)
        context.timer.mark("content_classification")

        context.envelope.policy_decision = context.services.policy_engine.decide(context.envelope)
        context.timer.mark("policy_decision")

        if context.envelope.policy_decision.action not in {"deny", "challenge"}:
            redactor = getattr(context.services.llm_guard, "redact_envelope_pii", None)
            if callable(redactor) and inspect.iscoroutinefunction(redactor):
                await redactor(context.envelope)
                context.timer.mark("llm_input_redaction")

        if context.envelope.policy_decision.action == "deny":
            context.services.session_manager.record_refusal(session_state.session_id)
            context.services.session_manager.record_injection_attempt(
                session_id=session_state.session_id,
                deterministic_score=context.envelope.input_scan.score if context.envelope.input_scan else 0,
            )
            context.services.attacker_profiler.record_refusal(
                client_id=context.client_id,
                subject=context.security_context.subject,
                reason_codes=context.envelope.policy_decision.reason_codes,
            )
            context.services.audit_bus.emit_for_envelope(context.envelope)
            context.services.decision_logger.log(context.envelope, context.timer.snapshot(), {"status": "denied"})
            handler = DenyHandler()
            handler.create_exception(
                ErrorHandlerContext(
                    trace_id=context.trace_id,
                    session_id=session_state.session_id,
                    reason_codes=context.envelope.policy_decision.reason_codes,
                    policy_action=context.envelope.policy_decision.action,
                )
            )

        if context.envelope.policy_decision.action == "challenge":
            context.services.audit_bus.emit_for_envelope(context.envelope)
            context.services.decision_logger.log(context.envelope, context.timer.snapshot(), {"status": "challenge"})
            handler = ChallengeHandler()
            handler.create_exception(
                ErrorHandlerContext(
                    trace_id=context.trace_id,
                    session_id=session_state.session_id,
                    reason_codes=context.envelope.policy_decision.reason_codes,
                )
            )


class RetrievalAndPromptStep(PipelineStep):
    async def handle(self, context: PipelineContext) -> None:
        assert context.envelope is not None
        assert context.session_state is not None

        context.envelope.retrieval_result = await context.services.retrieval_gateway.retrieve(context.envelope)
        context.timer.mark("retrieval")

        redactor = getattr(context.services.llm_guard, "redact_envelope_pii", None)
        if callable(redactor) and inspect.iscoroutinefunction(redactor):
            await redactor(context.envelope)
            context.timer.mark("llm_post_retrieval_redaction")

        context.envelope.tool_decisions = context.services.tool_gateway.evaluate_requested_tools(context.envelope)
        context.timer.mark("tool_evaluation")

        context.envelope.tool_execution_records = await context.services.tool_gateway.execute_allowed_tools(
            envelope=context.envelope,
            decisions=context.envelope.tool_decisions,
        )
        context.timer.mark("tool_execution")

        if any(record.allowed for record in context.envelope.tool_execution_records):
            context.services.session_manager.record_tool_request(context.session_state.session_id)

        context.envelope.prompt_package = context.services.prompt_builder.build(context.envelope)
        context.timer.mark("prompt_build")

        if context.envelope.prompt_package.token_budget_exceeded:
            logging.getLogger("main").warning(
                "prompt_token_budget_exceeded trace_id=%s estimate=%d limit_chars=%d",
                context.trace_id,
                context.envelope.prompt_package.token_estimate,
                context.services.settings.max_prompt_chars,
            )
            enforce_budget = context.services.settings.enforce_token_budget or bool(
                context.envelope.policy_decision and context.envelope.policy_decision.enforce_token_budget
            )
            if enforce_budget:
                if context.services.settings.token_budget_mode == "truncate":
                    context.envelope.prompt_package = context.services.prompt_builder.truncate_to_budget(
                        context.envelope.prompt_package,
                        context.services.settings.max_prompt_chars,
                    )
                else:
                    handler = PromptBudgetExceededHandler()
                    handler.create_exception(
                        ErrorHandlerContext(
                            trace_id=context.trace_id,
                            session_id=context.session_state.session_id,
                            reason_codes=["PROMPT_TOKEN_BUDGET_EXCEEDED"],
                        )
                    )


class UpstreamAndOutputStep(PipelineStep):
    async def handle(self, context: PipelineContext) -> None:
        assert context.envelope is not None
        assert context.session_state is not None

        context.upstream_response = await context.forward_fn(
            payload=context.envelope.model_dump(),
            trace_id=context.trace_id,
            auth_header=context.authorization,
        )
        context.timer.mark("forward_upstream")

        context.output_text = (
            context.upstream_response.get("answer")
            or context.upstream_response.get("message")
            or context.upstream_response.get("output_text")
            or str(context.upstream_response)
        )

        context.envelope.llm_output_guard = await context.services.llm_guard.analyze_output(context.output_text)
        context.timer.mark("llm_output_guard")

        context.envelope.output_guard = context.services.output_guard.inspect(context.envelope, context.upstream_response)
        context.timer.mark("output_guard")

        context.services.audit_bus.emit_for_envelope(context.envelope)

        if context.envelope.output_guard.action == "block":
            context.services.decision_logger.log(context.envelope, context.timer.snapshot(), {"status": "blocked_output"})
            handler = OutputBlockedHandler()
            handler.create_exception(
                ErrorHandlerContext(
                    trace_id=context.trace_id,
                    session_id=context.session_state.session_id,
                    reason_codes=context.envelope.output_guard.reason_codes,
                )
            )

        context.client_response = dict(context.upstream_response)
        if context.envelope.output_guard.action == "redact":
            redact_handler = OutputRedactHandler()
            redact_handler.apply_redaction(
                client_response=context.client_response,
                redacted_text=context.envelope.output_guard.redacted_text,
            )

        context.services.decision_logger.log(
            envelope=context.envelope,
            timings_ms=context.timer.snapshot(),
            outcome={"status": "ok", "output_action": context.envelope.output_guard.action},
        )

        context.response = ChatResponse(
            trace_id=context.trace_id,
            status="ok",
            response={
                "policy_action": context.envelope.policy_decision.action,
                "policy": context.envelope.policy_decision.model_dump(),
                "llm_input_guard": context.envelope.llm_input_guard.model_dump() if context.envelope.llm_input_guard else None,
                "classification": context.envelope.content_classification.model_dump() if context.envelope.content_classification else None,
                "dlp_scan": context.envelope.dlp_scan.model_dump() if context.envelope.dlp_scan else None,
                "retrieval_result": context.envelope.retrieval_result.model_dump() if context.envelope.retrieval_result else None,
                "tool_decisions": [decision.model_dump() for decision in context.envelope.tool_decisions],
                "tool_execution_records": [record.model_dump() for record in context.envelope.tool_execution_records],
                "prompt_package": context.envelope.prompt_package.model_dump() if context.envelope.prompt_package else None,
                "llm_output_guard": context.envelope.llm_output_guard.model_dump() if context.envelope.llm_output_guard else None,
                "output_guard": context.envelope.output_guard.model_dump() if context.envelope.output_guard else None,
                "upstream_response": context.client_response,
            },
        )
