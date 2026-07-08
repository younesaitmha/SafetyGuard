"""
Unit tests for pipeline steps with isolated mocked services.

Tests each pipeline step in isolation to verify correct behavior and error handling.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, Mock
from fastapi import HTTPException, Request

from app.chat_pipeline import (
    PreflightAndNormalizeStep,
    SessionPolicyStep,
    RetrievalAndPromptStep,
    UpstreamAndOutputStep,
    PipelineContext,
)
from app.models import (
    ChatRequest,
    ChatMessage,
    SecurityContext,
    SessionState,
    InputScanResult,
    DLPScanResult,
    LLMGuardAnalysis,
    ContentClassification,
    PolicyDecision,
    SessionRiskAssessment,
    RetrievalResult,
    PromptPackage,
    PromptSection,
    ToolDecision,
    ToolExecutionRecord,
    OutputGuardResult,
    CanonicalRequestEnvelope,
    ChatResponse,
    NormalizedMessage,
)
from app.observability import RequestTimer


@pytest.fixture
def mock_request():
    """Create a mock HTTP request."""
    request = MagicMock(spec=Request)
    request.headers.get.side_effect = lambda key: {
        "content-length": "100",
        "user-agent": "test-client",
    }.get(key)
    return request


@pytest.fixture
def mock_security_context():
    """Create a mock security context."""
    return SecurityContext(
        subject="test-user",
        user_id="user-123",
        tenant_id="tenant-456",
        roles=["user"],
        permissions=["read"],
        auth_level="standard",
        issuer="https://auth.example.com",
        audience="api.example.com",
    )


@pytest.fixture
def mock_services():
    """Create a mock services container."""
    services = MagicMock()
    services.settings = MagicMock()
    services.settings.max_request_bytes = 1000000
    services.settings.max_prompt_chars = 5000
    services.settings.enforce_token_budget = False
    services.settings.token_budget_mode = "reject"
    return services


@pytest.fixture
def chat_request():
    """Create a test chat request."""
    return ChatRequest(
        session_id="session-789",
        user_id="user-123",
        messages=[
            ChatMessage(role="user", content="Hello"),
        ],
    )


@pytest.fixture
async def pipeline_context(mock_request, chat_request, mock_security_context, mock_services):
    """Create a test pipeline context."""
    forward_fn = AsyncMock(return_value={"answer": "test response"})
    return PipelineContext(
        request=mock_request,
        body=chat_request,
        authorization="Bearer test-token",
        security_context=mock_security_context,
        trace_id="trace-123",
        forward_fn=forward_fn,
        services=mock_services,
        timer=RequestTimer(),
    )


class TestPreflightAndNormalizeStep:
    """Tests for PreflightAndNormalizeStep."""

    @pytest.mark.asyncio
    async def test_preflight_success(self, mock_request, chat_request, mock_security_context, mock_services):
        """Test successful preflight and normalization."""
        context = PipelineContext(
            request=mock_request,
            body=chat_request,
            authorization="Bearer test-token",
            security_context=mock_security_context,
            trace_id="trace-123",
            forward_fn=AsyncMock(),
            services=mock_services,
            timer=RequestTimer(),
        )

        step = PreflightAndNormalizeStep()
        await step.handle(context)

        assert context.envelope is not None
        assert context.envelope.trace_id == "trace-123"
        assert context.envelope.user_id == "user-123"
        assert len(context.envelope.messages) == 1
        assert context.client_id is not None
        assert context.rate_limit_key is not None

    @pytest.mark.asyncio
    async def test_preflight_request_too_large(self, chat_request, mock_security_context, mock_services):
        """Test rejection of oversized requests."""
        mock_request = MagicMock(spec=Request)
        mock_request.headers.get.side_effect = lambda key: {
            "content-length": "2000000",  # Exceeds max_request_bytes
            "user-agent": "test-client",
        }.get(key)

        context = PipelineContext(
            request=mock_request,
            body=chat_request,
            authorization="Bearer test-token",
            security_context=mock_security_context,
            trace_id="trace-123",
            forward_fn=AsyncMock(),
            services=mock_services,
            timer=RequestTimer(),
        )

        step = PreflightAndNormalizeStep()
        with pytest.raises(HTTPException) as exc:
            await step.handle(context)
        assert exc.value.status_code == 413


class TestSessionPolicyStep:
    """Tests for SessionPolicyStep."""

    @pytest.mark.asyncio
    async def test_session_policy_allow(self, pipeline_context):
        """Test allowed request through session policy."""
        pipeline_context.envelope = MagicMock(spec=CanonicalRequestEnvelope)
        pipeline_context.envelope.session_id = "session-789"
        pipeline_context.envelope.input_scan = InputScanResult(score=10, labels=[])
        pipeline_context.envelope.dlp_scan = DLPScanResult(score=5, labels=[])

        session_state = SessionState(
            session_id="session-789",
            subject="test-user",
            created_at=0,
            last_seen_at=0,
        )

        pipeline_context.services.session_manager = MagicMock()
        pipeline_context.services.session_manager.get_or_create_session.return_value = session_state
        pipeline_context.services.session_manager.get_injection_attempt_count.return_value = 0

        pipeline_context.services.input_scanner = MagicMock()
        pipeline_context.services.input_scanner.scan.return_value = InputScanResult(score=10, labels=[])

        pipeline_context.services.rate_limiter = MagicMock()
        pipeline_context.services.rate_limiter.allow.return_value = (True, "allowed")

        pipeline_context.services.attacker_profiler = MagicMock()
        pipeline_context.services.attacker_profiler.get_adaptive_rate_limit_multiplier.return_value = 1.0

        pipeline_context.services.risk_engine = MagicMock()
        pipeline_context.services.risk_engine.assess.return_value = SessionRiskAssessment(
            score=10, state="normal"
        )

        pipeline_context.services.dlp_scanner = MagicMock()
        pipeline_context.services.dlp_scanner.scan.return_value = DLPScanResult(score=5, labels=[])

        pipeline_context.services.llm_guard = MagicMock()
        pipeline_context.services.llm_guard.analyze_input = AsyncMock(
            return_value=LLMGuardAnalysis(
                label="benign", confidence=0.95, risk_score=0, recommended_action="allow"
            )
        )

        pipeline_context.services.content_classifier = MagicMock()
        pipeline_context.services.content_classifier.classify.return_value = ContentClassification(
            label="benign", confidence=0.95
        )

        pipeline_context.services.policy_engine = MagicMock()
        pipeline_context.services.policy_engine.decide.return_value = PolicyDecision(
            action="allow", reason_codes=[]
        )

        step = SessionPolicyStep()
        await step.handle(pipeline_context)

        assert pipeline_context.session_state is not None
        assert pipeline_context.session_state.session_id == "session-789"

    @pytest.mark.asyncio
    async def test_session_policy_deny(self, pipeline_context):
        """Test denied request by policy."""
        pipeline_context.envelope = MagicMock(spec=CanonicalRequestEnvelope)
        pipeline_context.envelope.session_id = "session-789"
        pipeline_context.envelope.input_scan = InputScanResult(score=90, labels=["injection"])
        pipeline_context.envelope.policy_decision = PolicyDecision(
            action="deny", reason_codes=["HIGH_RISK_INPUT"]
        )

        session_state = SessionState(
            session_id="session-789",
            subject="test-user",
            created_at=0,
            last_seen_at=0,
        )

        pipeline_context.services.session_manager = MagicMock()
        pipeline_context.services.session_manager.get_or_create_session.return_value = session_state
        pipeline_context.services.session_manager.get_injection_attempt_count.return_value = 0

        pipeline_context.services.input_scanner = MagicMock()
        pipeline_context.services.input_scanner.scan.return_value = InputScanResult(score=90, labels=["injection"])

        pipeline_context.services.rate_limiter = MagicMock()
        pipeline_context.services.rate_limiter.allow.return_value = (True, "allowed")

        pipeline_context.services.attacker_profiler = MagicMock()
        pipeline_context.services.attacker_profiler.get_adaptive_rate_limit_multiplier.return_value = 1.0

        pipeline_context.services.risk_engine = MagicMock()
        pipeline_context.services.risk_engine.assess.return_value = SessionRiskAssessment(
            score=50, state="elevated"
        )

        pipeline_context.services.dlp_scanner = MagicMock()
        pipeline_context.services.dlp_scanner.scan.return_value = DLPScanResult(score=5, labels=[])

        pipeline_context.services.llm_guard = MagicMock()
        pipeline_context.services.llm_guard.analyze_input = AsyncMock(
            return_value=LLMGuardAnalysis(
                label="jailbreak_attempt", confidence=0.92, risk_score=85, recommended_action="deny"
            )
        )

        pipeline_context.services.content_classifier = MagicMock()
        pipeline_context.services.content_classifier.classify.return_value = ContentClassification(
            label="jailbreak_attempt", confidence=0.92
        )

        pipeline_context.services.policy_engine = MagicMock()
        pipeline_context.services.policy_engine.decide.return_value = PolicyDecision(
            action="deny", reason_codes=["HIGH_RISK_INPUT"]
        )

        pipeline_context.services.audit_bus = MagicMock()
        pipeline_context.services.decision_logger = MagicMock()

        step = SessionPolicyStep()
        with pytest.raises(HTTPException) as exc:
            await step.handle(pipeline_context)
        assert exc.value.status_code == 403

    @pytest.mark.asyncio
    async def test_session_policy_rate_limit(self, pipeline_context):
        """Test rate limit exceeded."""
        pipeline_context.envelope = MagicMock(spec=CanonicalRequestEnvelope)
        pipeline_context.envelope.session_id = "session-789"
        pipeline_context.envelope.input_scan = InputScanResult(score=50, labels=[])

        session_state = SessionState(
            session_id="session-789",
            subject="test-user",
            created_at=0,
            last_seen_at=0,
        )

        pipeline_context.services.session_manager = MagicMock()
        pipeline_context.services.session_manager.get_or_create_session.return_value = session_state
        pipeline_context.services.session_manager.get_injection_attempt_count.return_value = 10

        pipeline_context.services.input_scanner = MagicMock()
        pipeline_context.services.input_scanner.scan.return_value = InputScanResult(score=50, labels=[])

        pipeline_context.services.rate_limiter = MagicMock()
        pipeline_context.services.rate_limiter.allow.return_value = (False, "quota exceeded")

        pipeline_context.services.attacker_profiler = MagicMock()
        pipeline_context.services.attacker_profiler.get_adaptive_rate_limit_multiplier.return_value = 2.0

        step = SessionPolicyStep()
        with pytest.raises(HTTPException) as exc:
            await step.handle(pipeline_context)
        assert exc.value.status_code == 429


class TestRetrievalAndPromptStep:
    """Tests for RetrievalAndPromptStep."""

    @pytest.mark.asyncio
    async def test_retrieval_and_prompt_success(self, pipeline_context):
        """Test successful retrieval and prompt building."""
        pipeline_context.envelope = MagicMock(spec=CanonicalRequestEnvelope)
        pipeline_context.session_state = SessionState(
            session_id="session-789",
            subject="test-user",
            created_at=0,
            last_seen_at=0,
        )
        pipeline_context.envelope.policy_decision = PolicyDecision(action="allow", reason_codes=[])

        pipeline_context.services.retrieval_gateway = MagicMock()
        pipeline_context.services.retrieval_gateway.retrieve = AsyncMock(
            return_value=RetrievalResult(query="test", chunks=[])
        )

        pipeline_context.services.tool_gateway = MagicMock()
        pipeline_context.services.tool_gateway.evaluate_requested_tools.return_value = []
        pipeline_context.services.tool_gateway.execute_allowed_tools = AsyncMock(return_value=[])

        pipeline_context.services.prompt_builder = MagicMock()
        pipeline_context.services.prompt_builder.build.return_value = PromptPackage(
            mode="normal",
            prompt_text="test prompt",
            token_estimate=100,
            token_budget_exceeded=False,
        )

        step = RetrievalAndPromptStep()
        await step.handle(pipeline_context)

        assert pipeline_context.envelope.retrieval_result is not None
        assert pipeline_context.envelope.prompt_package is not None
        assert not pipeline_context.envelope.prompt_package.token_budget_exceeded

    @pytest.mark.asyncio
    async def test_retrieval_and_prompt_token_budget_exceeded(self, pipeline_context):
        """Test token budget exceeded."""
        pipeline_context.envelope = MagicMock(spec=CanonicalRequestEnvelope)
        pipeline_context.session_state = SessionState(
            session_id="session-789",
            subject="test-user",
            created_at=0,
            last_seen_at=0,
        )
        pipeline_context.envelope.policy_decision = PolicyDecision(
            action="allow", reason_codes=[], enforce_token_budget=True
        )

        pipeline_context.services.settings.enforce_token_budget = True
        pipeline_context.services.settings.token_budget_mode = "reject"

        pipeline_context.services.retrieval_gateway = MagicMock()
        pipeline_context.services.retrieval_gateway.retrieve = AsyncMock(
            return_value=RetrievalResult(query="test", chunks=[])
        )

        pipeline_context.services.tool_gateway = MagicMock()
        pipeline_context.services.tool_gateway.evaluate_requested_tools.return_value = []
        pipeline_context.services.tool_gateway.execute_allowed_tools = AsyncMock(return_value=[])

        pipeline_context.services.prompt_builder = MagicMock()
        pipeline_context.services.prompt_builder.build.return_value = PromptPackage(
            mode="normal",
            prompt_text="x" * 10000,
            token_estimate=10000,
            token_budget_exceeded=True,
        )

        step = RetrievalAndPromptStep()
        with pytest.raises(HTTPException) as exc:
            await step.handle(pipeline_context)
        assert exc.value.status_code == 413


class TestUpstreamAndOutputStep:
    """Tests for UpstreamAndOutputStep."""

    @pytest.mark.asyncio
    async def test_upstream_and_output_success(self, pipeline_context):
        """Test successful upstream call and output inspection."""
        pipeline_context.envelope = MagicMock(spec=CanonicalRequestEnvelope)
        pipeline_context.session_state = SessionState(
            session_id="session-789",
            subject="test-user",
            created_at=0,
            last_seen_at=0,
        )
        pipeline_context.envelope.policy_decision = PolicyDecision(action="allow", reason_codes=[])
        pipeline_context.envelope.llm_input_guard = LLMGuardAnalysis(
            label="benign", confidence=0.98, risk_score=0, recommended_action="allow"
        )
        pipeline_context.envelope.content_classification = ContentClassification(
            label="benign", confidence=0.98
        )
        pipeline_context.envelope.dlp_scan = DLPScanResult(score=0, labels=[])
        pipeline_context.envelope.retrieval_result = RetrievalResult(query="test", chunks=[])
        pipeline_context.envelope.tool_decisions = []
        pipeline_context.envelope.tool_execution_records = []
        pipeline_context.envelope.prompt_package = PromptPackage(
            mode="normal", prompt_text="test", token_estimate=10
        )
        pipeline_context.upstream_response = {"answer": "test response"}

        pipeline_context.services.llm_guard = MagicMock()
        pipeline_context.services.llm_guard.analyze_output = AsyncMock(
            return_value=LLMGuardAnalysis(
                label="benign", confidence=0.98, risk_score=0, recommended_action="allow"
            )
        )

        pipeline_context.services.output_guard = MagicMock()
        pipeline_context.services.output_guard.inspect.return_value = OutputGuardResult(
            action="allow", reason_codes=[]
        )

        pipeline_context.services.audit_bus = MagicMock()
        pipeline_context.services.decision_logger = MagicMock()

        step = UpstreamAndOutputStep()
        await step.handle(pipeline_context)

        assert pipeline_context.response is not None
        assert isinstance(pipeline_context.response, ChatResponse)
        assert pipeline_context.response.status == "ok"

    @pytest.mark.asyncio
    async def test_upstream_and_output_blocked(self, pipeline_context):
        """Test blocked output by output guard."""
        pipeline_context.envelope = MagicMock(spec=CanonicalRequestEnvelope)
        pipeline_context.session_state = SessionState(
            session_id="session-789",
            subject="test-user",
            created_at=0,
            last_seen_at=0,
        )
        pipeline_context.envelope.policy_decision = PolicyDecision(action="allow", reason_codes=[])
        pipeline_context.upstream_response = {"answer": "malicious response"}

        pipeline_context.services.llm_guard = MagicMock()
        pipeline_context.services.llm_guard.analyze_output = AsyncMock(
            return_value=LLMGuardAnalysis(
                label="unsafe_output", confidence=0.95, risk_score=90, recommended_action="block"
            )
        )

        pipeline_context.services.output_guard = MagicMock()
        pipeline_context.services.output_guard.inspect.return_value = OutputGuardResult(
            action="block", reason_codes=["UNSAFE_OUTPUT"]
        )

        pipeline_context.services.audit_bus = MagicMock()
        pipeline_context.services.decision_logger = MagicMock()

        step = UpstreamAndOutputStep()
        with pytest.raises(HTTPException) as exc:
            await step.handle(pipeline_context)
        assert exc.value.status_code == 502

    @pytest.mark.asyncio
    async def test_upstream_and_output_redacted(self, pipeline_context):
        """Test redacted output by output guard."""
        pipeline_context.envelope = MagicMock(spec=CanonicalRequestEnvelope)
        pipeline_context.session_state = SessionState(
            session_id="session-789",
            subject="test-user",
            created_at=0,
            last_seen_at=0,
        )
        pipeline_context.envelope.policy_decision = PolicyDecision(action="allow", reason_codes=[])
        pipeline_context.envelope.llm_input_guard = LLMGuardAnalysis(
            label="benign", confidence=0.98, risk_score=0, recommended_action="allow"
        )
        pipeline_context.envelope.content_classification = ContentClassification(
            label="benign", confidence=0.98
        )
        pipeline_context.envelope.dlp_scan = DLPScanResult(score=0, labels=[])
        pipeline_context.envelope.retrieval_result = RetrievalResult(query="test", chunks=[])
        pipeline_context.envelope.tool_decisions = []
        pipeline_context.envelope.tool_execution_records = []
        pipeline_context.envelope.prompt_package = PromptPackage(
            mode="normal", prompt_text="test", token_estimate=10
        )
        pipeline_context.upstream_response = {"answer": "response with sensitive data"}

        pipeline_context.services.llm_guard = MagicMock()
        pipeline_context.services.llm_guard.analyze_output = AsyncMock(
            return_value=LLMGuardAnalysis(
                label="benign", confidence=0.90, risk_score=10, recommended_action="allow"
            )
        )

        pipeline_context.services.output_guard = MagicMock()
        pipeline_context.services.output_guard.inspect.return_value = OutputGuardResult(
            action="redact",
            reason_codes=["SENSITIVE_DATA"],
            redacted_text="[REDACTED]",
        )

        pipeline_context.services.audit_bus = MagicMock()
        pipeline_context.services.decision_logger = MagicMock()

        step = UpstreamAndOutputStep()
        await step.handle(pipeline_context)

        assert pipeline_context.response is not None
        assert pipeline_context.client_response["answer"] == "[REDACTED]"
