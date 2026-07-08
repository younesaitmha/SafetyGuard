"""
Type protocols for SafetyGuard services.

This module defines Protocol interfaces for all services used in the chat pipeline,
enabling proper type checking and IDE support across the codebase.
"""

from typing import Any, Dict, List, Literal, Optional, Protocol

from app.models import (
    CanonicalRequestEnvelope,
    ContentClassification,
    DLPScanResult,
    InputScanResult,
    LLMGuardAnalysis,
    PolicyDecision,
    PromptPackage,
    RetrievalResult,
    SessionRiskAssessment,
    SessionState,
    ToolDecision,
    ToolExecutionRecord,
)


class RateLimiter(Protocol):
    """Rate limiter service protocol."""

    def allow(
        self,
        key: str,
        severity_score: int = 0,
        injection_attempt_count: int = 0,
        profile_multiplier: float = 1.0,
    ) -> tuple[bool, str]:
        """
        Check if a request is allowed under rate limits.

        Returns:
            Tuple of (allowed: bool, reason: str)
        """
        ...


class SessionManager(Protocol):
    """Session management service protocol."""

    def get_or_create_session(
        self,
        session_id: Optional[str],
        subject: str,
        tenant_id: Optional[str],
    ) -> SessionState:
        """Get or create a session."""
        ...

    def update_from_request(
        self,
        session_state: SessionState,
        envelope: CanonicalRequestEnvelope,
    ) -> None:
        """Update session state from request envelope."""
        ...

    def get_injection_attempt_count(self, session_id: str) -> int:
        """Get the number of injection attempts for a session."""
        ...

    def append_risk_score(
        self,
        session_id: str,
        score: int,
        state_name: str,
    ) -> None:
        """Append a risk score to session history."""
        ...

    def record_refusal(self, session_id: str) -> None:
        """Record a refusal event."""
        ...

    def record_injection_attempt(
        self,
        session_id: str,
        deterministic_score: int = 0,
    ) -> None:
        """Record an injection attempt."""
        ...

    def record_tool_request(self, session_id: str) -> None:
        """Record a tool request."""
        ...


class RiskEngine(Protocol):
    """Risk assessment service protocol."""

    def assess(
        self,
        envelope: CanonicalRequestEnvelope,
        session_state: SessionState,
    ) -> SessionRiskAssessment:
        """Assess session risk."""
        ...


class InputScanner(Protocol):
    """Input scanning service protocol."""

    def scan(self, envelope: CanonicalRequestEnvelope) -> InputScanResult:
        """Scan request input for threats."""
        ...


class DLPScanner(Protocol):
    """Data loss prevention scanner protocol."""

    def scan(self, envelope: CanonicalRequestEnvelope) -> DLPScanResult:
        """Scan for sensitive data."""
        ...


class LLMGuard(Protocol):
    """LLM-based analysis service protocol."""

    async def analyze_input(
        self,
        envelope: CanonicalRequestEnvelope,
    ) -> LLMGuardAnalysis:
        """Analyze request input using LLM."""
        ...

    async def analyze_output(self, text: str) -> LLMGuardAnalysis:
        """Analyze response output using LLM."""
        ...


class ContentClassifier(Protocol):
    """Content classification service protocol."""

    def classify(self, envelope: CanonicalRequestEnvelope) -> ContentClassification:
        """Classify request content."""
        ...


class PolicyEngine(Protocol):
    """Policy decision engine protocol."""

    def decide(self, envelope: CanonicalRequestEnvelope) -> PolicyDecision:
        """Make policy decision for request."""
        ...


class RetrievalGateway(Protocol):
    """Retrieval/RAG gateway protocol."""

    async def retrieve(
        self,
        envelope: CanonicalRequestEnvelope,
    ) -> RetrievalResult:
        """Retrieve context for request."""
        ...


class ToolGateway(Protocol):
    """Tool execution gateway protocol."""

    def evaluate_requested_tools(
        self,
        envelope: CanonicalRequestEnvelope,
    ) -> List[ToolDecision]:
        """Evaluate requested tools."""
        ...

    async def execute_allowed_tools(
        self,
        envelope: CanonicalRequestEnvelope,
        decisions: List[ToolDecision],
    ) -> List[ToolExecutionRecord]:
        """Execute allowed tools."""
        ...


class PromptBuilder(Protocol):
    """Prompt building service protocol."""

    def build(self, envelope: CanonicalRequestEnvelope) -> PromptPackage:
        """Build prompt package."""
        ...

    def truncate_to_budget(
        self,
        package: PromptPackage,
        max_chars: int,
    ) -> PromptPackage:
        """Truncate prompt to token budget."""
        ...


class OutputGuard(Protocol):
    """Output inspection and guarding protocol."""

    def inspect(
        self,
        envelope: CanonicalRequestEnvelope,
        upstream_response: Dict[str, Any],
    ) -> DLPScanResult:
        """Inspect output for safety issues."""
        ...


class AttackerProfiler(Protocol):
    """Attacker profiling service protocol."""

    def get_adaptive_rate_limit_multiplier(
        self,
        client_id: str,
        subject: str,
    ) -> float:
        """Get adaptive rate limit multiplier for user profile."""
        ...

    def record_refusal(
        self,
        client_id: str,
        subject: str,
        reason_codes: List[str],
    ) -> None:
        """Record a refusal event for attacker profiling."""
        ...


class AuditBus(Protocol):
    """Audit event bus protocol."""

    def emit_for_envelope(self, envelope: CanonicalRequestEnvelope) -> None:
        """Emit audit events for envelope."""
        ...


class DecisionLogger(Protocol):
    """Decision logging service protocol."""

    def log(
        self,
        envelope: CanonicalRequestEnvelope,
        timings_ms: Dict[str, float],
        outcome: Dict[str, Any],
    ) -> None:
        """Log decision with timing and outcome."""
        ...


class Settings(Protocol):
    """Configuration settings protocol."""

    max_request_bytes: int
    max_prompt_chars: int
    enforce_token_budget: bool
    token_budget_mode: Literal["truncate", "reject"]


class OrchestratorServicesProtocol(Protocol):
    """Protocol for orchestrator services container."""

    rate_limiter: RateLimiter
    session_manager: SessionManager
    risk_engine: RiskEngine
    input_scanner: InputScanner
    dlp_scanner: DLPScanner
    llm_guard: LLMGuard
    content_classifier: ContentClassifier
    policy_engine: PolicyEngine
    retrieval_gateway: RetrievalGateway
    tool_gateway: ToolGateway
    prompt_builder: PromptBuilder
    output_guard: OutputGuard
    attacker_profiler: AttackerProfiler
    audit_bus: AuditBus
    decision_logger: DecisionLogger
    settings: Settings
