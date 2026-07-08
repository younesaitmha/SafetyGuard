from typing import Any, Dict, List, Literal, Optional
import time

from pydantic import BaseModel, Field


class ChatMessage(BaseModel):
    role: Literal["system", "user", "assistant", "developer"] = "user"
    content: str = Field(..., min_length=1, max_length=20000)


class Attachment(BaseModel):
    name: str
    content_type: Optional[str] = None
    size_bytes: Optional[int] = None
    uri: Optional[str] = None
    source: str = "user"
    content: Optional[str] = None  # Text content for DLP scanning


class ChatRequest(BaseModel):
    session_id: Optional[str] = None
    user_id: Optional[str] = None
    messages: List[ChatMessage]
    attachments: List[Attachment] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SecurityContext(BaseModel):
    subject: str
    user_id: str
    tenant_id: Optional[str] = None
    roles: List[str] = Field(default_factory=list)
    permissions: List[str] = Field(default_factory=list)
    auth_level: str = "standard"
    step_up_authenticated: bool = False
    issuer: str
    audience: str | List[str]
    claims: Dict[str, Any] = Field(default_factory=dict)


class NormalizedMessage(BaseModel):
    role: Literal["system", "user", "assistant", "developer"]
    content: str
    source_label: Literal["trusted", "semi_trusted", "untrusted"]
    content_length: int
    has_control_chars: bool = False
    encoding_hints: List[str] = Field(default_factory=list)


class NormalizedAttachment(BaseModel):
    name: str
    content_type: Optional[str] = None
    size_bytes: Optional[int] = None
    uri: Optional[str] = None
    source_label: Literal["trusted", "semi_trusted", "untrusted"]
    source: str = "user"
    content: Optional[str] = None  # Text content for DLP scanning


class SessionState(BaseModel):
    session_id: str
    subject: str
    tenant_id: Optional[str] = None
    created_at: float
    last_seen_at: float
    request_count: int = 0
    total_message_count: int = 0
    total_attachment_count: int = 0
    refusal_count: int = 0
    suspicious_attempt_count: int = 0
    tool_request_count: int = 0
    injection_attempt_count: int = 0  # NEW: cumulative jailbreak/injection attempts
    escalation_pattern_count: int = 0  # NEW: attempts to escalate privileges/bypass
    risk_history: List[int] = Field(default_factory=list)
    state: Literal["normal", "elevated", "restricted", "blocked"] = "normal"


class SessionRiskAssessment(BaseModel):
    score: int
    state: Literal["normal", "elevated", "restricted", "blocked"]
    reasons: List[str] = Field(default_factory=list)
    features: Dict[str, Any] = Field(default_factory=dict)


class InputScanSignal(BaseModel):
    category: str
    severity: Literal["low", "medium", "high", "critical"]
    message_index: Optional[int] = None
    pattern: Optional[str] = None
    evidence: Optional[str] = None


class InputScanResult(BaseModel):
    score: int
    labels: List[str] = Field(default_factory=list)
    signals: List[InputScanSignal] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)


class DLPMatch(BaseModel):
    category: str
    severity: Literal["low", "medium", "high", "critical"]
    message_index: Optional[int] = None
    pattern_name: str
    evidence_preview: str


class DLPScanResult(BaseModel):
    score: int
    labels: List[str] = Field(default_factory=list)
    matches: List[DLPMatch] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)


class LLMGuardAnalysis(BaseModel):
    label: Literal[
        "benign",
        "suspicious",
        "prompt_injection",
        "jailbreak_attempt",
        "secret_exfiltration_intent",
        "exploit_or_malware_intent",
        "sensitive_data_submission",
        "policy_leakage",
        "unsafe_output",
        # Extended labels (OWASP LLM Top 10 coverage)
        "indirect_injection",
        "encoding_obfuscation",
        "escalation_attempt",
        "denial_of_service_attempt",
        "tool_abuse_attempt",
        "model_theft_probe",
    ]
    confidence: float = Field(ge=0.0, le=1.0)
    risk_score: int = Field(ge=0, le=100)
    reasons: List[str] = Field(default_factory=list)
    recommended_action: Literal["allow", "allow_with_restrictions", "deny", "redact", "block"] = "allow"
    raw_response: Dict[str, Any] = Field(default_factory=dict)
    # Extended fields returned by the enhanced prompts
    owasp_categories: List[str] = Field(default_factory=list)
    attack_techniques: List[str] = Field(default_factory=list)
    sensitive_patterns: List[str] = Field(default_factory=list)


class ContentClassification(BaseModel):
    label: Literal[
        "benign",
        "suspicious",
        "prompt_injection",
        "jailbreak_attempt",
        "secret_exfiltration_intent",
        "exploit_or_malware_intent",
        "sensitive_data_submission",
    ]
    confidence: float = Field(ge=0.0, le=1.0)
    reasons: List[str] = Field(default_factory=list)
    features: Dict[str, Any] = Field(default_factory=dict)


class PolicyDecision(BaseModel):
    action: Literal["allow", "allow_with_restrictions", "deny", "challenge"]
    reason_codes: List[str] = Field(default_factory=list)
    disable_tools: bool = False
    allow_retrieval: bool = True
    max_context_sensitivity: Literal["public", "internal", "confidential", "restricted"] = "internal"
    require_human_approval: bool = False
    response_mode: Literal["normal", "guarded", "restricted"] = "normal"
    enforce_token_budget: bool = False  # NEW: block if token_budget_exceeded


class PolicyRule(BaseModel):
    name: str
    enabled: bool = True
    condition: Dict[str, Any]
    decision: PolicyDecision


class PolicyBundle(BaseModel):
    version: str
    rules: List[PolicyRule] = Field(default_factory=list)
    default_decision: PolicyDecision


class RetrievalChunk(BaseModel):
    chunk_id: str
    document_id: str
    text: str
    score: float
    source_uri: Optional[str] = None
    tenant_id: Optional[str] = None
    sensitivity: Literal["public", "internal", "confidential", "restricted"] = "internal"
    trust_level: Literal["semi_trusted", "untrusted"] = "semi_trusted"
    content_hash: Optional[str] = None  # NEW: SHA256 hash for integrity validation
    source_signature: Optional[str] = None  # NEW: HMAC signature from retrieval backend
    last_modified: Optional[float] = None  # NEW: timestamp for freshness check
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RetrievalResult(BaseModel):
    query: str
    chunks: List[RetrievalChunk] = Field(default_factory=list)
    filtered_out_count: int = 0
    injection_filtered_count: int = 0
    integrity_filtered_count: int = 0
    allowed_count: int = 0
    dlp_scan: Optional[DLPScanResult] = None


class ToolDefinition(BaseModel):
    name: str
    description: str
    required_permission: str
    sensitivity: Literal["public", "internal", "confidential", "restricted"] = "internal"
    enabled: bool = True


class ToolDecision(BaseModel):
    tool_name: str
    allowed: bool
    reason_codes: List[str] = Field(default_factory=list)
    sanitized_arguments: Dict[str, Any] = Field(default_factory=dict)


class ToolExecutionRecord(BaseModel):
    tool_name: str
    allowed: bool
    reason_codes: List[str] = Field(default_factory=list)
    arguments: Dict[str, Any] = Field(default_factory=dict)


class OutputGuardResult(BaseModel):
    action: Literal["allow", "redact", "block"]
    reason_codes: List[str] = Field(default_factory=list)
    redacted_text: Optional[str] = None
    dlp_scan: Optional[DLPScanResult] = None
    leakage_signals: List[str] = Field(default_factory=list)


class AuditEvent(BaseModel):
    event_type: str
    trace_id: str
    session_id: Optional[str] = None
    subject: Optional[str] = None
    tenant_id: Optional[str] = None
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    timestamp: float = Field(default_factory=lambda: time.time())
    details: Dict[str, Any] = Field(default_factory=dict)


class DecisionLogRecord(BaseModel):
    trace_id: str
    session_id: Optional[str] = None
    subject: Optional[str] = None
    tenant_id: Optional[str] = None
    timestamp: float = Field(default_factory=lambda: time.time())
    request_summary: Dict[str, Any] = Field(default_factory=dict)
    decisions: Dict[str, Any] = Field(default_factory=dict)
    timings_ms: Dict[str, float] = Field(default_factory=dict)
    outcome: Dict[str, Any] = Field(default_factory=dict)


class PromptSection(BaseModel):
    name: str
    trust_level: Literal["trusted", "semi_trusted", "untrusted"]
    content: str


class PromptPackage(BaseModel):
    mode: Literal["normal", "guarded", "restricted"]
    sections: List[PromptSection] = Field(default_factory=list)
    prompt_text: str
    token_estimate: int = 0
    token_budget_exceeded: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CanonicalRequestEnvelope(BaseModel):
    trace_id: str
    session_id: Optional[str] = None
    user_id: str
    tenant_id: Optional[str] = None
    source: Dict[str, Any] = Field(default_factory=dict)
    messages: List[NormalizedMessage]
    attachments: List[NormalizedAttachment] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    security_context: SecurityContext
    request_facts: Dict[str, Any] = Field(default_factory=dict)
    session_state: Optional[SessionState] = None
    session_risk: Optional[SessionRiskAssessment] = None
    input_scan: Optional[InputScanResult] = None
    dlp_scan: Optional[DLPScanResult] = None
    llm_input_guard: Optional[LLMGuardAnalysis] = None
    content_classification: Optional[ContentClassification] = None
    policy_decision: Optional[PolicyDecision] = None
    retrieval_result: Optional[RetrievalResult] = None
    tool_decisions: List[ToolDecision] = Field(default_factory=list)
    tool_execution_records: List[ToolExecutionRecord] = Field(default_factory=list)
    prompt_package: Optional[PromptPackage] = None
    llm_output_guard: Optional[LLMGuardAnalysis] = None
    output_guard: Optional[OutputGuardResult] = None


class ChatResponse(BaseModel):
    trace_id: str
    status: str
    response: Dict[str, Any]
