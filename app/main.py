import json
import time
import uuid
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, Header, status
from fastapi.security import APIKeyHeader
from fastapi.responses import StreamingResponse

from .audit_bus import AuditBus
from .attacker_profiler import AttackerProfiler
from .chat_orchestrator import ChatOrchestrator, OrchestratorServices
from .config import settings
from .content_classifier import ContentClassifier
from .dlp_scanner import DLPScanner
from .forwarder import forward_to_security_gateway
from .identity import build_security_context
from .input_scanner import InputSecurityScanner
from .llm_guard import OpenSourceLLMGuard
from .middleware import TraceIDMiddleware
from .models import ChatRequest, ChatResponse
from .observability import DecisionLogger
from .output_guard import OutputGuard
from .policy_engine import PolicyEngine
from .prompt_builder import PromptBuilder
from .rate_limit import InMemoryRateLimiter
from .retrieval_gateway import RetrievalGateway
from .risk_engine import SessionRiskEngine
from .session_manager import InMemorySessionManager
from .tool_gateway import ToolGateway

app = FastAPI(title=settings.app_name)
app.add_middleware(TraceIDMiddleware)

rate_limiter = InMemoryRateLimiter(
    max_requests=settings.rate_limit_requests,
    window_seconds=settings.rate_limit_window_seconds,
)

session_manager = InMemorySessionManager()
risk_engine = SessionRiskEngine()
input_scanner = InputSecurityScanner()
dlp_scanner = DLPScanner()
llm_guard = OpenSourceLLMGuard()
content_classifier = ContentClassifier()
policy_engine = PolicyEngine()
retrieval_gateway = RetrievalGateway()
tool_gateway = ToolGateway()
prompt_builder = PromptBuilder()
output_guard = OutputGuard()
attacker_profiler = AttackerProfiler()
audit_bus = AuditBus()
decision_logger = DecisionLogger()
chat_orchestrator = ChatOrchestrator(
    OrchestratorServices(
        rate_limiter=rate_limiter,
        session_manager=session_manager,
        risk_engine=risk_engine,
        input_scanner=input_scanner,
        dlp_scanner=dlp_scanner,
        llm_guard=llm_guard,
        content_classifier=content_classifier,
        policy_engine=policy_engine,
        retrieval_gateway=retrieval_gateway,
        tool_gateway=tool_gateway,
        prompt_builder=prompt_builder,
        output_guard=output_guard,
        attacker_profiler=attacker_profiler,
        audit_bus=audit_bus,
        decision_logger=decision_logger,
        settings=settings,
    )
)

_admin_key_header = APIKeyHeader(name="X-Admin-Key", auto_error=False)


def _is_local_request(request: Request) -> bool:
    host = request.client.host if request.client else None
    return host in {"127.0.0.1", "::1", "localhost"}


async def _require_admin(
    request: Request,
    key: str | None = Depends(_admin_key_header),
) -> None:
    """Dependency that rejects requests without a valid admin API key."""
    expected = (settings.admin_api_key or "").strip()

    # Optional local-development fallback (must be explicitly enabled).
    if (
        settings.admin_allow_localhost_fallback
        and expected == "change-me-replace-in-production"
        and _is_local_request(request)
    ):
        return

    if not expected or key != expected:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access denied: provide valid X-Admin-Key (APP_ADMIN_API_KEY)",
        )


@app.get("/health")
async def health():
    return {"status": "ok", "service": settings.app_name}


@app.get("/ready")
async def ready():
    return {"status": "ready"}


@app.get("/admin/audit/events", dependencies=[Depends(_require_admin)])
async def get_audit_events(limit: int = 100, offset: int = 0):
    # NEW: Enforce parameter limits to prevent abuse
    limit = min(max(1, limit), 10000)  # Clamp between 1 and 10,000
    offset = max(0, offset)

    events = audit_bus.recent_events(limit=limit + offset)
    return {"events": [e.model_dump() for e in events[offset:offset+limit]]}


@app.post("/admin/policies/reload", dependencies=[Depends(_require_admin)])
async def reload_policies():
    policy_engine.reload()
    return {"status": "reloaded", "version": policy_engine.policy_service.bundle.version}


@app.post("/v1/chat", response_model=ChatResponse)
async def chat(
    request: Request,
    body: ChatRequest,
    authorization: str | None = Header(default=None),
):
    trace_id = request.state.trace_id
    security_context = await build_security_context(authorization)
    return await chat_orchestrator.execute(
        request=request,
        body=body,
        authorization=authorization,
        security_context=security_context,
        trace_id=trace_id,
        forward_fn=forward_to_security_gateway,
    )


_REASON_LABELS: dict[str, str] = {
    # Policy / injection
    "prompt_injection": "injection de prompt détectée",
    "jailbreak_attempt": "tentative de contournement (jailbreak)",
    "moderation_bypass": "tentative de contournement des modérations",
    # Content
    "hate_content": "contenu haineux",
    "discriminatory_content": "contenu discriminatoire",
    "insult_content": "contenu insultant",
    "obfuscation": "obfuscation / encodage suspect",
    # Data
    "secret_exfiltration": "tentative d'exfiltration de secrets",
    "pii_detected": "données personnelles (PII) détectées",
    "sensitive_data": "données sensibles détectées",
    # Session
    "session_risk_high": "session à risque élevé",
    "repeated_violations": "violations répétées en session",
    # Rate limit
    "RATE_LIMIT_EXCEEDED": "limite de requêtes dépassée",
    # Output
    "output_blocked": "réponse LLM bloquée par le filtre de sortie",
    # Misc
    "PROMPT_TOKEN_BUDGET_EXCEEDED": "budget de tokens dépassé",
}


def _format_block_reason(exc: HTTPException) -> str:
    """Build a human-readable assistant message from a blocked-request HTTPException."""
    detail = exc.detail or {}
    if isinstance(detail, dict):
        # Nested safetyguard_error wrapper
        inner = detail.get("details") or detail
        raw_codes: list[str] = inner.get("reason_codes") or []
        policy_action: str = inner.get("policy_action") or inner.get("action") or ""
        message: str = inner.get("message") or ""
    else:
        raw_codes = []
        policy_action = ""
        message = str(detail)

    human_reasons = [
        _REASON_LABELS.get(code, code.replace("_", " ").lower())
        for code in raw_codes
    ]

    if exc.status_code == 429:
        return (
            "⚠️ **Requête limitée** : vous avez dépassé le quota de requêtes. "
            "Veuillez patienter quelques secondes avant de réessayer."
        )

    if exc.status_code == 413:
        return (
            "⚠️ **Requête trop longue** : votre message dépasse le budget de tokens autorisé. "
            "Veuillez raccourcir votre message."
        )

    action_label = {
        "deny": "bloquée",
        "challenge": "mise en attente (authentification supplémentaire requise)",
    }.get(policy_action, "bloquée")

    parts = [f"🚫 **Requête {action_label} par SafetyGuard.**"]

    if human_reasons:
        reasons_str = "\n".join(f"- {r}" for r in human_reasons)
        parts.append(f"\n**Raisons détectées :**\n{reasons_str}")
    elif message:
        parts.append(f"\n**Raison :** {message}")

    parts.append(
        "\n\nSi vous pensez qu'il s'agit d'une erreur, contactez votre administrateur "
        f"en mentionnant l'identifiant de trace."
    )
    return "\n".join(parts)


def _coerce_openai_content(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if not isinstance(item, dict):
                continue
            item_type = str(item.get("type", "")).lower()
            if item_type in {"text", "input_text"}:
                text = item.get("text")
                if isinstance(text, str):
                    parts.append(text)
        return "\n".join(parts).strip()
    return str(content) if content is not None else ""


def _extract_assistant_text(chat_response: ChatResponse) -> str:
    upstream = chat_response.response.get("upstream_response", {})
    if isinstance(upstream, dict):
        for key in ("answer", "message", "output_text"):
            value = upstream.get(key)
            if isinstance(value, str) and value.strip():
                return value
    output_guard_payload = chat_response.response.get("output_guard", {})
    if isinstance(output_guard_payload, dict):
        redacted_text = output_guard_payload.get("redacted_text")
        if isinstance(redacted_text, str) and redacted_text.strip():
            return redacted_text
    return ""


def _build_openai_streaming_response(model: str, assistant_text: str) -> StreamingResponse:
    completion_id = f"chatcmpl-{uuid.uuid4().hex}"
    created = int(time.time())

    content_chunks = [assistant_text[i:i + 120] for i in range(0, len(assistant_text), 120)] or [""]

    async def _event_stream():
        first_chunk = {
            "id": completion_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}],
        }
        yield f"data: {json.dumps(first_chunk)}\n\n"

        for chunk_text in content_chunks:
            if not chunk_text:
                continue
            chunk_payload = {
                "id": completion_id,
                "object": "chat.completion.chunk",
                "created": created,
                "model": model,
                "choices": [{"index": 0, "delta": {"content": chunk_text}, "finish_reason": None}],
            }
            yield f"data: {json.dumps(chunk_payload)}\n\n"

        stop_chunk = {
            "id": completion_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
        }
        yield f"data: {json.dumps(stop_chunk)}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(_event_stream(), media_type="text/event-stream")


@app.get("/v1/models")
async def openai_models():
    model_ids = []
    for model_id in (settings.openai_compat_default_model, settings.guard_llm_model):
        if model_id and model_id not in model_ids:
            model_ids.append(model_id)

    return {
        "object": "list",
        "data": [
            {
                "id": model_id,
                "object": "model",
                "created": int(time.time()),
                "owned_by": "safetyguard",
            }
            for model_id in model_ids
        ],
    }


@app.post("/v1/chat/completions")
async def openai_chat_completions(
    request: Request,
    body: dict[str, Any],
    authorization: str | None = Header(default=None),
):
    stream_requested = body.get("stream") is True

    raw_messages = body.get("messages")
    if not isinstance(raw_messages, list) or not raw_messages:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"message": "messages is required", "type": "invalid_request_error"}},
        )

    mapped_messages: list[dict[str, str]] = []
    for msg in raw_messages:
        if not isinstance(msg, dict):
            continue
        role = str(msg.get("role", "user"))
        if role not in {"system", "user", "assistant", "developer"}:
            role = "user"
        content_text = _coerce_openai_content(msg.get("content"))
        if content_text.strip():
            mapped_messages.append({"role": role, "content": content_text})

    if not mapped_messages:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": {"message": "No valid messages content", "type": "invalid_request_error"}},
        )

    chat_body = ChatRequest(
        session_id=body.get("user") or body.get("session_id"),
        user_id=body.get("user") or "openai-client",
        messages=mapped_messages,
        metadata={
            "client_format": "openai_chat_completions",
            "requested_model": body.get("model"),
        },
    )

    trace_id = request.state.trace_id
    security_context = await build_security_context(authorization)

    try:
        chat_response = await chat_orchestrator.execute(
            request=request,
            body=chat_body,
            authorization=authorization,
            security_context=security_context,
            trace_id=trace_id,
            forward_fn=forward_to_security_gateway,
        )
    except HTTPException as exc:
        block_text = _format_block_reason(exc)
        block_model = body.get("model") or settings.openai_compat_default_model
        if stream_requested:
            return _build_openai_streaming_response(model=block_model, assistant_text=block_text)
        return {
            "id": f"chatcmpl-{uuid.uuid4().hex}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": block_model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": block_text},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }

    assistant_text = _extract_assistant_text(chat_response)
    completion_tokens = max(1, len(assistant_text) // 4) if assistant_text else 0

    prompt_package = chat_response.response.get("prompt_package", {})
    prompt_tokens = 0
    if isinstance(prompt_package, dict):
        token_estimate = prompt_package.get("token_estimate")
        if isinstance(token_estimate, int):
            prompt_tokens = token_estimate

    model_name = body.get("model") or settings.openai_compat_default_model or settings.guard_llm_model
    if stream_requested:
        return _build_openai_streaming_response(model=model_name, assistant_text=assistant_text)

    return {
        "id": f"chatcmpl-{uuid.uuid4().hex}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model_name,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": assistant_text},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        },
    }
