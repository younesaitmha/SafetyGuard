import httpx
from fastapi import HTTPException, status

from .config import settings
from .observability import UpstreamMetrics


upstream_metrics = UpstreamMetrics()


def _extract_messages(payload: dict) -> list[dict]:
    """Extract messages list from envelope payload."""
    # Envelope may have messages at top-level or nested under 'request'
    messages = payload.get("messages") or payload.get("request", {}).get("messages") or []
    # Normalise roles: drop unknown roles that Ollama rejects
    cleaned = []
    for m in messages:
        role = m.get("role", "user")
        if role not in ("system", "user", "assistant"):
            role = "user"
        cleaned.append({"role": role, "content": m.get("content", "")})
    return cleaned


async def _forward_to_ollama(payload: dict, trace_id: str) -> dict:
    """Call Ollama /api/chat and return a normalized response dict."""
    messages = _extract_messages(payload)
    if not messages:
        messages = [{"role": "user", "content": str(payload)}]

    model = settings.ollama_model
    ollama_payload = {"model": model, "messages": messages, "stream": False}
    url = f"{settings.ollama_url}/api/chat"

    async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
        response = await client.post(url, json=ollama_payload)
        response.raise_for_status()
        data = response.json()

    # Ollama response: {"message": {"role": "assistant", "content": "..."}, ...}
    answer = (
        data.get("message", {}).get("content")
        or data.get("response")
        or str(data)
    )
    upstream_metrics.record_success()
    return {"answer": answer, "model": model, "forwarder_mode": "ollama"}


async def forward_to_security_gateway(payload: dict, trace_id: str, auth_header: str | None):
    # First try the configured security gateway (if it's not the default stub URL)
    url = f"{settings.security_gateway_url}/internal/chat"
    headers = {"X-Trace-Id": trace_id}
    if auth_header:
        headers["Authorization"] = auth_header

    if settings.security_gateway_url != "http://localhost:9999":
        try:
            async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
                response = await client.post(url, json=payload, headers=headers)
                response.raise_for_status()
                upstream_metrics.record_success()
                return response.json()
        except Exception as exc:
            upstream_metrics.record_failure(type(exc).__name__, settings.security_gateway_fail_open)
            if not settings.security_gateway_fail_open:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail={
                        "message": "Downstream security gateway unavailable",
                        "trace_id": trace_id,
                        "reason": type(exc).__name__,
                    },
                )

    # Fall back to Ollama direct
    try:
        return await _forward_to_ollama(payload, trace_id)
    except Exception as exc:
        upstream_metrics.record_failure(type(exc).__name__, settings.security_gateway_fail_open)
        if not settings.security_gateway_fail_open:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail={
                    "message": "Ollama unavailable",
                    "trace_id": trace_id,
                    "reason": type(exc).__name__,
                },
            )
        return {
            "answer": (
                "⚠️ **Service LLM temporairement indisponible.**\n\n"
                "Votre requête a été analysée et autorisée par SafetyGuard, "
                "mais le modèle de langage en aval est inaccessible en ce moment.\n\n"
                f"Erreur : `{type(exc).__name__}` — `{settings.ollama_url}`\n\n"
                "Veuillez réessayer dans quelques instants ou contacter votre administrateur."
            ),
            "decision": "allow_with_restrictions",
            "forwarder_mode": "fail_open",
        }
