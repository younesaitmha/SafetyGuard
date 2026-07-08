"""
Error handlers for pipeline steps.

This module encapsulates error response generation logic for the chat pipeline,
following the Strategy pattern. Each handler is responsible for creating appropriate
HTTP responses and recording necessary state transitions.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Protocol

from fastapi import HTTPException, status

from app.models import CanonicalRequestEnvelope


class ErrorHandlerContext:
    """Context passed to error handlers containing necessary information for response generation."""

    def __init__(
        self,
        trace_id: str,
        session_id: str,
        reason_codes: list[str],
        policy_action: str = None,
    ):
        self.trace_id = trace_id
        self.session_id = session_id
        self.reason_codes = reason_codes
        self.policy_action = policy_action


class ErrorHandler(ABC):
    """Abstract base class for error handlers in the pipeline."""

    @abstractmethod
    def create_exception(self, context: ErrorHandlerContext) -> HTTPException:
        """
        Create an HTTPException for the given context.

        Args:
            context: ErrorHandlerContext containing necessary information for the response

        Returns:
            HTTPException: The HTTP exception to raise

        Raises:
            HTTPException: Always raises the created exception
        """
        pass


class DenyHandler(ErrorHandler):
    """Handles policy deny actions (HTTP 403 Forbidden)."""

    def create_exception(self, context: ErrorHandlerContext) -> HTTPException:
        """Create a 403 Forbidden exception for denied requests."""
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "message": "Request denied by policy",
                "trace_id": context.trace_id,
                "session_id": context.session_id,
                "reason_codes": context.reason_codes,
                "policy_action": context.policy_action,
            },
        )


class ChallengeHandler(ErrorHandler):
    """Handles policy challenge actions (HTTP 403 with challenge requirement)."""

    def create_exception(self, context: ErrorHandlerContext) -> HTTPException:
        """Create a 403 Forbidden exception requiring additional authentication challenge."""
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "message": "Additional authentication challenge required",
                "trace_id": context.trace_id,
                "session_id": context.session_id,
                "reason_codes": context.reason_codes,
                "policy_action": "challenge",
                "challenge_required": True,
            },
        )


class RateLimitHandler(ErrorHandler):
    """Handles rate limit exceeded responses (HTTP 429 Too Many Requests)."""

    def __init__(self, reason: str = "Rate limit exceeded"):
        self.reason = reason

    def create_exception(self, context: ErrorHandlerContext) -> HTTPException:
        """Create a 429 Too Many Requests exception."""
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"{self.reason}: {context.reason_codes[0] if context.reason_codes else 'quota exceeded'}",
        )


class PromptBudgetExceededHandler(ErrorHandler):
    """Handles prompt token budget exceeded responses (HTTP 413 Payload Too Large)."""

    def create_exception(self, context: ErrorHandlerContext) -> HTTPException:
        """Create a 413 Payload Too Large exception."""
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail={
                "message": "Prompt exceeds token budget",
                "trace_id": context.trace_id,
                "session_id": context.session_id,
                "reason_codes": context.reason_codes,
            },
        )


class OutputBlockedHandler(ErrorHandler):
    """Handles output guard block actions (HTTP 502 Bad Gateway)."""

    def create_exception(self, context: ErrorHandlerContext) -> HTTPException:
        """Create a 502 Bad Gateway exception for blocked output."""
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "message": "Unsafe response blocked by output guard",
                "trace_id": context.trace_id,
                "session_id": context.session_id,
                "reason_codes": context.reason_codes,
            },
        )


class OutputRedactHandler:
    """
    Handles output redaction actions (no exception, modifies response in-place).

    This handler does not raise an exception; instead it modifies the response
    dictionary to replace the output with redacted text.
    """

    def apply_redaction(
        self,
        client_response: Dict[str, Any],
        redacted_text: str,
    ) -> None:
        """
        Apply redaction to the client response.

        Args:
            client_response: The response dictionary to modify
            redacted_text: The text to substitute for the original output
        """
        if "answer" in client_response:
            client_response["answer"] = redacted_text
        elif "message" in client_response:
            client_response["message"] = redacted_text
        elif "output_text" in client_response:
            client_response["output_text"] = redacted_text
        else:
            client_response["guarded_output"] = redacted_text


# Registry of error handlers by action type
ERROR_HANDLERS: Dict[str, type[ErrorHandler]] = {
    "deny": DenyHandler,
    "challenge": ChallengeHandler,
    "rate_limit": RateLimitHandler,
    "prompt_budget_exceeded": PromptBudgetExceededHandler,
    "output_blocked": OutputBlockedHandler,
}


def get_error_handler(action: str) -> ErrorHandler:
    """
    Get an error handler for the given action.

    Args:
        action: The action type (e.g., "deny", "challenge", "rate_limit")

    Returns:
        ErrorHandler: An instance of the appropriate error handler

    Raises:
        ValueError: If the action is not recognized
    """
    handler_class = ERROR_HANDLERS.get(action)
    if handler_class is None:
        raise ValueError(f"Unknown error action: {action}")
    return handler_class()
