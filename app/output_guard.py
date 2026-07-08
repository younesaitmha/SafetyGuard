from __future__ import annotations

import re
from typing import List

from .dlp_engine import DETECTORS, build_scan_result, scan_text_with_detectors
from .models import CanonicalRequestEnvelope, DLPScanResult, OutputGuardResult

PROMPT_LEAK_PATTERNS = [
    r"system prompt",
    r"developer prompt",
    r"hidden instructions",
    r"internal policy",
    r"do not reveal",
    r"you are instructed",
    r"you must",
]

SECRET_REDACTION_PATTERNS = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", re.IGNORECASE), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b", re.IGNORECASE), "[REDACTED_SLACK_TOKEN]"),
    (re.compile(r"\b(password|passwd|pwd)\s*[:=]\s*\S+", re.IGNORECASE), "[REDACTED_PASSWORD]"),
    (re.compile(r"\b(api[_\- ]?key|secret[_\- ]?key|client[_\- ]?secret)\s*[:=]\s*\S+", re.IGNORECASE), "[REDACTED_SECRET]"),
]


class OutputGuard:
    def inspect(self, envelope: CanonicalRequestEnvelope, response_payload: dict) -> OutputGuardResult:
        text = self._extract_text(response_payload)
        dlp_scan = self._scan_text(text)
        leakage_signals = self._detect_leakage(text)
        
        # NEW: Check for prompt extrapolation (hallucination / training data leak)
        extrapolation_reason = self._detect_prompt_extrapolation(envelope, text)

        if extrapolation_reason:
            return OutputGuardResult(
                action="redact",
                reason_codes=["OUTPUT_EXTRAPOLATION_DETECTED"],
                redacted_text=text[:500] + "..." if len(text) > 500 else text,  # Truncate
                dlp_scan=dlp_scan,
                leakage_signals=leakage_signals + [extrapolation_reason],
            )

        if envelope.llm_output_guard:
            llm = envelope.llm_output_guard
            # Only block if very high confidence (95%) and explicit block recommendation
            if llm.recommended_action == "block" and llm.confidence >= 0.95 and llm.risk_score >= 85:
                return OutputGuardResult(
                    action="block",
                    reason_codes=["LLM_OUTPUT_GUARD_BLOCK"] + llm.reasons,
                    redacted_text=None,
                    dlp_scan=dlp_scan,
                    leakage_signals=leakage_signals,
                )
            # Prefer redaction over blocking for moderate signals
            if llm.recommended_action in ("redact", "deny") or llm.risk_score >= 70:
                return OutputGuardResult(
                    action="redact",
                    reason_codes=["LLM_OUTPUT_GUARD_REDACT"] + llm.reasons,
                    redacted_text=self._redact_prompt_leakage(self._redact_text(text)),
                    dlp_scan=dlp_scan,
                    leakage_signals=leakage_signals,
                )

        if dlp_scan.score >= 50:
            return OutputGuardResult(
                action="redact",
                reason_codes=["OUTPUT_DLP_HIGH_RISK"],
                redacted_text=self._redact_text(text),
                dlp_scan=dlp_scan,
                leakage_signals=leakage_signals,
            )

        if leakage_signals:
            if envelope.policy_decision and envelope.policy_decision.response_mode == "restricted":
                return OutputGuardResult(
                    action="block",
                    reason_codes=["OUTPUT_PROMPT_OR_POLICY_LEAKAGE"],
                    redacted_text=None,
                    dlp_scan=dlp_scan,
                    leakage_signals=leakage_signals,
                )

            return OutputGuardResult(
                action="redact",
                reason_codes=["OUTPUT_PROMPT_OR_POLICY_LEAKAGE"],
                redacted_text=self._redact_prompt_leakage(text),
                dlp_scan=dlp_scan,
                leakage_signals=leakage_signals,
            )

        return OutputGuardResult(
            action="allow",
            reason_codes=["OUTPUT_ALLOWED"],
            redacted_text=text,
            dlp_scan=dlp_scan,
            leakage_signals=leakage_signals,
        )

    def _extract_text(self, response_payload: dict) -> str:
        for key in ("answer", "message", "output_text"):
            if isinstance(response_payload.get(key), str):
                return response_payload[key]
        return str(response_payload)

    def _scan_text(self, text: str) -> DLPScanResult:
        matches, labels, score = scan_text_with_detectors(
            text,
            DETECTORS,
            message_index=None,
        )
        return build_scan_result(matches, labels, score)

    def _detect_leakage(self, text: str) -> List[str]:
        text_l = text.lower()
        return [p for p in PROMPT_LEAK_PATTERNS if re.search(p, text_l)]

    def _redact_text(self, text: str) -> str:
        out = text
        for regex, replacement in SECRET_REDACTION_PATTERNS:
            out = regex.sub(replacement, out)
        return out

    def _redact_prompt_leakage(self, text: str) -> str:
        out = text
        for pattern in PROMPT_LEAK_PATTERNS:
            out = re.sub(pattern, "[REDACTED_POLICY_CONTENT]", out, flags=re.IGNORECASE)
        return out

    def _detect_prompt_extrapolation(self, envelope: CanonicalRequestEnvelope, response_text: str) -> str | None:
        """
        NEW: Detect if output is suspiciously longer than expected from prompt.

        Indicators of hallucination / training data leak:
        - Output length >> input prompt length
        - Suggests model generated content not grounded in prompt
        """
        if not envelope.prompt_package:
            return None

        prompt_len = len(envelope.prompt_package.prompt_text or "")
        response_len = len(response_text)

        # If response is >3x longer than prompt, flag as extrapolation
        # (higher threshold to reduce false positives)
        if prompt_len > 0 and response_len > prompt_len * 3:
            return f"response_length_anomaly: output={response_len} vs prompt={prompt_len}"

        # Also flag if output is very long without corresponding long input
        if prompt_len < 500 and response_len > 5000:
            return f"high_output_without_high_input: output={response_len} vs prompt={prompt_len}"

        return None
