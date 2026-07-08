from __future__ import annotations

import re
from typing import List, Pattern, Set, Tuple

from .models import DLPMatch, DLPScanResult

Detector = Tuple[str, str, str, Pattern[str]]


def _compile(pattern: str) -> Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


DETECTORS: List[Detector] = [
    ("aws_access_key", "secret", "critical", _compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("generic_bearer_token", "secret", "high", _compile(r"\bBearer\s+[A-Za-z0-9\-\._~\+\/]+=*\b")),
    ("private_key_block", "secret", "critical", _compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("password_assignment", "credential", "high", _compile(r"\b(password|passwd|pwd)\s*[:=]\s*\S+")),
    ("api_key_assignment", "secret", "high", _compile(r"\b(api[_\- ]?key|secret[_\- ]?key|client[_\- ]?secret)\s*[:=]\s*\S+")),
    ("slack_token", "secret", "high", _compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    ("github_token", "secret", "high", _compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("email_address", "pii", "medium", _compile(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b")),
    ("phone_number", "pii", "medium", _compile(r"\b(?:\+?\d{1,3}[\s\-]?)?(?:\(?\d{2,4}\)?[\s\-]?)?\d{3,4}[\s\-]?\d{4}\b")),
    ("iban_like", "financial", "high", _compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
]


def severity_to_score(severity: str) -> int:
    if severity == "critical":
        return 30
    if severity == "high":
        return 20
    if severity == "medium":
        return 10
    return 5


def scan_text_with_detectors(
    text: str,
    detectors: List[Detector],
    *,
    message_index: int | None,
) -> tuple[List[DLPMatch], Set[str], int]:
    matches: List[DLPMatch] = []
    labels: Set[str] = set()
    score = 0

    for pattern_name, category, severity, regex in detectors:
        for match in regex.finditer(text):
            preview = text[max(0, match.start() - 20): min(len(text), match.end() + 20)].replace("\n", " ")
            matches.append(
                DLPMatch(
                    category=category,
                    severity=severity,  # type: ignore[arg-type]
                    message_index=message_index,
                    pattern_name=pattern_name,
                    evidence_preview=preview[:160],
                )
            )
            labels.add(category)
            score += severity_to_score(severity)

    return matches, labels, score


def build_scan_result(matches: List[DLPMatch], labels: Set[str], score: int) -> DLPScanResult:
    return DLPScanResult(
        score=min(score, 100),
        labels=sorted(labels),
        matches=matches,
        summary={
            "match_count": len(matches),
            "categories": sorted(labels),
            "critical_match_count": sum(1 for m in matches if m.severity == "critical"),
            "high_match_count": sum(1 for m in matches if m.severity == "high"),
        },
    )
