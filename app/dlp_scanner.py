from __future__ import annotations

import re
from typing import List, Pattern

from .dlp_engine import DETECTORS, build_scan_result, scan_text_with_detectors, severity_to_score
from .models import CanonicalRequestEnvelope, DLPMatch, DLPScanResult


def _compile(pattern: str) -> Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


METADATA_INJECTION_REGEXES: List[tuple[str, Pattern[str]]] = [
    ("metadata_script_tag", _compile(r"<script|</script>")),
    ("metadata_js_scheme", _compile(r"javascript:\s*")),
    ("metadata_event_handler", _compile(r"on(error|load|click)\s*=")),
    ("metadata_code_eval", _compile(r"\beval\s*\(")),
    ("metadata_command_exec", _compile(r"\b(import\s+os|system\s*\(|__import__)")),
]


class DLPScanner:
    def scan(self, envelope: CanonicalRequestEnvelope) -> DLPScanResult:
        matches: List[DLPMatch] = []
        labels: set[str] = set()
        score = 0

        for idx, msg in enumerate(envelope.messages):
            message_matches, message_labels, message_score = scan_text_with_detectors(
                msg.content,
                DETECTORS,
                message_index=idx,
            )
            matches.extend(message_matches)
            labels.update(message_labels)
            score += message_score

        for att in envelope.attachments:
            if att.content:
                attachment_matches, attachment_labels, attachment_score = scan_text_with_detectors(
                    att.content,
                    DETECTORS,
                    message_index=None,
                )
                matches.extend(attachment_matches)
                labels.update(attachment_labels)
                score += attachment_score

            metadata_fields = [att.name or "", att.content_type or "", att.uri or ""]
            metadata_text = " | ".join(metadata_fields)
            for pattern_name, regex in METADATA_INJECTION_REGEXES:
                for match in regex.finditer(metadata_text):
                    preview = metadata_text[max(0, match.start() - 20): min(len(metadata_text), match.end() + 20)]
                    matches.append(
                        DLPMatch(
                            category="metadata_injection",
                            severity="high",
                            message_index=None,
                            pattern_name=pattern_name,
                            evidence_preview=preview[:160],
                        )
                    )
                    labels.add("metadata_injection")
                    score += severity_to_score("high")

        return build_scan_result(matches, labels, score)
