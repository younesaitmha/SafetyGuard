from __future__ import annotations

import re

from .models import CanonicalRequestEnvelope, InputScanResult, InputScanSignal

PROMPT_INJECTION_PATTERNS = [
    r"ignore previous instructions",
    r"disregard all prior rules",
    r"system prompt",
    r"developer prompt",
    r"reveal hidden instructions",
    r"show me your policy",
]

SECRET_EXFIL_PATTERNS = [
    r"show.*api key",
    r"reveal.*token",
    r"dump.*credentials",
    r"show.*secret",
]

EXPLOIT_PATTERNS = [
    r"write malware",
    r"build ransomware",
    r"exploit vulnerability",
    r"privilege escalation",
]

JAILBREAK_PATTERNS = [
    # Original patterns
    r"pretend you (are|have no|don'?t have)\b",
    r"act as (if|though) you (are|have|were|had)\b",
    r"you are now\b",
    r"ignore (all|your|any|previous|safety|security) (rules|instructions|constraints|guidelines|restrictions|policies?|policy)\b",
    r"\b(DAN|STAN|DUDE|KEVIN|AIM)\b",
    r"\bjailbreak\b",
    r"\bdo anything now\b",
    r"bypass.{0,20}(filter|guard|policy|restriction|safety)",
    r"no (restrictions|limits|rules|guidelines) apply",
    r"(roleplay|role.play|simulate).{0,40}(no (rules|restrictions|limits)|evil|unrestricted|without.{0,15}(filter|safety|guardrail))",
    # Extended patterns for variants
    r"\b(forget|reset|clear|erase|wipe).{0,20}(instruction|rule|policy|constraint)",
    r"\b(IgnoRe|SYSTEM_PROMPT|SyStEm).{0,10}(prompt|instruction|rule)",
    r"#\s*\[instruction_cache:|# \[JAILBREAK",
    r"(as if|pretend|imagine|suppose) (you|the system) (has no|doesn't have|never had) (restriction|safety|rule)",
    r"(forget|discard) (everything|all) (you|were told|instructed|taught)",
    r"(act like|behave like|roleplay as) (a|an) (unfiltered|uncensored|unrestricted)",
    r"(\[BEGIN|\[START|\[INIT\].*?JAILBREAK|\[OVERRIDE)",
]

OBFUSCATION_PATTERNS = [
    r"(?:[A-Za-z0-9+/]{20,}={0,2})",   # Long Base64-like strings
    r"(?:\\u[0-9a-fA-F]{4}){4,}",       # Multiple unicode escapes
    r"(?:&#\d{2,5};){4,}",              # Multiple HTML entities
    r"(?:0x[0-9a-fA-F]{2}\s*){6,}",    # Hex byte sequences
    r"(?:&#x[0-9a-fA-F]{4};){3,}",     # Hex HTML entities
]

MODERATION_BYPASS_PATTERNS = [
    r"bypass.{0,20}(moderation|content policy|safety policy|safety filter|guardrail)",
    r"disable.{0,20}(moderation|safety filter|guardrail)",
    r"ignore.{0,20}(moderation|content policy|safety policy)",
    r"contourner.{0,20}(mod[ée]ration|filtre|politique)",
]

HATE_CONTENT_PATTERNS = [
    r"\bkill all\s+(?:[a-z]+)\b",
    r"\bhate\s+(?:all\s+)?(?:[a-z]+)\b",
    r"\b(?:exterminate|eradicate)\s+(?:all\s+)?(?:[a-z]+)\b",
]

DISCRIMINATION_PATTERNS = [
    r"\b(?:ban|exclude|refuse|reject)\s+(?:all\s+)?(?:women|men|muslims|jews|christians|black people|white people|asians|arabs|immigrants)\b",
    r"\b(?:inferior|superior)\s+(?:race|gender|religion|ethnicity)\b",
    r"\b(?:racial|ethnic|religious|gender)\s+purity\b",
]

INSULT_PATTERNS = [
    r"\b(?:idiot|moron|stupid|dumbass|loser|trash)\b",
    r"\b(?:tu es|you're|you are)\s+(?:stupid|an idiot|a moron|trash)\b",
]

# NEW: Unicode homoglyph tricks and zero-width characters
UNICODE_TRICKS_PATTERNS = [
    r"[\u0600-\u06FF]",  # Arabic (often used for homoglyphs)
    r"[\u2060\u200B\u200C\u200D\uFEFF]",  # Zero-width characters, ZWNJ, ZWJ, BOM
    r"[\u202E\u202D]",  # Right-to-left, Left-to-right overrides
    r"[\u0301-\u0308]",  # Combining marks that modify characters
]


def _detect_nested_encoding(text: str, max_depth: int = 3) -> int:
    """Detect if text has nested Base64/hex encoding layers. Returns nesting depth."""
    depth = 0
    current = text.strip()
    
    for _ in range(max_depth):
        # Try Base64 decode
        try:
            import base64
            decoded = base64.b64decode(current, validate=True).decode('utf-8', errors='ignore')
            if decoded != current and len(decoded) > 10:
                depth += 1
                current = decoded.strip()
                continue
        except Exception:
            pass
        
        # Try hex decode
        try:
            decoded_hex = bytes.fromhex(current).decode('utf-8', errors='ignore')
            if decoded_hex and decoded_hex != current and len(decoded_hex) > 10:
                depth += 1
                current = decoded_hex.strip()
                continue
        except Exception:
            pass
        
        break
    
    return depth


class InputSecurityScanner:
    def scan(self, envelope: CanonicalRequestEnvelope) -> InputScanResult:
        signals: list[InputScanSignal] = []
        labels: set[str] = set()
        score = 0

        for idx, msg in enumerate(envelope.messages):
            text = msg.content.lower()

            # Detect nested encoding
            nesting_depth = _detect_nested_encoding(msg.content)
            if nesting_depth >= 2:
                signals.append(
                    InputScanSignal(
                        category="obfuscation",
                        severity="high",
                        message_index=idx,
                        pattern="nested_encoding",
                        evidence=msg.content[:200],
                    )
                )
                labels.add("obfuscation")
                score += 20

            # Detect Unicode tricks
            if any(re.search(p, msg.content) for p in UNICODE_TRICKS_PATTERNS):
                signals.append(
                    InputScanSignal(
                        category="obfuscation",
                        severity="medium",
                        message_index=idx,
                        pattern="unicode_tricks",
                        evidence=msg.content[:200],
                    )
                )
                labels.add("obfuscation")
                score += 15

            for pattern in MODERATION_BYPASS_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    signals.append(
                        InputScanSignal(
                            category="moderation_bypass",
                            severity="critical",
                            message_index=idx,
                            pattern=pattern,
                            evidence=msg.content[:200],
                        )
                    )
                    labels.add("moderation_bypass")
                    score += 30

            for pattern in HATE_CONTENT_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    signals.append(
                        InputScanSignal(
                            category="hate_content",
                            severity="high",
                            message_index=idx,
                            pattern=pattern,
                            evidence=msg.content[:200],
                        )
                    )
                    labels.add("hate_content")
                    score += 20

            for pattern in DISCRIMINATION_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    signals.append(
                        InputScanSignal(
                            category="discriminatory_content",
                            severity="high",
                            message_index=idx,
                            pattern=pattern,
                            evidence=msg.content[:200],
                        )
                    )
                    labels.add("discriminatory_content")
                    score += 20

            for pattern in INSULT_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    signals.append(
                        InputScanSignal(
                            category="insult_content",
                            severity="medium",
                            message_index=idx,
                            pattern=pattern,
                            evidence=msg.content[:200],
                        )
                    )
                    labels.add("insult_content")
                    score += 10

            for pattern in PROMPT_INJECTION_PATTERNS:
                if re.search(pattern, text):
                    signals.append(
                        InputScanSignal(
                            category="prompt_injection",
                            severity="high",
                            message_index=idx,
                            pattern=pattern,
                            evidence=msg.content[:200],
                        )
                    )
                    labels.add("prompt_injection")
                    if "system prompt" in pattern or "developer prompt" in pattern:
                        labels.add("prompt_leakage")
                    score += 15

            for pattern in SECRET_EXFIL_PATTERNS:
                if re.search(pattern, text):
                    signals.append(
                        InputScanSignal(
                            category="secret_exfiltration",
                            severity="critical",
                            message_index=idx,
                            pattern=pattern,
                            evidence=msg.content[:200],
                        )
                    )
                    labels.add("secret_exfiltration")
                    score += 30

            for pattern in EXPLOIT_PATTERNS:
                if re.search(pattern, text):
                    signals.append(
                        InputScanSignal(
                            category="exploit_intent",
                            severity="critical",
                            message_index=idx,
                            pattern=pattern,
                            evidence=msg.content[:200],
                        )
                    )
                    labels.add("exploit_intent")
                    score += 30

            for pattern in JAILBREAK_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    signals.append(
                        InputScanSignal(
                            category="jailbreak_attempt",
                            severity="high",
                            message_index=idx,
                            pattern=pattern,
                            evidence=msg.content[:200],
                        )
                    )
                    labels.add("jailbreak_attempt")
                    score += 25

            for pattern in OBFUSCATION_PATTERNS:
                if re.search(pattern, msg.content):
                    signals.append(
                        InputScanSignal(
                            category="obfuscation",
                            severity="medium",
                            message_index=idx,
                            pattern=pattern,
                            evidence=msg.content[:200],
                        )
                    )
                    labels.add("obfuscation")
                    score += 15

        return InputScanResult(
            score=min(score, 100),
            labels=sorted(labels),
            signals=signals,
            summary={
                "signal_count": len(signals),
                "labels": sorted(labels),
            },
        )
