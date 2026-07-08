from __future__ import annotations

from .models import CanonicalRequestEnvelope, ContentClassification


class ContentClassifier:
    def classify(self, envelope: CanonicalRequestEnvelope) -> ContentClassification:
        reasons: list[str] = []
        features: dict = {}

        input_scan_score = envelope.input_scan.score if envelope.input_scan else 0
        input_labels = set(envelope.input_scan.labels if envelope.input_scan else [])
        dlp_score = envelope.dlp_scan.score if envelope.dlp_scan else 0
        dlp_labels = set(envelope.dlp_scan.labels if envelope.dlp_scan else [])
        session_risk_score = envelope.session_risk.score if envelope.session_risk else 0
        session_risk_state = envelope.session_risk.state if envelope.session_risk else "normal"

        features["input_scan_score"] = input_scan_score
        features["dlp_score"] = dlp_score
        features["session_risk_score"] = session_risk_score
        features["session_risk_state"] = session_risk_state
        features["input_labels"] = sorted(input_labels)
        features["dlp_labels"] = sorted(dlp_labels)

        if envelope.llm_input_guard:
            features["llm_guard_label"] = envelope.llm_input_guard.label
            features["llm_guard_confidence"] = envelope.llm_input_guard.confidence
            features["llm_guard_risk_score"] = envelope.llm_input_guard.risk_score

            corroborated_attack = (
                "prompt_injection" in input_labels
                or "jailbreak_attempt" in input_labels
                or "secret_exfiltration" in input_labels
                or "exploit_intent" in input_labels
                or input_scan_score >= 50
            )

            # Reclassify plain secret/PII submission as sensitive_data_submission
            # when there is no deterministic exfiltration or injection signal.
            if (
                envelope.llm_input_guard.label == "secret_exfiltration_intent"
                and "secret_exfiltration" not in input_labels
                and "prompt_injection" not in input_labels
                and "jailbreak_attempt" not in input_labels
                and "exploit_intent" not in input_labels
                and ({"secret", "pii", "financial"} & dlp_labels)
            ):
                reasons.append("secret_submission_without_exfiltration_request")
                return ContentClassification(
                    label="sensitive_data_submission",
                    confidence=min(0.90, envelope.llm_input_guard.confidence),
                    reasons=reasons,
                    features=features,
                )

            # Guard-only hard-attack labels must be corroborated by deterministic signals.
            if (
                envelope.llm_input_guard.label in {
                    "prompt_injection",
                    "jailbreak_attempt",
                    "secret_exfiltration_intent",
                    "exploit_or_malware_intent",
                }
                and envelope.llm_input_guard.confidence >= 0.75
                and not corroborated_attack
            ):
                reasons.append("llm_guard_unconfirmed_by_deterministic_signals")
                if {"secret", "pii", "financial"} & dlp_labels:
                    return ContentClassification(
                        label="sensitive_data_submission",
                        confidence=0.80,
                        reasons=reasons,
                        features=features,
                    )
                return ContentClassification(
                    label="suspicious",
                    confidence=0.70,
                    reasons=reasons,
                    features=features,
                )

            # NEW: cross-check guard output against deterministic signals
            guard_says_allow = envelope.llm_input_guard.recommended_action in {"allow", "allow_with_restrictions"}
            deterministic_high_risk = (
                input_scan_score >= 50 or
                dlp_score >= 40 or
                "prompt_injection" in input_labels or
                "jailbreak_attempt" in input_labels or
                "secret_exfiltration" in input_labels
            )
            
            if guard_says_allow and deterministic_high_risk and envelope.llm_input_guard.confidence < 0.95:
                # Guard conflicts with strong deterministic signals; downgrade confidence
                reasons.append("llm_guard_conflict_with_deterministic")
                features["llm_guard_confidence_adjusted"] = 0.3
                # Fall through to deterministic classification
            elif envelope.llm_input_guard.label in {
                "prompt_injection",
                "jailbreak_attempt",
                "secret_exfiltration_intent",
                "exploit_or_malware_intent",
                "sensitive_data_submission",
            } and envelope.llm_input_guard.confidence >= 0.75:
                return ContentClassification(
                    label=envelope.llm_input_guard.label,  # type: ignore[arg-type]
                    confidence=envelope.llm_input_guard.confidence,
                    reasons=envelope.llm_input_guard.reasons,
                    features=features,
                )

        if "prompt_leakage" in input_labels:
            reasons.append("prompt_leakage_signal")
            return ContentClassification(label="prompt_injection", confidence=0.95, reasons=reasons, features=features)

        if "prompt_injection" in input_labels:
            reasons.append("prompt_injection_signal")
            return ContentClassification(label="prompt_injection", confidence=0.90, reasons=reasons, features=features)

        if "jailbreak_attempt" in input_labels:
            reasons.append("jailbreak_attempt_signal")
            return ContentClassification(label="jailbreak_attempt", confidence=0.90, reasons=reasons, features=features)

        if "secret_exfiltration" in input_labels:
            reasons.append("secret_exfiltration_signal")
            return ContentClassification(label="secret_exfiltration_intent", confidence=0.95, reasons=reasons, features=features)

        if "exploit_intent" in input_labels:
            reasons.append("exploit_intent_signal")
            return ContentClassification(label="exploit_or_malware_intent", confidence=0.90, reasons=reasons, features=features)

        if "secret" in dlp_labels or "financial" in dlp_labels:
            reasons.append("sensitive_content_detected")
            return ContentClassification(label="sensitive_data_submission", confidence=0.88, reasons=reasons, features=features)

        if input_scan_score >= 50:
            reasons.append("high_input_scan_score")
            return ContentClassification(label="jailbreak_attempt", confidence=0.80, reasons=reasons, features=features)

        if input_scan_score >= 20 or dlp_score >= 20 or session_risk_state in {"elevated", "restricted"}:
            reasons.append("elevated_heuristic_signals")
            return ContentClassification(label="suspicious", confidence=0.65, reasons=reasons, features=features)

        return ContentClassification(
            label="benign",
            confidence=0.90,
            reasons=["no_material_risk_signals"],
            features=features,
        )
