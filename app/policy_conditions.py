from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from .models import CanonicalRequestEnvelope


class ConditionEvaluator(ABC):
    key: str

    @abstractmethod
    def evaluate(self, expected: Any, envelope: CanonicalRequestEnvelope) -> bool:
        raise NotImplementedError


class MissingPermissionEvaluator(ConditionEvaluator):
    key = "missing_permission"

    def evaluate(self, expected: Any, envelope: CanonicalRequestEnvelope) -> bool:
        return expected not in envelope.security_context.permissions


class InputScanHasLabelEvaluator(ConditionEvaluator):
    key = "input_scan_has_label"

    def evaluate(self, expected: Any, envelope: CanonicalRequestEnvelope) -> bool:
        return bool(envelope.input_scan and expected in envelope.input_scan.labels)


class InputScanScoreGteEvaluator(ConditionEvaluator):
    key = "input_scan_score_gte"

    def evaluate(self, expected: Any, envelope: CanonicalRequestEnvelope) -> bool:
        return bool(envelope.input_scan and envelope.input_scan.score >= int(expected))


class SessionRiskStateEvaluator(ConditionEvaluator):
    key = "session_risk_state"

    def evaluate(self, expected: Any, envelope: CanonicalRequestEnvelope) -> bool:
        return bool(envelope.session_risk and envelope.session_risk.state == expected)


class StepUpAuthenticatedEvaluator(ConditionEvaluator):
    key = "step_up_authenticated"

    def evaluate(self, expected: Any, envelope: CanonicalRequestEnvelope) -> bool:
        return envelope.security_context.step_up_authenticated == expected


class DLPHasLabelEvaluator(ConditionEvaluator):
    key = "dlp_has_label"

    def evaluate(self, expected: Any, envelope: CanonicalRequestEnvelope) -> bool:
        return bool(envelope.dlp_scan and expected in envelope.dlp_scan.labels)


class DLPScoreGteEvaluator(ConditionEvaluator):
    key = "dlp_score_gte"

    def evaluate(self, expected: Any, envelope: CanonicalRequestEnvelope) -> bool:
        return bool(envelope.dlp_scan and envelope.dlp_scan.score >= int(expected))


class ClassificationLabelEvaluator(ConditionEvaluator):
    key = "classification_label"

    def evaluate(self, expected: Any, envelope: CanonicalRequestEnvelope) -> bool:
        return bool(envelope.content_classification and envelope.content_classification.label == expected)


class ClassificationConfidenceGteEvaluator(ConditionEvaluator):
    key = "classification_confidence_gte"

    def evaluate(self, expected: Any, envelope: CanonicalRequestEnvelope) -> bool:
        return bool(envelope.content_classification and envelope.content_classification.confidence >= float(expected))


DEFAULT_CONDITION_EVALUATORS: tuple[ConditionEvaluator, ...] = (
    MissingPermissionEvaluator(),
    InputScanHasLabelEvaluator(),
    InputScanScoreGteEvaluator(),
    SessionRiskStateEvaluator(),
    StepUpAuthenticatedEvaluator(),
    DLPHasLabelEvaluator(),
    DLPScoreGteEvaluator(),
    ClassificationLabelEvaluator(),
    ClassificationConfidenceGteEvaluator(),
)
