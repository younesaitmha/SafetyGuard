from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import settings
from .models import CanonicalRequestEnvelope, PolicyBundle, PolicyDecision
from .policy_conditions import DEFAULT_CONDITION_EVALUATORS, ConditionEvaluator


class PolicyService:
    def __init__(self, bundle_path: str | None = None):
        self.bundle_path = Path(bundle_path or settings.policy_bundle_path)
        self.bundle = self._load_bundle()
        self._condition_evaluators: dict[str, ConditionEvaluator] = {
            evaluator.key: evaluator for evaluator in DEFAULT_CONDITION_EVALUATORS
        }

    def _load_bundle(self) -> PolicyBundle:
        with self.bundle_path.open("r", encoding="utf-8") as f:
            raw = json.load(f)
        return PolicyBundle.model_validate(raw)

    def reload(self) -> None:
        self.bundle = self._load_bundle()

    def evaluate(self, envelope: CanonicalRequestEnvelope) -> PolicyDecision:
        for rule in self.bundle.rules:
            if rule.enabled and self._matches(rule.condition, envelope):
                return rule.decision
        return self.bundle.default_decision

    def _matches(self, condition: dict[str, Any], envelope: CanonicalRequestEnvelope) -> bool:
        return all(self._match_condition(k, v, envelope) for k, v in condition.items())

    def _match_condition(self, key: str, expected: Any, envelope: CanonicalRequestEnvelope) -> bool:
        evaluator = self._condition_evaluators.get(key)
        if not evaluator:
            return False
        return evaluator.evaluate(expected, envelope)
