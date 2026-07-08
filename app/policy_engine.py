from .models import CanonicalRequestEnvelope, PolicyDecision
from .policy_service import PolicyService


class PolicyEngine:
    def __init__(self):
        self.policy_service = PolicyService()

    def decide(self, envelope: CanonicalRequestEnvelope) -> PolicyDecision:
        return self.policy_service.evaluate(envelope)

    def reload(self) -> None:
        self.policy_service.reload()
