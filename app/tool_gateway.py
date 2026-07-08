from __future__ import annotations

import re
from typing import Any, Dict, List

from .models import CanonicalRequestEnvelope, ToolDecision, ToolDefinition, ToolExecutionRecord

TOOL_REGISTRY: Dict[str, ToolDefinition] = {
    "browser.search": ToolDefinition(
        name="browser.search",
        description="Search public web content",
        required_permission="tool:browser.search",
        sensitivity="public",
        enabled=True,
    ),
    "kb.lookup": ToolDefinition(
        name="kb.lookup",
        description="Lookup internal knowledge base documents",
        required_permission="tool:kb.lookup",
        sensitivity="internal",
        enabled=True,
    ),
    "ticket.create": ToolDefinition(
        name="ticket.create",
        description="Create support tickets",
        required_permission="tool:ticket.create",
        sensitivity="internal",
        enabled=True,
    ),
    "email.send": ToolDefinition(
        name="email.send",
        description="Send email through enterprise mail service",
        required_permission="tool:email.send",
        sensitivity="confidential",
        enabled=True,
    ),
}


class ToolGateway:
    def evaluate_requested_tools(self, envelope: CanonicalRequestEnvelope) -> List[ToolDecision]:
        requested_tools = envelope.metadata.get("requested_tools", [])
        decisions: List[ToolDecision] = []

        for item in requested_tools:
            decisions.append(
                self._evaluate_single_tool(
                    tool_name=item.get("name"),
                    arguments=item.get("arguments", {}),
                    envelope=envelope,
                )
            )

        return decisions

    def _evaluate_single_tool(
        self,
        tool_name: str | None,
        arguments: Dict[str, Any],
        envelope: CanonicalRequestEnvelope,
    ) -> ToolDecision:
        if not tool_name or tool_name not in TOOL_REGISTRY:
            return ToolDecision(
                tool_name=tool_name or "unknown",
                allowed=False,
                reason_codes=["UNKNOWN_TOOL"],
                sanitized_arguments={},
            )

        definition = TOOL_REGISTRY[tool_name]

        if not definition.enabled:
            return ToolDecision(tool_name=tool_name, allowed=False, reason_codes=["TOOL_DISABLED"], sanitized_arguments={})

        if envelope.policy_decision and envelope.policy_decision.disable_tools:
            return ToolDecision(tool_name=tool_name, allowed=False, reason_codes=["TOOLS_DISABLED_BY_POLICY"], sanitized_arguments={})

        if definition.required_permission not in envelope.security_context.permissions:
            return ToolDecision(tool_name=tool_name, allowed=False, reason_codes=["MISSING_TOOL_PERMISSION"], sanitized_arguments={})

        sensitivity_rank = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}
        max_allowed = envelope.policy_decision.max_context_sensitivity if envelope.policy_decision else "internal"

        if sensitivity_rank[definition.sensitivity] > sensitivity_rank[max_allowed]:
            return ToolDecision(tool_name=tool_name, allowed=False, reason_codes=["TOOL_SENSITIVITY_EXCEEDS_POLICY"], sanitized_arguments={})

        if envelope.content_classification and envelope.content_classification.label in {
            "prompt_injection",
            "jailbreak_attempt",
            "secret_exfiltration_intent",
            "exploit_or_malware_intent",
        }:
            return ToolDecision(tool_name=tool_name, allowed=False, reason_codes=["TOOL_BLOCKED_BY_CONTENT_CLASSIFICATION"], sanitized_arguments={})

        if self._arguments_contain_injection(arguments):
            return ToolDecision(
                tool_name=tool_name,
                allowed=False,
                reason_codes=["TOOL_ARGUMENT_INJECTION_DETECTED"],
                sanitized_arguments={},
            )

        if self._arguments_contain_tool_chain(arguments):
            return ToolDecision(
                tool_name=tool_name,
                allowed=False,
                reason_codes=["TOOL_CHAIN_INJECTION_DETECTED"],
                sanitized_arguments={},
            )

        return ToolDecision(
            tool_name=tool_name,
            allowed=True,
            reason_codes=["TOOL_ALLOWED"],
            sanitized_arguments=self._sanitize_arguments(arguments),
        )

    def _sanitize_arguments(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        sanitized = {}
        for key, value in arguments.items():
            if isinstance(value, str):
                sanitized[key] = value.replace("\x00", "").strip()[:1000]
            else:
                sanitized[key] = value
        return sanitized

    _ARGUMENT_INJECTION_PATTERNS = [
        r"ignore previous instructions",
        r"disregard.{0,20}(prior|previous|all).{0,20}(rules|instructions)",
        r"you are now\b",
        r"\bjailbreak\b",
        r"pretend you are",
        r"act as if you (are|have|were)",
    ]

    def _arguments_contain_injection(self, arguments: Dict[str, Any]) -> bool:
        """Return True if any string argument contains a prompt injection pattern."""
        for value in arguments.values():
            if isinstance(value, str):
                text = value.lower()
                if any(re.search(p, text) for p in self._ARGUMENT_INJECTION_PATTERNS):
                    return True
        return False

    def _arguments_contain_tool_chain(self, arguments: Dict[str, Any]) -> bool:
        chain_patterns = [
            r"\b(call|invoke|execute|run)\b.{0,30}\b(browser\.search|kb\.lookup|email\.send|ticket\.create)\b",
            r"\btool\s*:\s*[a-z0-9_\.]+",
            r"\bexecute_tool\s*\(",
            r"\bfunction_call\b",
        ]
        for value in arguments.values():
            if isinstance(value, str):
                text = value.lower()
                if any(re.search(p, text) for p in chain_patterns):
                    return True
        return False

    async def execute_allowed_tools(
        self,
        envelope: CanonicalRequestEnvelope,
        decisions: List[ToolDecision],
    ) -> List[ToolExecutionRecord]:
        requested_tools = envelope.metadata.get("requested_tools", [])
        decision_map = {d.tool_name: d for d in decisions}
        records: List[ToolExecutionRecord] = []

        for item in requested_tools:
            tool_name = item.get("name", "unknown")
            decision = decision_map.get(tool_name)

            if not decision or not decision.allowed:
                records.append(
                    ToolExecutionRecord(
                        tool_name=tool_name,
                        allowed=False,
                        reason_codes=decision.reason_codes if decision else ["TOOL_NOT_ALLOWED"],
                        arguments={},
                    )
                )
                continue

            # NEW: check if tool output would contain injection patterns
            # This is a preventive check for tool chaining attacks
            synthetic_output = str(decision.sanitized_arguments)
            if self._detect_tool_chain_injection(synthetic_output):
                records.append(
                    ToolExecutionRecord(
                        tool_name=tool_name,
                        allowed=False,
                        reason_codes=["TOOL_CHAIN_INJECTION_OUTPUT_DETECTED"],
                        arguments={},
                    )
                )
                continue

            tool_exec_record = ToolExecutionRecord(
                tool_name=tool_name,
                allowed=True,
                reason_codes=["TOOL_EXECUTION_STUB"],
                arguments=decision.sanitized_arguments,
            )
            records.append(tool_exec_record)

        return records

    def _detect_tool_chain_injection(self, tool_output: str) -> bool:
        """Detect if tool output contains tool invocation patterns (tool chaining attack)."""
        # Patterns that look like tool calls or instructions to call tools
        chain_patterns = [
            r"(call|invoke|execute).{0,20}(tool|function|api).{0,20}\(",
            r"(tool_name|function_name).*?[:=]\s*['\"]?\w+['\"]?",
            r"\b(tool|api)\.(\w+)\s*\(",
            r"(execute|run).{0,10}(command|tool|script).{0,10}['\"]",
        ]
        text = tool_output.lower()
        if any(re.search(p, text) for p in chain_patterns):
            return True
        return False
