from app.llm_guard import OpenSourceLLMGuard


def test_parse_json_from_markdown_fence():
    guard = OpenSourceLLMGuard()
    raw = '''```json
{"label":"benign","confidence":0.9,"risk_score":10,"reasons":["ok"],"recommended_action":"allow"}
```'''

    parsed = guard._parse_json(raw)

    assert parsed["label"] == "benign"
    assert parsed["recommended_action"] == "allow"


def test_parse_json_from_embedded_object():
    guard = OpenSourceLLMGuard()
    raw = "Result below:\n{\"label\":\"jailbreak_attempt\",\"confidence\":0.88,\"risk_score\":82,\"reasons\":[\"unsafe\"],\"recommended_action\":\"deny\"}\nThanks"

    parsed = guard._parse_json(raw)

    assert parsed["label"] == "jailbreak_attempt"
    assert parsed["recommended_action"] == "deny"


def test_non_json_fallback_normalization():
    guard = OpenSourceLLMGuard()
    raw = "UNSAFE. Prompt injection attempt detected. Recommended action: deny. Category: LLM01"

    parsed = guard._parse_json(raw)
    normalized = guard._normalize_payload(parsed)

    assert normalized["label"] in {"prompt_injection", "unsafe_output", "jailbreak_attempt"}
    assert normalized["recommended_action"] in {"deny", "block"}
    assert normalized["risk_score"] >= 70
