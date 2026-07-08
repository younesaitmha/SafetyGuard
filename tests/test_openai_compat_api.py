from app.models import SecurityContext


def _mock_security_context() -> SecurityContext:
    return SecurityContext(
        subject="user-1",
        user_id="user-1",
        tenant_id="tenant-a",
        roles=["user"],
        permissions=["llm:chat", "tool:kb.lookup"],
        auth_level="standard",
        step_up_authenticated=True,
        issuer="issuer",
        audience="aud",
        claims={},
    )


def test_openai_models_endpoint(client):
    response = client.get("/v1/models")

    assert response.status_code == 200
    payload = response.json()
    assert payload["object"] == "list"
    assert isinstance(payload["data"], list)
    assert len(payload["data"]) >= 1


def test_openai_chat_completions_happy_path(client, monkeypatch):
    async def mock_build_security_context(_authorization):
        return _mock_security_context()

    async def mock_forward_to_security_gateway(payload, trace_id, auth_header):
        return {"answer": "Hello from OpenAI-compatible endpoint."}

    async def mock_analyze_input(_envelope):
        return None

    async def mock_analyze_output(_text):
        return None

    monkeypatch.setattr("app.main.build_security_context", mock_build_security_context)
    monkeypatch.setattr("app.main.forward_to_security_gateway", mock_forward_to_security_gateway)
    monkeypatch.setattr("app.main.llm_guard.analyze_input", mock_analyze_input)
    monkeypatch.setattr("app.main.llm_guard.analyze_output", mock_analyze_output)

    response = client.post(
        "/v1/chat/completions",
        headers={"Authorization": "Bearer test"},
        json={
            "model": "qwen2.5",
            "messages": [{"role": "user", "content": "Hello"}],
            "stream": False,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["object"] == "chat.completion"
    assert payload["choices"][0]["message"]["content"] == "Hello from OpenAI-compatible endpoint."
    assert "usage" in payload


def test_openai_chat_completions_streaming_supported(client, monkeypatch):
    async def mock_build_security_context(_authorization):
        return _mock_security_context()

    async def mock_forward_to_security_gateway(payload, trace_id, auth_header):
        return {"answer": "Streaming response from SafetyGuard."}

    async def mock_analyze_input(_envelope):
        return None

    async def mock_analyze_output(_text):
        return None

    monkeypatch.setattr("app.main.build_security_context", mock_build_security_context)
    monkeypatch.setattr("app.main.forward_to_security_gateway", mock_forward_to_security_gateway)
    monkeypatch.setattr("app.main.llm_guard.analyze_input", mock_analyze_input)
    monkeypatch.setattr("app.main.llm_guard.analyze_output", mock_analyze_output)

    response = client.post(
        "/v1/chat/completions",
        headers={"Authorization": "Bearer test"},
        json={
            "model": "qwen2.5",
            "messages": [{"role": "user", "content": "Hello"}],
            "stream": True,
        },
    )

    assert response.status_code == 200
    assert "text/event-stream" in response.headers.get("content-type", "")
    assert "chat.completion.chunk" in response.text
    assert "[DONE]" in response.text
