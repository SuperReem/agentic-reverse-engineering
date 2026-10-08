from langchain_core.messages import HumanMessage

from binary_insight import agents


def test_tool_requests_use_responses_api(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key-not-used-for-network")
    agents.get_model.cache_clear()
    try:
        model = agents.get_model()
        tool = {
            "type": "function",
            "function": {
                "name": "inspect_binary",
                "description": "Inspect metadata",
                "parameters": {"type": "object", "properties": {}},
            },
        }
        bound = model.bind_tools([tool])
        payload = model._get_request_payload([HumanMessage(content="Inspect the binary")], **bound.kwargs)
        assert model.use_responses_api is True
        assert model._use_responses_api(payload)
        assert "input" in payload and "messages" not in payload
        assert payload["tools"][0]["name"] == "inspect_binary"
        assert "temperature" not in payload
        # Structured reports share this same configured Responses client.
        assert model.with_structured_output(agents.AnalysisResult, include_raw=True) is not None
    finally:
        agents.get_model.cache_clear()
