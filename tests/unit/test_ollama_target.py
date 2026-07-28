from unittest.mock import MagicMock, patch

from argus.targets.ollama_target import OllamaTarget


def test_name_includes_model():
    target = OllamaTarget(model="llama3")
    assert target.name == "ollama/llama3"


@patch("argus.targets.ollama_target.httpx.post")
def test_send_posts_prompt_and_returns_response_text(mock_post):
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"response": "hello there"}
    mock_post.return_value = mock_resp

    target = OllamaTarget(model="qwen2.5:7b", system_prompt="be terse")
    result = target.send("hi")

    assert result == "hello there"
    _, kwargs = mock_post.call_args
    assert kwargs["json"]["model"] == "qwen2.5:7b"
    assert kwargs["json"]["prompt"] == "hi"
    assert kwargs["json"]["system"] == "be terse"
    assert kwargs["json"]["stream"] is False


@patch("argus.targets.ollama_target.httpx.post")
def test_send_omits_system_key_when_not_set(mock_post):
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"response": "ok"}
    mock_post.return_value = mock_resp

    target = OllamaTarget(model="llama3")
    target.send("hi")

    _, kwargs = mock_post.call_args
    assert "system" not in kwargs["json"]
