from __future__ import annotations

from autosecaudit.integrations.llm_router import (
    LLMRouterError,
    LLMProviderConfig,
    LLMRequestConfig,
    LLMRouter,
    OpenAICompatibleProvider,
    extract_text_from_openai_compatible_response,
)


def _provider() -> OpenAICompatibleProvider:
    return OpenAICompatibleProvider(
        LLMProviderConfig(
            name="test",
            provider_type="openai_compatible",
            base_url="https://api.example.test/v1",
            timeout_seconds=10.0,
        ),
        LLMRequestConfig(),
    )


def test_openai_compatible_extractor_supports_reasoning_content_fallback() -> None:
    provider = _provider()

    text = provider._extract_text_from_openai_compatible_response(  # noqa: SLF001
        {
            "choices": [
                {
                    "message": {
                        "content": None,
                        "reasoning_content": '{"tools":["nmap_scan"]}',
                    }
                }
            ]
        }
    )

    assert text == '{"tools":["nmap_scan"]}'


def test_openai_compatible_extract_function_returns_meta_for_reasoning_fallback() -> None:
    text, meta = extract_text_from_openai_compatible_response(
        {
            "choices": [
                {
                    "message": {
                        "content": "",
                        "reasoning_content": '{"tools":["waf_detector"]}',
                    }
                }
            ]
        }
    )

    assert text == '{"tools":["waf_detector"]}'
    assert meta["source"] == "choices[0].message.reasoning_content"
    assert meta["is_empty"] is False
    assert meta["length"] == len(text)


def test_openai_compatible_extractor_prefers_content_over_reasoning_content() -> None:
    provider = _provider()

    text = provider._extract_text_from_openai_compatible_response(  # noqa: SLF001
        {
            "choices": [
                {
                    "message": {
                        "content": '{"tools":["dynamic_crawl"]}',
                        "reasoning_content": '{"tools":["nmap_scan"]}',
                    }
                }
            ]
        }
    )

    assert text == '{"tools":["dynamic_crawl"]}'


def test_openai_compatible_extractor_supports_text_value_content_blocks() -> None:
    provider = _provider()

    text = provider._extract_text_from_openai_compatible_response(  # noqa: SLF001
        {
            "choices": [
                {
                    "message": {
                        "content": [
                            {"type": "output_text", "text": {"value": '{"tools":["dynamic_crawl"]}'}}
                        ]
                    }
                }
            ]
        }
    )

    assert text == '{"tools":["dynamic_crawl"]}'


def test_openai_compatible_extractor_supports_choice_text_mode() -> None:
    provider = _provider()

    text = provider._extract_text_from_openai_compatible_response(  # noqa: SLF001
        {
            "choices": [
                {
                    "text": '{"tools":["deepseek-chat"]}',
                }
            ]
        }
    )

    assert text == '{"tools":["deepseek-chat"]}'


def test_openai_compatible_extractor_supports_nested_gateway_wrappers() -> None:
    provider = _provider()

    text = provider._extract_text_from_openai_compatible_response(  # noqa: SLF001
        {
            "data": {
                "choices": [
                    {
                        "message": {
                            "content": "wrapped response"
                        }
                    }
                ]
            }
        }
    )

    assert text == "wrapped response"


def test_openai_compatible_extractor_supports_gemini_like_candidates() -> None:
    provider = _provider()

    text = provider._extract_text_from_openai_compatible_response(  # noqa: SLF001
        {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {"text": '{"tools":["api_schema_discovery"]}'}
                        ]
                    }
                }
            ]
        }
    )

    assert text == '{"tools":["api_schema_discovery"]}'


def test_openai_compatible_empty_text_error_includes_response_summary() -> None:
    provider = _provider()
    summary = provider._summarize_response_payload(  # noqa: SLF001
        {
            "choices": [
                {
                    "finish_reason": "length",
                    "message": {"content": None, "reasoning": None},
                }
            ],
            "usage": {"completion_tokens": 1200},
        }
    )

    assert '"choices_count":1' in summary
    assert '"finish_reason":"length"' in summary
    assert '"usage_keys":["completion_tokens"]' in summary


def test_openai_compatible_generate_text_reports_response_summary_on_empty_content(monkeypatch) -> None:
    provider = _provider()

    class _FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            return b'{"choices":[{"finish_reason":"stop","message":{"content":null}}],"usage":{"completion_tokens":0}}'

    monkeypatch.setattr("urllib.request.urlopen", lambda request, timeout: _FakeResponse())

    try:
        provider.generate_text("demo-model", "demo prompt")
    except LLMRouterError as exc:
        message = str(exc)
    else:
        raise AssertionError("expected LLMRouterError")

    assert "response_summary=" in message
    assert '"choices_count":1' in message
    assert '"finish_reason":"stop"' in message


def test_openai_compatible_empty_text_logs_safe_debug_summary(monkeypatch) -> None:
    captured: list[str] = []

    class _Logger:
        def warning(self, message, *args):
            captured.append(str(message) % args if args else str(message))

    provider = OpenAICompatibleProvider(
        LLMProviderConfig(
            name="deepseek",
            provider_type="openai_compatible",
            base_url="https://api.deepseek.com/v1",
            timeout_seconds=10.0,
        ),
        LLMRequestConfig(),
        logger=_Logger(),
    )

    class _FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self) -> bytes:
            return (
                b'{"choices":[{"finish_reason":"stop","message":{"content":"","reasoning_content":""}}]}'
            )

    monkeypatch.setattr("urllib.request.urlopen", lambda request, timeout: _FakeResponse())

    try:
        provider.generate_text("deepseek-reasoner", "demo prompt")
    except LLMRouterError:
        pass
    else:
        raise AssertionError("expected LLMRouterError")

    assert captured
    assert "provider=deepseek" in captured[0]
    assert "model=deepseek-reasoner" in captured[0]
    assert "base_url=https://api.deepseek.com/v1" in captured[0]
    assert '"choices_count":1' in captured[0]


def test_router_auto_adds_deepseek_chat_fallback_and_uses_it(monkeypatch) -> None:
    messages: list[str] = []

    class _Logger:
        def info(self, message, *args):
            messages.append(str(message) % args if args else str(message))

        def warning(self, message, *args):
            messages.append(str(message) % args if args else str(message))

    router = LLMRouter.from_dict(
        {
            "primary_model": "deepseek-reasoner",
            "default_provider": "openai",
            "providers": {
                "openai": {
                    "type": "openai_compatible",
                    "base_url": "https://api.deepseek.com/v1",
                }
            },
        },
        logger=_Logger(),
    )

    assert router.config.fallback_models == ["openai/deepseek-chat"]

    class _FakeProvider:
        def generate_text(self, model: str, prompt: str) -> str:
            del prompt
            if model == "deepseek-reasoner":
                raise LLMRouterError("openai returned empty completion text")
            if model == "deepseek-chat":
                return '{"tools":["api_schema_discovery"]}'
            raise AssertionError(f"unexpected model {model}")

    monkeypatch.setattr(router, "_get_provider", lambda provider_name: _FakeProvider())

    result = router.complete("demo prompt")

    assert result == '{"tools":["api_schema_discovery"]}'
    assert any("trying fallback openai/deepseek-chat" in item for item in messages)
