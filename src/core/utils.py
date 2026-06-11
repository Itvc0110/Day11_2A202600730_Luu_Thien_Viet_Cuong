"""
Lab 11 - Helper Utilities
"""
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass

try:
    from google.genai import types
except ImportError:  # Allows deterministic guardrail tests without ADK/GenAI.
    class _Part:
        def __init__(self, text=""):
            self.text = text

        @classmethod
        def from_text(cls, text):
            return cls(text=text)

    class _Content:
        def __init__(self, role=None, parts=None):
            self.role = role
            self.parts = parts or []

    class _Types:
        Content = _Content
        Part = _Part

    types = _Types()

from core.config import OPENROUTER_BASE_URL, OPENROUTER_MODEL


@dataclass
class OpenRouterAgent:
    """Tiny agent object for OpenRouter-backed local runs."""

    name: str
    instruction: str
    model: str = OPENROUTER_MODEL


@dataclass
class OpenRouterRunner:
    """Tiny runner object that mirrors the fields used by chat_with_agent()."""

    agent: OpenRouterAgent
    app_name: str
    plugins: list
    use_openrouter: bool = True


def _extract_text_from_content(content) -> str:
    """Extract text from ADK/GenAI Content-like objects."""
    text = ""
    if content and getattr(content, "parts", None):
        for part in content.parts:
            part_text = getattr(part, "text", "")
            if part_text:
                text += part_text
    return text


async def openrouter_chat(
    system_prompt: str,
    user_message: str,
    model: str = OPENROUTER_MODEL,
    temperature: float = 0.0,
    max_tokens: int = 512,
) -> str:
    """Call OpenRouter's OpenAI-compatible chat completions endpoint.

    This is intentionally small and dependency-free so the arena can use the
    strongest allowed Gemini 2.5 Flash Lite path without changing frameworks.
    """
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY is required for OpenRouter LLM calls.")

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        OPENROUTER_BASE_URL,
        data=data,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": os.getenv("OPENROUTER_SITE_URL", "http://localhost"),
            "X-Title": os.getenv("OPENROUTER_APP_TITLE", "Day 11 Guardrails VinBank"),
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"OpenRouter request failed: {exc.code} {detail}") from exc

    return body["choices"][0]["message"].get("content", "")


async def _run_input_plugins(runner, user_message: str):
    """Run OpenRouter-mode input plugins before the model call."""
    content = types.Content(
        role="user",
        parts=[types.Part.from_text(text=user_message)],
    )

    for plugin in getattr(runner, "plugins", []) or []:
        callback = getattr(plugin, "on_user_message_callback", None)
        if callback is None:
            continue
        blocked = await callback(invocation_context=None, user_message=content)
        if blocked is not None:
            return _extract_text_from_content(blocked), getattr(plugin, "name", "input_plugin")
    return None, None


async def _run_output_plugins(runner, response_text: str) -> str:
    """Run OpenRouter-mode output plugins after the model call."""
    class SimpleResponse:
        pass

    llm_response = SimpleResponse()
    llm_response.content = types.Content(
        role="model",
        parts=[types.Part.from_text(text=response_text)],
    )

    plugins = getattr(runner, "plugins", []) or []
    ordered_plugins = [
        plugin for plugin in plugins if getattr(plugin, "name", "") != "audit_log"
    ] + [
        plugin for plugin in plugins if getattr(plugin, "name", "") == "audit_log"
    ]
    for plugin in ordered_plugins:
        callback = getattr(plugin, "after_model_callback", None)
        if callback is None:
            continue
        updated = await callback(callback_context=None, llm_response=llm_response)
        if updated is not None:
            llm_response = updated
    return _extract_text_from_content(llm_response.content)


async def chat_with_agent(agent, runner, user_message: str, session_id=None):
    """Send a message to an ADK or OpenRouter-backed agent.

    Args:
        agent: The LlmAgent/OpenRouterAgent instance
        runner: The InMemoryRunner/OpenRouterRunner instance
        user_message: Plain text message to send
        session_id: Optional session ID to continue a conversation

    Returns:
        Tuple of (response_text, session)
    """
    if getattr(runner, "use_openrouter", False):
        blocked, blocked_by = await _run_input_plugins(runner, user_message)
        if blocked is not None:
            for plugin in getattr(runner, "plugins", []) or []:
                marker = getattr(plugin, "mark_blocked", None)
                if marker is not None:
                    marker(user_id="anonymous", blocked_by=blocked_by)
            blocked = await _run_output_plugins(runner, blocked)
            return blocked, None
        response = await openrouter_chat(
            system_prompt=agent.instruction,
            user_message=user_message,
            model=getattr(agent, "model", OPENROUTER_MODEL),
        )
        response = await _run_output_plugins(runner, response)
        return response, None

    user_id = "student"
    app_name = runner.app_name

    session = None
    if session_id is not None:
        try:
            session = await runner.session_service.get_session(
                app_name=app_name, user_id=user_id, session_id=session_id
            )
        except (ValueError, KeyError):
            pass

    if session is None:
        try:
            session = await runner.session_service.create_session(
                app_name=app_name, user_id=user_id
            )
        except Exception:
            session = await runner.session_service.create_session(
                app_name=app_name, user_id=user_id
            )

    content = types.Content(
        role="user",
        parts=[types.Part.from_text(text=user_message)],
    )

    final_response = ""
    async for event in runner.run_async(
        user_id=user_id, session_id=session.id, new_message=content
    ):
        if hasattr(event, "content") and event.content and event.content.parts:
            for part in event.content.parts:
                if hasattr(part, "text") and part.text:
                    final_response += part.text

    return final_response, session
