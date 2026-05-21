"""
AI-powered root-cause hypothesis generator.

Sends each crash timeline to Claude and returns a concise SRE diagnosis.
Requires the 'anthropic' package and ANTHROPIC_API_KEY environment variable.
The feature degrades gracefully — the rest of the tool works without it.

Prompt caching is applied to the system message so repeated calls across
many crash events share the cached tokens rather than re-sending every time.
"""

from __future__ import annotations

import os
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from reconstructor import CrashEvent

_SYSTEM_PROMPT = (
    "You are an expert Site Reliability Engineer (SRE) analyzing server crash timelines.\n\n"
    "You will be given a sequence of HTTP requests made by a specific IP address, "
    "culminating in a server error (5xx).\n\n"
    "Provide a concise root-cause hypothesis in 2-3 sentences. Focus on:\n"
    "- The pattern in the request sequence that likely triggered the crash\n"
    "- The probable underlying technical cause (connection pool exhaustion, "
    "memory spike, lock contention, rate limiting, etc.)\n"
    "- One concrete thing the on-call engineer should check first\n\n"
    "Do NOT state 'the server crashed' — that is already known. "
    "Say WHY it likely crashed based on the evidence."
)


def _format_timeline(event: "CrashEvent") -> str:
    lines = [
        "CRASH REPORT",
        f"IP Address : {event.ip}",
        f"Crash      : {event.crash_method} {event.crash_path}"
        f" → HTTP {event.crash_status}"
        f" at {event.crash_ts or 'unknown time'}",
        "",
        "Request history leading to crash (oldest first):",
    ]
    for i, req in enumerate(event.preceding, 1):
        ms = f"{int(req['response_ms'])}ms" if req["response_ms"] is not None else "?ms"
        lines.append(
            f"  {i}. {req['method']} {req['path']}"
            f" → {req['status']} ({ms})"
        )
    lines.append(
        f"  CRASH: {event.crash_method} {event.crash_path} → {event.crash_status}"
    )
    return "\n".join(lines)


def create_client():
    """
    Return an Anthropic client if the package is installed and the API key is
    set.  Returns None silently so callers can skip AI analysis without error.
    """
    try:
        import anthropic  # noqa: PLC0415
    except ImportError:
        return None

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None

    return anthropic.Anthropic(api_key=api_key)


def analyze_crash(event: "CrashEvent", client) -> Optional[str]:
    """
    Send a single crash timeline to Claude Haiku and return the hypothesis.
    The system prompt is marked for caching — Anthropic reuses it across the
    batch of calls within the same session, cutting latency and token cost.
    """
    try:
        import anthropic  # noqa: PLC0415

        response = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=300,
            system=[
                {
                    "type": "text",
                    "text": _SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[
                {"role": "user", "content": _format_timeline(event)}
            ],
        )
        return response.content[0].text.strip()
    except anthropic.APIStatusError as exc:
        return f"[AI analysis failed: HTTP {exc.status_code}]"
    except Exception as exc:  # noqa: BLE001
        return f"[AI analysis unavailable: {exc}]"
