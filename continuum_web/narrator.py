"""Bounded OpenAI narration for Continuum Studio.

Deterministic retrieval selects evidence first; GPT-5.6 may only turn that
evidence into plain language. It cannot unlock, classify, or modify a vault.
"""
from __future__ import annotations

import os
from typing import Iterable


class NarrationError(RuntimeError):
    """A recoverable failure from the optional narration service."""


def enabled(*, opted_in: bool) -> bool:
    """Narration requires both a configured key and explicit user consent."""
    return opted_in and bool(os.environ.get("OPENAI_API_KEY"))


def narrate(question: str, deterministic_answer: str, excerpts: Iterable[str]) -> str:
    """Narrate a core-selected result through the optional Agents SDK.

    The SDK uses the Responses API for OpenAI models.  This is deliberately a
    stateless, untraced single turn: selected evidence is the complete context,
    with no history, tools, or authority to ask the core for anything else.
    """
    if not os.environ.get("OPENAI_API_KEY"):
        raise NarrationError("OpenAI narration is not configured.")
    try:
        from agents import Agent, ModelSettings, RunConfig, Runner
    except ImportError as exc:
        raise NarrationError(
            "OpenAI narration needs the optional 'openai-agents' dependency."
        ) from exc
    evidence = "\n".join(f"- {item}" for item in excerpts)
    agent = Agent(
        name="Continuum narrator",
        model=os.environ.get("CONTINUUM_OPENAI_MODEL", "gpt-5.6"),
        model_settings=ModelSettings(store=False),
        instructions=(
            "You narrate a result already selected by Continuum's deterministic "
            "core. Use only the supplied deterministic result and evidence. Do "
            "not invent, omit, reorder, or add facts. Do not give legal, medical, "
            "or financial advice. Do not claim an access decision. If the result "
            "says no information was found, state that clearly and stop."
        ),
    )
    try:
        result = Runner.run_sync(
            agent,
            f"Question: {question}\n\nDeterministic result:\n{deterministic_answer}"
            f"\n\nSelected evidence:\n{evidence}",
            max_turns=1,
            run_config=RunConfig(tracing_disabled=True),
        )
    except Exception as exc:
        raise NarrationError("OpenAI narration is temporarily unavailable.") from exc
    if not result.final_output:
        raise NarrationError("OpenAI narration returned no text.")
    return str(result.final_output).strip()
