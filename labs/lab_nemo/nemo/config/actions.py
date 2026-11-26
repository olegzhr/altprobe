"""Deterministic NeMo Guardrails input rail for the lab.

The lab does not try to model a full safety classifier. It demonstrates that
NeMo Guardrails is the enforcement point: a small, explicit policy blocks
classic prompt-injection/jailbreak markers before the LLM is called.
"""
from nemoguardrails.actions import action

BLOCKED_MARKERS = (
    "ignore previous",
    "ignore all previous",
    "system prompt",
    "reveal your instructions",
    "jailbreak",
    "developer mode",
    "bypass safety",
)


@action(name="nemo_check_input_action")
async def nemo_check_input_action(context: dict | None = None):
    text = ""
    if isinstance(context, dict):
        text = str(context.get("user_message") or "")
    lowered = text.lower()
    return "block" if any(marker in lowered for marker in BLOCKED_MARKERS) else "allow"
