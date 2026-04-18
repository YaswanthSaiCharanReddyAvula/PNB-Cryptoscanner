"""
QuantumShield — AI-Driven Adaptive Intelligence Engine (Stage 17)

Uses the existing LM Studio LLM (lm_studio_client.py) to make real-time
scan decisions after each pipeline stage.  The LLM suggests structured
JSON actions validated against a whitelist.  Falls back silently when
the LLM is unreachable.
"""

from __future__ import annotations

import json
import time
from typing import Any

from app.scanner.models import AdaptiveAction, AdaptiveDecisionLog, StageResult
from app.utils.logger import get_logger

logger = get_logger(__name__)

ALLOWED_ACTIONS = frozenset({
    "escalate_scan_depth",
    "add_target_paths",
    "add_target_ports",
    "enable_full_cipher_enum",
    "enable_browser_scan",
    "flag_for_deep_fuzz",
    "skip_host",
    "increase_crawl_depth",
    "probe_graphql",
    "test_auth_bypass",
})

SYSTEM_PROMPT = """You are a cybersecurity scanning advisor inside the QuantumShield scanner.
You receive findings from a domain intelligence scan in progress.
Your job: decide what additional probing actions to take based on what was found.

RULES:
- Respond with valid JSON ONLY — no markdown, no explanation.
- Only suggest actions from the ALLOWED list.
- Each action must have a "reason" explaining why.
- Be specific: include the host, port, or path the action applies to.
- Do NOT suggest actions outside the authorized scope.
- If nothing interesting, return {"analysis":"nothing notable","actions":[]}.

ALLOWED ACTIONS: {allowed}

RESPONSE FORMAT:
{{"analysis":"<1-2 sentence assessment>","risk_level":"low|medium|high|critical","actions":[{{"action":"<name>","target":"<host or path>","reason":"<why>","priority":1}}]}}"""


class AIAdaptiveEngine:
    """
    Not a pipeline stage — a hook called after each stage by PipelineManager.
    """

    def __init__(self) -> None:
        self.decision_log: list[dict] = []

    async def analyze_and_decide(
        self,
        stage_name: str,
        findings_summary: dict,
        context_summary: dict,
    ) -> list[AdaptiveAction]:
        from app.modules.lm_studio_client import chat_completion_safe

        user_msg = (
            f"Stage '{stage_name}' completed.\n\n"
            f"Domain: {context_summary.get('domain', 'unknown')}\n"
            f"Assets found: {context_summary.get('asset_count', 0)}\n"
            f"Open ports: {context_summary.get('total_open_ports', 0)}\n\n"
            f"Key findings:\n{json.dumps(findings_summary, indent=2, default=str)[:3000]}"
        )

        system = SYSTEM_PROMPT.format(allowed=", ".join(sorted(ALLOWED_ACTIONS)))

        raw = await chat_completion_safe(
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user_msg},
            ],
            fallback='{"analysis":"LLM unavailable","actions":[]}',
        )

        actions = self._parse(raw)

        self.decision_log.append(AdaptiveDecisionLog(
            stage=stage_name,
            findings_summary_hash=str(hash(json.dumps(findings_summary, default=str)))[:16],
            llm_raw_response=raw[:2000],
            parsed_actions=actions,
            actions_executed=[a.action for a in actions],
            actions_rejected=[],
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        ).model_dump())

        return actions

    @staticmethod
    def _parse(raw: str) -> list[AdaptiveAction]:
        try:
            cleaned = raw.strip()
            if cleaned.startswith("```"):
                cleaned = cleaned.split("\n", 1)[1].rsplit("```", 1)[0]
            data = json.loads(cleaned)
        except (json.JSONDecodeError, IndexError, ValueError):
            return []

        result: list[AdaptiveAction] = []
        analysis = data.get("analysis", "")
        for item in data.get("actions", []):
            action_name = item.get("action", "")
            if action_name not in ALLOWED_ACTIONS:
                continue
            result.append(AdaptiveAction(
                action=action_name,
                target=str(item.get("target", "")),
                reason=str(item.get("reason", "")),
                priority=int(item.get("priority", 5)),
                llm_analysis=analysis,
            ))
        return sorted(result, key=lambda a: a.priority)
