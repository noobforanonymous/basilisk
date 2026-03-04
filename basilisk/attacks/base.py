"""
Basilisk Attack Base — abstract interface for all attack modules.

Every attack module implements this interface to provide uniform access
from the scanner engine, enabling modular attack orchestration.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, AsyncIterator

import yaml

from basilisk.core.finding import AttackCategory, Finding, Message, Severity
from basilisk.core.profile import BasiliskProfile
from basilisk.core.session import ScanSession
from basilisk.providers.base import ProviderAdapter, ProviderMessage, ProviderResponse

logger = logging.getLogger("basilisk.attacks")


class BasiliskAttack(ABC):
    """
    Abstract base class for all Basilisk attack modules.

    Subclasses implement execute() to run their specific attack logic
    and generate_payloads() to produce attack payloads from YAML databases.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this attack module."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of the attack."""
        ...

    @property
    @abstractmethod
    def category(self) -> AttackCategory:
        """OWASP LLM Top 10 category mapping."""
        ...

    @property
    def severity_default(self) -> Severity:
        """Default severity for findings from this module."""
        return Severity.MEDIUM

    @property
    def rate_limit_delay(self) -> float:
        """Delay in seconds between requests for this module."""
        return 0.0

    @abstractmethod
    async def execute(
        self,
        provider: ProviderAdapter,
        session: ScanSession,
        profile: BasiliskProfile,
    ) -> list[Finding]:
        """
        Execute the attack against the target.

        Args:
            provider: The LLM provider adapter to send messages through
            session: Current scan session for persistence
            profile: Target profile from recon

        Returns:
            List of findings discovered during the attack
        """
        ...

    def generate_payloads(self) -> list[str]:
        """
        Generate attack payloads for this module.
        Can be overridden by subclasses to provide dynamic or file-based payloads.
        """
        return []

    def load_payloads(self, yaml_path: str | Path) -> list[dict[str, Any]]:
        """Load payloads from a YAML file."""
        path = Path(yaml_path)
        if not path.exists():
            logger.warning(f"Payload file not found: {path}")
            return []
        with open(path) as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, list) else []

    async def send_and_evaluate(
        self,
        provider: ProviderAdapter,
        payload: str,
        system_context: list[ProviderMessage] | None = None,
        temperature: float = 0.7,
    ) -> tuple[ProviderResponse, bool]:
        """
        Send a payload and evaluate if the response indicates success.

        Returns (response, is_interesting) tuple.
        """
        messages = list(system_context or [])
        messages.append(ProviderMessage(role="user", content=payload))

        if self.rate_limit_delay > 0:
            await asyncio.sleep(self.rate_limit_delay)

        resp = await provider.send(messages, temperature=temperature, max_tokens=2048)

        # A response is interesting if it's NOT a refusal and has substance
        is_interesting = (
            not resp.error
            and not resp.is_refusal
            and len(resp.content) > 20
        )

        return resp, is_interesting

    def create_finding(
        self,
        title: str,
        payload: str,
        response: str,
        severity: Severity | None = None,
        description: str = "",
        remediation: str = "",
        confidence: float = 0.8,
        conversation: list[Message] | None = None,
        evolution_gen: int | None = None,
    ) -> Finding:
        """Create a standardized finding."""
        return Finding(
            title=title,
            description=description,
            severity=severity or self.severity_default,
            category=self.category,
            attack_module=f"basilisk.attacks.{self.name}",
            payload=payload,
            response=response,
            conversation=conversation or [
                Message(role="user", content=payload),
                Message(role="assistant", content=response),
            ],
            evolution_generation=evolution_gen,
            confidence=confidence,
            remediation=remediation,
            references=[f"https://owasp.org/www-project-top-10-for-large-language-model-applications/ ({self.category.owasp_id})"],
        )


def get_all_attack_modules() -> list[BasiliskAttack]:
    """Import and instantiate all attack modules."""
    from basilisk.attacks.injection.direct import DirectInjection
    from basilisk.attacks.injection.indirect import IndirectInjection
    from basilisk.attacks.injection.multilingual import MultilingualInjection
    from basilisk.attacks.injection.encoding import EncodingInjection
    from basilisk.attacks.injection.split import SplitPayloadInjection
    from basilisk.attacks.extraction.role_confusion import RoleConfusionExtraction
    from basilisk.attacks.extraction.translation import TranslationExtraction
    from basilisk.attacks.extraction.simulation import SimulationExtraction
    from basilisk.attacks.extraction.gradient_walk import GradientWalkExtraction
    from basilisk.attacks.exfil.training_data import TrainingDataExfil
    from basilisk.attacks.exfil.rag_data import RAGDataExfil
    from basilisk.attacks.exfil.tool_schema import ToolSchemaExfil
    from basilisk.attacks.toolabuse.ssrf import SSRFToolAbuse
    from basilisk.attacks.toolabuse.sqli import SQLiToolAbuse
    from basilisk.attacks.toolabuse.command_injection import CommandInjectionToolAbuse
    from basilisk.attacks.toolabuse.chained import ChainedToolAbuse
    from basilisk.attacks.guardrails.roleplay import RoleplayBypass
    from basilisk.attacks.guardrails.encoding_bypass import EncodingBypass
    from basilisk.attacks.guardrails.logic_trap import LogicTrapBypass
    from basilisk.attacks.guardrails.systematic import SystematicBypass
    from basilisk.attacks.dos.token_exhaustion import TokenExhaustion
    from basilisk.attacks.dos.context_bomb import ContextBomb
    from basilisk.attacks.dos.loop_trigger import LoopTrigger
    from basilisk.attacks.multiturn.escalation import GradualEscalation
    from basilisk.attacks.multiturn.persona_lock import PersonaLock
    from basilisk.attacks.multiturn.memory_manipulation import MemoryManipulation
    from basilisk.attacks.rag.poisoning import RAGPoisoning
    from basilisk.attacks.rag.document_injection import DocumentInjection
    from basilisk.attacks.rag.knowledge_enum import KnowledgeBaseEnum

    return [
        DirectInjection(), IndirectInjection(), MultilingualInjection(),
        EncodingInjection(), SplitPayloadInjection(),
        RoleConfusionExtraction(), TranslationExtraction(),
        SimulationExtraction(), GradientWalkExtraction(),
        TrainingDataExfil(), RAGDataExfil(), ToolSchemaExfil(),
        SSRFToolAbuse(), SQLiToolAbuse(), CommandInjectionToolAbuse(),
        ChainedToolAbuse(),
        RoleplayBypass(), EncodingBypass(), LogicTrapBypass(), SystematicBypass(),
        TokenExhaustion(), ContextBomb(), LoopTrigger(),
        GradualEscalation(), PersonaLock(), MemoryManipulation(),
        RAGPoisoning(), DocumentInjection(), KnowledgeBaseEnum(),
    ]
