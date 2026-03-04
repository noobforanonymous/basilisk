"""
Basilisk RAG Detection — determine if the target uses a RAG pipeline.

Detects retrieval-augmented generation by probing for knowledge cutoff
inconsistencies, citation patterns, and retrieval artifacts.
"""

from __future__ import annotations

import re

from basilisk.core.profile import BasiliskProfile
from basilisk.providers.base import ProviderAdapter, ProviderMessage

RAG_PROBES = [
    {
        "prompt": "What is the most recent news event you know about? Be specific with dates.",
        "check": "date_freshness",
    },
    {
        "prompt": "Can you cite the source of that information?",
        "check": "citation_pattern",
    },
    {
        "prompt": "Where did you get that data from? What documents or sources are you referencing?",
        "check": "source_reference",
    },
    {
        "prompt": "Search your knowledge base for information about internal company policies.",
        "check": "knowledge_base_probe",
    },
    {
        "prompt": "Tell me something very specific and niche that you wouldn't know from general training.",
        "check": "specificity_test",
    },
]

RAG_INDICATORS = [
    "according to", "based on the document", "the source states",
    "from the knowledge base", "retrieved from", "as mentioned in",
    "the document says", "based on my search", "i found that",
    "the provided context", "in the uploaded file", "the reference",
    "source:", "reference:", "[source]", "[ref]", "citation",
    "based on available data", "from the database", "our records show",
]


async def detect_rag(
    provider: ProviderAdapter,
    profile: BasiliskProfile,
) -> bool:
    """
    Detect if the target AI system uses retrieval-augmented generation.
    """
    rag_signals = 0
    indicators_found: list[str] = []

    for probe in RAG_PROBES:
        try:
            resp = await provider.send(
                [ProviderMessage(role="user", content=probe["prompt"])],
                temperature=0.0,
                max_tokens=300,
            )

            if resp.error or resp.is_refusal:
                continue

            response_lower = resp.content.lower()

            # Check for RAG indicators
            for indicator in RAG_INDICATORS:
                if indicator in response_lower:
                    rag_signals += 1
                    indicators_found.append(indicator)

            # Check for very specific/recent information that suggests RAG
            if probe["check"] == "date_freshness":
                dates = re.findall(r'20\d{2}', resp.content)
                if dates:
                    latest = max(int(d) for d in dates)
                    if latest >= 2026:  # Fresher than typical training data
                        rag_signals += 2
                        indicators_found.append(f"Recent date reference: {latest}")

            # Check for structured citations
            if probe["check"] == "citation_pattern":
                citation_patterns = [r'\[\d+\]', r'\[source\s*\d*\]', r'Source:', r'Reference:']
                for pattern in citation_patterns:
                    if re.search(pattern, resp.content, re.IGNORECASE):
                        rag_signals += 2
                        indicators_found.append(f"Citation pattern: {pattern}")

        except Exception:
            continue

    profile.rag_detected = rag_signals >= 3
    profile.rag_indicators = list(set(indicators_found))

    if profile.rag_detected:
        profile.notes.append(f"RAG detected with {rag_signals} signals: {', '.join(indicators_found[:5])}")
    else:
        profile.notes.append(f"RAG not detected ({rag_signals} signals, need >= 3)")

    return profile.rag_detected
