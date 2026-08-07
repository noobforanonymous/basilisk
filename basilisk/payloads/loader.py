"""
Basilisk Probe Loader — unified access to the YAML payload database.

Loads, indexes, and filters probe payloads across all YAML files
in the payloads directory. Supports filtering by category, tags,
severity, and free-text search.
"""

from __future__ import annotations

import logging
import hashlib
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("basilisk.payloads")

PAYLOADS_DIR = Path(__file__).parent
CORPUS_SCHEMA_VERSION = "3"


@dataclass(frozen=True)
class ProbeMessage:
    """One immutable role/content item in a fabricated-history probe."""

    role: str
    content: str


@dataclass(frozen=True)
class ProbeTurn:
    """One structured turn in a canonical multi-turn probe sequence."""

    content: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"content": self.content, **deepcopy(self.metadata)}


@dataclass(frozen=True)
class ProbeSequence:
    """Structured scenario data used by advanced multi-turn modules."""

    name: str
    description: str
    turns: tuple[ProbeTurn, ...]
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_scenario(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            **deepcopy(self.attributes),
            "turns": [turn.to_dict() for turn in self.turns],
        }


@dataclass(frozen=True)
class Probe:
    """A single attack probe from the payload database."""
    id: str
    name: str
    payload: str
    turns: tuple[str, ...] = ()
    messages: tuple[ProbeMessage, ...] = ()
    sequence: ProbeSequence | None = None
    signals: list[str] = field(default_factory=list)
    severity: str = "high"
    tags: list[str] = field(default_factory=list)
    category: str = ""
    subcategory: str = ""
    objective: str = ""
    expected_signals: list[str] = field(default_factory=list)
    negative_signals: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    target_archetypes: list[str] = field(default_factory=list)
    tool_requirements: list[str] = field(default_factory=list)
    success_criteria: list[str] = field(default_factory=list)
    failure_modes: list[str] = field(default_factory=list)
    follow_up_probe_ids: list[str] = field(default_factory=list)
    owasp_id: str = ""
    verification_steps: list[str] = field(default_factory=list)
    expected_false_positives: list[str] = field(default_factory=list)
    request_cost: int = 1
    safety_classification: str = "bounded"
    version: str = "1"

    def matches_filter(
        self,
        category: str = "",
        tags: list[str] | None = None,
        severity: str = "",
        query: str = "",
    ) -> bool:
        """Check if this probe matches the given filter criteria."""
        if category and self.category.lower() != category.lower():
            return False
        if severity and self.severity.lower() != severity.lower():
            return False
        if tags and not set(tags) & set(self.tags):
            return False
        if query:
            q = query.lower()
            sequence_text = " ".join(self.turns) + " " + " ".join(
                message.content for message in self.messages
            )
            searchable = f"{self.id} {self.name} {self.payload} {sequence_text}".lower()
            if q not in searchable:
                return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "payload": self.payload,
            "turns": list(self.turns),
            "messages": [
                {"role": message.role, "content": message.content}
                for message in self.messages
            ],
            "sequence": self.sequence.to_scenario() if self.sequence else None,
            "signals": self.signals,
            "severity": self.severity,
            "tags": self.tags,
            "category": self.category,
            "subcategory": self.subcategory,
            "objective": self.objective,
            "expected_signals": self.expected_signals,
            "negative_signals": self.negative_signals,
            "preconditions": self.preconditions,
            "target_archetypes": self.target_archetypes,
            "tool_requirements": self.tool_requirements,
            "success_criteria": self.success_criteria,
            "failure_modes": self.failure_modes,
            "follow_up_probe_ids": self.follow_up_probe_ids,
            "owasp_id": self.owasp_id,
            "verification_steps": self.verification_steps,
            "expected_false_positives": self.expected_false_positives,
            "request_cost": self.request_cost,
            "safety_classification": self.safety_classification,
            "version": self.version,
        }


# Category → OWASP mapping
_CATEGORY_MAP: dict[str, tuple[str, str]] = {
    "injection": ("Prompt Injection", "LLM01"),
    "extraction": ("Sensitive Information Disclosure", "LLM06"),
    "exfiltration": ("Sensitive Information Disclosure", "LLM06"),
    "guardrails": ("Improper Output Handling", "LLM02"),
    "toolabuse": ("Excessive Agency", "LLM08"),
    "multiturn_rag": ("Insecure Plugin Design", "LLM07"),
    "dos": ("Denial of Service", "LLM04"),
    "multiturn": ("Overreliance", "LLM09"),
    "multimodal": ("Prompt Injection", "LLM01"),
}


def _infer_category(filename: str) -> tuple[str, str, str]:
    """Infer category, pretty name, and OWASP ID from filename."""
    stem = Path(filename).stem
    if stem in _CATEGORY_MAP:
        pretty, owasp = _CATEGORY_MAP[stem]
        return stem, pretty, owasp
    return stem, stem.replace("_", " ").title(), ""


def _load_file(path: Path) -> list[Probe]:
    """Load probes from a single YAML file."""
    try:
        data = yaml.safe_load(path.read_text("utf-8"))
    except Exception as e:
        logger.warning(f"Failed to load {path}: {e}")
        return []

    if not isinstance(data, list):
        return []

    category, _, owasp_id = _infer_category(path.name)
    probes: list[Probe] = []

    for entry in data:
        if not isinstance(entry, dict):
            continue
        try:
            sequence = _as_probe_sequence(entry.get("sequence"))
            simple_turns = tuple(_as_str_list(entry.get("turns", [])))
            if not simple_turns and sequence:
                simple_turns = tuple(turn.content for turn in sequence.turns)
            payload = str(entry.get("payload", ""))
            if not payload and sequence:
                payload = sequence.turns[-1].content
            probe = Probe(
                id=str(entry.get("id", "")),
                name=str(entry.get("name", "")),
                payload=payload,
                turns=simple_turns,
                messages=_as_probe_messages(entry.get("messages", [])),
                sequence=sequence,
                signals=entry.get("signals", []),
                severity=str(entry.get("severity", "high")),
                tags=entry.get("tags", []),
                category=category,
                subcategory=str(entry.get("category", "")),
                objective=str(entry.get("objective", "")),
                expected_signals=_as_str_list(entry.get("expected_signals", entry.get("signals", []))),
                negative_signals=_as_str_list(entry.get("negative_signals", [])),
                preconditions=_as_str_list(entry.get("preconditions", [])),
                target_archetypes=_as_str_list(entry.get("target_archetypes", [])),
                tool_requirements=_as_str_list(entry.get("tool_requirements", [])),
                success_criteria=_as_str_list(entry.get("success_criteria", [])),
                failure_modes=_as_str_list(entry.get("failure_modes", [])),
                follow_up_probe_ids=_as_str_list(entry.get("follow_up_probe_ids", [])),
                owasp_id=owasp_id,
                verification_steps=_as_str_list(entry.get("verification_steps", [])),
                expected_false_positives=_as_str_list(entry.get("expected_false_positives", [])),
                request_cost=max(1, int(entry.get("request_cost", 1))),
                safety_classification=str(entry.get("safety_classification", "bounded")),
                version=str(entry.get("version", "1")),
            )
            if probe.id and (probe.payload or probe.turns or probe.messages or probe.sequence):
                probes.append(probe)
        except Exception as e:
            logger.debug(f"Skipping malformed entry in {path}: {e}")

    return probes


def _as_probe_messages(value: Any) -> tuple[ProbeMessage, ...]:
    if not isinstance(value, list):
        return ()
    messages: list[ProbeMessage] = []
    allowed_roles = {"system", "user", "assistant", "tool"}
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("probe messages must contain role/content mappings")
        role = str(item.get("role", "")).strip().casefold()
        content = str(item.get("content", ""))
        if role not in allowed_roles or not content:
            raise ValueError("probe message role/content is invalid")
        messages.append(ProbeMessage(role=role, content=content))
    return tuple(messages)


def _as_probe_sequence(value: Any) -> ProbeSequence | None:
    if value in (None, ""):
        return None
    if not isinstance(value, dict):
        raise ValueError("probe sequence must be a mapping")
    name = str(value.get("name", "")).strip()
    description = str(value.get("description", "")).strip()
    raw_turns = value.get("turns", [])
    if not name or not description or not isinstance(raw_turns, list) or not raw_turns:
        raise ValueError("probe sequence requires name, description, and turns")
    turns: list[ProbeTurn] = []
    for raw_turn in raw_turns:
        if not isinstance(raw_turn, dict):
            raise ValueError("structured probe turns must be mappings")
        content = str(raw_turn.get("content", ""))
        if not content:
            raise ValueError("structured probe turn content is required")
        metadata = {
            str(key): deepcopy(item)
            for key, item in raw_turn.items()
            if key != "content"
        }
        turns.append(ProbeTurn(content=content, metadata=metadata))
    attributes = {
        str(key): deepcopy(item)
        for key, item in value.items()
        if key not in {"name", "description", "turns"}
    }
    return ProbeSequence(
        name=name,
        description=description,
        turns=tuple(turns),
        attributes=attributes,
    )


# ── Module-level cache ──

_cache: list[Probe] | None = None


def load_probes(
    *,
    category: str = "",
    tags: list[str] | None = None,
    severity: str = "",
    query: str = "",
    force_reload: bool = False,
) -> list[Probe]:
    """Load all probes from the payloads directory, with optional filtering.

    Results are cached after the first call. Use force_reload=True
    to re-read from disk.

    Args:
        category: Filter by category (e.g. "injection", "dos").
        tags: Filter by tags (matches any).
        severity: Filter by severity (critical, high, medium, low).
        query: Free-text search across id, name, payload.
        force_reload: Force re-read from disk.

    Returns:
        List of matching Probe objects.
    """
    global _cache
    if _cache is None or force_reload:
        _cache = []
        for yaml_file in sorted(PAYLOADS_DIR.glob("*.yaml")):
            _cache.extend(_load_file(yaml_file))
        logger.info(f"Loaded {len(_cache)} probes from {PAYLOADS_DIR}")

    if not category and not tags and not severity and not query:
        return list(_cache)

    return [p for p in _cache if p.matches_filter(category, tags, severity, query)]


def load_probes_by_id(probe_ids: list[str], *, strict: bool = False) -> list[Probe]:
    """Resolve stable probe identifiers while preserving the manifest order."""
    index: dict[str, Probe] = {}
    duplicates: set[str] = set()
    for probe in load_probes():
        if probe.id in index:
            duplicates.add(probe.id)
        index[probe.id] = probe
    if duplicates:
        raise ValueError(f"Duplicate canonical probe IDs: {', '.join(sorted(duplicates))}")
    missing = [probe_id for probe_id in probe_ids if probe_id not in index]
    if strict and missing:
        raise ValueError(f"Unknown canonical probe IDs: {', '.join(missing)}")
    return [index[probe_id] for probe_id in probe_ids if probe_id in index]


def load_probe_scenarios(probe_ids: list[str]) -> list[dict[str, Any]]:
    """Return validated structured scenarios for canonical probe identifiers."""
    probes = load_probes_by_id(probe_ids, strict=True)
    missing = [probe.id for probe in probes if probe.sequence is None]
    if missing:
        raise ValueError(
            "Canonical probes do not define structured sequences: "
            + ", ".join(missing)
        )
    return [probe.sequence.to_scenario() for probe in probes if probe.sequence]


def probe_corpus_version() -> str:
    """Content-addressed corpus identity for reproducible evidence."""
    digest = hashlib.sha256()
    digest.update(f"schema:{CORPUS_SCHEMA_VERSION}\n".encode())
    for yaml_file in sorted(PAYLOADS_DIR.glob("*.yaml")):
        digest.update(yaml_file.name.encode())
        digest.update(b"\0")
        digest.update(yaml_file.read_bytes())
        digest.update(b"\0")
    return f"{CORPUS_SCHEMA_VERSION}-{digest.hexdigest()[:16]}"


def probe_stats() -> dict[str, Any]:
    """Get aggregate statistics about the probe database."""
    probes = load_probes()

    by_category: dict[str, int] = {}
    by_subcategory: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    all_tags: dict[str, int] = {}

    for p in probes:
        by_category[p.category] = by_category.get(p.category, 0) + 1
        if p.subcategory:
            by_subcategory[p.subcategory] = by_subcategory.get(p.subcategory, 0) + 1
        by_severity[p.severity] = by_severity.get(p.severity, 0) + 1
        for tag in p.tags:
            all_tags[tag] = all_tags.get(tag, 0) + 1

    return {
        "total": len(probes),
        "by_category": dict(sorted(by_category.items(), key=lambda x: -x[1])),
        "by_subcategory": dict(sorted(by_subcategory.items(), key=lambda x: -x[1])),
        "by_severity": dict(sorted(by_severity.items(), key=lambda x: -x[1])),
        "top_tags": dict(sorted(all_tags.items(), key=lambda x: -x[1])[:20]),
        "categories": sorted(by_category.keys()),
    }


def probes_as_seed_population(
    *,
    category: str = "",
    severity: str = "",
    tags: list[str] | None = None,
    limit: int = 100,
) -> list[str]:
    """Extract probe payloads as seed population for the evolution engine.

    Returns a deduplicated list of probe payload strings suitable for
    initializing a genetic population. Dedup uses SHA256 of the
    stripped, lowercased payload text.

    Args:
        category: Filter by category (e.g. "injection").
        severity: Filter by severity (e.g. "critical").
        tags: Filter by tags (matches any).
        limit: Maximum number of seeds to return.

    Returns:
        List of unique payload strings.
    """
    import hashlib

    probes = load_probes(category=category, severity=severity, tags=tags)

    seen: set[str] = set()
    seeds: list[str] = []

    for p in probes:
        key = hashlib.sha256(p.payload.strip().lower().encode()).hexdigest()
        if key not in seen:
            seen.add(key)
            seeds.append(p.payload)
            if len(seeds) >= limit:
                break

    logger.info(f"Generated {len(seeds)} seed payloads from {len(probes)} probes")
    return seeds


def find_probe_by_payload(payload: str) -> Probe | None:
    """Locate the canonical probe entry that exactly matches a payload."""
    needle = _normalize_payload(payload)
    for probe in load_probes():
        if _normalize_payload(probe.payload) == needle:
            return probe
    return None


def probe_signal_profile(payloads: list[str]) -> dict[str, Any]:
    """Aggregate categories, subcategories, signals, and tags for seed payloads."""
    matched: list[Probe] = []
    unmatched = 0
    for payload in payloads:
        probe = find_probe_by_payload(payload)
        if probe:
            matched.append(probe)
        else:
            unmatched += 1

    categories: list[str] = []
    subcategories: list[str] = []
    signals: list[str] = []
    expected_signals: list[str] = []
    negative_signals: list[str] = []
    severities: list[str] = []
    tags: list[str] = []
    objectives: list[str] = []
    archetypes: list[str] = []
    tool_requirements: list[str] = []
    success_criteria: list[str] = []
    failure_modes: list[str] = []
    follow_up_probe_ids: list[str] = []

    for probe in matched:
        if probe.category and probe.category not in categories:
            categories.append(probe.category)
        if probe.subcategory and probe.subcategory not in subcategories:
            subcategories.append(probe.subcategory)
        for signal in probe.signals:
            if signal not in signals:
                signals.append(signal)
        for signal in probe.expected_signals:
            if signal not in expected_signals:
                expected_signals.append(signal)
        for signal in probe.negative_signals:
            if signal not in negative_signals:
                negative_signals.append(signal)
        if probe.severity not in severities:
            severities.append(probe.severity)
        for tag in probe.tags:
            if tag not in tags:
                tags.append(tag)
        if probe.objective and probe.objective not in objectives:
            objectives.append(probe.objective)
        for item in probe.target_archetypes:
            if item not in archetypes:
                archetypes.append(item)
        for item in probe.tool_requirements:
            if item not in tool_requirements:
                tool_requirements.append(item)
        for item in probe.success_criteria:
            if item not in success_criteria:
                success_criteria.append(item)
        for item in probe.failure_modes:
            if item not in failure_modes:
                failure_modes.append(item)
        for item in probe.follow_up_probe_ids:
            if item not in follow_up_probe_ids:
                follow_up_probe_ids.append(item)

    return {
        "matched": len(matched),
        "unmatched": unmatched,
        "categories": categories,
        "subcategories": subcategories,
        "signals": signals,
        "expected_signals": expected_signals,
        "negative_signals": negative_signals,
        "severities": severities,
        "tags": tags,
        "objectives": objectives,
        "target_archetypes": archetypes,
        "tool_requirements": tool_requirements,
        "success_criteria": success_criteria,
        "failure_modes": failure_modes,
        "follow_up_probe_ids": follow_up_probe_ids,
    }


def _normalize_payload(payload: str) -> str:
    return " ".join(payload.strip().lower().split())


def _as_str_list(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    return [str(value)]
