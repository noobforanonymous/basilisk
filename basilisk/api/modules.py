"""Attack module, provider, and operator catalog routes."""

from __future__ import annotations

import os

from fastapi import APIRouter, Depends

from basilisk.api.shared import get_api_key, verify_token
from basilisk.core.redaction import sanitize_error_text

router = APIRouter()


@router.get("/api/modules", dependencies=[Depends(verify_token)])
async def list_modules():
    try:
        from basilisk.attacks.base import describe_attack_module, get_all_attack_modules
        modules = get_all_attack_modules()
        return {
            "total": len(modules),
            "modules": [
                {
                    "name": descriptor.name,
                    "category": descriptor.category.value,
                    "owasp_id": descriptor.category.owasp_id,
                    "severity": descriptor.severity.value,
                    "description": descriptor.description,
                    "trust_tier": descriptor.trust_tier,
                    "success_criteria": descriptor.success_criteria,
                    "evidence_requirements": descriptor.evidence_requirements,
                    "is_multiturn": descriptor.is_multiturn,
                    "has_baseline_probe": descriptor.supports_baseline_differential,
                    "requires_tool_proof": descriptor.requires_tool_proof,
                    "applicable_probe_ids": descriptor.applicable_probe_ids,
                    "preconditions": descriptor.preconditions,
                    "required_target_capabilities": descriptor.required_target_capabilities,
                    "verification_steps": descriptor.verification_steps,
                    "expected_false_positives": descriptor.expected_false_positives,
                    "request_cost": descriptor.request_cost,
                    "safety_classification": descriptor.safety_classification,
                    "default_enabled": descriptor.trust_tier != "research",
                }
                for descriptor in (describe_attack_module(module) for module in modules)
            ],
        }
    except Exception as exc:
        return {"error": sanitize_error_text(exc), "modules": [], "total": 0}


@router.get("/api/modules/multiturn", dependencies=[Depends(verify_token)])
async def list_multiturn_modules():
    result = {}
    try:
        from basilisk.attacks.multiturn.cultivation import CULTIVATION_SCENARIOS
        result["cultivation"] = {
            "total_scenarios": len(CULTIVATION_SCENARIOS),
            "scenarios": [s["name"] for s in CULTIVATION_SCENARIOS],
            "features": [
                "baseline_divergence_proof",
                "adaptive_shadow_monitor",
                "documented_transcripts",
                "semantic_drift_tracking",
                "spe_nl_evolution_retry",
                "guardrail_priority_routing",
            ],
        }
    except ImportError:
        result["cultivation"] = {"error": "not available"}

    try:
        from basilisk.attacks.multiturn.authority_escalation import AUTHORITY_SEQUENCES
        result["authority_escalation"] = {
            "total_sequences": len(AUTHORITY_SEQUENCES),
            "sequences": [s["name"] for s in AUTHORITY_SEQUENCES],
            "features": [
                "baseline_divergence_proof",
                "escalation_arc_tracking",
                "per_turn_authority_levels",
                "role_acceptance_detection",
            ],
        }
    except ImportError:
        result["authority_escalation"] = {"error": "not available"}

    try:
        from basilisk.attacks.multiturn.sycophancy import SYCOPHANCY_SEQUENCES
        result["sycophancy"] = {
            "total_sequences": len(SYCOPHANCY_SEQUENCES),
            "sequences": [s["name"] for s in SYCOPHANCY_SEQUENCES],
            "features": [
                "baseline_divergence_proof",
                "identity_acceptance_arc",
                "sycophancy_acceleration_metric",
                "per_turn_acceptance_scoring",
            ],
        }
    except ImportError:
        result["sycophancy"] = {"error": "not available"}
    return result


@router.get("/api/evolution/operators", dependencies=[Depends(verify_token)])
async def evolution_operators():
    try:
        from basilisk.evolution import PopulationStats, _LOOP_CLOSE_SUFFIXES, _METAPHOR_SWAPS, _OPENER_VARIANTS
        return {
            "operators": ["mutate", "crossover", "tournament_select", "diversity_select"],
            "metaphor_vocabulary_size": len(_METAPHOR_SWAPS),
            "opener_variants": len(_OPENER_VARIANTS),
            "closer_variants": len(_LOOP_CLOSE_SUFFIXES),
            "genome_fields": ["name", "description", "turns", "generation", "parent_names", "fitness", "lineage"],
            "population_stats_fields": list(PopulationStats().to_dict().keys()),
            "features": [
                "adaptive_mutation_rate",
                "tournament_selection_k3",
                "population_diversity_tracking",
                "stagnation_detection",
                "lineage_ancestry_chain",
                "response_cache_p0",
                "adaptive_population_shrinking_p0",
                "early_exit_p0",
                "novelty_archive_p1",
                "niche_crowding_p1",
                "diversity_injection_p1",
                "intent_scoring_p2",
                "intent_drift_tracking_p2",
            ],
        }
    except Exception as exc:
        return {"error": sanitize_error_text(exc)}


@router.get("/api/providers", dependencies=[Depends(verify_token)])
async def list_providers():
    providers = [
        {"id": "openai", "name": "OpenAI", "models": ["gpt-4", "gpt-4o", "gpt-4o-mini", "gpt-3.5-turbo"], "env_var": "OPENAI_API_KEY"},
        {"id": "anthropic", "name": "Anthropic", "models": ["claude-3-5-sonnet-20241022", "claude-3-opus-20240229", "claude-3-haiku-20240307"], "env_var": "ANTHROPIC_API_KEY"},
        {"id": "google", "name": "Google", "models": ["gemini/gemini-2.0-flash", "gemini/gemini-1.5-pro"], "env_var": "GOOGLE_API_KEY"},
        {"id": "azure", "name": "Azure OpenAI", "models": ["azure/gpt-4", "azure/gpt-35-turbo"], "env_var": "AZURE_API_KEY"},
        {"id": "xai", "name": "xAI (Grok)", "models": ["grok-beta", "grok-2", "grok-2-1212"], "env_var": "XAI_API_KEY"},
        {"id": "groq", "name": "Groq", "models": ["llama-3.1-8b-instant", "llama-3.3-70b-versatile", "mixtral-8x7b-32768"], "env_var": "GROQ_API_KEY"},
        {"id": "github", "name": "GitHub Models (Free)", "models": ["gpt-4o-mini", "gpt-4o", "gpt-4.1-mini", "gpt-4.1", "gpt-4.1-nano", "o3-mini", "o4-mini", "gpt-5-nano", "gpt-5-mini"], "env_var": "GH_MODELS_TOKEN"},
        {"id": "ollama", "name": "Ollama (Local)", "models": ["ollama/llama3.1", "ollama/mistral", "ollama/codellama"], "env_var": ""},
        {"id": "bedrock", "name": "AWS Bedrock", "models": ["bedrock/anthropic.claude-3-sonnet", "bedrock/meta.llama3"], "env_var": "AWS_ACCESS_KEY_ID"},
        {"id": "custom", "name": "Custom HTTP", "models": [], "env_var": "BASILISK_API_KEY"},
    ]
    for provider in providers:
        if provider["env_var"]:
            provider["configured"] = bool(get_api_key(provider["id"]) or os.environ.get(provider["env_var"], ""))
        else:
            provider["configured"] = True
    return {"providers": providers}


@router.get("/api/mutations", dependencies=[Depends(verify_token)])
async def list_mutations():
    try:
        from basilisk.evolution.operators import ALL_OPERATORS
        return {
            "mutations": [
                {
                    "name": op.name,
                    "description": op.__doc__.strip() if op.__doc__ else "No description",
                    "lang": "Python/Go",
                }
                for op in ALL_OPERATORS
            ]
        }
    except ImportError:
        return {
            "mutations": [
                {"name": "metaphor_swap", "description": "Replace metaphors with semantic equivalents", "lang": "Python"},
                {"name": "register_prefix", "description": "Add conversational register prefix", "lang": "Python"},
                {"name": "opener_variant", "description": "Swap opening paradox entry", "lang": "Python"},
                {"name": "closer_suffix", "description": "Append loop-closure variant", "lang": "Python"},
                {"name": "crossover", "description": "Splice two scenario genomes", "lang": "Python"},
            ]
        }


@router.get("/api/multimodal/techniques", dependencies=[Depends(verify_token)])
async def list_multimodal_techniques():
    try:
        from basilisk.attacks.multimodal import generate_multimodal_payloads
        samples = generate_multimodal_payloads("test")
        techniques = [
            {
                "name": payload.technique,
                "description": payload.description,
                "has_image": bool(payload.image_data),
                "text_preview": payload.text[:100],
            }
            for payload in samples
        ]
        return {
            "total": len(techniques),
            "techniques": techniques,
            "pillow_available": _check_pillow(),
        }
    except Exception as exc:
        return {"error": sanitize_error_text(exc), "techniques": [], "total": 0}


def _check_pillow() -> bool:
    try:
        import PIL  # noqa: F401
        return True
    except ImportError:
        return False
