"""Eval, probes, curiosity, and effectiveness routes."""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException

from basilisk.api.shared import CuriosityExploreRequest, EvalRunConfig, _eval_results, get_api_key, verify_token
from basilisk.core.redaction import sanitize_error_text

router = APIRouter()


@router.get("/api/probes", dependencies=[Depends(verify_token)])
async def list_probes(
    category: str = "",
    tag: str = "",
    severity: str = "",
    query: str = "",
    limit: int = 100,
):
    try:
        from basilisk.payloads.loader import load_probes
        tags = [tag] if tag else None
        results = load_probes(category=category, tags=tags, severity=severity, query=query)
        return {
            "total": len(results),
            "showing": min(len(results), limit),
            "probes": [p.to_dict() for p in results[:limit]],
        }
    except Exception as exc:
        raise HTTPException(500, {"error": sanitize_error_text(exc)})


@router.get("/api/probes/stats", dependencies=[Depends(verify_token)])
async def probes_statistics():
    try:
        from basilisk.payloads.loader import probe_stats
        return probe_stats()
    except Exception as exc:
        raise HTTPException(500, {"error": sanitize_error_text(exc)})


@router.post("/api/eval/run", dependencies=[Depends(verify_token)])
async def run_eval(config: EvalRunConfig):
    try:
        from basilisk.eval import report as eval_report
        from basilisk.eval.config import load_eval_config
        from basilisk.eval.runner import EvalRunner

        if config.config_path:
            eval_cfg = load_eval_config(config.config_path)
        elif config.config_yaml:
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
            tmp.write(config.config_yaml)
            tmp.close()
            eval_cfg = load_eval_config(tmp.name)
            os.unlink(tmp.name)
        else:
            raise HTTPException(400, {"error": "Provide config_path or config_yaml"})

        if config.tags:
            filtered = eval_cfg.filter_by_tags(config.tags)
            eval_cfg = eval_cfg.__class__(
                target=eval_cfg.target,
                defaults=eval_cfg.defaults,
                tests=filtered,
                metadata=eval_cfg.metadata,
            )

        runner = EvalRunner(
            eval_cfg,
            parallel=config.parallel,
            credential_override=get_api_key(eval_cfg.target.provider),
        )
        result = await runner.run()

        if config.output_format == "json":
            formatted = eval_report.format_json(result)
        elif config.output_format == "junit":
            formatted = eval_report.format_junit_xml(result)
        elif config.output_format == "markdown":
            formatted = eval_report.format_markdown(result)
        else:
            formatted = eval_report.format_console(result)

        result_id = f"eval-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        result_dict = result.to_dict()
        _eval_results[result_id] = result_dict
        return {
            "result_id": result_id,
            "summary": result_dict["summary"],
            "formatted_output": formatted,
            "tests": result_dict["tests"],
        }
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(400, {"error": sanitize_error_text(exc)}) from exc
    except Exception as exc:
        raise HTTPException(500, {"error": sanitize_error_text(exc)})


@router.get("/api/eval/results", dependencies=[Depends(verify_token)])
async def list_eval_results():
    return {
        "results": [
            {"id": rid, "summary": data.get("summary", {})}
            for rid, data in _eval_results.items()
        ]
    }


@router.get("/api/eval/results/{result_id}", dependencies=[Depends(verify_token)])
async def get_eval_result(result_id: str):
    if result_id not in _eval_results:
        raise HTTPException(404, {"error": "Result not found"})
    return _eval_results[result_id]


@router.get("/api/curiosity/stats", dependencies=[Depends(verify_token)])
async def curiosity_stats():
    try:
        from basilisk.evolution.curiosity import BehavioralSpace
        space = BehavioralSpace(n_bins=25)
        return {
            "available": True,
            "stats": space.stats(),
            "features": [
                "behavioral_space_partitioning",
                "tfidf_clustering",
                "semantic_similarity_novelty",
                "jaccard_fallback_binning",
                "logarithmic_curiosity_decay",
                "exploration_coverage_tracking",
                "fitness_integration",
            ],
        }
    except Exception as exc:
        return {"available": False, "error": sanitize_error_text(exc)}


@router.post("/api/curiosity/explore", dependencies=[Depends(verify_token)])
async def curiosity_explore(req: CuriosityExploreRequest):
    try:
        from basilisk.evolution.curiosity import BehavioralSpace
        space = BehavioralSpace(n_bins=req.n_bins)
        results = []
        for resp in req.responses:
            bonus = space.curiosity_bonus(resp)
            bin_id = space.update(resp)
            results.append({
                "response_preview": resp[:100],
                "bin_id": bin_id,
                "curiosity_bonus": round(bonus, 4),
            })
        return {
            "responses_analyzed": len(results),
            "results": results,
            "stats": space.stats(),
        }
    except Exception as exc:
        raise HTTPException(500, {"error": sanitize_error_text(exc)})


@router.get("/api/probes/effectiveness/{probe_id}", dependencies=[Depends(verify_token)])
async def get_probe_effectiveness(probe_id: str):
    try:
        from basilisk.payloads.effectiveness import probe_effectiveness
        return probe_effectiveness(probe_id)
    except Exception as exc:
        raise HTTPException(500, {"error": sanitize_error_text(exc)})


@router.get("/api/probes/effectiveness", dependencies=[Depends(verify_token)])
async def get_effectiveness_summary():
    try:
        from basilisk.payloads.effectiveness import stats_summary
        return stats_summary()
    except Exception as exc:
        raise HTTPException(500, {"error": sanitize_error_text(exc)})


@router.get("/api/probes/leaderboard", dependencies=[Depends(verify_token)])
async def get_probe_leaderboard(category: str = ""):
    try:
        from basilisk.payloads.effectiveness import category_leaderboard
        return {"probes": category_leaderboard(category)}
    except Exception as exc:
        raise HTTPException(500, {"error": sanitize_error_text(exc)})


@router.get("/api/models/{provider}/{model}/effectiveness", dependencies=[Depends(verify_token)])
async def get_model_effectiveness(provider: str, model: str):
    try:
        from basilisk.payloads.effectiveness import model_effectiveness
        return model_effectiveness(provider, model)
    except Exception as exc:
        raise HTTPException(500, {"error": sanitize_error_text(exc)})
