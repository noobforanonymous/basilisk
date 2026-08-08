"""
Basilisk Eval Runner — async test execution engine.

Runs test suites against LLM targets, evaluating each test's
assertions and collecting structured results with timing data.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from datetime import datetime, timezone

from basilisk.core.redaction import sanitize_error_text
from basilisk.eval.config import EvalConfig, EvalTest, Assertion
from basilisk.eval.assertions import evaluate_assertion, AssertionResult

logger = logging.getLogger("basilisk.eval")


def _elapsed_ms(start_ns: int, *, minimum_ms: float = 0.001) -> float:
    """Return a positive elapsed duration, even on coarse platform clocks."""
    elapsed = (time.perf_counter_ns() - start_ns) / 1_000_000
    return max(elapsed, minimum_ms)


@dataclass
class EvalTestResult:
    """Result of running a single eval test."""
    test_id: str
    test_name: str
    prompt: str
    response: str
    passed: bool
    assertions: list[AssertionResult] = field(default_factory=list)
    duration_ms: float = 0.0
    error: str | None = None

    @property
    def score(self) -> float:
        if not self.assertions:
            return 0.0
        return sum(a.score for a in self.assertions) / len(self.assertions)

    @property
    def failed_assertions(self) -> list[AssertionResult]:
        return [a for a in self.assertions if not a.passed]

    def to_dict(self) -> dict[str, Any]:
        return {
            "test_id": self.test_id,
            "test_name": self.test_name,
            "prompt": self.prompt,
            "response": self.response[:500],
            "passed": self.passed,
            "score": round(self.score, 4),
            "assertions": [a.to_dict() for a in self.assertions],
            "duration_ms": round(self.duration_ms, 1),
            "error": self.error,
        }


@dataclass
class EvalResult:
    """Aggregated result of running a complete eval suite."""
    config_path: str = ""
    target_provider: str = ""
    target_model: str = ""
    tests: list[EvalTestResult] = field(default_factory=list)
    started_at: str = ""
    completed_at: str = ""
    total_duration_ms: float = 0.0

    @property
    def total_tests(self) -> int:
        return len(self.tests)

    @property
    def passed_tests(self) -> int:
        return sum(1 for t in self.tests if t.passed)

    @property
    def failed_tests(self) -> int:
        return sum(1 for t in self.tests if not t.passed)

    @property
    def pass_rate(self) -> float:
        return self.passed_tests / self.total_tests if self.total_tests else 0.0

    @property
    def avg_score(self) -> float:
        if not self.tests:
            return 0.0
        return sum(t.score for t in self.tests) / len(self.tests)

    def to_dict(self) -> dict[str, Any]:
        return {
            "config_path": self.config_path,
            "target": {
                "provider": self.target_provider,
                "model": self.target_model,
            },
            "summary": {
                "total": self.total_tests,
                "passed": self.passed_tests,
                "failed": self.failed_tests,
                "pass_rate": round(self.pass_rate, 4),
                "avg_score": round(self.avg_score, 4),
            },
            "tests": [t.to_dict() for t in self.tests],
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "total_duration_ms": round(self.total_duration_ms, 1),
        }


class EvalRunner:
    """Async evaluation runner.

    Executes test suites against LLM targets using the Basilisk
    provider abstraction layer.

    Usage:
        config = load_eval_config("eval.yaml")
        runner = EvalRunner(config)
        result = await runner.run()
    """

    def __init__(
        self,
        config: EvalConfig,
        provider: Any | None = None,
        grader_fn: Callable | None = None,
        parallel: bool | int = False,
        on_test_complete: Callable | None = None,
        rate_limit: float = 0,
        credential_override: str | None = None,
    ) -> None:
        self.config = config
        self.provider = provider
        self.grader_fn = grader_fn
        self.parallel = parallel
        self.on_test_complete = on_test_complete
        self.rate_limit = rate_limit  # requests per minute, 0 = unlimited
        self.credential_override = credential_override
        self._request_interval = (60.0 / rate_limit) if rate_limit > 0 else 0.0

    async def run(self) -> EvalResult:
        """Run all tests in the eval suite."""
        result = EvalResult(
            target_provider=self.config.target.provider,
            target_model=self.config.target.model,
            started_at=datetime.now(timezone.utc).isoformat(),
        )

        start = time.perf_counter_ns()

        # Create provider if not injected
        provider = self.provider
        if provider is None:
            provider = await self._create_provider()

        try:
            parallelism = 0
            if self.parallel is True:
                parallelism = 5
            elif isinstance(self.parallel, int) and self.parallel > 1:
                parallelism = self.parallel

            if parallelism:
                sem = asyncio.Semaphore(parallelism)
                async def _run_with_sem(test: EvalTest) -> EvalTestResult:
                    async with sem:
                        if self._request_interval > 0:
                            await asyncio.sleep(self._request_interval)
                        return await self._run_test(test, provider)
                results = await asyncio.gather(
                    *(_run_with_sem(t) for t in self.config.tests)
                )
                result.tests = list(results)
            else:
                for i, test in enumerate(self.config.tests):
                    if i > 0 and self._request_interval > 0:
                        await asyncio.sleep(self._request_interval)
                    test_result = await self._run_test(test, provider)
                    result.tests.append(test_result)
                    if self.on_test_complete:
                        try:
                            self.on_test_complete(test_result)
                        except Exception:
                            logger.exception("Eval completion callback failed for %s", test_result.test_id)
        finally:
            if self.provider is None and provider is not None:
                try:
                    await provider.close()
                except Exception:
                    logger.exception("Eval provider cleanup failed")

        result.completed_at = datetime.now(timezone.utc).isoformat()
        result.total_duration_ms = _elapsed_ms(start)

        return result

    def _effective_timeout(self, test: EvalTest) -> float:
        """Resolve timeout: test-level > config-level > 30s fallback."""
        if test.timeout > 0:
            return test.timeout
        if self.config.defaults.timeout > 0:
            return self.config.defaults.timeout
        return 30.0

    async def _run_test(self, test: EvalTest, provider: Any) -> EvalTestResult:
        """Run a single test and evaluate its assertions."""
        start = time.perf_counter_ns()
        timeout = self._effective_timeout(test)

        try:
            # Build message
            from basilisk.providers.base import ProviderMessage
            messages = []
            if test.context:
                messages.append(ProviderMessage(role="system", content=test.context))
            messages.append(ProviderMessage(role="user", content=test.prompt))

            # Send to provider with timeout
            try:
                response = await asyncio.wait_for(
                    provider.send(
                        messages,
                        temperature=self.config.defaults.temperature,
                    ),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                logger.warning(f"Test '{test.id}' timed out after {timeout}s")
                return EvalTestResult(
                    test_id=test.id,
                    test_name=test.name,
                    prompt=test.prompt,
                    response="",
                    passed=False,
                    error="TIMEOUT",
                    duration_ms=_elapsed_ms(start, minimum_ms=timeout * 1000),
                )

            response_text = response.content or ""

            # Evaluate assertions
            assertion_results: list[AssertionResult] = []
            for assertion in test.assertions:
                ar = evaluate_assertion(
                    assertion.type,
                    response_text,
                    values=assertion.values,
                    threshold=assertion.threshold,
                    pattern=assertion.pattern,
                    grader_prompt=assertion.grader_prompt,
                    expected=assertion.expected,
                    grader_fn=self.grader_fn,
                )
                assertion_results.append(ar)

            all_passed = all(a.passed for a in assertion_results)

            return EvalTestResult(
                test_id=test.id,
                test_name=test.name,
                prompt=test.prompt,
                response=response_text,
                passed=all_passed,
                assertions=assertion_results,
                duration_ms=_elapsed_ms(start),
            )

        except Exception as e:
            logger.error(f"Test '{test.id}' failed with error: {e}")
            return EvalTestResult(
                test_id=test.id,
                test_name=test.name,
                prompt=test.prompt,
                response="",
                passed=False,
                error=sanitize_error_text(e),
                duration_ms=_elapsed_ms(start),
            )

    async def _create_provider(self) -> Any:
        """Create a provider from eval config."""
        from basilisk.core.config import BasiliskConfig, TargetConfig
        from basilisk.policy.models import ScanPolicy
        from basilisk.runtime.orchestrator import create_provider

        target = self.config.target
        credential = (
            self.credential_override
            if self.credential_override is not None
            else target.resolve_api_key()
        )
        cfg = BasiliskConfig(
            target=TargetConfig(
                provider=target.provider,
                model=target.model,
                api_key="",
                url=target.api_base,
                timeout=self.config.defaults.timeout,
                max_retries=self.config.defaults.max_retries,
            ),
            policy=ScanPolicy(
                request_budget=max(
                    1,
                    len(self.config.tests) * (self.config.defaults.max_retries + 1),
                ),
                request_timeout=self.config.defaults.timeout,
                retry_attempts=self.config.defaults.max_retries,
                max_concurrency=5 if self.parallel else 1,
            ),
        )
        return create_provider(
            cfg,
            namespace="eval",
            credential_override=credential,
        )


def diff_eval_results(
    current: EvalResult,
    previous: EvalResult,
) -> dict[str, Any]:
    """Compare two eval runs and produce a diff report.

    Returns a dict with regressions (tests that went from pass->fail),
    improvements (fail->pass), and unchanged results.
    """
    prev_map: dict[str, EvalTestResult] = {t.test_id: t for t in previous.tests}
    curr_map: dict[str, EvalTestResult] = {t.test_id: t for t in current.tests}

    regressions: list[dict[str, Any]] = []
    improvements: list[dict[str, Any]] = []
    unchanged: list[dict[str, Any]] = []
    new_tests: list[dict[str, Any]] = []
    removed_tests: list[str] = []

    for test_id, curr in curr_map.items():
        prev = prev_map.get(test_id)
        if prev is None:
            new_tests.append({"test_id": test_id, "passed": curr.passed})
        elif prev.passed and not curr.passed:
            regressions.append({
                "test_id": test_id,
                "test_name": curr.test_name,
                "prev_score": round(prev.score, 4),
                "curr_score": round(curr.score, 4),
                "failed_assertions": [a.to_dict() for a in curr.failed_assertions],
            })
        elif not prev.passed and curr.passed:
            improvements.append({
                "test_id": test_id,
                "test_name": curr.test_name,
                "prev_score": round(prev.score, 4),
                "curr_score": round(curr.score, 4),
            })
        else:
            unchanged.append({"test_id": test_id, "passed": curr.passed})

    for test_id in prev_map:
        if test_id not in curr_map:
            removed_tests.append(test_id)

    return {
        "regressions": regressions,
        "improvements": improvements,
        "unchanged": unchanged,
        "new_tests": new_tests,
        "removed_tests": removed_tests,
        "summary": {
            "total_regressions": len(regressions),
            "total_improvements": len(improvements),
            "current_pass_rate": round(current.pass_rate, 4),
            "previous_pass_rate": round(previous.pass_rate, 4),
        },
    }


# ── Persistence ──

_RESULTS_DIR = Path.home() / ".basilisk" / "eval-results"


def _config_hash(config: EvalConfig) -> str:
    """SHA256 hash of config content + provider + model for unique identification."""
    raw = f"{config.to_dict()}|{config.target.provider}|{config.target.model}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


def save_result(result: EvalResult, path: str | Path | None = None) -> Path:
    """Serialize an EvalResult to a JSON file.

    If path is None, auto-saves to ~/.basilisk/eval-results/{timestamp}_{hash}.json.
    Returns the path the file was written to.
    """
    if path is None:
        _RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        cfg_hash = hashlib.sha256(
            f"{result.config_path}|{result.target_provider}|{result.target_model}".encode()
        ).hexdigest()[:12]
        path = _RESULTS_DIR / f"{ts}_{cfg_hash}.json"
    else:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

    data = result.to_dict()
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info(f"Eval result saved to {path}")
    return path


def load_result(path: str | Path) -> EvalResult:
    """Deserialize an EvalResult from a JSON file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Eval result not found: {path}")

    data = json.loads(path.read_text(encoding="utf-8"))
    target = data.get("target", {})

    tests: list[EvalTestResult] = []
    for t in data.get("tests", []):
        from basilisk.eval.assertions import AssertionResult
        assertions = [
            AssertionResult(
                passed=a["passed"],
                assertion_type=a["type"],
                score=a.get("score", 0.0),
                reason=a.get("reason", ""),
                details=a.get("details"),
            )
            for a in t.get("assertions", [])
        ]
        tests.append(EvalTestResult(
            test_id=t["test_id"],
            test_name=t.get("test_name", ""),
            prompt=t.get("prompt", ""),
            response=t.get("response", ""),
            passed=t["passed"],
            assertions=assertions,
            duration_ms=t.get("duration_ms", 0.0),
            error=t.get("error"),
        ))

    return EvalResult(
        config_path=data.get("config_path", ""),
        target_provider=target.get("provider", ""),
        target_model=target.get("model", ""),
        tests=tests,
        started_at=data.get("started_at", ""),
        completed_at=data.get("completed_at", ""),
        total_duration_ms=data.get("total_duration_ms", 0.0),
    )
