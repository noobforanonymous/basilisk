"""Policy-enforced transport wrapper shared by every Basilisk request path."""

from __future__ import annotations

import asyncio
import hashlib
import json
import random
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Callable

from basilisk.core.redaction import sanitize_error_text
from basilisk.providers.base import ProviderAdapter, ProviderMessage, ProviderResponse


CURRENT_REQUEST_MODULE: ContextVar[str] = ContextVar(
    "basilisk_request_module",
    default="request_engine",
)


@contextmanager
def request_module_context(module: str):
    token = CURRENT_REQUEST_MODULE.set(module)
    try:
        yield
    finally:
        CURRENT_REQUEST_MODULE.reset(token)


class RequestPolicyError(RuntimeError):
    """A request was rejected by deterministic scanner policy."""


class RequestBudgetExceeded(RequestPolicyError):
    pass


class ResponseLimitExceeded(RequestPolicyError):
    pass


@dataclass(frozen=True)
class RequestPolicy:
    max_requests: int
    max_input_tokens: int
    max_output_tokens: int
    max_response_bytes: int
    timeout_seconds: float
    max_concurrency: int
    minimum_delay_seconds: float
    jitter_seconds: float = 0.0
    retry_attempts: int = 0

    def __post_init__(self) -> None:
        if self.max_requests < 1:
            raise ValueError("max_requests must be positive")
        if self.max_input_tokens < 1 or self.max_output_tokens < 1:
            raise ValueError("token budgets must be positive")
        if self.max_response_bytes < 1:
            raise ValueError("max_response_bytes must be positive")
        if self.timeout_seconds <= 0 or self.max_concurrency < 1:
            raise ValueError("timeout and concurrency must be positive")
        if self.minimum_delay_seconds < 0 or self.jitter_seconds < 0:
            raise ValueError("request delays cannot be negative")
        if self.retry_attempts < 0:
            raise ValueError("retry_attempts cannot be negative")


@dataclass
class RequestRecord:
    request_id: str
    attempt: int
    started_at: float
    completed_at: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    response_bytes: int = 0
    error: str = ""
    request_sha256: str = ""
    response_sha256: str = ""
    model: str = ""
    temperature: float = 0.0
    max_tokens: int = 0
    latency_ms: float = 0.0


@dataclass
class RequestStats:
    reserved_requests: int = 0
    completed_requests: int = 0
    failed_requests: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    response_bytes: int = 0
    records: list[RequestRecord] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "reserved_requests": self.reserved_requests,
            "completed_requests": self.completed_requests,
            "failed_requests": self.failed_requests,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "response_bytes": self.response_bytes,
            "records": [record.__dict__.copy() for record in self.records],
        }


class RequestLedger:
    """Shared scan-wide counters and concurrency/rate-limit coordination."""

    def __init__(self, policy: RequestPolicy, *, random_seed: int = 0) -> None:
        self.policy = policy
        self.stats = RequestStats()
        self.semaphore = asyncio.Semaphore(policy.max_concurrency)
        self.state_lock = asyncio.Lock()
        self.next_request_at = 0.0
        self.random = random.Random(random_seed)


class RequestExecutor(ProviderAdapter):
    """Provider facade enforcing scan-wide transport policy for every API call."""

    def __init__(
        self,
        provider: ProviderAdapter,
        policy: RequestPolicy,
        *,
        namespace: str = "scan",
        audit: Any | None = None,
        target: str = "",
        stop_check: Callable[[], Any] | None = None,
        random_seed: int = 0,
        ledger: RequestLedger | None = None,
    ) -> None:
        self.provider = provider
        self.policy = policy
        self.namespace = namespace or "scan"
        self.audit = audit
        self.target = target
        self.stop_check = stop_check
        self.stats = RequestStats()
        self.ledger = ledger or RequestLedger(policy, random_seed=random_seed)
        if self.ledger.policy != policy:
            raise ValueError("shared request ledger policy does not match executor policy")
        self._semaphore = self.ledger.semaphore
        self._state_lock = self.ledger.state_lock
        self._cancelled = asyncio.Event()

    @property
    def name(self) -> str:
        return f"request-engine:{self.provider.name}"

    def cancel(self) -> None:
        self._cancelled.set()

    def estimate_tokens(self, text: str) -> int:
        return self.provider.estimate_tokens(text)

    def is_refusal(self, response: ProviderResponse) -> bool:
        return self.provider.is_refusal(response)

    async def send(
        self,
        messages: list[ProviderMessage],
        model: str = "",
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> ProviderResponse:
        module = str(kwargs.pop("_basilisk_module", CURRENT_REQUEST_MODULE.get()))
        last_response: ProviderResponse | None = None
        for attempt in range(self.policy.retry_attempts + 1):
            try:
                request_id, input_tokens, request_hash = await self._reserve(
                    messages, attempt, model, temperature, max_tokens, module
                )
            except RequestPolicyError as exc:
                return ProviderResponse(
                    error=sanitize_error_text(exc),
                    raw_response={"policy_error": type(exc).__name__},
                )
            record = RequestRecord(
                request_id,
                attempt,
                time.monotonic(),
                input_tokens=input_tokens,
                request_sha256=request_hash,
                model=model,
                temperature=temperature,
                max_tokens=min(max_tokens, self.policy.max_output_tokens),
            )
            self.stats.records.append(record)
            self.ledger.stats.records.append(record)
            await self._rate_limit()
            try:
                async with self._semaphore:
                    self._check_cancelled()
                    if self.audit:
                        self.audit.log_prompt_sent(
                            module,
                            "\n".join(message.content for message in messages),
                            self.provider.name,
                            model,
                            self.target,
                        )
                    response = await asyncio.wait_for(
                        self.provider.send(
                            messages,
                            model=model,
                            temperature=temperature,
                            max_tokens=min(max_tokens, self.policy.max_output_tokens),
                            **kwargs,
                        ),
                        timeout=self.policy.timeout_seconds,
                    )
                # Response validation and shared-ledger accounting must be one
                # atomic operation. Otherwise concurrent requests can each
                # observe enough remaining output budget and collectively
                # exceed the scan-wide ceiling.
                async with self._state_lock:
                    self._validate_response(response, request_id)
                    self._complete(record, response)
                if self.audit:
                    self.audit.log_response_received(
                        module,
                        response.content,
                        response.latency_ms,
                        response.total_tokens,
                        self.provider.is_refusal(response),
                    )
                if not response.error or not self._is_transient(response.error):
                    return response
                last_response = response
            except asyncio.TimeoutError as exc:
                record.error = sanitize_error_text(exc) or type(exc).__name__
                record.completed_at = time.monotonic()
                async with self._state_lock:
                    self.stats.failed_requests += 1
                    self.ledger.stats.failed_requests += 1
                last_response = ProviderResponse(
                    error=record.error,
                    raw_response={"request_id": request_id, "policy_error": type(exc).__name__},
                )
            except RequestPolicyError as exc:
                record.error = sanitize_error_text(exc) or type(exc).__name__
                record.completed_at = time.monotonic()
                async with self._state_lock:
                    self.stats.failed_requests += 1
                    self.ledger.stats.failed_requests += 1
                return ProviderResponse(
                    error=record.error,
                    raw_response={"request_id": request_id, "policy_error": type(exc).__name__},
                )
            except Exception as exc:
                record.error = sanitize_error_text(exc) or type(exc).__name__
                record.completed_at = time.monotonic()
                async with self._state_lock:
                    self.stats.failed_requests += 1
                    self.ledger.stats.failed_requests += 1
                last_response = ProviderResponse(
                    error=record.error,
                    raw_response={"request_id": request_id, "provider_error": type(exc).__name__},
                )
                if not self._is_transient(record.error):
                    return last_response
            if attempt < self.policy.retry_attempts:
                await asyncio.sleep(min(0.25 * (2**attempt), 2.0))
        return last_response or ProviderResponse(error="request failed")

    async def send_streaming(
        self,
        messages: list[ProviderMessage],
        model: str = "",
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        module = str(kwargs.pop("_basilisk_module", CURRENT_REQUEST_MODULE.get()))
        request_id, input_tokens, request_hash = await self._reserve(
            messages, 0, model, temperature, max_tokens, module
        )
        record = RequestRecord(
            request_id,
            0,
            time.monotonic(),
            input_tokens=input_tokens,
            request_sha256=request_hash,
            model=model,
            temperature=temperature,
            max_tokens=min(max_tokens, self.policy.max_output_tokens),
        )
        self.stats.records.append(record)
        self.ledger.stats.records.append(record)
        await self._rate_limit()
        total_bytes = 0
        output_tokens = 0
        response_digest = hashlib.sha256()
        try:
            async with self._semaphore:
                self._check_cancelled()
                if self.audit:
                    self.audit.log_prompt_sent(
                        module,
                        "\n".join(message.content for message in messages),
                        self.provider.name,
                        model,
                        self.target,
                    )
                async with asyncio.timeout(self.policy.timeout_seconds):
                    async for chunk in self.provider.send_streaming(
                        messages,
                        model=model,
                        temperature=temperature,
                        max_tokens=min(max_tokens, self.policy.max_output_tokens),
                        **kwargs,
                    ):
                        self._check_cancelled()
                        raw_chunk = chunk.encode("utf-8", errors="replace")
                        chunk_bytes = len(raw_chunk)
                        chunk_tokens = self.provider.estimate_tokens(chunk)
                        next_total_bytes = total_bytes + chunk_bytes
                        if next_total_bytes > self.policy.max_response_bytes:
                            raise ResponseLimitExceeded(
                                f"response exceeded {self.policy.max_response_bytes} bytes"
                            )
                        async with self._state_lock:
                            if (
                                self.ledger.stats.output_tokens + chunk_tokens
                                > self.policy.max_output_tokens
                            ):
                                raise RequestBudgetExceeded(
                                    "output token budget exhausted "
                                    f"({self.policy.max_output_tokens})"
                                )
                            # Charge each accepted chunk before yielding it so
                            # every concurrent stream sees the current balance.
                            self.stats.output_tokens += chunk_tokens
                            self.ledger.stats.output_tokens += chunk_tokens
                        total_bytes = next_total_bytes
                        output_tokens += chunk_tokens
                        response_digest.update(raw_chunk)
                        yield chunk
            record.response_bytes = total_bytes
            record.output_tokens = output_tokens
            record.response_sha256 = response_digest.hexdigest()
            record.completed_at = time.monotonic()
            record.latency_ms = (record.completed_at - record.started_at) * 1000
            async with self._state_lock:
                self.stats.completed_requests += 1
                self.stats.response_bytes += total_bytes
                self.ledger.stats.completed_requests += 1
                self.ledger.stats.response_bytes += total_bytes
            if self.audit:
                self.audit.log_response_received(
                    module,
                    f"stream-sha256:{record.response_sha256}",
                    record.latency_ms,
                    input_tokens + output_tokens,
                    False,
                )
        except (Exception, asyncio.CancelledError) as exc:
            record.error = sanitize_error_text(exc) or type(exc).__name__
            record.completed_at = time.monotonic()
            record.output_tokens = output_tokens
            record.response_bytes = total_bytes
            record.response_sha256 = response_digest.hexdigest()
            record.latency_ms = (record.completed_at - record.started_at) * 1000
            async with self._state_lock:
                self.stats.failed_requests += 1
                self.stats.response_bytes += total_bytes
                self.ledger.stats.failed_requests += 1
                self.ledger.stats.response_bytes += total_bytes
            raise

    async def close(self) -> None:
        self.cancel()
        await self.provider.close()

    async def _reserve(
        self,
        messages: list[ProviderMessage],
        attempt: int,
        model: str,
        temperature: float,
        max_tokens: int,
        module: str,
    ) -> tuple[str, int, str]:
        self._check_cancelled()
        request_payload = json.dumps(
            {
                "messages": [message.to_dict() for message in messages],
                "model": model,
                "temperature": temperature,
                "max_tokens": min(max_tokens, self.policy.max_output_tokens),
            },
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        request_bytes = request_payload.encode("utf-8", errors="replace")
        text_tokens = sum(self.provider.estimate_tokens(message.content) for message in messages)
        # Serialized-size fallback also accounts for images, tools, and message
        # metadata that a text-only estimator cannot see.
        input_tokens = max(text_tokens, max(1, (len(request_bytes) + 3) // 4))
        request_hash = hashlib.sha256(request_bytes).hexdigest()
        async with self._state_lock:
            if self.ledger.stats.reserved_requests >= self.policy.max_requests:
                raise RequestBudgetExceeded(
                    f"request budget exhausted ({self.policy.max_requests} actual API calls)"
                )
            if self.ledger.stats.input_tokens + input_tokens > self.policy.max_input_tokens:
                raise RequestBudgetExceeded(
                    f"input token budget exhausted ({self.policy.max_input_tokens})"
                )
            sequence = self.ledger.stats.reserved_requests
            request_id = hashlib.sha256(
                (
                    f"{self.namespace}:{module}:{sequence}:{attempt}:{request_hash}"
                ).encode("utf-8")
            ).hexdigest()[:24]
            self.stats.reserved_requests += 1
            self.stats.input_tokens += input_tokens
            self.ledger.stats.reserved_requests += 1
            self.ledger.stats.input_tokens += input_tokens
        return request_id, input_tokens, request_hash

    async def _rate_limit(self) -> None:
        async with self._state_lock:
            now = time.monotonic()
            delay = max(0.0, self.ledger.next_request_at - now)
            spacing = self.policy.minimum_delay_seconds
            if self.policy.jitter_seconds:
                spacing += self.ledger.random.uniform(0.0, self.policy.jitter_seconds)
            self.ledger.next_request_at = max(now, self.ledger.next_request_at) + spacing
        if delay:
            await asyncio.sleep(delay)

    def _check_cancelled(self) -> None:
        if self._cancelled.is_set():
            raise asyncio.CancelledError("request executor cancelled")
        if self.stop_check:
            self.stop_check()

    def _validate_response(self, response: ProviderResponse, request_id: str) -> None:
        response_size = len((response.content or "").encode("utf-8", errors="replace"))
        if response_size > self.policy.max_response_bytes:
            raise ResponseLimitExceeded(
                f"response exceeded {self.policy.max_response_bytes} bytes"
            )
        output_tokens = int(response.output_tokens or 0)
        if response.content and output_tokens <= 0:
            output_tokens = self.provider.estimate_tokens(response.content)
            response.output_tokens = output_tokens
            if int(response.total_tokens or 0) <= 0:
                response.total_tokens = output_tokens
        if self.ledger.stats.output_tokens + output_tokens > self.policy.max_output_tokens:
            raise RequestBudgetExceeded(
                f"output token budget exhausted ({self.policy.max_output_tokens})"
            )
        source_metadata = response.raw_response or {}
        response.raw_response = {
            key: source_metadata[key]
            for key in ("id", "system_fingerprint", "provider", "model_version")
            if key in source_metadata
        } | {
            "basilisk_request_id": request_id,
        }

    def _complete(self, record: RequestRecord, response: ProviderResponse) -> None:
        record.completed_at = time.monotonic()
        record.output_tokens = int(response.output_tokens or 0)
        record.response_bytes = len((response.content or "").encode("utf-8", errors="replace"))
        record.response_sha256 = hashlib.sha256(
            (response.content or "").encode("utf-8", errors="replace")
        ).hexdigest()
        record.latency_ms = float(response.latency_ms or ((record.completed_at - record.started_at) * 1000))
        record.error = response.error or ""
        self.stats.output_tokens += record.output_tokens
        self.stats.response_bytes += record.response_bytes
        self.ledger.stats.output_tokens += record.output_tokens
        self.ledger.stats.response_bytes += record.response_bytes
        if response.error:
            self.stats.failed_requests += 1
            self.ledger.stats.failed_requests += 1
        else:
            self.stats.completed_requests += 1
            self.ledger.stats.completed_requests += 1

    @staticmethod
    def _is_transient(error: str) -> bool:
        lower = error.casefold()
        return any(marker in lower for marker in ("timeout", "temporar", "rate limit", "429", "502", "503", "504"))
