"""Property tests for attacker-controlled text normalization and redaction."""

from __future__ import annotations

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, strategies as st

from basilisk.core.redaction import sanitize_value
from basilisk.core.verification import stable_response_fingerprint


@given(st.text(max_size=10_000))
def test_response_fingerprint_is_total_and_fixed_width(value: str):
    fingerprint = stable_response_fingerprint(value)
    assert len(fingerprint) == 64
    assert set(fingerprint) <= set("0123456789abcdef")


@given(st.text(max_size=4_000))
def test_preview_sanitizer_never_returns_raw_arbitrary_strings(value: str):
    sanitized = sanitize_value(value, include_raw=False, redact_all_strings=True)
    if value:
        assert sanitized != value

