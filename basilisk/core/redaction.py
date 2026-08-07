"""Central secret classification and privacy-preserving serialization helpers."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterable


SENSITIVE_KEY_FRAGMENTS = (
    "api_key",
    "apikey",
    "authorization",
    "auth_header",
    "bearer",
    "cookie",
    "credential",
    "password",
    "private_key",
    "secret",
    "session_token",
    "token",
)


def is_sensitive_key(key: str) -> bool:
    """Return whether a mapping key conventionally carries credential material."""
    normalized = key.casefold().replace("-", "_").replace(" ", "_")
    return any(fragment in normalized for fragment in SENSITIVE_KEY_FRAGMENTS)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def redacted_descriptor(value: Any) -> str:
    """Describe protected content without preserving any of its original characters."""
    if value in (None, "", b""):
        return ""
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        raw = value.encode("utf-8", errors="replace")
    else:
        raw = json.dumps(value, sort_keys=True, default=str).encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    return f"[redacted] sha256={digest} bytes={len(raw)}"


def sanitize_value(
    value: Any,
    *,
    include_raw: bool = False,
    redact_all_strings: bool = True,
    key: str = "",
) -> Any:
    """Recursively sanitize arbitrary persisted or externally returned values."""
    if include_raw:
        return value
    if key and is_sensitive_key(key):
        return redacted_descriptor(value)
    if isinstance(value, str):
        return redacted_descriptor(value) if redact_all_strings else value
    if isinstance(value, bytes):
        return redacted_descriptor(value)
    if isinstance(value, dict):
        return {
            str(item_key): sanitize_value(
                item_value,
                include_raw=False,
                redact_all_strings=redact_all_strings,
                key=str(item_key),
            )
            for item_key, item_value in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [
            sanitize_value(item, include_raw=False, redact_all_strings=redact_all_strings)
            for item in value
        ]
    return value


def sanitize_mapping(
    values: dict[str, Any],
    *,
    include_raw: bool = False,
    redact_all_strings: bool = True,
) -> dict[str, Any]:
    return {
        str(key): sanitize_value(
            value,
            include_raw=include_raw,
            redact_all_strings=redact_all_strings,
            key=str(key),
        )
        for key, value in values.items()
    }


def public_fields(values: dict[str, Any], allowed: Iterable[str]) -> dict[str, Any]:
    """Copy only explicitly public keys, preventing future credential fields from leaking."""
    allowed_set = set(allowed)
    return {key: values[key] for key in allowed_set if key in values}


_SECRET_VALUE_PATTERNS = (
    re.compile(r"(?i)\b(?:nvapi|sk|xai|ghp|github_pat|AIza)[-_][A-Za-z0-9._-]{8,}"),
    re.compile(
        r"(?i)\b(authorization|api[-_ ]?key|access[-_ ]?token|token|cookie|password|secret)"
        r"\s*[:=]\s*(?:bearer\s+)?[^\s,;]+"
    ),
    re.compile(
        r"(?i)([?&](?:api[-_]?key|access[-_]?token|token|secret|password)=)[^&#\s]+"
    ),
)

_UNSAFE_DISPLAY_CODEPOINTS = {
    0x061C,  # Arabic letter mark
    0x200E, 0x200F,  # left/right-to-left marks
    *range(0x202A, 0x202F),  # bidi embedding/override and formatting controls
    *range(0x2066, 0x206A),  # bidi isolates
}


def escape_untrusted_text(value: Any, *, maximum: int = 1_000) -> str:
    """Render hostile text without terminal control or log-line injection."""
    if isinstance(value, BaseException):
        text = str(value) or type(value).__name__
    elif value is None:
        text = ""
    else:
        text = str(value)
    escaped: list[str] = []
    for character in text:
        codepoint = ord(character)
        if character == "\n":
            escaped.append("\\n")
        elif character == "\r":
            escaped.append("\\r")
        elif character == "\t":
            escaped.append("\\t")
        elif codepoint < 0x20 or 0x7F <= codepoint <= 0x9F or codepoint in _UNSAFE_DISPLAY_CODEPOINTS:
            escaped.append(f"\\u{codepoint:04x}")
        else:
            escaped.append(character)
        if sum(len(part) for part in escaped) >= maximum:
            break
    return "".join(escaped)[:maximum]


def sanitize_error_text(value: Any, *, secrets: Iterable[str] = ()) -> str:
    """Preserve useful error context while removing credential-like material."""
    if isinstance(value, BaseException):
        text = str(value) or type(value).__name__
    elif value is None:
        text = ""
    else:
        text = str(value)
    for secret in secrets:
        if secret:
            text = text.replace(str(secret), "[redacted]")
    text = _SECRET_VALUE_PATTERNS[0].sub("[redacted]", text)
    text = _SECRET_VALUE_PATTERNS[1].sub(
        lambda match: f"{match.group(1)}=[redacted]",
        text,
    )
    text = _SECRET_VALUE_PATTERNS[2].sub(
        lambda match: f"{match.group(1)}[redacted]",
        text,
    )
    return escape_untrusted_text(text, maximum=1_000)
