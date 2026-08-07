"""Security regressions for credential omission and raw-evidence handling."""

from basilisk.core.audit import AuditLogger
from basilisk.core.finding import Finding, Message
from basilisk.core.redaction import redacted_descriptor, sanitize_error_text, sanitize_mapping
from basilisk.differential import DiffReport, DiffProbeResult, ModelResult


def test_redacted_descriptor_contains_no_source_characters():
    secret = "nvapi-secret-do-not-persist"
    descriptor = redacted_descriptor(secret)
    assert secret not in descriptor
    assert "nvapi" not in descriptor
    assert descriptor.startswith("[redacted] sha256=")
    assert "bytes=" in descriptor


def test_sensitive_mapping_fields_are_centrally_redacted():
    payload = {
        "provider": "nvidia",
        "api_key": "nvapi-secret",
        "nested": {"Authorization": "Bearer private", "model": "model-name"},
    }
    sanitized = sanitize_mapping(payload, redact_all_strings=False)
    assert sanitized["provider"] == "nvidia"
    assert "nvapi-secret" not in sanitized["api_key"]
    assert "Bearer private" not in sanitized["nested"]["Authorization"]
    assert sanitized["nested"]["model"] == "model-name"


def test_error_text_escapes_terminal_log_and_bidi_controls():
    hostile = "\x1b[2Jforged\nentry\u202etest"
    sanitized = sanitize_error_text(hostile)
    assert "\x1b" not in sanitized
    assert "\n" not in sanitized
    assert "\u202e" not in sanitized
    assert sanitized == "\\u001b[2Jforged\\nentry\\u202etest"


def test_empty_timeout_retains_its_actionable_exception_type():
    assert sanitize_error_text(TimeoutError()) == "TimeoutError"


def test_empty_display_text_stays_empty_instead_of_becoming_type_name():
    from basilisk.core.redaction import escape_untrusted_text

    assert escape_untrusted_text("") == ""


def test_differential_report_omits_all_credentials_and_raw_response():
    report = DiffReport(
        targets=[{
            "provider": "nvidia",
            "model": "meta/llama",
            "api_key": "nvapi-secret",
            "Authorization": "Bearer private",
        }],
        probe_results=[DiffProbeResult(
            probe_category="injection",
            probe_text="probe",
            results=[ModelResult(provider="nvidia", model="meta/llama", response="private answer")],
        )],
    )
    serialized = report.to_dict()
    assert serialized["targets"] == [{"provider": "nvidia", "model": "meta/llama"}]
    response = serialized["probes"][0]["results"][0]
    assert "private answer" not in response["response_preview"]
    assert response["response_length"] == len("private answer")
    assert len(response["response_sha256"]) == 64


def test_finding_metadata_does_not_reappear_when_conversation_is_redacted():
    secret = "metadata-private-secret"
    finding = Finding(
        payload="payload-private-secret",
        response="response-private-secret",
        metadata={"nested": {"token": secret}, "note": secret},
        conversation=[Message(role="user", content=secret)],
    )
    serialized = finding.sanitized_dict()
    text = str(serialized)
    assert secret not in text
    assert "payload-private-secret" not in text
    assert "response-private-secret" not in text
    assert serialized["metadata"]["conversation_redacted"] is True


def test_audit_prompt_and_response_events_are_hash_only(tmp_path):
    logger = AuditLogger(output_dir=str(tmp_path), session_id="redaction")
    logger.log_prompt_sent("module", "prompt-private-secret", "provider", "model", "target")
    logger.log_response_received("module", "response-private-secret", 1.0)
    logger.close()
    content = next(tmp_path.glob("audit_*.jsonl")).read_text(encoding="utf-8")
    assert "prompt-private-secret" not in content
    assert "response-private-secret" not in content
    assert "[redacted] sha256=" in content
