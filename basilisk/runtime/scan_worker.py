"""Private child-process entrypoint for a restricted Basilisk scan."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

from basilisk.cli.encoding import configure_output_encoding
from basilisk.runtime.isolation import (
    WorkerLimits,
    apply_worker_limits,
    install_worker_audit_policy,
)


def _remove_cwd_from_import_path() -> None:
    """Prevent imports from probing an otherwise unauthorized caller directory."""
    cwd = Path.cwd().resolve()
    retained: list[str] = []
    for entry in sys.path:
        if not entry:
            continue
        try:
            if Path(entry).resolve() == cwd:
                continue
        except (OSError, RuntimeError):
            pass
        retained.append(entry)
    sys.path[:] = retained


def main() -> int:
    configure_output_encoding()
    if os.environ.get("BASILISK_RESTRICTED_WORKER") != "1":
        raise SystemExit("scan_worker may only be launched by the Basilisk supervisor")
    if len(sys.argv) != 2:
        raise SystemExit("usage: python -m basilisk.runtime.scan_worker REQUEST.json")
    request_path = Path(sys.argv[1]).resolve(strict=True)
    document = json.loads(request_path.read_text(encoding="utf-8"))
    arguments = document["arguments"]
    limits = WorkerLimits(**document["limits"])
    backend = apply_worker_limits(limits)
    os.environ["BASILISK_ISOLATION_BACKEND"] = backend
    _remove_cwd_from_import_path()
    install_worker_audit_policy(arguments, request_path)

    from basilisk.cli.scan import run_scan

    return int(asyncio.run(run_scan(**arguments)))


if __name__ == "__main__":
    raise SystemExit(main())
