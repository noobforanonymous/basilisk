"""Console encoding compatibility for Basilisk command-line entry points."""

from __future__ import annotations

import sys
from collections.abc import Iterable
from typing import TextIO


def configure_output_encoding(
    *,
    platform: str | None = None,
    streams: Iterable[TextIO] | None = None,
) -> None:
    """Make Unicode CLI output safe on legacy Windows console streams.

    Restricted scan workers do not enter through Click's main module, so every
    executable entry point calls this helper before creating a Rich console.
    Streams without ``reconfigure`` support are left unchanged.
    """

    current_platform = sys.platform if platform is None else platform
    if current_platform != "win32":
        return
    output_streams = (sys.stdout, sys.stderr) if streams is None else streams
    for stream in output_streams:
        reconfigure = getattr(stream, "reconfigure", None)
        if not callable(reconfigure):
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            # Closed or host-managed streams cannot always be reconfigured.
            continue
