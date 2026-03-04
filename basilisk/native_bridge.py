"""
Basilisk Native Bridge — Python ctypes bindings for C/Go shared libraries.

Provides Python wrappers around the compiled native extensions:
  - Token analyzer (C)   → fast token estimation, entropy, similarity
  - Encoder (C)          → base64, hex, ROT13, URL encoding
  - Fuzzer (Go)          → mutation operators, crossover, batch ops
  - Matcher (Go)         → Aho-Corasick multi-pattern matching, refusal detection

Falls back to pure Python implementations if native libraries aren't available.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import os
import sys
from pathlib import Path
from typing import Optional

logger = logging.getLogger("basilisk.native")

# Library search paths
_LIB_DIRS = [
    Path(__file__).parent / "native_libs",
    Path(__file__).parent.parent / "native" / "build",
    Path("/usr/local/lib"),
    Path("/usr/lib"),
]

_EXT = ".so"
if sys.platform == "win32":
    _EXT = ".dll"
elif sys.platform == "darwin":
    _EXT = ".dylib"


def _find_lib(name: str) -> Optional[ctypes.CDLL]:
    """Find and load a shared library by name."""
    for d in _LIB_DIRS:
        path = d / f"{name}{_EXT}"
        if path.exists():
            try:
                lib = ctypes.CDLL(str(path))
                logger.info(f"Loaded native library: {path}")
                return lib
            except OSError as e:
                logger.warning(f"Failed to load {path}: {e}")
    logger.info(f"Native library {name} not found — using Python fallback")
    return None
