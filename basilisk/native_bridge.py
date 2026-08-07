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
import base64
import hashlib
import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:  # pragma: no cover - depends on runtime package availability
    from cryptography.hazmat.primitives.asymmetric import ed25519
except ImportError:  # pragma: no cover - optional runtime state
    ed25519 = None

logger = logging.getLogger("basilisk.native")
_TRUSTED_NATIVE_SIGNING_PUBLIC_KEY_HEX = "e3c9e3fdd324da269e27f769ee7a67b8fdadfb19b8b1b52dc736887764532fe9"
_MAX_NATIVE_TEXT_BYTES = max(4096, int(os.environ.get("BASILISK_NATIVE_TEXT_MAX_BYTES", "262144")))
_MAX_NATIVE_PAIR_BYTES = max(
    _MAX_NATIVE_TEXT_BYTES,
    int(os.environ.get("BASILISK_NATIVE_PAIR_MAX_BYTES", str(_MAX_NATIVE_TEXT_BYTES * 2))),
)

# Library search paths
_LIB_DIRS = [
    Path(__file__).parent / "native_libs",
    Path(__file__).parent.parent / "native" / "build",
]

if os.environ.get("BASILISK_ALLOW_SYSTEM_NATIVE_LIBS", "").lower() == "true":
    logger.warning("System native library loading enabled via BASILISK_ALLOW_SYSTEM_NATIVE_LIBS=true")
    _LIB_DIRS.extend([
        Path("/usr/local/lib"),
        Path("/usr/lib"),
    ])

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
            if not _verify_library_integrity(path):
                logger.warning("Rejected native library without verified integrity: %s", path)
                continue
            try:
                lib = ctypes.CDLL(str(path))
                logger.info(f"Loaded native library: {path}")
                return lib
            except OSError as e:
                logger.warning(f"Failed to load {path}: {e}")
    logger.info(f"Native library {name} not found — using Python fallback")
    return None


# ============================================================
# Load libraries lazily
# ============================================================

_tokens_lib: Optional[ctypes.CDLL] = None
_encoder_lib: Optional[ctypes.CDLL] = None
_fuzzer_lib: Optional[ctypes.CDLL] = None
_matcher_lib: Optional[ctypes.CDLL] = None
_loaded = False


def _ensure_loaded():
    """Load all native libraries on first use."""
    global _tokens_lib, _encoder_lib, _fuzzer_lib, _matcher_lib, _loaded
    if _loaded:
        return
    _loaded = True

    _tokens_lib = _find_lib("libbasilisk_tokens")
    _encoder_lib = _find_lib("libbasilisk_encoder")
    _fuzzer_lib = _find_lib("libbasilisk_fuzzer")
    _matcher_lib = _find_lib("libbasilisk_matcher")

    # Set up C function signatures for tokens lib
    if _tokens_lib:
        _tokens_lib.basilisk_estimate_tokens.argtypes = [ctypes.c_char_p]
        _tokens_lib.basilisk_estimate_tokens.restype = ctypes.c_int
        _tokens_lib.basilisk_entropy.argtypes = [ctypes.c_char_p]
        _tokens_lib.basilisk_entropy.restype = ctypes.c_double
        _tokens_lib.basilisk_levenshtein.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        _tokens_lib.basilisk_levenshtein.restype = ctypes.c_int
        _tokens_lib.basilisk_similarity.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        _tokens_lib.basilisk_similarity.restype = ctypes.c_double
        _tokens_lib.basilisk_count_confusables.argtypes = [ctypes.c_char_p]
        _tokens_lib.basilisk_count_confusables.restype = ctypes.c_int
        _tokens_lib.basilisk_fast_search.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        _tokens_lib.basilisk_fast_search.restype = ctypes.c_int

    # Set up C function signatures for encoder lib
    if _encoder_lib:
        _encoder_lib.basilisk_base64_encode.argtypes = [ctypes.c_char_p, ctypes.c_int]
        _encoder_lib.basilisk_base64_encode.restype = ctypes.c_void_p
        _encoder_lib.basilisk_rot13.argtypes = [ctypes.c_char_p]
        _encoder_lib.basilisk_rot13.restype = ctypes.c_void_p
        _encoder_lib.basilisk_url_encode.argtypes = [ctypes.c_char_p]
        _encoder_lib.basilisk_url_encode.restype = ctypes.c_void_p
        _encoder_lib.basilisk_unicode_escape.argtypes = [ctypes.c_char_p]
        _encoder_lib.basilisk_unicode_escape.restype = ctypes.c_void_p
        _encoder_lib.basilisk_reverse.argtypes = [ctypes.c_char_p]
        _encoder_lib.basilisk_reverse.restype = ctypes.c_void_p
        _encoder_lib.basilisk_free.argtypes = [ctypes.c_void_p]
        _encoder_lib.basilisk_free.restype = None

    # Set up Go function signatures for fuzzer lib
    if _fuzzer_lib:
        _fuzzer_lib.BasiliskMutate.argtypes = [ctypes.c_char_p, ctypes.c_int]
        _fuzzer_lib.BasiliskMutate.restype = ctypes.c_void_p
        _fuzzer_lib.BasiliskMutateRandom.argtypes = [ctypes.c_char_p]
        _fuzzer_lib.BasiliskMutateRandom.restype = ctypes.c_void_p
        _fuzzer_lib.BasiliskCrossover.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
        _fuzzer_lib.BasiliskCrossover.restype = ctypes.c_void_p
        _fuzzer_lib.BasiliskHomoglyphTransform.argtypes = [ctypes.c_char_p, ctypes.c_double]
        _fuzzer_lib.BasiliskHomoglyphTransform.restype = ctypes.c_void_p
        _fuzzer_lib.BasiliskZeroWidthInject.argtypes = [ctypes.c_char_p]
        _fuzzer_lib.BasiliskZeroWidthInject.restype = ctypes.c_void_p
        _fuzzer_lib.BasiliskCountRunes.argtypes = [ctypes.c_char_p]
        _fuzzer_lib.BasiliskCountRunes.restype = ctypes.c_int
        _fuzzer_lib.BasiliskGetMutationCount.argtypes = []
        _fuzzer_lib.BasiliskGetMutationCount.restype = ctypes.c_int
        _fuzzer_lib.BasiliskFreeString.argtypes = [ctypes.c_void_p]
        _fuzzer_lib.BasiliskFreeString.restype = None

    # Set up Go function signatures for matcher lib
    if _matcher_lib:
        _matcher_lib.BasiliskMatcherCreate.argtypes = []
        _matcher_lib.BasiliskMatcherCreate.restype = ctypes.c_int
        _matcher_lib.BasiliskMatcherAddPattern.argtypes = [ctypes.c_int, ctypes.c_char_p]
        _matcher_lib.BasiliskMatcherAddPattern.restype = ctypes.c_int
        _matcher_lib.BasiliskMatcherBuild.argtypes = [ctypes.c_int]
        _matcher_lib.BasiliskMatcherBuild.restype = None
        _matcher_lib.BasiliskMatcherSearch.argtypes = [ctypes.c_int, ctypes.c_char_p]
        _matcher_lib.BasiliskMatcherSearch.restype = ctypes.c_void_p
        _matcher_lib.BasiliskMatcherDestroy.argtypes = [ctypes.c_int]
        _matcher_lib.BasiliskMatcherDestroy.restype = None
        _matcher_lib.BasiliskDetectRefusal.argtypes = [ctypes.c_char_p]
        _matcher_lib.BasiliskDetectRefusal.restype = ctypes.c_double
        _matcher_lib.BasiliskDetectSensitiveData.argtypes = [ctypes.c_char_p]
        _matcher_lib.BasiliskDetectSensitiveData.restype = ctypes.c_void_p
        _matcher_lib.BasiliskFreeStr.argtypes = [ctypes.c_void_p]
        _matcher_lib.BasiliskFreeStr.restype = None


# ============================================================
# Status
# ============================================================

def native_status() -> Dict[str, bool]:
    """Return availability status of each native library."""
    _ensure_loaded()
    return {
        "tokens_c": _tokens_lib is not None,
        "encoder_c": _encoder_lib is not None,
        "fuzzer_go": _fuzzer_lib is not None,
        "matcher_go": _matcher_lib is not None,
    }


def _string_from_ptr(ptr: Optional[int], free_func) -> Optional[str]:
    """Helper to convert a native char* to a Python string and free the original memory."""
    if ptr is None or ptr == 0:
        return None
    try:
        # Convert to bytes and then to string
        val = ctypes.string_at(ptr).decode("utf-8")
        return val
    finally:
        # Always free the native memory
        free_func(ptr)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_native_manifest(directory: Path) -> dict[str, str]:
    manifest_path = directory / "manifest.json"
    if not manifest_path.exists():
        return {}
    try:
        payload = json.loads(manifest_path.read_text("utf-8"))
    except Exception as exc:
        logger.warning("Failed to parse native integrity manifest %s: %s", manifest_path, exc)
        return {}
    entries = payload.get("libraries", {})
    normalized: dict[str, str] = {}
    if isinstance(entries, dict):
        for name, entry in entries.items():
            if isinstance(entry, str):
                normalized[name] = entry
            elif isinstance(entry, dict) and isinstance(entry.get("sha256"), str):
                normalized[name] = entry["sha256"]
    return normalized


def _verify_library_integrity(path: Path, public_key_hex: str | None = None) -> bool:
    if not _verify_manifest_signature(path.parent, public_key_hex=public_key_hex):
        return False
    manifest = _load_native_manifest(path.parent)
    if not manifest:
        return False
    expected = manifest.get(path.name, "")
    if not expected:
        return False
    actual = _sha256_file(path)
    if actual != expected:
        logger.error("Native library hash mismatch for %s", path)
        return False
    return True


def _verify_manifest_signature(directory: Path, public_key_hex: str | None = None) -> bool:
    manifest_path = directory / "manifest.json"
    signature_path = directory / "manifest.sig"
    if not manifest_path.exists() or not signature_path.exists():
        logger.warning("Missing signed native manifest in %s", directory)
        return False
    if ed25519 is None:
        logger.warning("cryptography not available — refusing native library without signature verification")
        return False

    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(public_key_hex or _TRUSTED_NATIVE_SIGNING_PUBLIC_KEY_HEX)
        )
        signature = base64.b64decode(signature_path.read_text("utf-8").strip())
        public_key.verify(signature, manifest_path.read_bytes())
        return True
    except Exception as exc:
        logger.error("Native manifest signature verification failed for %s: %s", directory, exc)
        return False


def _native_input_allowed(*values: str | bytes, total_limit: int = _MAX_NATIVE_TEXT_BYTES) -> bool:
    total = 0
    for value in values:
        size = len(value if isinstance(value, bytes) else value.encode("utf-8"))
        if size > _MAX_NATIVE_TEXT_BYTES:
            return False
        total += size
    return total <= total_limit


# ============================================================
# Token Analyzer Wrappers (C)
# ============================================================

def estimate_tokens(text: str) -> int:
    """Estimate BPE token count. Falls back to Python heuristic."""
    _ensure_loaded()
    if _tokens_lib and _native_input_allowed(text):
        return _tokens_lib.basilisk_estimate_tokens(text.encode("utf-8"))
    # Python fallback: rough 4-chars-per-token
    return max(1, len(text) // 4)


def entropy(text: str) -> float:
    """Calculate Shannon entropy (bits per byte)."""
    _ensure_loaded()
    if _tokens_lib and _native_input_allowed(text):
        return _tokens_lib.basilisk_entropy(text.encode("utf-8"))
    # Python fallback
    import math
    from collections import Counter
    if not text:
        return 0.0
    freq = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def levenshtein(s1: str, s2: str) -> int:
    """Levenshtein edit distance between two strings."""
    _ensure_loaded()
    if _tokens_lib and _native_input_allowed(s1, s2, total_limit=_MAX_NATIVE_PAIR_BYTES):
        return _tokens_lib.basilisk_levenshtein(s1.encode("utf-8"), s2.encode("utf-8"))
    # Python fallback (naive DP)
    if not _native_input_allowed(s1, s2, total_limit=_MAX_NATIVE_PAIR_BYTES):
        raise ValueError("Input too large for safe Levenshtein evaluation")
    m, n = len(s1), len(s2)
    if m > n:
        s1, s2, m, n = s2, s1, n, m
    prev = list(range(m + 1))
    for j in range(1, n + 1):
        curr = [j] + [0] * m
        for i in range(1, m + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            curr[i] = min(prev[i] + 1, curr[i - 1] + 1, prev[i - 1] + cost)
        prev = curr
    return prev[m]


def similarity(s1: str, s2: str) -> float:
    """Normalized similarity 0.0 to 1.0."""
    _ensure_loaded()
    if _tokens_lib and _native_input_allowed(s1, s2, total_limit=_MAX_NATIVE_PAIR_BYTES):
        return _tokens_lib.basilisk_similarity(s1.encode("utf-8"), s2.encode("utf-8"))
    if not _native_input_allowed(s1, s2, total_limit=_MAX_NATIVE_PAIR_BYTES):
        raise ValueError("Input too large for safe similarity evaluation")
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    return 1.0 - levenshtein(s1, s2) / max_len


def count_confusables(text: str) -> int:
    """Count Unicode confusable characters in text."""
    _ensure_loaded()
    if _tokens_lib and _native_input_allowed(text):
        return _tokens_lib.basilisk_count_confusables(text.encode("utf-8"))
    return 0  # Fallback: no detection


def fast_search(text: str, pattern: str) -> int:
    """Fast substring search. Returns position or -1."""
    _ensure_loaded()
    if _tokens_lib and _native_input_allowed(text, pattern, total_limit=_MAX_NATIVE_PAIR_BYTES):
        return _tokens_lib.basilisk_fast_search(text.encode("utf-8"), pattern.encode("utf-8"))
    pos = text.lower().find(pattern.lower())
    return pos


# ============================================================
# Encoder Wrappers (C)
# ============================================================

def base64_encode(data: bytes) -> str:
    """Fast base64 encoding."""
    _ensure_loaded()
    if _encoder_lib and _native_input_allowed(data):
        ptr = _encoder_lib.basilisk_base64_encode(data, len(data))
        result = _string_from_ptr(ptr, _encoder_lib.basilisk_free)
        if result is not None:
            return result
    import base64 as b64
    return b64.b64encode(data).decode("utf-8")


def rot13(text: str) -> str:
    """ROT13 transform."""
    _ensure_loaded()
    if _encoder_lib and _native_input_allowed(text):
        ptr = _encoder_lib.basilisk_rot13(text.encode("utf-8"))
        result = _string_from_ptr(ptr, _encoder_lib.basilisk_free)
        if result is not None:
            return result
    import codecs
    return codecs.encode(text, "rot_13")


def url_encode(text: str) -> str:
    """URL-encode a string."""
    _ensure_loaded()
    if _encoder_lib and _native_input_allowed(text):
        ptr = _encoder_lib.basilisk_url_encode(text.encode("utf-8"))
        result = _string_from_ptr(ptr, _encoder_lib.basilisk_free)
        if result is not None:
            return result
    from urllib.parse import quote_plus
    return quote_plus(text)


def unicode_escape(text: str) -> str:
    """Convert to Unicode escape sequences."""
    _ensure_loaded()
    if _encoder_lib and _native_input_allowed(text):
        ptr = _encoder_lib.basilisk_unicode_escape(text.encode("utf-8"))
        result = _string_from_ptr(ptr, _encoder_lib.basilisk_free)
        if result is not None:
            return result
    return "".join(f"\\u{ord(c):04x}" for c in text)


def reverse_string(text: str) -> str:
    """UTF-8 aware string reversal."""
    _ensure_loaded()
    if _encoder_lib and _native_input_allowed(text):
        ptr = _encoder_lib.basilisk_reverse(text.encode("utf-8"))
        result = _string_from_ptr(ptr, _encoder_lib.basilisk_free)
        if result is not None:
            return result
    return text[::-1]


# ============================================================
# Fuzzer Wrappers (Go)
# ============================================================

def mutate(text: str, mutation_type: int = -1) -> str:
    """Apply a mutation to text. -1 = random mutation type."""
    _ensure_loaded()
    if _fuzzer_lib and _native_input_allowed(text):
        encoded = text.encode("utf-8")
        if mutation_type < 0:
            ptr = _fuzzer_lib.BasiliskMutateRandom(encoded)
        else:
            ptr = _fuzzer_lib.BasiliskMutate(encoded, mutation_type)
        result = _string_from_ptr(ptr, _fuzzer_lib.BasiliskFreeString)
        if result is not None:
            return result
    # Python fallback
    return text


def crossover(parent1: str, parent2: str, strategy: int = 0) -> str:
    """Crossover two parent strings. strategy: 0=single-point, 1=uniform, 2=prefix-suffix."""
    _ensure_loaded()
    if _fuzzer_lib and _native_input_allowed(parent1, parent2, total_limit=_MAX_NATIVE_PAIR_BYTES):
        ptr = _fuzzer_lib.BasiliskCrossover(
            parent1.encode("utf-8"),
            parent2.encode("utf-8"),
            strategy,
        )
        result = _string_from_ptr(ptr, _fuzzer_lib.BasiliskFreeString)
        if result is not None:
            return result
    # Fallback: simple half-and-half
    words1 = parent1.split()
    words2 = parent2.split()
    return " ".join(words1[: len(words1) // 2] + words2[len(words2) // 2 :])


def homoglyph_transform(text: str, rate: float = 0.15) -> str:
    """Replace characters with Unicode confusables."""
    _ensure_loaded()
    if _fuzzer_lib and _native_input_allowed(text):
        ptr = _fuzzer_lib.BasiliskHomoglyphTransform(text.encode("utf-8"), rate)
        result = _string_from_ptr(ptr, _fuzzer_lib.BasiliskFreeString)
        if result is not None:
            return result
    return text


def zero_width_inject(text: str) -> str:
    """Insert zero-width characters into text."""
    _ensure_loaded()
    if _fuzzer_lib and _native_input_allowed(text):
        ptr = _fuzzer_lib.BasiliskZeroWidthInject(text.encode("utf-8"))
        result = _string_from_ptr(ptr, _fuzzer_lib.BasiliskFreeString)
        if result is not None:
            return result
    return text


def count_runes(text: str) -> int:
    """Count Unicode rune count (character count)."""
    _ensure_loaded()
    if _fuzzer_lib and _native_input_allowed(text):
        return _fuzzer_lib.BasiliskCountRunes(text.encode("utf-8"))
    return len(text)


def get_mutation_count() -> int:
    """Get total number of available native mutation operators."""
    _ensure_loaded()
    if _fuzzer_lib:
        return _fuzzer_lib.BasiliskGetMutationCount()
    return 0


# ============================================================
# Matcher Wrappers (Go)
# ============================================================

def detect_refusal(text: str) -> float:
    """Detect refusal patterns. Returns confidence 0.0-1.0."""
    _ensure_loaded()
    if _matcher_lib and _native_input_allowed(text):
        return _matcher_lib.BasiliskDetectRefusal(text.encode("utf-8"))
    # Python fallback — use canonical refusal module
    from basilisk.core.refusal import refusal_confidence
    return refusal_confidence(text)


def detect_sensitive_data(text: str) -> str:
    """Detect sensitive data patterns. Returns JSON string of matches."""
    _ensure_loaded()
    if _matcher_lib and _native_input_allowed(text):
        ptr = _matcher_lib.BasiliskDetectSensitiveData(text.encode("utf-8"))
        result = _string_from_ptr(ptr, _matcher_lib.BasiliskFreeStr)
        if result is not None:
            return result
    return "[]"


class PatternMatcher:
    """Managed Aho-Corasick pattern matcher instance."""

    def __init__(self):
        _ensure_loaded()
        self._native = _matcher_lib is not None
        self._id = None
        self._patterns: List[str] = []
        if self._native:
            self._id = _matcher_lib.BasiliskMatcherCreate()

    def add_pattern(self, pattern: str) -> int:
        """Add a pattern to the matcher. Returns pattern index."""
        if self._native and _native_input_allowed(pattern):
            return _matcher_lib.BasiliskMatcherAddPattern(self._id, pattern.encode("utf-8"))
        idx = len(self._patterns)
        self._patterns.append(pattern.lower())
        return idx

    def build(self):
        """Build the automaton (must call after adding all patterns)."""
        if self._native:
            _matcher_lib.BasiliskMatcherBuild(self._id)

    def search(self, text: str) -> str:
        """Search text for patterns. Returns JSON string of matches."""
        if self._native and _native_input_allowed(text):
            ptr = _matcher_lib.BasiliskMatcherSearch(self._id, text.encode("utf-8"))
            result = _string_from_ptr(ptr, _matcher_lib.BasiliskFreeStr)
            if result is not None:
                return result
        # Python fallback
        import json
        matches = []
        lower = text.lower()
        for idx, pattern in enumerate(self._patterns):
            pos = lower.find(pattern)
            while pos >= 0:
                matches.append({"pattern_index": idx, "pattern": pattern, "position": pos})
                pos = lower.find(pattern, pos + 1)
        return json.dumps(matches)

    def destroy(self):
        """Free native resources."""
        if self._native and self._id is not None:
            _matcher_lib.BasiliskMatcherDestroy(self._id)
            self._id = None

    def __del__(self):
        self.destroy()
