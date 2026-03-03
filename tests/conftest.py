"""
Basilisk test configuration and shared fixtures.
"""

import pytest
import sys
from pathlib import Path

# Ensure basilisk package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
