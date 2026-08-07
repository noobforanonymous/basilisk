"""Task-local deterministic randomness for evolution runs.

Evolution can run concurrently in the desktop backend.  Mutating Python's
process-wide ``random`` state would make otherwise identical scans influence
one another, so every run receives an independent generator through a
``ContextVar``.  Child asyncio tasks inherit the active context and offspring
tasks can fork independent streams before they perform asynchronous work.
"""

from __future__ import annotations

import contextvars
import random as _stdlib_random
from typing import Any


_ACTIVE_RANDOM: contextvars.ContextVar[_stdlib_random.Random | None] = (
    contextvars.ContextVar("basilisk_evolution_random", default=None)
)


class ContextRandom:
    """Proxy random operations to the generator owned by the active scan."""

    @staticmethod
    def _current() -> _stdlib_random.Random:
        generator = _ACTIVE_RANDOM.get()
        if generator is None:
            # Utility functions remain usable outside an EvolutionEngine run,
            # while engine-controlled execution is always explicitly seeded.
            generator = _stdlib_random.Random()
            _ACTIVE_RANDOM.set(generator)
        return generator

    def set_seed(self, seed: int) -> contextvars.Token[_stdlib_random.Random | None]:
        return _ACTIVE_RANDOM.set(_stdlib_random.Random(int(seed)))

    @staticmethod
    def reset(token: contextvars.Token[_stdlib_random.Random | None]) -> None:
        _ACTIVE_RANDOM.reset(token)

    def choice(self, sequence: Any) -> Any:
        return self._current().choice(sequence)

    def randint(self, start: int, stop: int) -> int:
        return self._current().randint(start, stop)

    def random(self) -> float:
        return self._current().random()

    def sample(self, population: Any, k: int) -> list[Any]:
        return self._current().sample(population, k)

    def shuffle(self, values: list[Any]) -> None:
        self._current().shuffle(values)

    def getrandbits(self, bits: int) -> int:
        return self._current().getrandbits(bits)

    def betavariate(self, alpha: float, beta: float) -> float:
        return self._current().betavariate(alpha, beta)


random = ContextRandom()
