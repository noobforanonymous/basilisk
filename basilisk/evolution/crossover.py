"""
Basilisk Crossover — breeding strategies for combining successful payloads.

Takes two parent payloads and produces hybrid offspring that combine
the most effective elements of each.
"""

from __future__ import annotations

from dataclasses import dataclass

from basilisk.evolution.randomness import random


@dataclass
class CrossoverResult:
    """Result of a crossover operation."""
    parent_a: str
    parent_b: str
    offspring: str
    strategy: str


def crossover(parent_a: str, parent_b: str) -> CrossoverResult:
    """
    Apply a random crossover strategy to produce offspring.

    Strategies:
    - single_point: split both at a point and swap tails
    - uniform: randomly pick words from either parent
    - prefix_suffix: use beginning of A and end of B
    - semantic_blend: interleave sentences
    - best_of_both: take the longest clauses from each
    """
    strategy = random.choice([
        "single_point", "uniform", "prefix_suffix",
        "semantic_blend", "best_of_both",
    ])

    if strategy == "single_point":
        offspring = _single_point_crossover(parent_a, parent_b)
    elif strategy == "uniform":
        offspring = _uniform_crossover(parent_a, parent_b)
    elif strategy == "prefix_suffix":
        offspring = _prefix_suffix_crossover(parent_a, parent_b)
    elif strategy == "semantic_blend":
        offspring = _semantic_blend(parent_a, parent_b)
    else:
        offspring = _best_of_both(parent_a, parent_b)

    return CrossoverResult(parent_a, parent_b, offspring, strategy)


def _single_point_crossover(a: str, b: str) -> str:
    """Split each parent at a random point and swap second halves."""
    words_a = a.split()
    words_b = b.split()

    if len(words_a) < 2 or len(words_b) < 2:
        return a  # Can't crossover very short payloads

    point_a = random.randint(1, len(words_a) - 1)
    point_b = random.randint(1, len(words_b) - 1)

    offspring_words = words_a[:point_a] + words_b[point_b:]
    return " ".join(offspring_words)


def _uniform_crossover(a: str, b: str) -> str:
    """Randomly select each word from either parent."""
    words_a = a.split()
    words_b = b.split()
    max_len = max(len(words_a), len(words_b))

    offspring = []
    for i in range(max_len):
        if i < len(words_a) and i < len(words_b):
            offspring.append(random.choice([words_a[i], words_b[i]]))
        elif i < len(words_a):
            offspring.append(words_a[i])
        else:
            offspring.append(words_b[i])

    return " ".join(offspring)


def _prefix_suffix_crossover(a: str, b: str) -> str:
    """Take the beginning of parent A and the end of parent B."""
    words_a = a.split()
    words_b = b.split()

    if len(words_a) < 2 or len(words_b) < 2:
        return a  # Can't crossover very short payloads

    take_from_a = random.randint(1, max(1, len(words_a) // 2))
    take_from_b = random.randint(max(1, len(words_b) // 2), max(1, len(words_b)))

    return " ".join(words_a[:take_from_a] + words_b[take_from_b:])


def _semantic_blend(a: str, b: str) -> str:
    """Interleave sentences from both parents."""
    # Split by sentence boundaries
    import re
    sentences_a = re.split(r'[.!?]+', a)
    sentences_b = re.split(r'[.!?]+', b)

    sentences_a = [s.strip() for s in sentences_a if s.strip()]
    sentences_b = [s.strip() for s in sentences_b if s.strip()]

    blended = []
    max_len = max(len(sentences_a), len(sentences_b))
    for i in range(max_len):
        if i < len(sentences_a):
            blended.append(sentences_a[i])
        if i < len(sentences_b):
            blended.append(sentences_b[i])

    return ". ".join(blended) + "."


def _best_of_both(a: str, b: str) -> str:
    """Extract the most unique/long clauses from each parent."""
    import re
    clauses_a = re.split(r'[,;:]+', a)
    clauses_b = re.split(r'[,;:]+', b)

    all_clauses = [(c.strip(), len(c.strip())) for c in clauses_a + clauses_b if c.strip()]
    all_clauses.sort(key=lambda x: x[1], reverse=True)

    # Take the top clauses that fit
    selected = [c[0] for c in all_clauses[:5]]
    random.shuffle(selected)
    return ", ".join(selected) + "."
