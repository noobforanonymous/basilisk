"""
Basilisk Population — manages the pool of prompt payloads across generations.

Handles selection, elitism, and population diversity tracking for SPE-NL.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Individual:
    """A single payload in the population with its fitness data."""
    payload: str
    fitness: float = 0.0
    generation: int = 0
    parent_id: str | None = None
    operator_used: str = ""
    response: str = ""
    id: str = field(default_factory=lambda: f"ind-{__import__('uuid').uuid4().hex[:8]}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "payload": self.payload,
            "fitness": self.fitness,
            "generation": self.generation,
            "parent_id": self.parent_id,
            "operator_used": self.operator_used,
        }


class Population:
    """
    Manages a population of prompt payloads for the genetic algorithm.

    Supports tournament selection, elitism, and diversity enforcement.
    """

    def __init__(self, max_size: int = 100, elite_count: int = 10) -> None:
        self.max_size = max_size
        self.elite_count = elite_count
        self.individuals: list[Individual] = []
        self.generation: int = 0
        self.history: list[dict[str, Any]] = []  # Per-generation stats

    def seed(self, payloads: list[str]) -> None:
        """Initialize population from seed payloads."""
        self.individuals = [
            Individual(payload=p, generation=0)
            for p in payloads[:self.max_size]
        ]
        random.shuffle(self.individuals)

    def add(self, individual: Individual) -> None:
        """Add an individual to the population."""
        individual.generation = self.generation
        self.individuals.append(individual)

    def tournament_select(self, tournament_size: int = 5) -> Individual:
        """Select an individual via tournament selection."""
        tournament = random.sample(
            self.individuals,
            min(tournament_size, len(self.individuals)),
        )
        return max(tournament, key=lambda ind: ind.fitness)

    def get_elite(self) -> list[Individual]:
        """Return the top N individuals by fitness (elitism)."""
        sorted_pop = sorted(self.individuals, key=lambda x: x.fitness, reverse=True)
        return sorted_pop[: self.elite_count]

    def advance_generation(self, new_individuals: list[Individual]) -> dict[str, Any]:
        """
        Move to the next generation.

        Keeps elite individuals, replaces the rest with new offspring.
        Returns generation statistics.
        """
        elite = self.get_elite()
        self.generation += 1

        # Combine elite with new individuals
        combined = elite + new_individuals
        combined = combined[: self.max_size]
        for ind in combined:
            ind.generation = self.generation

        # Track stats
        fitnesses = [ind.fitness for ind in combined]
        stats = {
            "generation": self.generation,
            "population_size": len(combined),
            "best_fitness": max(fitnesses) if fitnesses else 0.0,
            "avg_fitness": sum(fitnesses) / len(fitnesses) if fitnesses else 0.0,
            "min_fitness": min(fitnesses) if fitnesses else 0.0,
            "elite_preserved": len(elite),
            "new_offspring": len(new_individuals),
            "best_payload": max(combined, key=lambda x: x.fitness).payload if combined else "",
            "breakthroughs": sum(1 for ind in combined if ind.fitness >= 0.85),
        }
        self.history.append(stats)
        self.individuals = combined
        return stats

    @property
    def best(self) -> Individual | None:
        """Return the highest-fitness individual."""
        if not self.individuals:
            return None
        return max(self.individuals, key=lambda x: x.fitness)

    @property
    def avg_fitness(self) -> float:
        if not self.individuals:
            return 0.0
        return sum(ind.fitness for ind in self.individuals) / len(self.individuals)

    @property
    def breakthroughs(self) -> list[Individual]:
        """Return all individuals with fitness >= 0.85."""
        return [ind for ind in self.individuals if ind.fitness >= 0.85]

    @property
    def diversity_score(self) -> float:
        """Measure population diversity (0=homogeneous, 1=diverse)."""
        if len(self.individuals) < 2:
            return 0.0
        payloads = [ind.payload for ind in self.individuals]
        unique = len(set(payloads))
        return unique / len(payloads)

    def get_genealogy(self, individual_id: str) -> list[Individual]:
        """Trace an individual's ancestry through parent_ids."""
        ancestry = []
        current_id = individual_id
        all_individuals = {ind.id: ind for ind in self.individuals}

        while current_id and current_id in all_individuals:
            ind = all_individuals[current_id]
            ancestry.append(ind)
            current_id = ind.parent_id
            if len(ancestry) > 50:  # Prevent infinite loops
                break

        return list(reversed(ancestry))
