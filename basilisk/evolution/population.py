"""
Basilisk Population — manages the pool of prompt payloads across generations.

Handles selection, elitism, and population diversity tracking for SPE-NL.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from basilisk.evolution.randomness import random


@dataclass
class Individual:
    """A single payload in the population with its fitness data."""
    payload: str
    fitness: float = 0.0
    generation: int = 0
    parent_id: str | None = None
    operator_used: str = ""
    response: str = ""
    objectives: dict[str, float] = field(default_factory=dict)
    pareto_rank: int | None = None
    crowding_distance: float = 0.0
    bandit_recorded: bool = False
    selection_context: str = ""
    behavioral_profile: dict[str, Any] = field(default_factory=dict)
    id: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            identity = f"{self.generation}\0{self.parent_id or ''}\0{self.operator_used}\0{self.payload}"
            self.id = f"ind-{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:12]}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "payload": self.payload,
            "fitness": self.fitness,
            "generation": self.generation,
            "parent_id": self.parent_id,
            "operator_used": self.operator_used,
            "objectives": self.objectives,
            "pareto_rank": self.pareto_rank,
            "crowding_distance": self.crowding_distance,
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
        self._refresh_multiobjective_state()
        tournament = random.sample(
            self.individuals,
            min(tournament_size, len(self.individuals)),
        )
        if self._has_multiobjective_state():
            return min(tournament, key=self._selection_sort_key)
        return max(tournament, key=lambda ind: ind.fitness)

    def diversity_select(
        self,
        tournament_size: int = 5,
        novelty_archive: Any = None,
        novelty_weight: float = 0.3,
    ) -> Individual:
        """Select via tournament with diversity pressure.

        Blends fitness (1 - novelty_weight) with novelty score (novelty_weight).
        Falls back to pure fitness if no archive provided.
        """
        if novelty_archive is None:
            return self.tournament_select(tournament_size)

        from basilisk.evolution.diversity import classify_behavior

        self._refresh_multiobjective_state()
        tournament = random.sample(
            self.individuals,
            min(tournament_size, len(self.individuals)),
        )

        def combined_score(ind: Individual) -> float:
            descriptor = classify_behavior(
                ind.payload, ind.response,
                ind.operator_used, ind.fitness,
            )
            novelty = novelty_archive.novelty_score(descriptor)
            base = ind.fitness
            if self._has_multiobjective_state():
                rank_bonus = 1.0 / (1 + (ind.pareto_rank or 0))
                crowding = ind.crowding_distance if ind.crowding_distance != float("inf") else 1.0
                crowding_bonus = min(crowding, 1.0)
                base = (0.55 * rank_bonus) + (0.15 * crowding_bonus) + (0.30 * ind.fitness)
            return base * (1 - novelty_weight) + novelty * novelty_weight

        return max(tournament, key=combined_score)

    def get_elite(self) -> list[Individual]:
        """Return the top N individuals by fitness (elitism)."""
        self._refresh_multiobjective_state()
        if self._has_multiobjective_state():
            sorted_pop = sorted(self.individuals, key=self._selection_sort_key)
        else:
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
        self.individuals = combined
        self._refresh_multiobjective_state()
        stats = {
            "generation": self.generation,
            "population_size": len(combined),
            "best_fitness": max(fitnesses) if fitnesses else 0.0,
            "avg_fitness": sum(fitnesses) / len(fitnesses) if fitnesses else 0.0,
            "min_fitness": min(fitnesses) if fitnesses else 0.0,
            "elite_preserved": len(elite),
            "new_offspring": len(new_individuals),
            "best_payload": self.best.payload if self.best else "",
            "breakthroughs": sum(1 for ind in combined if ind.fitness >= 0.85),
            "pareto_front_size": sum(1 for ind in combined if ind.pareto_rank == 0),
        }
        self.history.append(stats)
        return stats

    @property
    def best(self) -> Individual | None:
        """Return the highest-fitness individual."""
        if not self.individuals:
            return None
        self._refresh_multiobjective_state()
        if self._has_multiobjective_state():
            return min(self.individuals, key=self._selection_sort_key)
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

    def deduplicate(self) -> int:
        """Remove individuals with duplicate payloads, keeping higher-fitness ones.

        Returns the number of duplicates removed.
        """
        seen: dict[str, Individual] = {}
        for ind in self.individuals:
            if ind.payload in seen:
                # Keep the one with higher fitness
                if ind.fitness > seen[ind.payload].fitness:
                    seen[ind.payload] = ind
            else:
                seen[ind.payload] = ind

        removed = len(self.individuals) - len(seen)
        self.individuals = list(seen.values())
        return removed

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

    def _has_multiobjective_state(self) -> bool:
        return any(ind.objectives for ind in self.individuals)

    def _selection_sort_key(self, ind: Individual) -> tuple[float, float, float]:
        rank = float(ind.pareto_rank if ind.pareto_rank is not None else 10_000)
        crowding = ind.crowding_distance if ind.crowding_distance != float("inf") else 1_000.0
        return (rank, -crowding, -ind.fitness)

    def _refresh_multiobjective_state(self) -> None:
        if not self._has_multiobjective_state():
            for ind in self.individuals:
                ind.pareto_rank = None
                ind.crowding_distance = 0.0
            return

        active = [ind for ind in self.individuals if ind.objectives]
        inactive = [ind for ind in self.individuals if not ind.objectives]
        for ind in inactive:
            ind.pareto_rank = None
            ind.crowding_distance = 0.0

        dominates: dict[str, set[str]] = {ind.id: set() for ind in active}
        dominated_count: dict[str, int] = {ind.id: 0 for ind in active}
        fronts: list[list[Individual]] = [[]]

        for i, first in enumerate(active):
            for second in active[i + 1:]:
                if _dominates(first, second):
                    dominates[first.id].add(second.id)
                    dominated_count[second.id] += 1
                elif _dominates(second, first):
                    dominates[second.id].add(first.id)
                    dominated_count[first.id] += 1

        by_id = {ind.id: ind for ind in active}
        for ind in active:
            if dominated_count[ind.id] == 0:
                ind.pareto_rank = 0
                fronts[0].append(ind)

        rank = 0
        while rank < len(fronts) and fronts[rank]:
            next_front: list[Individual] = []
            for ind in fronts[rank]:
                for dominated_id in dominates[ind.id]:
                    dominated_count[dominated_id] -= 1
                    if dominated_count[dominated_id] == 0:
                        dominated = by_id[dominated_id]
                        dominated.pareto_rank = rank + 1
                        next_front.append(dominated)
            if next_front:
                fronts.append(next_front)
            rank += 1

        for front in fronts:
            if front:
                _assign_crowding_distance(front)


def _dominates(first: Individual, second: Individual) -> bool:
    keys = set(first.objectives) & set(second.objectives)
    if not keys:
        return False
    better_or_equal = all(first.objectives[key] >= second.objectives[key] for key in keys)
    strictly_better = any(first.objectives[key] > second.objectives[key] for key in keys)
    return better_or_equal and strictly_better


def _assign_crowding_distance(front: list[Individual]) -> None:
    if not front:
        return
    if len(front) <= 2:
        for ind in front:
            ind.crowding_distance = float("inf")
        return

    for ind in front:
        ind.crowding_distance = 0.0

    objective_keys = sorted(front[0].objectives.keys())
    for key in objective_keys:
        ordered = sorted(front, key=lambda ind: ind.objectives.get(key, 0.0))
        ordered[0].crowding_distance = float("inf")
        ordered[-1].crowding_distance = float("inf")
        min_value = ordered[0].objectives.get(key, 0.0)
        max_value = ordered[-1].objectives.get(key, 0.0)
        if max_value == min_value:
            continue
        for idx in range(1, len(ordered) - 1):
            if ordered[idx].crowding_distance == float("inf"):
                continue
            prev_value = ordered[idx - 1].objectives.get(key, 0.0)
            next_value = ordered[idx + 1].objectives.get(key, 0.0)
            ordered[idx].crowding_distance += (next_value - prev_value) / (max_value - min_value)
