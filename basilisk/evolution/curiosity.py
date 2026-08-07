"""
Basilisk Curiosity Steering — exploration-driven mutation rewards.

Partitions the response space into behavioral clusters using TF-IDF
vectors and rewards mutations that land in sparse, unexplored regions.
Uses curiosity-driven exploration to maximize attack surface coverage.
"""

from __future__ import annotations

import logging
import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("basilisk.evolution.curiosity")


@dataclass
class BehavioralRegion:
    """A cluster in the behavioral response space."""
    centroid_terms: list[str] = field(default_factory=list)
    visit_count: int = 0
    best_fitness: float = 0.0
    sample_responses: list[str] = field(default_factory=list)


class BehavioralSpace:
    """Tracks exploration coverage across the response space.

    Partitions responses into bins based on TF-IDF similarity,
    then computes curiosity bonuses that reward visiting
    under-explored regions.

    Works without sklearn by falling back to bag-of-words
    Jaccard binning.

    n_bins selection guidance:
        - 10:  small eval suites (<50 responses)
        - 25:  standard scans (default)
        - 100: deep/chaos mode scans with high response diversity

    When adaptive=True (default), bins that become overly dense
    are split incrementally. This prevents curiosity collapse
    where all responses cluster into a few bins. Splitting is
    gradual: n_bins grows by 1 per split, not doubling.
    """

    def __init__(
        self,
        n_bins: int = 25,
        max_samples_per_bin: int = 10,
        adaptive: bool = True,
        density_threshold: float = 3.0,
    ) -> None:
        self.n_bins = n_bins
        self.max_samples_per_bin = max_samples_per_bin
        self.adaptive = adaptive
        self.density_threshold = density_threshold
        self._responses: list[str] = []
        self._behavior_signatures: list[tuple[str, str, bool, bool, bool]] = []
        self._bins: dict[int, list[int]] = defaultdict(list)
        self._bin_fitness: dict[int, float] = defaultdict(float)
        self._total_visits = 0
        self._use_tfidf = False
        self._splits = 0

        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.cluster import MiniBatchKMeans
            self._use_tfidf = True
        except ImportError:
            pass

    def update(self, response: str, fitness: float = 0.0) -> int:
        """Add a response to the behavioral space.

        Returns the bin index the response was assigned to.
        If adaptive mode is on, may split a dense bin after assignment.
        """
        idx = len(self._responses)
        self._responses.append(response)
        self._behavior_signatures.append(self._behavior_signature(response))
        self._total_visits += 1

        bin_id = self._assign_bin(response)
        self._bins[bin_id].append(idx)
        self._bin_fitness[bin_id] = max(self._bin_fitness[bin_id], fitness)

        # Adaptive: split the assigned bin if it exceeds density threshold
        if self.adaptive and self._total_visits > self.n_bins:
            self._maybe_split_bin(bin_id)

        return bin_id

    def _maybe_split_bin(self, bin_id: int) -> None:
        """Split a single bin if it exceeds density_threshold * avg_density.

        Incremental growth: n_bins goes 25 -> 26 -> 27, not 25 -> 50.
        Only the dense bin's members are rehashed between the original
        bin and the new bin.
        """
        if not self._bins[bin_id]:
            return

        bin_count = len(self._bins[bin_id])
        occupied = sum(1 for v in self._bins.values() if v)
        avg_density = self._total_visits / max(occupied, 1)

        if bin_count <= self.density_threshold * avg_density:
            return

        # Create new bin by splitting the dense one
        new_bin_id = self.n_bins
        self.n_bins += 1
        self._splits += 1

        # Rehash members of the dense bin between original and new
        old_members = self._bins[bin_id]
        keep: list[int] = []
        move: list[int] = []

        for member_idx in old_members:
            resp = self._responses[member_idx]
            tokens = set(resp.lower().split())
            token_hash = hash(frozenset(list(tokens)[:20]))
            if abs(token_hash) % 2 == 0:
                keep.append(member_idx)
            else:
                move.append(member_idx)

        self._bins[bin_id] = keep
        self._bins[new_bin_id] = move

        logger.debug(
            f"Split bin {bin_id} ({bin_count} items) -> "
            f"bin {bin_id} ({len(keep)}) + bin {new_bin_id} ({len(move)}), "
            f"total bins: {self.n_bins}"
        )

    def curiosity_bonus(self, response: str) -> float:
        """Compute curiosity reward for a response.

        Returns 0.0 (well-explored region) to 1.0 (completely novel region).
        Higher bonus for responses that land in sparsely visited bins.
        """
        if self._total_visits == 0:
            return 1.0

        bin_id = self._assign_bin(response)
        visit_count = len(self._bins.get(bin_id, []))

        if visit_count == 0:
            return 1.0  # Completely new region

        # Inverse visit frequency
        avg_visits = self._total_visits / max(len(self._bins), 1)
        if avg_visits == 0:
            return 1.0

        # Curiosity decreases logarithmically with visits
        novelty = 1.0 / (1.0 + math.log1p(visit_count / avg_visits))
        semantic_novelty = self._semantic_novelty(response)
        behavioral_novelty = self._behavioral_novelty(response)
        combined = (0.38 * novelty) + (0.32 * semantic_novelty) + (0.30 * behavioral_novelty)
        return max(0.0, min(1.0, combined))

    def exploration_coverage(self) -> float:
        """Fraction of bins that have been visited at least once."""
        visited = sum(1 for b in self._bins.values() if len(b) > 0)
        return visited / self.n_bins if self.n_bins > 0 else 0.0

    def _assign_bin(self, response: str) -> int:
        """Assign a response to a behavioral bin."""
        if self._use_tfidf and len(self._responses) >= 5:
            return self._tfidf_bin(response)
        return self._jaccard_bin(response)

    def _jaccard_bin(self, response: str) -> int:
        """Fallback binning using token Jaccard similarity."""
        tokens = set(response.lower().split())
        if not tokens:
            return 0

        # Hash-based binning
        token_hash = hash(frozenset(list(tokens)[:20]))  # Limit tokens for stability
        return abs(token_hash) % self.n_bins

    def _tfidf_bin(self, response: str) -> int:
        """Bin using TF-IDF + KMeans clustering."""
        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.cluster import MiniBatchKMeans

            corpus = self._responses[-200:] + [response]
            n_clusters = min(self.n_bins, len(corpus))

            vectorizer = TfidfVectorizer(max_features=500, stop_words="english")
            tfidf = vectorizer.fit_transform(corpus)

            kmeans = MiniBatchKMeans(n_clusters=n_clusters, random_state=42, n_init=1)
            labels = kmeans.fit_predict(tfidf)

            return int(labels[-1])
        except (ImportError, ValueError) as exc:
            logger.debug("TF-IDF behavior binning unavailable: %s", exc)
            return self._jaccard_bin(response)
        except Exception:
            logger.exception("Unexpected TF-IDF behavior-binning failure")
            return self._jaccard_bin(response)

    def _semantic_novelty(self, response: str) -> float:
        """Estimate novelty via similarity to recent responses."""
        if not self._responses:
            return 1.0
        corpus = self._responses[-200:]
        if not corpus:
            return 1.0

        if self._use_tfidf and len(corpus) >= 5:
            try:
                from sklearn.feature_extraction.text import TfidfVectorizer
                from sklearn.metrics.pairwise import cosine_similarity

                vectorizer = TfidfVectorizer(
                    max_features=750,
                    ngram_range=(1, 2),
                    stop_words="english",
                )
                matrix = vectorizer.fit_transform(corpus + [response])
                similarity = cosine_similarity(matrix[-1], matrix[:-1]).max()
                return max(0.0, min(1.0, 1.0 - float(similarity)))
            except (ImportError, ValueError) as exc:
                logger.debug("TF-IDF semantic novelty unavailable: %s", exc)
            except Exception:
                logger.exception("Unexpected TF-IDF novelty failure")

        response_words = set(response.lower().split())
        if not response_words:
            return 0.0
        max_overlap = 0.0
        for seen in corpus:
            seen_words = set(seen.lower().split())
            if not seen_words:
                continue
            overlap = len(response_words & seen_words) / max(len(response_words | seen_words), 1)
            max_overlap = max(max_overlap, overlap)
        return max(0.0, min(1.0, 1.0 - max_overlap))

    def _behavior_signature(self, response: str) -> tuple[str, str, bool, bool, bool]:
        """Project a response into a coarse behavioral space."""
        from basilisk.core.refusal import classify_refusal_style, refusal_confidence

        lower = response.lower()
        refusal_style = classify_refusal_style(response)
        is_refusal = refusal_confidence(response) >= 0.4
        leakage = any(
            token in lower
            for token in ("system prompt", "api key", "token", "secret", "password", "credential", "instructions")
        )
        tool_surface = any(
            token in lower
            for token in ("http://", "https://", "localhost", "169.254.169.254", "uid=", "gid=", "select ", "/etc/")
        )
        partial_compliance = any(
            token in lower
            for token in ("hypothetical", "fictional", "for research", "example only", "simulated", "in a story")
        )

        if is_refusal:
            behavior = "refusal"
        elif leakage:
            behavior = "leakage"
        elif tool_surface:
            behavior = "tool_output"
        elif partial_compliance:
            behavior = "partial_compliance"
        elif len(response.split()) > 120:
            behavior = "substantive"
        else:
            behavior = "generic"

        return (behavior, refusal_style, leakage, tool_surface, partial_compliance)

    def _behavioral_novelty(self, response: str) -> float:
        """Reward novel response behavior, not just novel wording."""
        if not self._behavior_signatures:
            return 1.0
        signature = self._behavior_signature(response)
        recent = self._behavior_signatures[-200:]
        exact_matches = recent.count(signature)
        if exact_matches == 0:
            return 1.0

        best_similarity = 0.0
        for seen in recent:
            overlap = sum(1 for a, b in zip(signature, seen) if a == b) / len(signature)
            best_similarity = max(best_similarity, overlap)
        density_penalty = exact_matches / max(len(recent), 1)
        return max(0.0, min(1.0, 1.0 - ((0.65 * best_similarity) + (0.35 * density_penalty))))

    def stats(self) -> dict[str, Any]:
        """Return exploration statistics."""
        bin_sizes = {k: len(v) for k, v in self._bins.items() if v}
        return {
            "total_visits": self._total_visits,
            "bins_visited": len(bin_sizes),
            "total_bins": self.n_bins,
            "coverage": round(self.exploration_coverage(), 4),
            "mode": "tfidf_behavioral" if self._use_tfidf else "jaccard_behavioral",
            "bin_distribution": dict(sorted(bin_sizes.items())),
            "most_visited_bin": max(bin_sizes, key=bin_sizes.get) if bin_sizes else None,
            "least_visited_bin": min(bin_sizes, key=bin_sizes.get) if bin_sizes else None,
            "adaptive_splits": self._splits,
        }

    def top_unexplored_bins(self, n: int = 5) -> list[int]:
        """Return bin IDs with fewest visits (exploration targets)."""
        all_bins = {i: len(self._bins.get(i, [])) for i in range(self.n_bins)}
        sorted_bins = sorted(all_bins.items(), key=lambda x: x[1])
        return [b[0] for b in sorted_bins[:n]]
