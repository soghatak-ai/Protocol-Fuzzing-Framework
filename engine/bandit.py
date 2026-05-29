"""
RL Weight Adjuster — multiplier on top of base (AI/default) weights.

Each mutation strategy is an "arm". Rewards come from crashes/anomalies.
The RL module computes a multiplier per strategy:
  - Crash found   → multiplier increases  (boost)
  - No crash      → multiplier decreases very slowly  (fade)

Final weight = base_weight × rl_multiplier  (then normalized to 100%).
"""

import math
import random
import threading


class UCB1Bandit:
    """RL adjuster that modifies base weights rather than replacing them.

    - crash_boost:  how much each crash boosts the multiplier (0.5 = +50% per crash)
    - decay_rate:   how fast non-crashing strategies fade (0.1 = very slow)
    - min_mult:     minimum multiplier (prevents total starvation)
    - max_mult:     maximum multiplier cap
    """

    def __init__(self, arms, initial_weights=None,
                 crash_boost=0.5, decay_rate=0.1, min_mult=0.5, max_mult=3.0):
        self.arms = list(arms)
        self.n_arms = len(self.arms)
        self.crash_boost = crash_boost
        self.decay_rate = decay_rate
        self.min_mult = min_mult
        self.max_mult = max_mult
        self._lock = threading.Lock()

        # Per-arm counters
        self.pulls = {a: 0 for a in self.arms}
        self.rewards = {a: 0.0 for a in self.arms}
        self.total_pulls = 0

    def update(self, arm, reward):
        """Record the outcome of using an arm.

        Args:
            arm:    strategy name
            reward: float (1.0 for crash, 0.0 for nothing)
        """
        if arm not in self.pulls:
            return
        with self._lock:
            self.pulls[arm] += 1
            self.rewards[arm] += reward
            self.total_pulls += 1

    def get_multipliers(self):
        """Compute RL multiplier per arm (thread-safe).

        Returns dict {arm: multiplier} where:
          - multiplier > 1.0 for crash-producing strategies
          - multiplier ≈ 1.0 for untried/new strategies
          - multiplier < 1.0 for strategies that fade (slowly)
        """
        with self._lock:
            return self._get_multipliers_unlocked()

    def _get_multipliers_unlocked(self):
        """Internal: compute multipliers without lock."""
        if self.total_pulls == 0:
            return {a: 1.0 for a in self.arms}

        multipliers = {}
        for a in self.arms:
            if self.pulls[a] == 0:
                multipliers[a] = 1.0
            elif self.rewards[a] > 0:
                # Boost: each crash adds crash_boost to multiplier
                mult = 1.0 + self.rewards[a] * self.crash_boost
                multipliers[a] = min(self.max_mult, mult)
            else:
                # Slow fade: proportional to this arm's share of total pulls
                frac = self.pulls[a] / max(self.total_pulls, 1)
                mult = 1.0 - frac * self.decay_rate
                multipliers[a] = max(self.min_mult, mult)

        return multipliers

    def get_adjusted_weights(self, base_weights):
        """Apply RL multipliers to base weights and normalize.

        Args:
            base_weights: dict {strategy: weight} (AI or default weights)

        Returns:
            dict {strategy: adjusted_weight} normalized to sum=1.0
        """
        with self._lock:
            mults = self._get_multipliers_unlocked()

        adjusted = {}
        for a in self.arms:
            adjusted[a] = base_weights.get(a, 0) * mults.get(a, 1.0)

        total = sum(adjusted.values())
        if total > 0:
            adjusted = {a: round(v / total, 6) for a, v in adjusted.items()}
        return adjusted

    def select_with_weights(self, base_weights):
        """Pick a strategy using base_weights × RL multipliers.

        Args:
            base_weights: dict {strategy: weight}

        Returns:
            strategy name string
        """
        adjusted = self.get_adjusted_weights(base_weights)
        return random.choices(self.arms, weights=[adjusted[a] for a in self.arms])[0]

    def get_stats(self, base_weights=None):
        """Return bandit state for UI display."""
        with self._lock:
            mults = self._get_multipliers_unlocked()
            stats = {}
            for a in self.arms:
                stats[a] = {
                    "pulls": self.pulls[a],
                    "rewards": round(self.rewards[a], 2),
                    "multiplier": round(mults[a], 4),
                }

            # Compute adjusted weights if base provided
            rl_weights = {}
            if base_weights:
                raw = {a: base_weights.get(a, 0) * mults[a] for a in self.arms}
                total = sum(raw.values())
                if total > 0:
                    rl_weights = {a: round(v / total, 6) for a, v in raw.items()}
                for a in self.arms:
                    stats[a]["rl_weight"] = rl_weights.get(a, 0)
            else:
                for a in self.arms:
                    stats[a]["rl_weight"] = 0

            return {
                "total_pulls": self.total_pulls,
                "strategies": stats,
            }

    def reset(self):
        """Reset all learned data."""
        with self._lock:
            self.pulls = {a: 0 for a in self.arms}
            self.rewards = {a: 0.0 for a in self.arms}
            self.total_pulls = 0
