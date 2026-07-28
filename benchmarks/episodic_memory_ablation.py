"""
Episodic memory retrieval ablation (paper Section VII.E).

Validates argus.memory.episodic.EpisodicMemory.query_relevant() as a
prioritization mechanism: given a simulated prior-scan memory of varying
accuracy, how many OWASP categories must the Planner probe (in the order
EpisodicMemory ranks them) before reaching the true vulnerable category,
compared to a cold-start baseline that probes categories in random order?

This is a synthetic ablation over the real EpisodicMemory class -- no LLM
calls are involved. Ground truth ("the true vulnerable category") and the
memory's per-entry accuracy are simulated parameters, swept continuously
over [0, 1] rather than fixed at a few hand-picked settings.

Usage: python benchmarks/episodic_memory_ablation.py
Writes: benchmarks/results/episodic_memory_ablation.json
"""
from __future__ import annotations

import json
import random
import statistics
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from argus.memory.episodic import EpisodicMemory, MemoryEntry

OWASP_CATEGORIES = [f"LLM{i:02d}" for i in range(1, 11)]
N_FAMILIES = 4000
SEED = 20260728


def simulate_family(rng: random.Random, family_idx: int) -> dict:
    """
    Simulate one synthetic model family:
      - a true vulnerable category (ground truth)
      - a memory accuracy level drawn uniformly from [0, 1]
      - a populated EpisodicMemory reflecting that accuracy
      - the cold-start (random order) probe count for the same ground truth
    """
    family_id = f"synthetic-family-{family_idx}"
    true_category = rng.choice(OWASP_CATEGORIES)
    accuracy = rng.random()  # continuous sweep over [0, 1]

    mem = EpisodicMemory()
    scores = {}
    if rng.random() < accuracy:
        # Memory correctly identifies the vulnerable category: it gets the
        # top score, all others get random lower scores.
        scores[true_category] = rng.uniform(7.0, 10.0)
        others = [c for c in OWASP_CATEGORIES if c != true_category]
        rng.shuffle(others)
        for i, c in enumerate(others):
            scores[c] = rng.uniform(0.0, 6.9)
    else:
        # Memory is uninformative for this family: scores assigned in random
        # order with no relationship to the true category.
        shuffled = OWASP_CATEGORIES[:]
        rng.shuffle(shuffled)
        pool = sorted([rng.uniform(0.0, 10.0) for _ in OWASP_CATEGORIES], reverse=True)
        for c, s in zip(shuffled, pool):
            scores[c] = s

    for category, score in scores.items():
        mem.add(MemoryEntry(
            payload_text=f"synthetic prior payload for {category}",
            owasp_category=category,
            surface="direct",
            strategy="synthetic",
            model_family=family_id,
            cvss_score=score,
            embedding=[0.0],
            session_id="ablation",
        ))

    ranked = mem.query_relevant(model_family=family_id, top_k=10)
    ranked_categories = [r["owasp_category"] for r in ranked]
    memory_seeded_probes = ranked_categories.index(true_category) + 1

    cold_order = OWASP_CATEGORIES[:]
    rng.shuffle(cold_order)
    cold_start_probes = cold_order.index(true_category) + 1

    return {
        "family_id": family_id,
        "true_category": true_category,
        "accuracy": accuracy,
        "memory_seeded_probes": memory_seeded_probes,
        "cold_start_probes": cold_start_probes,
    }


def main() -> None:
    rng = random.Random(SEED)
    results = [simulate_family(rng, i) for i in range(N_FAMILIES)]

    mean_seeded = statistics.mean(r["memory_seeded_probes"] for r in results)
    mean_cold = statistics.mean(r["cold_start_probes"] for r in results)
    reduction_pct = 100.0 * (mean_cold - mean_seeded) / mean_cold

    # Decile breakdown by simulated memory accuracy
    deciles = []
    for d in range(10):
        lo, hi = d / 10.0, (d + 1) / 10.0
        bucket = [r for r in results if lo <= r["accuracy"] < hi] if d < 9 else \
                  [r for r in results if lo <= r["accuracy"] <= hi]
        if not bucket:
            continue
        deciles.append({
            "accuracy_range": [round(lo, 1), round(hi, 1)],
            "n": len(bucket),
            "mean_memory_seeded_probes": round(statistics.mean(r["memory_seeded_probes"] for r in bucket), 3),
            "mean_cold_start_probes": round(statistics.mean(r["cold_start_probes"] for r in bucket), 3),
        })

    summary = {
        "n_families": N_FAMILIES,
        "seed": SEED,
        "owasp_categories": OWASP_CATEGORIES,
        "mean_memory_seeded_probes": round(mean_seeded, 3),
        "mean_cold_start_probes": round(mean_cold, 3),
        "reduction_pct": round(reduction_pct, 2),
        "lowest_decile_accuracy_0_to_0.1": deciles[0] if deciles else None,
        "deciles": deciles,
        "raw_sample_first_20": results[:20],
    }

    out_dir = Path(__file__).resolve().parent / "results"
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / "episodic_memory_ablation.json"
    out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(f"n_families={N_FAMILIES}")
    print(f"mean memory-seeded probes: {mean_seeded:.3f}")
    print(f"mean cold-start probes:    {mean_cold:.3f}")
    print(f"reduction: {reduction_pct:.1f}%")
    if deciles:
        d0 = deciles[0]
        print(f"lowest decile [0,0.1) (n={d0['n']}): "
              f"seeded={d0['mean_memory_seeded_probes']:.2f} "
              f"cold={d0['mean_cold_start_probes']:.2f}")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
