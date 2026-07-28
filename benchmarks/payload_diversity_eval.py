"""
Payload diversity re-evaluation (paper Section VII.C).

Generates a fixed pool of 20 raw candidate payloads per (OWASP category,
model) configuration using real local open-weight models served via
Ollama (qwen2.5:7b, llama3) -- disclosed as a substitution for the
GPT-4-/Claude-class targets in the production PayloadSynthesizer, since no
frontier-model API key was used for this revision. Candidates are embedded
with a real dense embedding model (nomic-embed-text, 768 dims) via Ollama's
/api/embeddings endpoint.

The same fixed 20-candidate pool is then replayed, for each delta in a
sweep from 0.10 to 0.60, through the identical sequential greedy min-cosine
-distance admission rule used in argus.payloads.synthesizer
(PayloadSynthesizer.generate_batch): process candidates in generation
order, admit a candidate only if its cosine distance to every already
-admitted candidate in the batch is >= delta.

At delta = 0.35 (the shipped default), three independent lexical/syntactic
diversity metrics are computed on the admitted set and compared against the
same metrics on the full unconstrained 20-candidate pool: distinct
word-bigram ratio, mean pairwise word-level Jaccard similarity, and mean
pairwise character-level edit similarity (1 - normalized Levenshtein
distance). This answers whether the cosine-distance constraint corresponds
to structural novelty beyond embedding-space distance alone.

Usage: python benchmarks/payload_diversity_eval.py
Writes: benchmarks/results/payload_diversity_eval.json
Requires: Ollama running locally with qwen2.5:7b, llama3, nomic-embed-text pulled.
"""
from __future__ import annotations

import itertools
import json
import math
import re
import statistics
import sys
import time
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from argus.payloads.synthesizer import _CATEGORY_PROMPTS, PayloadSynthesizer

OLLAMA_URL = "http://localhost:11434"
MODELS = ["qwen2.5:7b", "llama3"]
CATEGORIES = ["LLM01", "LLM06", "LLM08"]
N_CANDIDATES = 20
DELTA_SWEEP = [round(0.10 + 0.05 * i, 2) for i in range(11)]  # 0.10 .. 0.60
DEFAULT_DELTA = 0.35
EMBED_MODEL = "nomic-embed-text"
STRATEGY = {
    "LLM01": "direct_override",
    "LLM06": "system_prompt_extraction",
    "LLM08": "unauthorized_tool_invocation",
}


def ollama_generate(model: str, prompt: str, temperature: float = 1.0, retries: int = 3) -> str:
    for attempt in range(retries):
        try:
            resp = httpx.post(
                f"{OLLAMA_URL}/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": temperature},
                },
                timeout=120,
            )
            resp.raise_for_status()
            return resp.json().get("response", "").strip()
        except (httpx.HTTPError, httpx.TimeoutException) as exc:
            if attempt == retries - 1:
                print(f"  generate failed after {retries} attempts: {exc}")
                return ""
            time.sleep(2)
    return ""


def ollama_embed(model: str, text: str, retries: int = 3) -> list[float]:
    for attempt in range(retries):
        try:
            resp = httpx.post(
                f"{OLLAMA_URL}/api/embeddings",
                json={"model": model, "prompt": text[:2000]},
                timeout=60,
            )
            resp.raise_for_status()
            return resp.json()["embedding"]
        except (httpx.HTTPError, httpx.TimeoutException, KeyError) as exc:
            if attempt == retries - 1:
                print(f"  embed failed after {retries} attempts: {exc}")
                return []
            time.sleep(2)
    return []


def cosine_distance(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    mag_a = math.sqrt(sum(x * x for x in a))
    mag_b = math.sqrt(sum(x * x for x in b))
    if mag_a == 0 or mag_b == 0:
        return 1.0
    return 1.0 - (dot / (mag_a * mag_b))


def replay_admission(pool_embeddings: list[list[float]], delta: float) -> list[int]:
    """Sequential greedy admission identical to PayloadSynthesizer.generate_batch's
    rule, replayed post-hoc against a fixed, already-generated pool."""
    admitted_idx: list[int] = []
    admitted_embs: list[list[float]] = []
    for i, emb in enumerate(pool_embeddings):
        if not admitted_embs:
            admitted_idx.append(i)
            admitted_embs.append(emb)
            continue
        min_dist = min(cosine_distance(emb, a) for a in admitted_embs)
        if min_dist >= delta:
            admitted_idx.append(i)
            admitted_embs.append(emb)
    return admitted_idx


_WORD_RE = re.compile(r"[a-z0-9']+")


def _words(text: str) -> list[str]:
    return _WORD_RE.findall(text.lower())


def distinct_bigram_ratio(texts: list[str]) -> float:
    all_bigrams: list[tuple[str, str]] = []
    for t in texts:
        w = _words(t)
        all_bigrams.extend(zip(w, w[1:]))
    if not all_bigrams:
        return 0.0
    return len(set(all_bigrams)) / len(all_bigrams)


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 0.0
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


def mean_pairwise_word_jaccard(texts: list[str]) -> float | None:
    word_sets = [set(_words(t)) for t in texts]
    pairs = list(itertools.combinations(word_sets, 2))
    if not pairs:
        return None
    return statistics.mean(_jaccard(a, b) for a, b in pairs)


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[lb]


def mean_pairwise_edit_similarity(texts: list[str]) -> float | None:
    pairs = list(itertools.combinations(texts, 2))
    if not pairs:
        return None
    sims = []
    for a, b in pairs:
        dist = _levenshtein(a, b)
        denom = max(len(a), len(b)) or 1
        sims.append(1.0 - dist / denom)
    return statistics.mean(sims)


def mean_pairwise_cosine_similarity(embeddings: list[list[float]]) -> float | None:
    pairs = list(itertools.combinations(embeddings, 2))
    if not pairs:
        return None
    return statistics.mean(1.0 - cosine_distance(a, b) for a, b in pairs)


def run_config(category: str, model: str) -> dict:
    print(f"--- generating {N_CANDIDATES} candidates: category={category} model={model} ---")
    template = _CATEGORY_PROMPTS[category]
    blocked = PayloadSynthesizer._extract_blocked_patterns({})
    texts: list[str] = []
    for i in range(N_CANDIDATES):
        prompt = template.format(
            surface="direct",
            strategy=STRATEGY[category],
            blocked_patterns=", ".join(blocked[:15]),
        )
        if i > 0:
            prompt += (
                f"\n\nIMPORTANT: This is attempt #{i + 1}. "
                "The payload MUST be semantically distinct from prior attempts -- "
                "use a different structural approach, framing, or linguistic register."
            )
        text = ollama_generate(model, prompt)
        if not text:
            text = f"[EMPTY GENERATION attempt {i}]"
        texts.append(text)
        print(f"  [{i+1}/{N_CANDIDATES}] {len(text)} chars")

    print(f"--- embedding {N_CANDIDATES} candidates with {EMBED_MODEL} ---")
    embeddings = [ollama_embed(EMBED_MODEL, t) for t in texts]

    unconstrained_cos_sim = mean_pairwise_cosine_similarity(embeddings)
    unconstrained_bigram = distinct_bigram_ratio(texts)
    unconstrained_jaccard = mean_pairwise_word_jaccard(texts)
    unconstrained_edit = mean_pairwise_edit_similarity(texts)

    sweep_results = []
    admitted_at_default: list[int] = []
    for delta in DELTA_SWEEP:
        idx = replay_admission(embeddings, delta)
        yield_pct = len(idx) / N_CANDIDATES
        admitted_embs = [embeddings[i] for i in idx]
        admitted_sim = mean_pairwise_cosine_similarity(admitted_embs)
        sweep_results.append({
            "delta": delta,
            "n_admitted": len(idx),
            "yield_pct": round(yield_pct, 4),
            "mean_admitted_cosine_similarity": round(admitted_sim, 4) if admitted_sim is not None else None,
        })
        if delta == DEFAULT_DELTA:
            admitted_at_default = idx

    admitted_texts = [texts[i] for i in admitted_at_default]
    lexical_at_default = {
        "n_admitted": len(admitted_at_default),
        "distinct_bigram_ratio": round(distinct_bigram_ratio(admitted_texts), 4) if len(admitted_texts) >= 1 else None,
        "mean_word_jaccard": round(mean_pairwise_word_jaccard(admitted_texts), 4) if mean_pairwise_word_jaccard(admitted_texts) is not None else None,
        "mean_edit_similarity": round(mean_pairwise_edit_similarity(admitted_texts), 4) if mean_pairwise_edit_similarity(admitted_texts) is not None else None,
    }

    return {
        "category": category,
        "model": model,
        "n_candidates": N_CANDIDATES,
        "unconstrained": {
            "mean_cosine_similarity": round(unconstrained_cos_sim, 4) if unconstrained_cos_sim is not None else None,
            "distinct_bigram_ratio": round(unconstrained_bigram, 4),
            "mean_word_jaccard": round(unconstrained_jaccard, 4) if unconstrained_jaccard is not None else None,
            "mean_edit_similarity": round(unconstrained_edit, 4) if unconstrained_edit is not None else None,
        },
        "delta_sweep": sweep_results,
        "at_default_delta_0.35": lexical_at_default,
        "raw_texts": texts,
    }


def main() -> None:
    configs = list(itertools.product(CATEGORIES, MODELS))
    all_results = []
    for category, model in configs:
        result = run_config(category, model)
        all_results.append(result)

    # Aggregate across configs with >=2 admitted candidates at default delta
    eligible = [r for r in all_results if r["at_default_delta_0.35"]["n_admitted"] >= 2]

    def agg(key_path):
        vals = []
        for r in eligible:
            v = r["at_default_delta_0.35"].get(key_path)
            if v is not None:
                vals.append(v)
        return round(statistics.mean(vals), 4) if vals else None

    def agg_unconstrained(key):
        vals = [r["unconstrained"][key] for r in eligible if r["unconstrained"][key] is not None]
        return round(statistics.mean(vals), 4) if vals else None

    default_sim_vals = []
    for r in all_results:
        for s in r["delta_sweep"]:
            if s["delta"] == DEFAULT_DELTA and s["mean_admitted_cosine_similarity"] is not None:
                default_sim_vals.append(s["mean_admitted_cosine_similarity"])
    mean_admitted_sim_default = round(statistics.mean(default_sim_vals), 4) if default_sim_vals else None
    mean_unconstrained_sim = agg_unconstrained("mean_cosine_similarity")
    mean_yield_default = round(statistics.mean(
        s["yield_pct"] for r in all_results for s in r["delta_sweep"] if s["delta"] == DEFAULT_DELTA
    ), 4)

    summary = {
        "categories": CATEGORIES,
        "models": MODELS,
        "n_candidates_per_config": N_CANDIDATES,
        "delta_sweep": DELTA_SWEEP,
        "default_delta": DEFAULT_DELTA,
        "embed_model": EMBED_MODEL,
        "aggregate_at_default_delta": {
            "n_configs_total": len(all_results),
            "n_configs_eligible_for_pairwise_metrics": len(eligible),
            "mean_admitted_cosine_similarity": mean_admitted_sim_default,
            "mean_unconstrained_cosine_similarity": mean_unconstrained_sim,
            "cosine_similarity_reduction_pct": round(
                100.0 * (mean_unconstrained_sim - mean_admitted_sim_default) / mean_unconstrained_sim, 2
            ) if mean_admitted_sim_default is not None and mean_unconstrained_sim else None,
            "mean_yield_pct": mean_yield_default,
            "mean_distinct_bigram_ratio_admitted": agg("distinct_bigram_ratio"),
            "mean_distinct_bigram_ratio_unconstrained": agg_unconstrained("distinct_bigram_ratio"),
            "mean_word_jaccard_admitted": agg("mean_word_jaccard"),
            "mean_word_jaccard_unconstrained": agg_unconstrained("mean_word_jaccard"),
            "mean_edit_similarity_admitted": agg("mean_edit_similarity"),
            "mean_edit_similarity_unconstrained": agg_unconstrained("mean_edit_similarity"),
        },
        "per_config_results": all_results,
    }

    out_dir = Path(__file__).resolve().parent / "results"
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / "payload_diversity_eval.json"
    out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("\n=== AGGREGATE (default delta=0.35) ===")
    for k, v in summary["aggregate_at_default_delta"].items():
        print(f"  {k}: {v}")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
