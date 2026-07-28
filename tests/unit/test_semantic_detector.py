from argus.detectors.semantic import SemanticProximityDetector, default_embed_fn


def _fixed_embedder(mapping: dict[str, list[float]]):
    def _fn(text: str) -> list[float]:
        return mapping.get(text, [0.0, 0.0])
    return _fn


def test_no_exemplars_registered_never_hits():
    detector = SemanticProximityDetector()
    verdict = detector.detect("LLM01", "anything at all")
    assert verdict.is_hit is False


def test_close_response_is_a_hit():
    embedder = _fixed_embedder({
        "the secret code is X": [1.0, 0.0],
        "here is the value: X": [0.99, 0.05],
        "sorry, I can't share that": [0.0, 1.0],
    })
    detector = SemanticProximityDetector(embed_fn=embedder, threshold=0.28)
    detector.load_exemplars("LLM06", ["the secret code is X"])

    hit = detector.detect("LLM06", "here is the value: X")
    miss = detector.detect("LLM06", "sorry, I can't share that")

    assert hit.is_hit is True
    assert miss.is_hit is False


def test_add_exemplar_expands_corpus_for_future_detections():
    embedder = _fixed_embedder({
        "seed exemplar": [1.0, 0.0],
        "novel jailbreak phrasing": [0.0, 1.0, 0.0],
        "unrelated": [0.0, 0.0, 1.0],
    })
    # pad vectors to equal length for cosine math
    embedder_padded = _fixed_embedder({
        "seed exemplar": [1.0, 0.0, 0.0],
        "novel jailbreak phrasing": [0.0, 1.0, 0.0],
        "unrelated": [0.0, 0.0, 1.0],
    })
    detector = SemanticProximityDetector(embed_fn=embedder_padded, threshold=0.28)
    detector.load_exemplars("LLM01", ["seed exemplar"])
    assert detector.detect("LLM01", "novel jailbreak phrasing").is_hit is False

    detector.add_exemplar("LLM01", "novel jailbreak phrasing")
    assert detector.detect("LLM01", "novel jailbreak phrasing").is_hit is True


def test_default_embed_fn_is_deterministic_and_normalized():
    import math
    v1 = default_embed_fn("hello world")
    v2 = default_embed_fn("hello world")
    assert v1 == v2
    norm = math.sqrt(sum(x * x for x in v1))
    assert abs(norm - 1.0) < 1e-9
