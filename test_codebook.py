"""Standalone codebook bootstrap test.

Usage:
  python test_codebook.py              # test bootstrap (may take up to 30s)
  python test_codebook.py --diagnose   # check existing codebook without rebuilding
"""
import os, sys, time, json

os.environ["HF_HUB_OFFLINE"] = "1"
os.environ["TRANSFORMERS_NO_ADVISORY_WARNINGS"] = "1"
os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["HF_HUB_NO_ADVISORY_WARNINGS"] = "1"

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def diagnose():
    path = os.path.join(".agent", "semantic_codebook.json")
    if not os.path.isfile(path):
        print(f"No codebook found at {path}")
        print("Run without --diagnose to generate one.")
        return
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    stats = data.get("stats", {})
    print(f"Codebook: {path}")
    print(f"  Version:        {data.get('version')}")
    print(f"  Tokenizer:      {data.get('tokenizer_model_id')}")
    print(f"  Anchor:         {data.get('anchor_model_id')}")
    print(f"  Level:          {data.get('level')}")
    print(f"  Created:        {time.ctime(data.get('created_at', 0))}")
    print(f"  Vocab size:     {stats.get('vocab_size')}")
    print(f"  Anchored tokens:{stats.get('anchored_tokens')}")
    print(f"  Protected:      {stats.get('skipped_protected')}")
    print(f"  Visual skip:    {stats.get('skipped_visual_collision')}")
    print(f"  Fallback:       {stats.get('fallback_class')}")
    print(f"  Mean cosine:    {stats.get('mean_cosine_similarity'):.4f}")
    print(f"  Mean Levenshtein: {stats.get('mean_levenshtein_distance'):.2f}")
    forward = data.get("forward", {})
    reverse = data.get("reverse", {})
    print(f"  Forward entries: {len(forward)}")
    print(f"  Reverse entries: {len(reverse)}")
    file_size = os.path.getsize(path)
    print(f"  File size:      {file_size:,} bytes ({file_size/1024:.0f} KB)")


def bootstrap():
    from transformers import AutoTokenizer
    from semantic_obfuscation import SemanticCodebook

    print("Loading tokenizer...")
    t0 = time.time()
    tokenizer = AutoTokenizer.from_pretrained(
        "Qwen/Qwen2.5-Coder-1.5B-Instruct", use_fast=True, trust_remote_code=True
    )
    print(f"  Vocab: {tokenizer.vocab_size} ({time.time()-t0:.1f}s)")

    cb = SemanticCodebook(
        tokenizer=tokenizer,
        level="standard",
        anchor_model_id="Qwen/Qwen2.5-Coder-1.5B-Instruct",
        load_anchor_model_body=False,
    )

    print("Building codebook (up to 30s)...")
    t0 = time.time()
    record = cb.bootstrap()
    elapsed = time.time() - t0
    print(f"  bootstrap() took {elapsed:.1f}s")

    if record:
        s = cb._record.stats
        print(f"  SUCCESS:")
        print(f"    Anchored:        {s.anchored_tokens}")
        print(f"    Vocab:           {s.vocab_size}")
        print(f"    Fallback:        {s.fallback_class}")
        print(f"    Mean Levenshtein: {s.mean_levenshtein_distance:.2f}")
    else:
        print(f"  FAILED: {cb._bootstrap_error}")

    diag = cb.diagnostics()
    print(f"  Diagnostics: {json.dumps(diag, indent=2)}")


if __name__ == "__main__":
    if "--diagnose" in sys.argv:
        diagnose()
    else:
        bootstrap()
