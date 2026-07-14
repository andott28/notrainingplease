import os, sys, time
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
sys.path.insert(0, "/addon")
from transformers import AutoTokenizer
from semantic_obfuscation import SemanticCodebook

print("[BUILD] Loading tokenizer...")
tokenizer = AutoTokenizer.from_pretrained("Qwen/Qwen2.5-Coder-1.5B-Instruct", use_fast=True, trust_remote_code=True)

print("[BUILD] Generating codebook...")
t0 = time.time()
codebook = SemanticCodebook(
    tokenizer=tokenizer,
    anchor_model_id="unknown",
    level="standard",
    load_anchor_model_body=False,
    path="/addon/.agent/semantic_codebook.json",
)
result = codebook.bootstrap()
elapsed = time.time() - t0
print(f"[BUILD] Codebook ready={result}, time={elapsed:.1f}s")
if result and codebook.ready:
    s = codebook._bootstrap_stats
    print(f"[BUILD] anchored={s.anchored_tokens}, mean_cos={s.mean_cosine_similarity:.4f}, mean_lev={s.mean_levenshtein_distance:.2f}")
    print("[BUILD] Codebook saved to /addon/.agent/semantic_codebook.json")
else:
    print(f"[BUILD] Codebook FAILED: {codebook._bootstrap_error}")
    sys.exit(1)
