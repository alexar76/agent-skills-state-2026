"""Draw the random sample of repositories from the code search results written by collect.py.

Usage: python draw_sample.py WORK [N] [SEED]
Reads WORK/raw/search_items.jsonl and writes WORK/raw/corpus.jsonl (one {"repo", "kinds"} per
sampled repository, the input build.py expects) and WORK/raw/sample.txt (one repository per line,
the input meta.py and fetch.py expect). Forks and the author's own repositories are excluded.
The pool is sorted by name before sampling, so the same search results and seed give the same draw.
"""
import json
import os
import random
import sys

W = sys.argv[1]
N = int(sys.argv[2]) if len(sys.argv) > 2 else 3000
SEED = int(sys.argv[3]) if len(sys.argv) > 3 else 20261013
EXCLUDE_OWNERS = {"basitalisandhu"}

kinds = {}
with open(os.path.join(W, "raw", "search_items.jsonl"), encoding="utf-8") as f:
    for line in f:
        it = json.loads(line)
        if it.get("fork") or it["owner"].lower() in EXCLUDE_OWNERS:
            continue
        kinds.setdefault(it["repo"], set()).add(it["kind"])

pool = sorted(kinds)
random.seed(SEED)
picked = sorted(random.sample(pool, min(N, len(pool))))
with open(os.path.join(W, "raw", "corpus.jsonl"), "w", encoding="utf-8") as f:
    for r in picked:
        f.write(json.dumps({"repo": r, "kinds": sorted(kinds[r])}) + "\n")
with open(os.path.join(W, "raw", "sample.txt"), "w", encoding="utf-8") as f:
    f.write("\n".join(picked) + "\n")
print(f"{len(pool)} distinct repositories; sampled {len(picked)} with seed {SEED}")
