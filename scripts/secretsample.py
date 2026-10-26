import json, os, random, sys
sys.path.insert(0, os.path.dirname(__file__)); from secretfeat import feat
W, rule, k, seed = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
pool = {}
for fn in sorted(os.listdir(os.path.join(W, "raw/scan"))):
    d = json.load(open(os.path.join(W, "raw/scan", fn)))
    for f in d["ssg"].get("findings", []):
        if f["rule"] == rule: pool.setdefault(d["dir"], []).append((f["file"], f["line"]))
random.seed(seed); rs = sorted(pool); random.shuffle(rs)
print(f"# {rule}: {sum(map(len,pool.values()))} findings in {len(pool)} repos")
for i, r in enumerate(rs[:k]):
    f, ln = random.choice(pool[r])
    print(f"[{i}] {r} :: {f}:{ln}\n    {feat(os.path.join(W,'repos',r,f), ln)}")
