"""Narrow secret-rule findings to possible live credentials using structure only. Prints nothing secret."""
import json, os, re, sys, hashlib
sys.path.insert(0, os.path.dirname(__file__)); from secretfeat import feat, ent
W = sys.argv[1]
TESTPATH = re.compile(r"(^|/)(tests?|__tests__|fixtures?|examples?|samples?|mocks?|testdata|spec)(/|$)|\.test\.|_test\.|test_", re.I)
out = []
for fn in sorted(os.listdir(os.path.join(W, "raw/scan"))):
    d = json.load(open(os.path.join(W, "raw/scan", fn)))
    for f in d["ssg"].get("findings", []):
        r = f["rule"]
        if r not in ("SSG405", "SSG501", "SSG502", "SSG503", "SSG203"): continue
        p = os.path.join(W, "repos", d["dir"], f["file"])
        try: L = open(p, encoding="utf-8", errors="replace").read().splitlines()
        except OSError: continue
        ln = f["line"]; line = L[ln-1] if 0 < ln <= len(L) else ""
        ft = feat(p, ln)
        q = re.findall(r"[\"'`]([^\"'`\s]{16,})[\"'`]", line) or re.findall(r"(?:Bearer|Basic|[:=])\s*([A-Za-z0-9+/=_\-.]{16,})", line)
        vals = [v for v in q if "://" not in v and not re.fullmatch(r"[A-Z0-9_]+", v) and re.search(r"\d", v) and re.search(r"[A-Za-z]", v)]
        if r == "SSG501" or r == "SSG203": vals = vals or re.findall(r"[A-Za-z0-9+/=_\-.]{16,}", line)
        best = max(vals, key=lambda v: ent(v) * min(len(v), 60), default="")
        e = ent(best)
        if r == "SSG203":
            if not re.search(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.", line): continue  # only JWTs
        if r == "SSG501" and ft["key_body_lines_after"] < 2: continue
        if r in ("SSG502", "SSG503", "SSG405") and (ft["placeholder"] or ft["template"] or ft["regex_like"] or e < 3.8 or len(best) < 20): continue
        if TESTPATH.search(f["file"]): continue
        h = hashlib.sha256(best.encode() if best else line.encode()).hexdigest()[:12]
        out.append({"repo": d["fetched"]["repo"], "dir": d["dir"], "file": f["file"], "line": ln, "rule": r, "value_hash": h,
                    "value_len": len(best), "entropy": round(e, 2), "keys": ft["keys"], "masked": ft["masked"]})
json.dump(out, open(os.path.join(W, "raw", "secret_candidates.json"), "w"), indent=1)
from collections import Counter
print(len(out), Counter(o["rule"] for o in out), len({o["repo"] for o in out}))
