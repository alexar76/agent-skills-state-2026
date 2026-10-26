"""Structural triage of secret candidates into 'possible live credential'. Never prints values."""
import json, os, re, sys, csv
sys.path.insert(0, os.path.dirname(__file__)); from secretfeat import ent
W = sys.argv[1]
C = json.load(open(os.path.join(W, "raw/secret_candidates2.json")))
DOC = re.compile(r"(?i)pattern|wp-security|security-guardrails|security-review|audit|guardrail|penetration|jailbreak|corriger|pourrie|secrets-manager|DEFAULT_PASSWORD|best-practice|anti-pattern")
RESEARCH = re.compile(r"dataset/|generated_skills|poisoned_skills|case_\d+|/V\d+/", re.I)
def value_of(c):
    p = os.path.join(W, "repos", c["dir"], c["file"]); L = open(p, encoding="utf-8", errors="replace").read().splitlines()
    line = L[c["line"]-1]
    q = re.findall(r"[\"'`]([^\"'`\s]{16,})[\"'`]", line) or re.findall(r"(?:Bearer|Basic|[:=])\s*([A-Za-z0-9+/=_\-.]{16,})", line)
    q = [v for v in q if "://" not in v and re.search(r"\d", v) and re.search(r"[A-Za-z]", v)] or re.findall(r"[A-Za-z0-9+/=_\-.]{16,}", line)
    return max(q, key=lambda v: ent(v) * min(len(v), 60), default=""), line
def seq_runs(v):
    n = 0; s = v.lower()
    for i in range(len(s) - 2):
        a, b, c = s[i:i+3]
        if a.isalnum() and ord(b) == ord(a) + 1 and ord(c) == ord(b) + 1: n += 1
    return n
def repeats(v):
    return sum(1 for i in range(len(v) - 7) if v.count(v[i:i+4]) > 1) > 0
rows = []
for c in C:
    v, line = value_of(c)
    reasons = []
    if RESEARCH.search(c["file"]): reasons.append("research-corpus path")
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", v) or re.search(r"token ?address|toToken|fromToken|_TOKEN\b.*0x|contract", line, re.I) and v.startswith("0x"): reasons.append("blockchain address")
    if v.startswith("$2") or "hash" in line.lower(): reasons.append("hash, not a credential")
    if seq_runs(v) >= 2: reasons.append("sequential characters (example value)")
    if re.search(r"\{env:|\$\{|process\.env", line): reasons.append("template")
    if re.search(r"(?i)(page|file|next)_token|tokenUrl|token_path", line): reasons.append("not a credential field")
    if c["rule"] == "SSG203":
        import base64, time
        m = re.search(r"eyJ[A-Za-z0-9_-]+\.(eyJ[A-Za-z0-9_-]+)\.", line)
        try:
            pl = json.loads(base64.urlsafe_b64decode(m.group(1) + "=" * (-len(m.group(1)) % 4)))
            exp = pl.get("exp") if isinstance(pl, dict) else None
            if exp and exp < time.time(): reasons.append("expired JWT")
        except Exception: pass
    if not reasons and DOC.search(c["file"] + " " + line): reasons.append("teaching example in a security or pattern skill")
    live = not reasons
    rows.append({**{k: c[k] for k in ("repo", "file", "line", "rule", "value_hash", "value_len")}, "entropy": c["entropy"],
                 "seq_runs": seq_runs(v), "possible_live": live, "excluded_because": "; ".join(reasons)})
json.dump(rows, open(os.path.join(W, "raw/secret_triage.json"), "w"), indent=1)
print(sum(r["possible_live"] for r in rows), "possible live of", len(rows), "in", len({r["repo"] for r in rows if r["possible_live"]}), "repos")
for i, r in enumerate(rows):
    if r["possible_live"] or r["rule"] == "SSG203": print(i, r["rule"], r["file"][-50:], r["value_len"], r["entropy"], r["possible_live"], r["excluded_because"])
