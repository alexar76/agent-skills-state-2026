"""Describe a secret-rule finding without printing any value: structure only."""
import sys, os, re, math, collections
def ent(s):
    if not s: return 0.0
    c = collections.Counter(s); return -sum(v/len(s)*math.log2(v/len(s)) for v in c.values())
def mask(line):
    # keep punctuation/structure and key names before = or :, replace every literal value with its class and length
    def rep(m):
        t = m.group(0)
        return f"<{len(t)}ch e{ent(t):.1f}>"
    return re.sub(r"[A-Za-z0-9+/=_\-.]{8,}", rep, line)[:200]
def feat(path, ln):
    L = open(path, encoding="utf-8", errors="replace").read().splitlines()
    line = L[ln-1] if 0 < ln <= len(L) else ""
    keys = re.findall(r"([A-Za-z_][A-Za-z0-9_]{0,40})\"?\s*[:=]", line)[:3]
    body = sum(1 for x in L[ln:ln+6] if re.fullmatch(r"\s*[A-Za-z0-9+/=]{40,}\s*\"?,?\\?n?", x))
    regexy = bool(re.search(r"\\s|\\-|\[A-Z|re\.compile|RegExp|/\^|\(\?", line))
    tmpl = bool(re.search(r"\$\{|\{\{|<[A-Z_ a-z]+>|%\(|process\.env|os\.environ|getenv", line))
    ph = bool(re.search(r"example|your[_-]|xxx|placeholder|dummy|fake|sample|changeme|redacted|replace|1234|abcd|test", line, re.I))
    return {"keys": keys, "masked": mask(line), "key_body_lines_after": body, "regex_like": regexy, "template": tmpl, "placeholder": ph}
if __name__ == "__main__":
    print(feat(sys.argv[1], int(sys.argv[2])))
