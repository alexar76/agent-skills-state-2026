"""Run the owner's scanners over each fetched repo folder; write one JSON per repo to raw/scan/. Repo content is read, never executed."""
import json, os, re, subprocess, sys, concurrent.futures as cf
import yaml
W = sys.argv[1]
REPOS = os.path.join(W, "repos"); OUT = os.path.join(W, "raw", "scan"); os.makedirs(OUT, exist_ok=True)
PY = os.path.join(W, "venv", "bin", "python")
SSG = os.path.join(W, "venv", "bin", "skill-scan-gate")
S = os.path.join(W, "tools/claude-code-tooling-skills/plugins/cc-setup-tooling/skills")
DL = f"{S}/skill-description-linter/scripts/description_lint.py"
PC = f"{S}/skill-portability-check/scripts/portability_check.py"
INV = f"{S}/skill-supply-chain-review/scripts/skill_inventory.py"
SECRET_RULES = {"SSG405", "SSG501", "SSG502", "SSG503"}
NET = re.compile(r"\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|nc|ncat|scp|rsync|ssh)\b|https?://|\bfetch\(|requests\.(get|post)|urllib|http\.client|axios", re.I)
FM = re.compile(r"\A﻿?---[ \t]*\r?\n(.*?)\r?\n---[ \t]*(\r?\n|\Z)", re.S)
def runj(args, t=240):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=t)
        return json.loads(p.stdout) if p.stdout.strip().startswith("{") else {"_error": (p.stderr or "")[-300:]}
    except Exception as e:
        return {"_error": repr(e)[:300]}
def skill_files(root):
    out = []
    for r, ds, fs in os.walk(root):
        ds[:] = [d for d in ds if d not in (".git", "node_modules")]
        for f in fs:
            if f == "SKILL.md": out.append(os.path.join(r, f))
    return out
def yaml_check(path):
    try: t = open(path, encoding="utf-8", errors="replace").read()
    except OSError: return "unreadable", None
    m = FM.match(t)
    if not m: return "no-front-matter", None
    try:
        d = yaml.safe_load(m.group(1))
    except yaml.YAMLError as e:
        return "reject", None
    if not isinstance(d, dict): return "not-mapping", None
    desc = d.get("description")
    return "ok", (desc if isinstance(desc, str) else None)
BROAD_WHEN = re.compile(r"\b(use (this|it|me)?\s*(skill\s*)?(when|whenever|if|for|to)|when (the )?(user|you|asked|working|needing|someone)|whenever|trigger(s|ed)? (on|when)|invoke when|activate when|applies when|use cases?:)", re.I)
def one(dname):
    root = os.path.join(REPOS, dname)
    out = os.path.join(OUT, dname + ".json")
    if os.path.exists(out): return dname
    fetched = json.load(open(os.path.join(root, ".fetched.json")))
    ssg = runj([SSG, "scan", root, "--format", "json", "--fail-on", "none"])
    for f in ssg.get("findings", []):
        if f.get("rule") in SECRET_RULES: f["evidence"] = "[withheld]"
    skills = skill_files(root)
    dl = runj([PY, "-I", DL, "--json", "--max-chars", "1024", root]) if skills else {}
    pc = runj([PY, "-I", PC, "--json", root]) if skills else {}
    inv = runj([PY, "-I", INV, "--json", root])
    for k in ("credential_paths", "urls", "shell_patterns", "files", "domains"):
        inv.pop(k, None)
    yres = []
    for s in skills:
        st, desc = yaml_check(s)
        yres.append({"file": os.path.relpath(s, root), "yaml": st, "desc_len": len(desc) if desc else None,
                     "broad_when": bool(desc and BROAD_WHEN.search(desc)), "has_desc": bool(desc)})
    hooks = inv.get("hooks", []) if isinstance(inv, dict) else []
    hook_net = [h for h in hooks if NET.search(str(h.get("command", "")))]
    hook_scripts_net = [s for s in (inv.get("scripts", []) if isinstance(inv, dict) else []) if "/hooks/" in "/" + s.get("path", "") and s.get("network")]
    rec = {"dir": dname, "fetched": fetched, "ssg": ssg, "desc_lint": dl, "portability": pc, "inventory": inv, "yaml": yres,
           "hook_net_cmds": [{"file": h.get("file"), "event": h.get("event"), "command": str(h.get("command"))[:300]} for h in hook_net],
           "hook_scripts_net": [{"path": s["path"], "network": s["network"]} for s in hook_scripts_net]}
    json.dump(rec, open(out, "w"))
    return dname
dirs = sorted(d for d in os.listdir(REPOS) if os.path.exists(os.path.join(REPOS, d, ".fetched.json")))
with cf.ThreadPoolExecutor(10) as ex:
    for i, _ in enumerate(ex.map(one, dirs)):
        if i % 200 == 0: print(i, flush=True)
print("done")
