import json, os, random, sys, re
W=sys.argv[1]; rule=sys.argv[2]; k=int(sys.argv[3]); seed=int(sys.argv[4]) if len(sys.argv)>4 else 7
SCAN=os.path.join(W,"raw","scan"); REPOS=os.path.join(W,"repos")
pool=[]
for fn in sorted(os.listdir(SCAN)):
    d=json.load(open(os.path.join(SCAN,fn)))
    if rule.startswith("SSG"):
        for f in d["ssg"].get("findings",[]):
            if f["rule"]==rule: pool.append((d["dir"],f["file"],f["line"],f.get("evidence","")))
    elif rule=="HOOKNET":
        for h in d["hook_net_cmds"]: pool.append((d["dir"],h["file"],0,h["command"]))
        for s in d["hook_scripts_net"]: pool.append((d["dir"],s["path"],0,"; ".join(s["network"])))
    else:
        for s in (d["desc_lint"].get("skills",[]) if isinstance(d["desc_lint"],dict) else []):
            for f in s.get("findings",[]):
                if f["rule"]==rule: pool.append((d["dir"],os.path.relpath(s["file"],os.path.join(REPOS,d["dir"])) if s["file"].startswith(REPOS) else s["file"].split(d["dir"]+"/",1)[-1],f["line"],f["detail"]))
random.seed(seed)
# one finding per repo first, to avoid one repo dominating the sample
byrepo={}
for p in pool: byrepo.setdefault(p[0],[]).append(p)
repos=list(byrepo); random.shuffle(repos)
picks=[random.choice(byrepo[r]) for r in repos[:k]]
print(f"# {rule}: pool {len(pool)} findings in {len(byrepo)} repos; sample {len(picks)}")
SECRET=rule in ("SSG405","SSG501","SSG502","SSG503")
for i,(d,f,ln,ev) in enumerate(picks):
    p=os.path.join(REPOS,d,f)
    try: L=open(p,encoding="utf-8",errors="replace").read().splitlines()
    except Exception: L=[]
    print(f"--- [{i}] {d} :: {f}:{ln}")
    if SECRET:
        line=L[ln-1] if 0<ln<=len(L) else ""
        toks=re.findall(r"[A-Za-z0-9_\-+/=.]{12,}",line)
        import math,collections
        def ent(s):
            c=collections.Counter(s); return -sum(v/len(s)*math.log2(v/len(s)) for v in c.values())
        best=max(toks,key=len) if toks else ""
        ph=bool(re.search(r"example|your|xxx|placeholder|dummy|test|fake|sample|<|\$\{|\{\{|changeme|redacted|\.\.\.|0000|1234|abcd",line,re.I))
        print(f"   ev={ev[:60] if rule=='SSG501' else '[withheld]'} file_ext={os.path.splitext(f)[1]} pathhint={bool(re.search(r'test|example|fixture|doc|sample|mock|template|reference|README|SKILL',f,re.I))} longest_token_len={len(best)} entropy={ent(best):.2f} placeholder_words={ph} keyname={re.findall(r'([A-Za-z_]*(?:KEY|key|TOKEN|token|SECRET|secret|PASSWORD|password|Passwd|pwd)[A-Za-z_]*)',line)[:2]}")
        if rule=="SSG501":
            nxt=" ".join(L[ln:ln+2])[:0]
    else:
        for j in range(max(0,ln-2),min(len(L),ln+1)) if ln else []:
            print("   ",j+1,re.sub(r"[A-Za-z0-9+/=_\-.]{24,}",lambda m:f"<blob {len(m.group(0))}>",L[j])[:220])
        if not ln: print("   ",re.sub(r"[A-Za-z0-9+/=_\-.]{24,}",lambda m:f"<blob {len(m.group(0))}>",ev)[:300])
