import json, subprocess, sys, time
LIST, OUT = sys.argv[1], sys.argv[2]
repos=[l.strip() for l in open(LIST) if l.strip()]
F = "nameWithOwner isFork isArchived isPrivate stargazerCount forkCount createdAt pushedAt diskUsage isSecurityPolicyEnabled licenseInfo{spdxId key} owner{__typename login} primaryLanguage{name}"
out=open(OUT,"w")
for i in range(0,len(repos),50):
    chunk=repos[i:i+50]
    parts=[]
    for j,r in enumerate(chunk):
        o,n=r.split("/",1)
        parts.append(f'r{j}: repository(owner:{json.dumps(o)}, name:{json.dumps(n)}) {{ {F} }}')
    q="query{ "+" ".join(parts)+" }"
    for a in range(3):
        p=subprocess.run(["gh","api","graphql","-f",f"query={q}"],capture_output=True,text=True)
        if p.stdout.strip().startswith("{"): break
        time.sleep(10)
    d=json.loads(p.stdout or "{}").get("data") or {}
    for j,r in enumerate(chunk):
        v=d.get(f"r{j}")
        out.write(json.dumps({"query_name":r,"meta":v})+"\n")
    time.sleep(1)
print("done")
