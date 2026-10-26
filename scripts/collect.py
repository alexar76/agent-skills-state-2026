import json, subprocess, time, sys, os
OUT = sys.argv[1]
queries = []
sk = [(0,300),(301,600),(601,900),(901,1200),(1201,1500),(1501,1800),(1801,2100),(2101,2500),(2501,3000),(3001,3500),(3501,4000),(4001,4700),(4701,5500),(5501,6500),(6501,8000),(8001,10000),(10001,13000),(13001,17000),(17001,25000),(25001,400000)]
for a,b in sk:
    queries.append(("skill", f"filename:SKILL.md size:{a}..{b}", 3))
for a,b in [(0,400),(401,800),(801,1500),(1501,400000)]:
    queries.append(("plugin", f"filename:plugin.json path:.claude-plugin size:{a}..{b}", 3))
for a,b in [(0,1000),(1001,3000),(3001,400000)]:
    queries.append(("marketplace", f"filename:marketplace.json path:.claude-plugin size:{a}..{b}", 3))
for a,b in [(0,800),(801,1500),(1501,3000),(3001,400000)]:
    queries.append(("mcp_server_json", f"filename:server.json modelcontextprotocol size:{a}..{b}", 3))
log = open(os.path.join(OUT,"search_log.jsonl"),"a")
items = open(os.path.join(OUT,"search_items.jsonl"),"a")
for kind,q,pages in queries:
    for p in range(1,pages+1):
        for attempt in range(4):
            r = subprocess.run(["gh","api","-X","GET","search/code","-f",f"q={q}","-f","per_page=100","-f",f"page={p}"],capture_output=True,text=True)
            if r.returncode==0: break
            time.sleep(30)
        if r.returncode!=0:
            log.write(json.dumps({"kind":kind,"q":q,"page":p,"error":r.stderr[:300]})+"\n"); log.flush(); break
        d = json.loads(r.stdout)
        n = len(d.get("items",[]))
        log.write(json.dumps({"kind":kind,"q":q,"page":p,"total_count":d.get("total_count"),"incomplete":d.get("incomplete_results"),"n":n,"ts":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())})+"\n"); log.flush()
        for it in d.get("items",[]):
            rp = it["repository"]
            items.write(json.dumps({"kind":kind,"repo":rp["full_name"],"fork":rp.get("fork"),"owner":rp["owner"]["login"],"path":it["path"],"sha":it.get("sha")})+"\n")
        items.flush()
        time.sleep(7)
        if n<100: break
print("done")
