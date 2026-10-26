"""Find committed tools/list JSON in fetched files and lint them with mcp-tools-lint (file targets only; no server is started)."""
import json, os, subprocess, sys
W = sys.argv[1]; REPOS = os.path.join(W, "repos"); CLI = os.path.join(W, "tools/mcp-tools-lint/dist/cli.js")
out = open(os.path.join(W, "raw", "mcplint.jsonl"), "w"); n = 0
for d in sorted(os.listdir(REPOS)):
    for r, ds, fs in os.walk(os.path.join(REPOS, d)):
        ds[:] = [x for x in ds if x != "node_modules"]
        for f in fs:
            if not f.endswith(".json"): continue
            p = os.path.join(r, f)
            try: t = open(p, encoding="utf-8", errors="replace").read()
            except OSError: continue
            if '"inputSchema"' not in t: continue
            try:
                j = json.loads(t)
            except Exception: continue
            tools = j.get("tools") if isinstance(j, dict) else j if isinstance(j, list) else None
            if isinstance(j, dict) and isinstance(j.get("result"), dict): tools = j["result"].get("tools")
            if not isinstance(tools, list) or not tools or not all(isinstance(x, dict) and "name" in x for x in tools): continue
            pr = subprocess.run(["node", CLI, p, "-f", "json", "--fail-on", "none"], capture_output=True, text=True, timeout=60)
            try: res = json.loads(pr.stdout)
            except Exception: res = {"_error": pr.stderr[-200:]}
            out.write(json.dumps({"dir": d, "file": os.path.relpath(p, os.path.join(REPOS, d)), "n_tools": len(tools), "result": res}) + "\n"); n += 1
print(n, "tool lists linted")
