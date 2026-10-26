"""Aggregate raw/scan/*.json + raw/meta.jsonl + corpus into out/dataset.csv and out/dataset.json. No secret values."""
import json, os, csv, sys, collections
W = sys.argv[1]
SCAN = os.path.join(W, "raw", "scan")
corpus = {r["repo"]: r for r in map(json.loads, open(os.path.join(W, "raw", "corpus.jsonl")))}
meta = {}
for l in open(os.path.join(W, "raw", "meta.jsonl")):
    d = json.loads(l); meta[d["query_name"]] = d["meta"]
RULES = ["SSG101","SSG102","SSG103","SSG104","SSG201","SSG202","SSG203","SSG204","SSG301","SSG302","SSG303","SSG304","SSG305","SSG306",
         "SSG401","SSG402","SSG403","SSG404","SSG405","SSG406","SSG501","SSG502","SSG503","SSG601","SSG602","SSG603","SSG604","SSG605","SSG606","SSG607","SSG701","SSG702"]
DLR = ["yaml-unsafe","description-too-long","description-no-use-when","description-missing","front-matter-missing","front-matter-unclosed","name-missing","name-mismatch","name-format"]
rows = []
ML = collections.defaultdict(lambda: [0, 0, set(), set()])
for l in open(os.path.join(W, "raw", "mcplint.jsonl")):
    x = json.loads(l); m = ML[x["dir"]]; m[0] += 1; m[1] += x["n_tools"]
    for f in (x["result"].get("findings", []) if isinstance(x["result"], dict) else []):
        key = (x["file"], f.get("toolIndex"))
        if f.get("ruleId") == "dialect-2020-12": m[2].add(key)
        if f.get("ruleId") == "missing-annotations": m[3].add(key)
PRIVATE = ("SSG203", "SSG405", "SSG501", "SSG502", "SSG503")  # per-repo counts withheld from the public dataset (disclosure)
agg = {r: [0, 0] for r in PRIVATE}; anysec = [0]
sys.path.insert(0, os.path.join(W, "bin")); from hooknet import v3
review = dict(l.strip().split(",") for l in open(os.path.join(W, "raw", "hook_review.csv")).readlines()[1:] if l.strip())
def present(dname, name, in_plugin_dir):
    for r, ds, fs in os.walk(os.path.join(W, "repos", dname)):
        ds[:] = [x for x in ds if x != "node_modules"]
        if name in fs and (not in_plugin_dir or os.path.basename(r) == ".claude-plugin"): return True
    return False
for fn in sorted(os.listdir(SCAN)):
    d = json.load(open(os.path.join(SCAN, fn)))
    full = d["fetched"]["repo"]; m = meta.get(full) or {}; c = corpus.get(full, {})
    inv = d["inventory"] if isinstance(d["inventory"], dict) else {}
    ssg = d["ssg"]; finds = ssg.get("findings", [])
    rc = collections.Counter(f["rule"] for f in finds)
    kinds = inv.get("kinds", {})
    skills_dl = d["desc_lint"].get("skills", []) if isinstance(d["desc_lint"], dict) else []
    dlc = collections.Counter(); per_skill = collections.defaultdict(set)
    for s in skills_dl:
        for f in s.get("findings", []):
            dlc[f["rule"]] += 1; per_skill[f["rule"]].add(s["file"])
    y = d["yaml"]
    n_sk = len(y)
    mcp = inv.get("mcp_servers", [])
    stdio = [s for s in mcp if s.get("type") in ("stdio", "") and s.get("command")]
    port = d["portability"].get("findings", []) if isinstance(d["portability"], dict) else []
    hooks = inv.get("hooks", [])
    ssg_hook_net = [f for f in finds if f["rule"] in ("SSG301","SSG202","SSG201") and ("hooks" in f["file"].split("/") or f["file"].endswith("hooks.json") or f["file"].endswith("settings.json"))]
    row = {
        "repo": full, "commit": d["fetched"]["sha"], "found_by": ";".join(sorted(c.get("kinds", []))),
        "stars": m.get("stargazerCount"), "owner_type": (m.get("owner") or {}).get("__typename"), "archived": m.get("isArchived"),
        "created_at": m.get("createdAt"), "pushed_at": m.get("pushedAt"), "language": (m.get("primaryLanguage") or {}).get("name"),
        "github_licence_spdx": (m.get("licenseInfo") or {}).get("spdxId"), "github_security_policy": m.get("isSecurityPolicyEnabled"),
        "files_fetched": d["fetched"]["files"], "bytes_fetched": d["fetched"]["bytes"],
        "n_skill_md": n_sk, "has_plugin_json": present(d["dir"], "plugin.json", True), "has_marketplace_json": present(d["dir"], "marketplace.json", True),
        "has_server_json": present(d["dir"], "server.json", False), "has_mcp_json": present(d["dir"], ".mcp.json", False), "has_hooks_json": present(d["dir"], "hooks.json", False),
        "n_hooks": len(hooks), "n_mcp_servers": len(mcp), "n_mcp_stdio": len(stdio),
        "ssg_total_public_rules": sum(v for k, v in rc.items() if k not in PRIVATE), "ssg_error": "_error" in ssg,
    }
    for r in RULES:
        if r not in PRIVATE: row[r] = rc.get(r, 0)
    for r in PRIVATE: agg[r][0] += rc.get(r, 0); agg[r][1] += rc.get(r, 0) > 0
    anysec[0] += any(rc.get(r, 0) for r in ("SSG405", "SSG501", "SSG502", "SSG503"))
    for r in DLR: row["dl_" + r] = len(per_skill.get(r, ()))
    row["n_skills_linted"] = len(skills_dl)
    row["n_skill_yaml_reject"] = sum(1 for s in y if s["yaml"] == "reject")
    row["n_skill_no_front_matter"] = sum(1 for s in y if s["yaml"] == "no-front-matter")
    row["n_skill_desc_over_1024"] = sum(1 for s in y if (s["desc_len"] or 0) > 1024)
    row["n_skill_with_desc"] = sum(1 for s in y if s["has_desc"])
    row["n_skill_no_broad_when"] = sum(1 for s in y if s["has_desc"] and not s["broad_when"])
    row["n_portability_findings"] = len(port)
    # derived repo-level booleans
    row["any_unrestricted_bash"] = rc["SSG607"] > 0
    ml = ML.get(d["dir"]) or [0, 0, set(), set()]
    row["mcp_tool_lists_linted"] = ml[0]; row["mcp_tools_linted"] = ml[1]; row["mcp_tools_dialect_error"] = len(ml[2]); row["mcp_tools_no_annotations"] = len(ml[3])
    row["hook_network_flag"] = bool(v3(d))
    row["hook_network_review"] = review.get(d["dir"], "") if row["hook_network_flag"] else ""
    row["any_unpinned_mcp"] = (rc["SSG401"] + rc["SSG402"] + rc["SSG403"]) > 0
    row["no_licence_file"] = rc["SSG702"] > 0
    row["no_security_md"] = rc["SSG701"] > 0
    row["any_yaml_reject"] = row["n_skill_yaml_reject"] > 0
    row["any_yaml_unsafe_flag"] = row["dl_yaml-unsafe"] > 0
    row["any_desc_over_1024"] = row["n_skill_desc_over_1024"] > 0
    row["any_no_use_when"] = row["dl_description-no-use-when"] > 0
    row["any_no_broad_when"] = row["n_skill_no_broad_when"] > 0
    rows.append(row)
os.makedirs(os.path.join(W, "out"), exist_ok=True)
with open(os.path.join(W, "out", "dataset.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
json.dump(rows, open(os.path.join(W, "out", "dataset.json"), "w"), indent=1)
with open(os.path.join(W, "out", "secret_rules_aggregate.csv"), "w", newline="") as f:
    w = csv.writer(f); w.writerow(["rule", "findings", "repositories_with_finding", "repositories_scanned"])
    for r in PRIVATE: w.writerow([r, agg[r][0], agg[r][1], len(rows)])
    w.writerow(["any of SSG405/SSG501/SSG502/SSG503", sum(agg[r][0] for r in PRIVATE if r != "SSG203"), anysec[0], len(rows)])
    tri = json.load(open(os.path.join(W, "raw", "secret_triage.json")))
    live = [t for t in tri if t["possible_live"]]
    w.writerow(["possible live credential after structural triage (not verified)", len(live), len({t["repo"] for t in live}), len(rows)])
print(len(rows), "rows")
