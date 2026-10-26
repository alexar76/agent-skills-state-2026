import csv, json, os, sys
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
W = sys.argv[1]; O = os.path.join(W, "out")
S = json.load(open(os.path.join(O, "stats.json")))
SURF, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11, "text.color": INK, "axes.labelcolor": INK2,
                     "xtick.color": INK2, "ytick.color": INK, "axes.edgecolor": GRID})
def frac(s): a, b = s.split(" ")[0].split("/"); return int(a), int(b)
def base(ax, fig):
    fig.patch.set_facecolor(SURF); ax.set_facecolor(SURF)
    for sp in ("top", "right", "left"): ax.spines[sp].set_visible(False)
    ax.tick_params(length=0); ax.xaxis.grid(True, color=GRID, lw=0.8); ax.set_axisbelow(True)
def foot(fig, t): fig.text(0.01, 0.015, t, fontsize=8.5, color=INK2, ha="left")
rows = []
# chart 1
items = [("No SECURITY.md in the repository", S["no_security_md"]),
         ("Stdio MCP server not pinned to a version", S["unpinned_mcp"]),
         ("No licence file at the root", S["no_licence_file"]),
         ("A skill allows unrestricted Bash", S["unrestricted_bash_repos"]),
         ("A SKILL.md has no front matter", S["no_front_matter_repos"]),
         ("A SKILL.md front matter fails YAML parsing", S["yaml_reject_repos"]),
         ("A skill description is over 1,024 characters", S["desc_over_1024_repos"]),
         ("A hook calls a non-local host (hand-verified)", f'{S["hook_review_remote_in_hook_repos"]}/{S["repos_with_hooks"]} x')]
fig, ax = plt.subplots(figsize=(10, 5.6)); base(ax, fig)
labels = [i[0] for i in items][::-1]; vals = []; dens = []
for name, s in items[::-1]:
    a, b = frac(s); vals.append(100*a/b); dens.append((a, b)); rows.append(("chart1", name, a, b, round(100*a/b, 1)))
ax.barh(labels, vals, color=BLUE, height=0.62)
for y, (v, (a, b)) in enumerate(zip(vals, dens)):
    ax.text(v + 1, y, f"{v:.1f}%  ({a:,} of {b:,})", va="center", fontsize=10, color=INK)
ax.set_xlim(0, 112); ax.set_xticks([0, 25, 50, 75, 100]); ax.set_xticklabels(["0%", "25%", "50%", "75%", "100%"])
ax.set_title("Share of repositories with each finding", loc="left", fontsize=14, fontweight="bold", pad=12)
foot(fig, "Sample of 2,999 public GitHub repositories with agent skills, plugin manifests or MCP server.json, collected 13 Oct 2026.\nDenominator per row: all repositories, repositories with SKILL.md (2,621), with a stdio MCP server (346) or with a hook config (373).")
fig.tight_layout(rect=(0, 0.08, 1, 1)); fig.savefig(os.path.join(O, "chart1-prevalence.png"), dpi=200); plt.close(fig)
# chart 2
c2 = S["chart2"]; bands = [c["band"] for c in c2]
series = [("No SECURITY.md", "no_security_md_pct", BLUE), ("No licence file", "no_licence_pct", ORANGE), ("Unpinned MCP (of repos with stdio MCP)", "unpinned_mcp_pct", AQUA)]
fig, ax = plt.subplots(figsize=(10, 5.4)); base(ax, fig); ax.xaxis.grid(False); ax.yaxis.grid(True, color=GRID, lw=0.8)
w = 0.26
for i, (nm, k, col) in enumerate(series):
    xs = [j + (i-1)*w for j in range(len(bands))]; vs = [c[k] for c in c2]
    ax.bar(xs, vs, width=w-0.03, color=col, label=nm)
    for x, v in zip(xs, vs): ax.text(x, v + 1.2, f"{v:.0f}%", ha="center", fontsize=9, color=INK)
    for c in c2: rows.append(("chart2", f'{nm} | stars {c["band"]}', "", c["mcp_repos"] if "MCP" in nm else c["repos"], c[k]))
ax.set_xticks(range(len(bands))); ax.set_xticklabels([f'{c["band"]} stars\n{c["repos"]:,} repos, {c["mcp_repos"]} with MCP' for c in c2])
ax.set_ylim(0, 100); ax.set_yticks([0, 25, 50, 75, 100]); ax.set_yticklabels(["0%", "25%", "50%", "75%", "100%"])
ax.spines["bottom"].set_visible(True)
ax.legend(frameon=False, loc="upper center", ncol=3, bbox_to_anchor=(0.5, 1.02), fontsize=9.5)
ax.set_title("More stars bring licences, not security policies or pinning", loc="left", fontsize=14, fontweight="bold", pad=26)
foot(fig, "Same 2,999-repository sample, grouped by GitHub stars on 13 Oct 2026. Licence files improve with stars; security policies and MCP pinning do not.")
fig.tight_layout(rect=(0, 0.05, 1, 1)); fig.savefig(os.path.join(O, "chart2-by-stars.png"), dpi=200); plt.close(fig)
# chart 3
P = list(csv.DictReader(open(os.path.join(O, "precision.csv"))))
pick = [("SSG607 unrestricted Bash", "SSG607", "skill allows unrestricted Bash"),
        ("Unpinned MCP (401+402+403)", "SSG401+SSG402+SSG403", None),
        ("YAML parse failure (PyYAML)", "PyYAML parse", None),
        ("SSG702 no licence file", "SSG702", None),
        ("SSG701 no security policy", "SSG701", None),
        ("Description over 1,024 chars", "description-too-long (description_lint.py)", None),
        ("Hook network call, any host (v3)", "hook network v3", "any network call in an agent hook"),
        ("Hook call to non-local host (v3)", "hook network v3", "outbound call to a non-local host by default"),
        ("Missing 'Use when' (linter)", "description-no-use-when (description_lint.py)", None),
        ("yaml-unsafe (linter)", "yaml-unsafe (description_lint.py)", None),
        ("SSG405 secret in MCP env", "SSG405", None),
        ("SSG503 hard-coded credential", "SSG503", None),
        ("SSG502 provider token", "SSG502", None),
        ("SSG501 private key block", "SSG501", None)]
lab, val, ns = [], [], []
for nm, rule, meas in pick:
    p = next(x for x in P if x["rule"] == rule and (meas is None or x["measure"] == meas))
    lab.append(nm); val.append(float(p["precision_pct"])); ns.append(f'{p["true_positives"]}/{p["sample_size"]}')
    rows.append(("chart3", nm, p["true_positives"], p["sample_size"], p["precision_pct"]))
fig, ax = plt.subplots(figsize=(10, 6.2)); base(ax, fig)
cols = [BLUE if v >= 70 else "#b5b3ad" for v in val]
ax.barh(lab[::-1], val[::-1], color=cols[::-1], height=0.62)
for y, (v, n) in enumerate(zip(val[::-1], ns[::-1])): ax.text(v + 1, y, f"{v:.0f}%  ({n})", va="center", fontsize=9.5)
ax.axvline(70, color=INK2, lw=1, ls=(0, (4, 3))); ax.text(70.5, len(lab) - 0.35, "70% bar", fontsize=9, color=INK2)
ax.set_xlim(0, 118); ax.set_xticks([0, 25, 50, 75, 100]); ax.set_xticklabels(["0%", "25%", "50%", "75%", "100%"])
ax.set_title("How often each check was right", loc="left", fontsize=14, fontweight="bold", pad=12)
foot(fig, "Precision = true positives / findings checked. Blue: kept (70% or more). Grey: dropped or replaced; the secret rules mostly fire on\ndocumentation examples, so secret findings were triaged separately and only counted. Large n = automated cross-check.")
fig.tight_layout(rect=(0, 0.08, 1, 1)); fig.savefig(os.path.join(O, "chart3-precision.png"), dpi=200); plt.close(fig)
with open(os.path.join(O, "chart-data.csv"), "w", newline="") as f:
    w = csv.writer(f); w.writerow(["chart", "row", "numerator", "denominator", "percent"]); w.writerows(rows)
print("ok")
