"""Hook-network measure v3: network use in agent hook commands, or network imports/calls in scripts under a hooks/ folder.
Excludes front-end React hooks (.ts/.tsx/.jsx, use*.js), parse-only or socket-module-only signals, and example/placeholder hosts."""
import os, re
WEAK = re.compile(r"^import (urllib\.parse|urllib\.error|urllib|net|socket) \(")
CMD_NET = re.compile(r"(^|[\s;|&(])(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\s|https?://(?!localhost|127\.0\.0\.1|example\.|[^/\s]*\.invalid)", re.I)
def is_frontend(p):
    b = os.path.basename(p)
    return p.endswith((".ts", ".tsx", ".jsx")) or re.match(r"use[A-Z]", b) is not None
def v3(d):
    inv = d["inventory"] if isinstance(d["inventory"], dict) else {}
    out = []
    for h in inv.get("hooks", []):
        if CMD_NET.search(str(h.get("command", ""))): out.append(("cmd", h.get("file"), str(h.get("command"))[:300]))
    for s in d["hook_scripts_net"]:
        if is_frontend(s["path"]): continue
        strong = [x for x in s["network"] if not WEAK.match(x)]
        if strong: out.append(("script", s["path"], "; ".join(strong)))
    return out
