"""Shallow, sparse, blob-capped clone of only the agent-config files of each repo. Never executes repo content."""
import json, subprocess, sys, os, shutil, concurrent.futures as cf
WORK = sys.argv[1]; LIST = sys.argv[2]
REPOS = os.path.join(WORK, "repos")
PATTERNS = ["**/SKILL.md", "**/skills/**", "**/.claude-plugin/**", "**/hooks/hooks.json", "**/hooks/*.sh", "**/hooks/*.py", "**/hooks/*.js",
            "**/.mcp.json", "**/server.json", "/LICENSE*", "/LICENCE*", "/COPYING*", "/license*", "/SECURITY.md", "/security.md",
            "/.github/SECURITY.md", "/docs/SECURITY.md"]
BIN_EXT = {".png",".jpg",".jpeg",".gif",".webp",".ico",".pdf",".zip",".tar",".gz",".tgz",".7z",".rar",".jar",".whl",".exe",".dll",".so",".dylib",".bin",".mp4",".mp3",".wav",".mov",".woff",".woff2",".ttf",".otf",".psd",".xlsx",".docx",".pptx",".skill",".pyc",".class",".o",".a",".node",".wasm",".sqlite",".db",".parquet",".npy",".pkl",".pt",".onnx"}
CAP_FILES = 3000; CAP_BYTES = 30_000_000
ENV = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1", GIT_CONFIG_NOSYSTEM="1")
def run(args, cwd=None, t=180):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=t, env=ENV)
def one(full):
    dest = os.path.join(REPOS, full.replace("/", "__"))
    if os.path.exists(os.path.join(dest, ".fetched.json")): return full, "cached"
    shutil.rmtree(dest, ignore_errors=True)
    try:
        r = run(["git","-c","core.hooksPath=/dev/null","-c","filter.lfs.smudge=","-c","filter.lfs.process=","-c","filter.lfs.required=false",
                 "clone","-q","--depth","1","--filter=blob:none","--no-checkout",f"https://github.com/{full}.git",dest])
        if r.returncode: return full, "clone_fail:"+r.stderr.strip()[:120]
        run(["git","sparse-checkout","set","--no-cone",*PATTERNS], cwd=dest)
        r = run(["git","-c","core.hooksPath=/dev/null","-c","core.symlinks=false","checkout","-q"], cwd=dest, t=300)
        removed=0; nfiles=0; nbytes=0
        for root, dirs, files in os.walk(dest):
            if ".git" in dirs: dirs.remove(".git")
            for f in files:
                p=os.path.join(root,f)
                if os.path.islink(p) or os.path.splitext(f)[1].lower() in BIN_EXT:
                    os.remove(p); removed+=1; continue
                try: sz=os.path.getsize(p)
                except OSError: continue
                if sz>1_000_000 or nfiles>=CAP_FILES or nbytes+sz>CAP_BYTES:
                    os.remove(p); removed+=1; continue
                nfiles+=1; nbytes+=sz
        sha = run(["git","rev-parse","HEAD"],cwd=dest).stdout.strip()
        shutil.rmtree(os.path.join(dest,".git"), ignore_errors=True)
        json.dump({"repo":full,"sha":sha,"files":nfiles,"bytes":nbytes,"removed":removed,"checkout_rc":r.returncode}, open(os.path.join(dest,".fetched.json"),"w"))
        return full, "ok"
    except subprocess.TimeoutExpired:
        shutil.rmtree(dest, ignore_errors=True); return full, "timeout"
os.makedirs(REPOS, exist_ok=True)
repos=[l.strip() for l in open(LIST) if l.strip()]
with cf.ThreadPoolExecutor(24) as ex, open(os.path.join(WORK,"raw","fetch_log.jsonl"),"a") as log:
    for i,(full,st) in enumerate(ex.map(one, repos)):
        log.write(json.dumps({"repo":full,"status":st})+"\n"); log.flush()
        if i%100==0: print(i, flush=True)
print("done")
