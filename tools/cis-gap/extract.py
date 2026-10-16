"""Extract inspector metadata (UUID, ID, title, description, internal-API usage) into <workdir>/repo.json."""
import glob
import json
import re
import sys
from pathlib import Path

repo_root, workdir = Path(sys.argv[1]), Path(sys.argv[2])
INTERNAL = re.compile(r"main\.iam\.ad\.ext\.azure\.com|admin\.microsoft\.com/admin/api")


def field(src, key):
    m = re.search(r"(?m)^\s*" + key + r'\s*=\s*"([^"]*)"', src)
    return m.group(1) if m else None


out = []
for p in sorted(glob.glob(str(repo_root / "inspectors/**/*.ps1"), recursive=True)):
    s = Path(p).read_text(encoding="utf-8-sig", errors="replace")
    bench = re.search(r"# Benchmark: (.*)", s)
    out.append(dict(path=str(Path(p).relative_to(repo_root)), uuid=field(s, "UUID"), id=field(s, "ID"),
                    title=field(s, "Title"), desc=field(s, "Description"),
                    bench=bench.group(1).strip() if bench else "", internal=bool(INTERNAL.search(s))))
(workdir / "repo.json").write_text(json.dumps(out, indent=1))
print(f"{len(out)} inspectors -> {workdir / 'repo.json'}")
