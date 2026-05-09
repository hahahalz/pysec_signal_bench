#!/usr/bin/env python3
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


def main():
    here = Path(__file__).resolve().parent
    manifest = json.loads((here / "manifest.json").read_text(encoding="utf-8"))

    repo = Path(os.environ.get("REPO_UNDER_TEST", "/repo")).resolve()
    if not repo.exists():
        repo = Path.cwd().resolve()

    copied = []
    for rel in manifest["test_files"]:
        src = here / "files" / rel
        dst = repo / rel
        if not src.exists():
            print(f"[ERROR] missing extracted test file: {src}", file=sys.stderr)
            return 2
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        copied.append(rel)

    pytest_prefix = manifest.get("pytest_prefix", "pytest -q").strip().split()
    cmd = [sys.executable, "-m", "pytest"]
    if pytest_prefix and pytest_prefix[0] in {"pytest", "python"}:
        # Keep only common pytest flags from the saved prefix; avoid duplicating python -m pytest.
        cmd = [sys.executable, "-m", "pytest"]
        cmd.extend([x for x in pytest_prefix[1:] if x != "-m" and x != "pytest"])
    else:
        cmd.extend(["-q"])
    cmd.extend(copied)

    print("[EXTRACTED_POC] copied fixed-version test files:")
    for rel in copied:
        print(f"  - {rel}")
    print("[EXTRACTED_POC] running:", " ".join(cmd))

    p = subprocess.run(cmd, cwd=str(repo))
    return p.returncode


if __name__ == "__main__":
    raise SystemExit(main())
