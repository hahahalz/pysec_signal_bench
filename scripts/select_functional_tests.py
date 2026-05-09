
#!/usr/bin/env python3
"""
Select functional tests and optionally extract upstream PoC/regression tests.

Functional-test rule:
  selected functional tests must PASS on both R_vuln and R_fix.

PoC-test rule:
  selected PoC candidates must FAIL on R_vuln and PASS on R_fix.
  Candidates are taken from the fixed snapshot, especially test files changed/added
  by the gold patch. The selected files are exported to:
      oracles/<instance_id>/extracted_poc/
  and instance.json environment.poc_test is set to a runner command:
      python /bench/oracles/<instance_id>/extracted_poc/run_extracted_poc.py

The runner copies the extracted fixed-version test files into the temporary repo
under evaluation and then runs pytest. This lets patch-added regression tests be
used as a benchmark oracle without requiring those tests to already exist in R_vuln.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


# -----------------------------------------------------------------------------
# Basic helpers
# -----------------------------------------------------------------------------


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_json_if_exists(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return load_json(path)


def save_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")


def run_cmd(cmd: List[str], timeout: int = 1800) -> Tuple[int, str]:
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired as e:
        return 124, f"[TIMEOUT] {' '.join(cmd)}\n{e}"


def tail_text(text: str, n: int = 80) -> str:
    lines = text.splitlines()
    return "\n".join(lines[-n:])


def normalize_relpath(p: str) -> str:
    p = p.replace("\\", "/").strip()
    while p.startswith("./"):
        p = p[2:]
    return p


def unique_keep_order(items: Iterable[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for x in items:
        x = normalize_relpath(str(x))
        if not x or x in seen:
            continue
        out.append(x)
        seen.add(x)
    return out


def list_from_dict(data: Dict[str, Any], key: str) -> List[str]:
    val = data.get(key)
    if isinstance(val, list):
        return [str(x) for x in val]
    return []


def safe_name(s: str) -> str:
    return (
        s.replace("/", "__")
        .replace("\\", "__")
        .replace(":", "_")
        .replace("[", "_")
        .replace("]", "_")
        .replace(" ", "_")
    )


# -----------------------------------------------------------------------------
# Instance / patch metadata
# -----------------------------------------------------------------------------


def get_snapshot_path(root: Path, inst: Dict[str, Any], new_key: str, old_key: str) -> Path:
    val = inst.get(new_key) or inst.get(old_key)
    if not val:
        raise ValueError(f"missing {new_key} / {old_key} in instance.json")
    return (root / val).resolve()


def is_test_file(path: str) -> bool:
    p = normalize_relpath(path).lower()
    name = Path(p).name
    return (
        p.endswith(".py")
        and (
            p.startswith("tests/")
            or "/tests/" in p
            or p.startswith("test/")
            or "/test/" in p
            or name.startswith("test_")
            or name.endswith("_test.py")
        )
    )


def is_test_or_doc_file(path: str) -> bool:
    p = normalize_relpath(path).lower()
    parts = p.split("/")
    if is_test_file(p):
        return True
    if "docs" in parts or "doc" in parts:
        return True
    if p.endswith((".md", ".rst", ".txt")):
        return True
    if "changelog" in p or "news" in p or "changes/" in p:
        return True
    return False


def parse_patch_files(patch_text: str) -> Tuple[List[str], List[str]]:
    """Return (changed_source_files, changed_test_files) from a unified diff."""
    source_files: List[str] = []
    test_files: List[str] = []

    for m in re.finditer(r"^diff --git a/(.+?) b/(.+)$", patch_text, flags=re.MULTILINE):
        rel = normalize_relpath(m.group(2))
        if rel == "/dev/null":
            continue
        if is_test_file(rel):
            test_files.append(rel)
        elif not is_test_or_doc_file(rel):
            source_files.append(rel)

    # Some patches may not include diff --git lines; fall back to +++ b/path.
    for m in re.finditer(r"^\+\+\+ b/(.+)$", patch_text, flags=re.MULTILINE):
        rel = normalize_relpath(m.group(1))
        if rel == "/dev/null":
            continue
        if is_test_file(rel):
            test_files.append(rel)
        elif not is_test_or_doc_file(rel):
            source_files.append(rel)

    return unique_keep_order(source_files), unique_keep_order(test_files)


def get_gold_patch_path(root: Path, inst: Dict[str, Any]) -> Optional[Path]:
    patch_key = inst.get("gold_patch") or inst.get("gold_patch_path") or inst.get("patch_file")
    if not patch_key:
        return None
    path = (root / patch_key).resolve()
    return path if path.exists() else None


def collect_files_from_metadata(meta: Dict[str, Any]) -> List[str]:
    """
    Only use affected_source_files-like fields.

    Do NOT use affected_files / changed_files / patch_files here,
    because those fields may include docs, changelog, tests, etc.
    """
    candidates: List[str] = []

    # Top-level metadata fields.
    for key in [
        "affected_source_files",
        "source_files_changed",
    ]:
        candidates.extend(list_from_dict(meta, key))

    # Nested metadata fields.
    for section_key in ["construction", "patch", "analysis", "instance_metadata"]:
        section = meta.get(section_key)
        if not isinstance(section, dict):
            continue

        for key in [
            "affected_source_files",
            "source_files_changed",
        ]:
            candidates.extend(list_from_dict(section, key))

    return candidates


def get_affected_files(inst: Dict[str, Any], meta: Dict[str, Any], root: Path) -> List[str]:
    """
    Return affected source files only.

    Priority:
      1. metadata.json affected_source_files
      2. instance.json affected_source_files, for backward compatibility
      3. fallback: parse gold patch and keep non-test, non-doc source files
    """
    candidates: List[str] = []

    # Preferred source: metadata.json affected_source_files.
    candidates.extend(collect_files_from_metadata(meta))

    # Backward compatibility: only source-file fields from instance.json.
    for key in [
        "affected_source_files",
        "source_files_changed",
    ]:
        candidates.extend(list_from_dict(inst, key))

    # Fallback only when affected_source_files is missing.
    # parse_patch_files() already filters docs/tests/changelog.
    if not candidates:
        patch_path = get_gold_patch_path(root, inst)
        if patch_path:
            source_files, _ = parse_patch_files(read_text(patch_path))
            candidates.extend(source_files)

    return unique_keep_order(
        f
        for f in candidates
        if f
        and f != "/dev/null"
        and not is_test_or_doc_file(f)
    )

def get_changed_test_files(inst: Dict[str, Any], meta: Dict[str, Any], root: Path) -> List[str]:
    candidates: List[str] = []

    for key in ["changed_test_files", "test_files_changed", "added_test_files", "poc_test_candidates"]:
        candidates.extend(list_from_dict(meta, key))
        candidates.extend(list_from_dict(inst, key))

    for section_key in ["construction", "patch", "analysis", "instance_metadata"]:
        section = meta.get(section_key)
        if isinstance(section, dict):
            for key in ["changed_test_files", "test_files_changed", "added_test_files", "poc_test_candidates"]:
                candidates.extend(list_from_dict(section, key))

    patch_path = get_gold_patch_path(root, inst)
    if patch_path:
        _, test_files = parse_patch_files(read_text(patch_path))
        candidates.extend(test_files)

    return unique_keep_order(f for f in candidates if is_test_file(f))


def make_tokens(affected_files: List[str]) -> List[str]:
    tokens = set()
    stop = {
        "",
        ".",
        "_",
        "-",
        "py",
        "python",
        "src",
        "lib",
        "tests",
        "test",
        "main",
        "init",
        "__init__",
    }

    for f in affected_files:
        f = normalize_relpath(f)
        no_ext = re.sub(r"\.py$", "", f)
        for part in no_ext.split("/"):
            part = part.strip()
            if part and part not in stop:
                tokens.add(part)
            for sub in re.split(r"[_\-.]+", part):
                sub = sub.strip()
                if len(sub) >= 3 and sub not in stop:
                    tokens.add(sub)

    return sorted(tokens)


def advisory_text(inst: Dict[str, Any], meta: Dict[str, Any]) -> str:
    chunks: List[str] = []
    for data in [inst, meta]:
        for key in ["summary", "details", "description", "full_advisory", "security_description", "task_description"]:
            val = data.get(key)
            if isinstance(val, str):
                chunks.append(val)
        sp = data.get("signal_probe")
        if isinstance(sp, dict):
            for val in sp.values():
                if isinstance(val, str):
                    chunks.append(val)
    return "\n".join(chunks)


# -----------------------------------------------------------------------------
# Test discovery and ranking
# -----------------------------------------------------------------------------


def discover_test_files(repo: Path) -> List[str]:
    test_roots: List[Path] = []
    for name in ["tests", "test"]:
        p = repo / name
        if p.exists() and p.is_dir():
            test_roots.append(p)
    if not test_roots:
        test_roots = [repo]

    files: List[str] = []
    for root in test_roots:
        for p in root.rglob("test*.py"):
            rel = normalize_relpath(str(p.relative_to(repo)))
            files.append(rel)
        for p in root.rglob("*_test.py"):
            rel = normalize_relpath(str(p.relative_to(repo)))
            files.append(rel)
    return sorted(set(files))


def score_test_file(test_file: str, tokens: List[str], affected_files: List[str]) -> int:
    p = test_file.lower()
    score = 0

    for tok in tokens:
        t = tok.lower()
        if not t:
            continue
        if t in p:
            score += 10
        if f"test_{t}" in p:
            score += 8
        if f"/{t}/" in p:
            score += 6

    affected_component_dirs = set()
    for f in affected_files:
        parts = normalize_relpath(f).split("/")
        if len(parts) >= 2:
            affected_component_dirs.add(parts[1])
        elif parts:
            affected_component_dirs.add(parts[0])

    for d in affected_component_dirs:
        d = d.lower()
        if d and d in p:
            score += 5

    score -= test_file.count("/")
    return score


def rank_candidate_tests(repo: Path, affected_files: List[str], max_candidates: int) -> List[str]:
    tokens = make_tokens(affected_files)
    test_files = discover_test_files(repo)

    scored = []
    for tf in test_files:
        s = score_test_file(tf, tokens, affected_files)
        if s > 0:
            scored.append((s, tf))
    scored.sort(key=lambda x: (-x[0], x[1]))

    candidates = [tf for _, tf in scored]
    if not candidates:
        candidates = test_files
    return candidates[:max_candidates]


def cwe_security_keywords(inst: Dict[str, Any], meta: Dict[str, Any]) -> List[str]:
    cwe_raw = inst.get("cwe") or meta.get("cwe") or []
    if isinstance(cwe_raw, str):
        cwes = [cwe_raw]
    else:
        cwes = [str(x) for x in cwe_raw]

    base = [
        "security",
        "vulnerability",
        "vulnerable",
        "cve",
        "ghsa",
        "poc",
        "proof",
        "exploit",
        "malicious",
        "attack",
        "unsafe",
        "sanitize",
        "validate",
        "reject",
        "forbidden",
        "unauthorized",
    ]

    mapping = {
        "22": ["path", "traversal", "directory", "dotdot", "..", "symlink", "resolve", "absolute", "static"],
        "23": ["path", "traversal", "relative", ".."],
        "35": ["path", "traversal", "absolute", ".."],
        "78": ["command", "shell", "subprocess", "exec", "injection"],
        "79": ["xss", "script", "html", "escape", "sanitize"],
        "89": ["sql", "query", "injection", "parameter"],
        "94": ["code", "eval", "exec", "template", "injection"],
        "1333": ["regex", "redos", "catastrophic", "backtracking"],
        "444": ["smuggling", "content-length", "transfer-encoding", "chunked", "header", "parser", "http"],
        "502": ["pickle", "deserialize", "yaml", "load", "object"],
        "611": ["xml", "xxe", "entity", "external"],
        "918": ["ssrf", "url", "request", "localhost", "internal"],
    }

    out = list(base)
    for cwe in cwes:
        m = re.search(r"CWE[-_ ]?(\d+)", cwe, flags=re.I)
        if m and m.group(1) in mapping:
            out.extend(mapping[m.group(1)])
    return unique_keep_order(out)


def score_poc_test_file(
    repo: Path,
    test_file: str,
    changed_tests: List[str],
    tokens: List[str],
    affected_files: List[str],
    security_keywords: List[str],
    adv_text: str,
) -> int:
    p = test_file.lower()
    content = read_text(repo / test_file).lower()
    score = score_test_file(test_file, tokens, affected_files)

    if test_file in changed_tests:
        score += 100

    for kw in security_keywords:
        k = kw.lower()
        if not k:
            continue
        if k in p:
            score += 6
        if k in content:
            score += 3

    # Use advisory words as soft hints, but avoid making this too noisy.
    adv_words = set(re.findall(r"[a-zA-Z][a-zA-Z0-9_-]{3,}", adv_text.lower()))
    stop = {"this", "that", "with", "from", "have", "will", "when", "using", "version", "affected", "python"}
    for w in sorted(adv_words - stop):
        if w in p:
            score += 2
        elif w in content:
            score += 1

    # Prefer focused files.
    score -= test_file.count("/")
    return score


def rank_poc_candidate_tests(
    repo_fix: Path,
    changed_tests: List[str],
    affected_files: List[str],
    inst: Dict[str, Any],
    meta: Dict[str, Any],
    max_candidates: int,
) -> List[str]:
    tokens = make_tokens(affected_files)
    all_tests = discover_test_files(repo_fix)
    security_keywords = cwe_security_keywords(inst, meta)
    adv = advisory_text(inst, meta)

    candidates: List[str] = []
    candidates.extend([t for t in changed_tests if (repo_fix / t).exists()])

    scored = []
    for tf in all_tests:
        s = score_poc_test_file(
            repo=repo_fix,
            test_file=tf,
            changed_tests=changed_tests,
            tokens=tokens,
            affected_files=affected_files,
            security_keywords=security_keywords,
            adv_text=adv,
        )
        if s > 0:
            scored.append((s, tf))

    scored.sort(key=lambda x: (-x[0], x[1]))
    candidates.extend([tf for _, tf in scored])

    if not candidates:
        candidates = all_tests

    return unique_keep_order(candidates)[:max_candidates]


# -----------------------------------------------------------------------------
# Validation runner
# -----------------------------------------------------------------------------


def make_runner_py() -> str:
    return r'''
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path


def tail_text(text, n=80):
    lines = text.splitlines()
    return "\n".join(lines[-n:])


def safe_name(s):
    return (
        s.replace("/", "__")
         .replace("\\", "__")
         .replace(":", "_")
         .replace("[", "_")
         .replace("]", "_")
         .replace(" ", "_")
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidates", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--log-dir", required=True)
    ap.add_argument("--timeout", type=int, default=300)
    args = ap.parse_args()

    candidates = [
        x.strip()
        for x in Path(args.candidates).read_text(encoding="utf-8").splitlines()
        if x.strip()
    ]

    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    results = {}

    for i, test_item in enumerate(candidates, start=1):
        print(f"[RUN] {i}/{len(candidates)} {test_item}", flush=True)
        cmd = [sys.executable, "-m", "pytest", "-q", test_item, "-vv", "--tb=short"]
        start = time.time()
        try:
            p = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=args.timeout,
            )
            rc = p.returncode
            output = p.stdout
        except subprocess.TimeoutExpired as e:
            rc = 124
            output = f"[TIMEOUT] {test_item}\n{e}"
        duration = time.time() - start

        log_path = log_dir / f"{safe_name(test_item)}.log"
        log_path.write_text(output, encoding="utf-8", errors="ignore")

        results[test_item] = {
            "returncode": rc,
            "status": "PASS" if rc == 0 else "FAIL",
            "duration_sec": round(duration, 2),
            "log": str(log_path),
            "tail": tail_text(output, 60),
        }
        print(f"[DONE] {test_item}: {results[test_item]['status']} ({duration:.1f}s)", flush=True)

    Path(args.out).write_text(json.dumps(results, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
'''


def prepare_validation_repo(
    snapshot: Path,
    work_dir: Path,
    overlay_repo: Optional[Path] = None,
    overlay_files: Optional[List[str]] = None,
) -> Path:
    """Create a writable repo copy when overlay files are needed."""
    overlay_files = overlay_files or []
    repo_copy = work_dir / "repo"
    if repo_copy.exists():
        shutil.rmtree(repo_copy)
    shutil.copytree(snapshot, repo_copy, ignore=shutil.ignore_patterns(".git", ".mypy_cache", ".pytest_cache", "__pycache__"))

    if overlay_repo and overlay_files:
        for rel in overlay_files:
            src = overlay_repo / rel
            dst = repo_copy / rel
            if not src.exists():
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)

    return repo_copy


def docker_validate_snapshot(
    snapshot: Path,
    image: str,
    install_command: str,
    candidates: List[str],
    work_dir: Path,
    per_test_timeout: int,
    docker_timeout: int,
    overlay_repo: Optional[Path] = None,
    overlay_files: Optional[List[str]] = None,
) -> Tuple[bool, Dict[str, Dict[str, Any]], str]:
    if work_dir.exists():
        shutil.rmtree(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    repo_for_run = prepare_validation_repo(snapshot, work_dir, overlay_repo, overlay_files)

    (work_dir / "candidates.txt").write_text("\n".join(candidates) + "\n", encoding="utf-8")
    (work_dir / "runner.py").write_text(make_runner_py(), encoding="utf-8")

    results_path = work_dir / "results.json"
    install_log = work_dir / "install.log"
    run_log = work_dir / "docker.log"
    logs_dir = work_dir / "logs"

    shell_cmd = f"""
set -euo pipefail
cd /repo

echo "[INSTALL] {install_command}"
({install_command}) > /io/install.log 2>&1

echo "[RUNNER] start"
python /io/runner.py \
  --candidates /io/candidates.txt \
  --out /io/results.json \
  --log-dir /io/logs \
  --timeout {per_test_timeout}
"""

    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{repo_for_run}:/repo",
        "-v",
        f"{work_dir}:/io",
        "-w",
        "/repo",
        image,
        "bash",
        "-lc",
        shell_cmd,
    ]

    rc, out = run_cmd(cmd, timeout=docker_timeout)
    run_log.write_text(out, encoding="utf-8", errors="ignore")

    if rc != 0:
        msg = "[DOCKER FAILED]\n\n"
        msg += "[DOCKER LOG TAIL]\n"
        msg += tail_text(out, 80)
        msg += "\n\n[INSTALL LOG TAIL]\n"
        msg += tail_text(read_text(install_log), 80)
        return False, {}, msg

    if not results_path.exists():
        msg = "[ERROR] Docker finished but results.json was not produced.\n\n"
        msg += "[DOCKER LOG TAIL]\n"
        msg += tail_text(out, 80)
        msg += "\n\n[INSTALL LOG TAIL]\n"
        msg += tail_text(read_text(install_log), 80)
        return False, {}, msg

    results = json.loads(results_path.read_text(encoding="utf-8"))
    return True, results, out


def local_validate_snapshot(
    snapshot: Path,
    install_command: str,
    candidates: List[str],
    per_test_timeout: int,
    work_dir: Path,
    overlay_repo: Optional[Path] = None,
    overlay_files: Optional[List[str]] = None,
) -> Dict[str, Dict[str, Any]]:
    repo_for_run = prepare_validation_repo(snapshot, work_dir, overlay_repo, overlay_files)
    old_cwd = Path.cwd()
    try:
        os.chdir(repo_for_run)
        print(f"[LOCAL INSTALL] {install_command}")
        rc, out = run_cmd(["bash", "-lc", install_command], timeout=1800)
        if rc != 0:
            raise RuntimeError(f"local install failed:\n{tail_text(out, 120)}")

        results: Dict[str, Dict[str, Any]] = {}
        for i, test_item in enumerate(candidates, start=1):
            print(f"[RUN] {i}/{len(candidates)} {test_item}")
            rc, out = run_cmd(
                [sys.executable, "-m", "pytest", "-q", test_item, "-vv", "--tb=short"],
                timeout=per_test_timeout,
            )
            results[test_item] = {
                "returncode": rc,
                "status": "PASS" if rc == 0 else "FAIL",
                "tail": tail_text(out, 60),
            }
        return results
    finally:
        os.chdir(old_cwd)


def validate_on_vuln_and_fix(
    *,
    root: Path,
    instance_id: str,
    subdir: str,
    r_vuln: Path,
    r_fix: Path,
    image: str,
    install_command: str,
    candidates: List[str],
    args: argparse.Namespace,
    overlay_for_vuln: Optional[List[str]] = None,
    overlay_for_fix: Optional[List[str]] = None,
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    base_work = root / "analysis" / subdir / instance_id

    if args.use_docker:
        if not image:
            raise ValueError("missing docker image. Provide --docker-image or instance.json environment.docker_image")

        ok_v, vuln_results, msg_v = docker_validate_snapshot(
            snapshot=r_vuln,
            image=image,
            install_command=install_command,
            candidates=candidates,
            work_dir=base_work / "R_vuln",
            per_test_timeout=args.per_test_timeout,
            docker_timeout=args.docker_timeout,
            overlay_repo=r_fix if overlay_for_vuln else None,
            overlay_files=overlay_for_vuln,
        )
        if not ok_v:
            print("\n[ERROR] R_vuln docker install or validation failed.")
            print(msg_v)
            raise RuntimeError("R_vuln docker install or validation failed")

        ok_f, fix_results, msg_f = docker_validate_snapshot(
            snapshot=r_fix,
            image=image,
            install_command=install_command,
            candidates=candidates,
            work_dir=base_work / "R_fix",
            per_test_timeout=args.per_test_timeout,
            docker_timeout=args.docker_timeout,
            overlay_repo=r_fix if overlay_for_fix else None,
            overlay_files=overlay_for_fix,
        )
        if not ok_f:
            print("\n[ERROR] R_fix docker install or validation failed.")
            print(msg_f)
            raise RuntimeError("R_fix docker install or validation failed")

    else:
        vuln_results = local_validate_snapshot(
            snapshot=r_vuln,
            install_command=install_command,
            candidates=candidates,
            per_test_timeout=args.per_test_timeout,
            work_dir=base_work / "R_vuln",
            overlay_repo=r_fix if overlay_for_vuln else None,
            overlay_files=overlay_for_vuln,
        )
        fix_results = local_validate_snapshot(
            snapshot=r_fix,
            install_command=install_command,
            candidates=candidates,
            per_test_timeout=args.per_test_timeout,
            work_dir=base_work / "R_fix",
            overlay_repo=r_fix if overlay_for_fix else None,
            overlay_files=overlay_for_fix,
        )

    return vuln_results, fix_results


def print_results_table(candidates: List[str], vuln_results: Dict[str, Any], fix_results: Dict[str, Any]) -> None:
    print("\n[RESULTS]")
    for t in candidates:
        v = vuln_results.get(t, {}).get("status", "MISSING")
        f = fix_results.get(t, {}).get("status", "MISSING")
        print(f"  {t}")
        print(f"    R_vuln: {v}")
        print(f"    R_fix : {f}")


def compact_results(results: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for test_item, r in results.items():
        out[test_item] = {
            "status": r.get("status"),
            "returncode": r.get("returncode"),
            "duration_sec": r.get("duration_sec"),
            "log": r.get("log"),
        }
    return out


def make_test_command(selected: List[str], pytest_prefix: str) -> Optional[str]:
    if not selected:
        return None
    return (pytest_prefix.strip() + " " + " ".join(selected)).strip()


def get_install_command(args: argparse.Namespace, env: Dict[str, Any]) -> str:
    if args.install_command:
        return args.install_command
    if env.get("install"):
        return env["install"]
    if env.get("install_repo_command"):
        return env["install_repo_command"]
    return "python -m pip install --no-deps --no-build-isolation -e ."


# -----------------------------------------------------------------------------
# Export extracted PoC tests as oracle files
# -----------------------------------------------------------------------------


def make_extracted_poc_runner_py() -> str:
    return r'''#!/usr/bin/env python3
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
'''


def export_extracted_poc_oracle(
    *,
    root: Path,
    instance_id: str,
    r_fix: Path,
    selected: List[str],
    pytest_prefix: str,
    meta: Dict[str, Any],
) -> str:
    oracle_dir = root / "oracles" / instance_id / "extracted_poc"
    files_dir = oracle_dir / "files"
    if oracle_dir.exists():
        shutil.rmtree(oracle_dir)
    files_dir.mkdir(parents=True, exist_ok=True)

    for rel in selected:
        src = r_fix / rel
        dst = files_dir / rel
        if not src.exists():
            raise FileNotFoundError(f"selected PoC test does not exist in R_fix: {src}")
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    manifest = {
        "instance_id": instance_id,
        "source": "fixed_snapshot_regression_tests",
        "test_files": selected,
        "pytest_prefix": pytest_prefix,
        "note": "These files are copied into /repo by run_extracted_poc.py before pytest is executed.",
    }
    save_json(oracle_dir / "manifest.json", manifest)
    runner = oracle_dir / "run_extracted_poc.py"
    runner.write_text(make_extracted_poc_runner_py(), encoding="utf-8")
    runner.chmod(0o755)

    meta["extracted_poc_oracle"] = {
        "oracle_dir": normalize_relpath(str(oracle_dir.relative_to(root))),
        "runner": normalize_relpath(str(runner.relative_to(root))),
        "manifest": normalize_relpath(str((oracle_dir / "manifest.json").relative_to(root))),
        "test_files": selected,
    }

    return f"python /bench/oracles/{instance_id}/extracted_poc/run_extracted_poc.py"


# -----------------------------------------------------------------------------
# Selection workflows
# -----------------------------------------------------------------------------


def select_functional_tests(
    *,
    root: Path,
    instance_id: str,
    inst: Dict[str, Any],
    meta: Dict[str, Any],
    r_vuln: Path,
    r_fix: Path,
    image: str,
    install_command: str,
    affected_files: List[str],
    args: argparse.Namespace,
) -> Dict[str, Any]:
    candidates = rank_candidate_tests(repo=r_vuln, affected_files=affected_files, max_candidates=args.max_candidates)

    print("\n[INFO] functional candidate test files:")
    for c in candidates:
        print(f"   {c}")

    vuln_results, fix_results = validate_on_vuln_and_fix(
        root=root,
        instance_id=instance_id,
        subdir="functional_selection",
        r_vuln=r_vuln,
        r_fix=r_fix,
        image=image,
        install_command=install_command,
        candidates=candidates,
        args=args,
    )
    print_results_table(candidates, vuln_results, fix_results)

    selected: List[str] = []
    for test_item in candidates:
        v = vuln_results.get(test_item, {}).get("status")
        f = fix_results.get(test_item, {}).get("status")
        if v == "PASS" and f == "PASS":
            selected.append(test_item)
        if len(selected) >= args.max_tests:
            break

    functional_cmd = make_test_command(selected, args.pytest_prefix)

    print("\n[RESULT] selected functional tests:")
    for s in selected:
        print(f"   {s}")
    print(f"[RESULT] functional_test command: {functional_cmd}")

    return {
        "status": "selected" if selected else "no_functional_tests_selected",
        "selected": selected,
        "command": functional_cmd,
        "candidate_tests": candidates,
        "selection_rule": "selected test files that PASS on both R_vuln and R_fix",
        "results": {"R_vuln": vuln_results, "R_fix": fix_results},
    }


def select_poc_tests(
    *,
    root: Path,
    instance_id: str,
    inst: Dict[str, Any],
    meta: Dict[str, Any],
    r_vuln: Path,
    r_fix: Path,
    image: str,
    install_command: str,
    affected_files: List[str],
    args: argparse.Namespace,
) -> Dict[str, Any]:
    changed_tests = get_changed_test_files(inst, meta, root)
    candidates = rank_poc_candidate_tests(
        repo_fix=r_fix,
        changed_tests=changed_tests,
        affected_files=affected_files,
        inst=inst,
        meta=meta,
        max_candidates=args.poc_max_candidates,
    )

    print("\n[INFO] changed/patch test files:")
    for c in changed_tests:
        print(f"   {c}")

    print("\n[INFO] PoC candidate test files from R_fix:")
    for c in candidates:
        print(f"   {c}")

    # Important: run fixed-version candidate tests against both snapshots. This is
    # what makes patch-added regression tests usable as an oracle.
    overlay_files = candidates if args.poc_use_fixed_tests else []
    vuln_results, fix_results = validate_on_vuln_and_fix(
        root=root,
        instance_id=instance_id,
        subdir="poc_selection",
        r_vuln=r_vuln,
        r_fix=r_fix,
        image=image,
        install_command=install_command,
        candidates=candidates,
        args=args,
        overlay_for_vuln=overlay_files,
        overlay_for_fix=overlay_files,
    )
    print_results_table(candidates, vuln_results, fix_results)

    selected: List[str] = []
    for test_item in candidates:
        v = vuln_results.get(test_item, {}).get("status")
        f = fix_results.get(test_item, {}).get("status")
        if v == "FAIL" and f == "PASS":
            selected.append(test_item)
        if len(selected) >= args.poc_max_tests:
            break

    print("\n[RESULT] selected PoC/upstream regression tests:")
    for s in selected:
        print(f"   {s}")

    poc_cmd: Optional[str] = None
    if selected and args.export_poc_oracle:
        poc_cmd = export_extracted_poc_oracle(
            root=root,
            instance_id=instance_id,
            r_fix=r_fix,
            selected=selected,
            pytest_prefix=args.pytest_prefix,
            meta=meta,
        )
    elif selected:
        poc_cmd = make_test_command(selected, args.pytest_prefix)

    print(f"[RESULT] poc_test command: {poc_cmd}")

    return {
        "status": "selected" if selected else "no_poc_tests_selected",
        "selected": selected,
        "command": poc_cmd,
        "changed_test_files": changed_tests,
        "candidate_tests": candidates,
        "selection_rule": "selected fixed-version regression tests that FAIL on R_vuln and PASS on R_fix",
        "used_fixed_test_overlay": bool(args.poc_use_fixed_tests),
        "exported_oracle": bool(selected and args.export_poc_oracle),
        "results": {"R_vuln": vuln_results, "R_fix": fix_results},
    }


# -----------------------------------------------------------------------------
# Batch processing and reports
# -----------------------------------------------------------------------------


def discover_instance_ids(root: Path, args: argparse.Namespace) -> List[str]:
    ids: List[str] = []

    if args.instance:
        ids.append(args.instance)
    if args.instances:
        ids.extend([x.strip() for x in args.instances.split(",") if x.strip()])
    if args.instances_file:
        path = root / args.instances_file
        if not path.exists():
            raise FileNotFoundError(f"instances file not found: {path}")
        ids.extend([
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ])
    if args.report_csv:
        import csv
        path = root / args.report_csv
        if not path.exists():
            raise FileNotFoundError(f"report csv not found: {path}")
        allowed_statuses = {"constructed", "constructed_pr_range_needs_review", "skipped_existing", "ready"}
        with path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                iid = row.get("instance_id", "").strip()
                status = row.get("status", "").strip()
                if iid and (not status or status in allowed_statuses):
                    ids.append(iid)
    if args.all:
        instances_root = root / "candidate_instances"
        if instances_root.exists():
            ids.extend([p.parent.name for p in sorted(instances_root.glob("*/instance.json"))])

    out: List[str] = []
    seen = set()
    for iid in ids:
        if iid not in seen:
            out.append(iid)
            seen.add(iid)

    if not out:
        raise ValueError(
            "No instances selected. Use --instance ID, --instances A,B, --instances-file file.txt, "
            "--report-csv analysis/report.csv, or --all."
        )
    return out


def write_batch_report(root: Path, rows: List[Dict[str, Any]]) -> None:
    import csv

    out = root / "analysis" / "test_selection_report.csv"
    out.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "instance_id",
        "status",
        "reason",
        "functional_status",
        "functional_selected_count",
        "functional_test",
        "poc_status",
        "poc_selected_count",
        "poc_test",
        "functional_candidate_count",
        "poc_candidate_count",
        "used_docker",
        "docker_image",
        "install",
    ]

    with out.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})

    print(f"\n[DONE] batch report written to: {out}")


def process_one_instance(root: Path, instance_id: str, args: argparse.Namespace) -> Dict[str, Any]:
    instance_dir = root / "candidate_instances" / instance_id
    inst_path = instance_dir / "instance.json"
    meta_path = instance_dir / "metadata.json"

    report_row: Dict[str, Any] = {
        "instance_id": instance_id,
        "status": "unknown",
        "reason": "",
        "functional_status": "not_run",
        "functional_selected_count": 0,
        "functional_test": "",
        "poc_status": "not_run",
        "poc_selected_count": 0,
        "poc_test": "",
        "functional_candidate_count": 0,
        "poc_candidate_count": 0,
        "used_docker": args.use_docker,
        "docker_image": "",
        "install": "",
    }

    if not inst_path.exists():
        report_row["status"] = "failed"
        report_row["reason"] = f"instance.json not found: {inst_path}"
        print(f"[ERROR] {report_row['reason']}")
        return report_row

    inst = load_json(inst_path)
    meta = load_json_if_exists(meta_path)

    env0 = inst.get("environment", {}) if isinstance(inst.get("environment"), dict) else {}
    if args.skip_existing:
        if args.select_functional and env0.get("functional_test"):
            print(f"[SKIP] {instance_id}: existing environment.functional_test")
            args.select_functional = False
        if args.select_poc and env0.get("poc_test"):
            print(f"[SKIP] {instance_id}: existing environment.poc_test")
            args.select_poc = False
        if not args.select_functional and not args.select_poc:
            report_row.update({
                "status": "skipped_existing",
                "reason": "requested fields already exist",
                "functional_test": env0.get("functional_test") or "",
                "poc_test": env0.get("poc_test") or "",
                "docker_image": env0.get("docker_image", ""),
                "install": env0.get("install", env0.get("install_repo_command", "")),
            })
            return report_row

    r_vuln = get_snapshot_path(root, inst, "vulnerable_snapshot", "vulnerable_snapshot_path")
    r_fix = get_snapshot_path(root, inst, "fixed_snapshot", "fixed_snapshot_path")
    affected_files = get_affected_files(inst, meta, root)
    tokens = make_tokens(affected_files)

    print("[INFO] affected files:")
    for f in affected_files:
        print(f"   {f}")
    print("[INFO] tokens:", ", ".join(tokens))

    env = inst.get("environment", {}) if isinstance(inst.get("environment"), dict) else {}
    image = args.docker_image or env.get("docker_image", "")
    install_command = get_install_command(args, env)

    if "/opt/pysec_install.sh" in install_command:
        print("\n[WARN] instance.json still uses old /opt/pysec_install.sh install command.")
        print("[WARN] Override it with: --install-command 'python -m pip install -e .'")
        install_command = "python -m pip install -e ."

    report_row["docker_image"] = image
    report_row["install"] = install_command
    print(f"[INFO] use docker image: {image or '(local)'}")
    print(f"[INFO] install command: {install_command}")

    functional_info: Optional[Dict[str, Any]] = None
    poc_info: Optional[Dict[str, Any]] = None

    if args.select_functional:
        functional_info = select_functional_tests(
            root=root,
            instance_id=instance_id,
            inst=inst,
            meta=meta,
            r_vuln=r_vuln,
            r_fix=r_fix,
            image=image,
            install_command=install_command,
            affected_files=affected_files,
            args=args,
        )
        report_row["functional_status"] = functional_info["status"]
        report_row["functional_selected_count"] = len(functional_info["selected"])
        report_row["functional_candidate_count"] = len(functional_info["candidate_tests"])
        report_row["functional_test"] = functional_info["command"] or ""

    if args.select_poc:
        poc_info = select_poc_tests(
            root=root,
            instance_id=instance_id,
            inst=inst,
            meta=meta,
            r_vuln=r_vuln,
            r_fix=r_fix,
            image=image,
            install_command=install_command,
            affected_files=affected_files,
            args=args,
        )
        report_row["poc_status"] = poc_info["status"]
        report_row["poc_selected_count"] = len(poc_info["selected"])
        report_row["poc_candidate_count"] = len(poc_info["candidate_tests"])
        report_row["poc_test"] = poc_info["command"] or ""

    if args.write:
        env = inst.get("environment")
        if not isinstance(env, dict):
            env = {}

        if functional_info is not None:
            env["functional_test"] = functional_info["command"]
        else:
            env.setdefault("functional_test", None)

        if poc_info is not None:
            env["poc_test"] = poc_info["command"]
        else:
            env.setdefault("poc_test", None)

        env.setdefault("property_test", None)
        inst["environment"] = env
        save_json(inst_path, inst)

        if functional_info is not None:
            meta["functional_test_selection"] = {
                "status": functional_info["status"],
                "selected": functional_info["selected"],
                "functional_test": functional_info["command"],
                "pytest_prefix": args.pytest_prefix,
                "candidate_tests": functional_info["candidate_tests"],
                "affected_files_used": affected_files,
                "selection_rule": functional_info["selection_rule"],
                "limits": {
                    "max_candidates": args.max_candidates,
                    "max_tests": args.max_tests,
                    "per_test_timeout": args.per_test_timeout,
                    "docker_timeout": args.docker_timeout,
                },
                "used_docker": args.use_docker,
                "docker_image": image if args.use_docker else None,
                "install": install_command,
                "results": {
                    "R_vuln": compact_results(functional_info["results"]["R_vuln"]),
                    "R_fix": compact_results(functional_info["results"]["R_fix"]),
                },
            }

        if poc_info is not None:
            meta["poc_test_selection"] = {
                "status": poc_info["status"],
                "selected": poc_info["selected"],
                "poc_test": poc_info["command"],
                "pytest_prefix": args.pytest_prefix,
                "changed_test_files": poc_info["changed_test_files"],
                "candidate_tests": poc_info["candidate_tests"],
                "affected_files_used": affected_files,
                "selection_rule": poc_info["selection_rule"],
                "used_fixed_test_overlay": poc_info["used_fixed_test_overlay"],
                "exported_oracle": poc_info["exported_oracle"],
                "limits": {
                    "poc_max_candidates": args.poc_max_candidates,
                    "poc_max_tests": args.poc_max_tests,
                    "per_test_timeout": args.per_test_timeout,
                    "docker_timeout": args.docker_timeout,
                },
                "used_docker": args.use_docker,
                "docker_image": image if args.use_docker else None,
                "install": install_command,
                "results": {
                    "R_vuln": compact_results(poc_info["results"]["R_vuln"]),
                    "R_fix": compact_results(poc_info["results"]["R_fix"]),
                },
            }

        save_json(meta_path, meta)
        print(f"\n[DONE] updated {inst_path}")
        print(f"[DONE] updated {meta_path}")
    else:
        print("\n[INFO] dry run only. Add --write to update instance.json and metadata.json.")

    statuses = [report_row["functional_status"], report_row["poc_status"]]
    if "failed" in statuses:
        report_row["status"] = "failed"
        report_row["reason"] = "one selection failed"
    elif any(s == "selected" for s in statuses):
        report_row["status"] = "selected"
        report_row["reason"] = "ok"
    else:
        report_row["status"] = "no_tests_selected"
        report_row["reason"] = "no selected tests under requested rules"

    return report_row


def main() -> None:
    ap = argparse.ArgumentParser()

    ap.add_argument("--root", default=".")
    ap.add_argument("--instance", default="", help="Process one instance ID.")
    ap.add_argument("--instances", default="", help="Comma-separated instance IDs, e.g. ID1,ID2.")
    ap.add_argument("--instances-file", default="", help="Text file containing one instance ID per line.")
    ap.add_argument("--all", action="store_true", help="Process all instances under instances/*/instance.json.")
    ap.add_argument("--report-csv", default="", help="Process instances listed in a construction report CSV.")

    ap.add_argument("--use-docker", action="store_true")
    ap.add_argument("--docker-image", default="")
    ap.add_argument("--install-command", default="")
    ap.add_argument("--per-test-timeout", type=int, default=300)
    ap.add_argument("--docker-timeout", type=int, default=7200)
    ap.add_argument("--pytest-prefix", default="pytest -q")

    ap.add_argument("--select-functional", action="store_true", help="Select functional tests: PASS on R_vuln and R_fix.")
    ap.add_argument("--select-poc", action="store_true", help="Select PoC/regression tests: FAIL on R_vuln and PASS on R_fix.")
    ap.add_argument("--max-candidates", type=int, default=30, help="Max functional-test candidates.")
    ap.add_argument("--max-tests", type=int, default=5, help="Max selected functional tests.")
    ap.add_argument("--poc-max-candidates", type=int, default=30, help="Max PoC-test candidates.")
    ap.add_argument("--poc-max-tests", type=int, default=3, help="Max selected PoC tests.")
    ap.add_argument(
        "--poc-use-fixed-tests",
        action="store_true",
        default=True,
        help="Run fixed-snapshot versions of candidate tests on both R_vuln and R_fix. Default: true.",
    )
    ap.add_argument(
        "--no-poc-use-fixed-tests",
        dest="poc_use_fixed_tests",
        action="store_false",
        help="Do not overlay fixed-snapshot test files when selecting PoC tests.",
    )
    ap.add_argument(
        "--export-poc-oracle",
        action="store_true",
        default=True,
        help="Export selected fixed-version tests to oracles/<ID>/extracted_poc and set environment.poc_test to the runner. Default: true.",
    )
    ap.add_argument(
        "--no-export-poc-oracle",
        dest="export_poc_oracle",
        action="store_false",
        help="Do not export selected PoC tests; store a direct pytest command instead.",
    )

    ap.add_argument("--write", action="store_true")
    ap.add_argument("--skip-existing", action="store_true")
    ap.add_argument("--stop-on-error", action="store_true")

    args = ap.parse_args()

    # Backward-compatible default: original script only selected functional tests.
    if not args.select_functional and not args.select_poc:
        args.select_functional = True

    root = Path(args.root).resolve()
    instance_ids = discover_instance_ids(root, args)

    rows: List[Dict[str, Any]] = []
    for idx, instance_id in enumerate(instance_ids, start=1):
        print("=" * 80)
        modes = []
        if args.select_functional:
            modes.append("functional")
        if args.select_poc:
            modes.append("poc")
        print(f"[{idx}/{len(instance_ids)}] selecting {'+'.join(modes)} tests for {instance_id}")

        try:
            # Avoid mutating args.select_* across instances when --skip-existing changes mode.
            per_instance_args = argparse.Namespace(**vars(args))
            row = process_one_instance(root, instance_id, per_instance_args)
        except Exception as e:
            row = {
                "instance_id": instance_id,
                "status": "failed",
                "reason": str(e).replace("\n", " ")[:500],
                "functional_status": "failed" if args.select_functional else "not_run",
                "functional_selected_count": 0,
                "functional_test": "",
                "poc_status": "failed" if args.select_poc else "not_run",
                "poc_selected_count": 0,
                "poc_test": "",
                "functional_candidate_count": 0,
                "poc_candidate_count": 0,
                "used_docker": args.use_docker,
                "docker_image": args.docker_image,
                "install": args.install_command,
            }
            print(f"[ERROR] {instance_id}: {row['reason']}")
            if args.stop_on_error:
                rows.append(row)
                write_batch_report(root, rows)
                raise

        rows.append(row)
        print(f"[SUMMARY] {instance_id}: {row['status']} | {row['reason']}")

    write_batch_report(root, rows)

    print("\n[FINAL SUMMARY]")
    print(f"processed: {len(rows)}")
    for status in ["selected", "no_tests_selected", "skipped_existing", "failed"]:
        print(f"{status}: {sum(1 for r in rows if r.get('status') == status)}")

    failed = [r for r in rows if r.get("status") == "failed"]
    if failed:
        print("\n[FAILED]")
        for r in failed:
            print(f"- {r['instance_id']}: {r['reason']}")


if __name__ == "__main__":
    main()
