#!/usr/bin/env python3
"""
Simple validator for benchmark instances.

It validates the relationship among R_vuln, R_fix, and gold_patch, and optionally
runs the configured oracle tests. The output is intentionally simple: each check
only reports success/failure and the failure reason.

Output files:
  analysis/gold_patch_validation/<instance_id>/validation_summary.json
  analysis/gold_patch_validation_report.csv
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


# -----------------------------------------------------------------------------
# Basic helpers
# -----------------------------------------------------------------------------
def ensure_local_git_repo(repo: Path) -> None:
    repo = repo.resolve()

    if not repo.exists():
        raise FileNotFoundError(f"repo does not exist: {repo}")
    if not repo.is_dir():
        raise NotADirectoryError(f"repo is not a directory: {repo}")

    # 如果临时 repo 自己已经有 .git，就不用重新 init
    if (repo / ".git").exists():
        return

    rc, out, _ = run_cmd(["git", "init", "-q"], cwd=repo, timeout=60)
    if rc != 0:
        raise RuntimeError(f"git init failed in {repo}: {tail_text(out, 20)}")

    # 避免权限位污染影响 git status / diff
    run_cmd(["git", "config", "core.filemode", "false"], cwd=repo, timeout=60)
    
def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_json_if_exists(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return load_json(path)


def save_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", errors="ignore")


def run_cmd(cmd: List[str], *, cwd: Optional[Path] = None, timeout: int = 1800) -> Tuple[int, str, float]:
    start = time.time()
    try:
        p = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
        return p.returncode, p.stdout, time.time() - start
    except subprocess.TimeoutExpired as e:
        return 124, f"[TIMEOUT] {' '.join(cmd)}\n{e}", time.time() - start


def run_shell(shell_cmd: str, *, cwd: Optional[Path] = None, timeout: int = 1800) -> Tuple[int, str, float]:
    return run_cmd(["bash", "-lc", shell_cmd], cwd=cwd, timeout=timeout)


def tail_text(text: str, n: int = 80) -> str:
    return "\n".join(text.splitlines()[-n:])


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
        if x and x not in seen:
            out.append(x)
            seen.add(x)
    return out


def list_from_dict(data: Dict[str, Any], key: str) -> List[str]:
    val = data.get(key)
    return [str(x) for x in val] if isinstance(val, list) else []


def safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "__", s).strip("_") or "item"


def sha256_file(path: Path) -> Optional[str]:
    if not path.exists() or not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def status_from_rc(rc: int) -> str:
    return "PASS" if rc == 0 else "FAIL"


def make_check(name: str, success: bool, reason: str, **extra: Any) -> Dict[str, Any]:
    d: Dict[str, Any] = {
        "name": name,
        "success": bool(success),
        "status": "PASS" if success else "FAIL",
        "reason": reason,
    }
    d.update(extra)
    return d


def extract_failure_reason(output: str, *, fallback: str = "command failed") -> str:
    """Return a short, human-readable failure reason from command output."""
    if not output:
        return fallback

    lines = [ln.rstrip() for ln in output.splitlines() if ln.strip()]
    if not lines:
        return fallback

    patterns = [
        r"ModuleNotFoundError:.*",
        r"ImportError:.*",
        r"AssertionError:.*",
        r"SyntaxError:.*",
        r"TypeError:.*",
        r"ValueError:.*",
        r"PermissionError:.*",
        r"FileNotFoundError:.*",
        r"Timeout.*",
        r"ERROR:.*",
        r"error:.*",
        r"FAILED .*",
        r"E\s+.*",
    ]

    hits: List[str] = []
    for line in lines:
        for pat in patterns:
            if re.search(pat, line):
                hits.append(line.strip())
                break

    if hits:
        # Keep the last few because pytest usually reports the most useful error near the end.
        return " | ".join(hits[-4:])[:1200]

    return " | ".join(lines[-8:])[:1200]


# -----------------------------------------------------------------------------
# Instance metadata
# -----------------------------------------------------------------------------


def get_snapshot_path(root: Path, inst: Dict[str, Any], new_key: str, old_key: str) -> Path:
    val = inst.get(new_key) or inst.get(old_key)
    if not val:
        raise ValueError(f"missing {new_key} / {old_key} in instance.json")
    return (root / str(val)).resolve()


def get_gold_patch_path(root: Path, inst: Dict[str, Any]) -> Path:
    val = inst.get("gold_patch") or inst.get("gold_patch_path") or inst.get("patch_file")
    if not val:
        raise ValueError("missing gold_patch / gold_patch_path / patch_file in instance.json")
    path = (root / str(val)).resolve()
    if not path.exists():
        raise FileNotFoundError(f"gold patch not found: {path}")
    return path


def is_test_file(path: str) -> bool:
    p = normalize_relpath(path).lower()
    name = Path(p).name
    return p.endswith(".py") and (
        p.startswith("tests/")
        or "/tests/" in p
        or p.startswith("test/")
        or "/test/" in p
        or name.startswith("test_")
        or name.endswith("_test.py")
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


def parse_patch_files(patch_text: str) -> Tuple[List[str], List[str], List[str]]:
    headers: List[str] = []

    for m in re.finditer(r"^diff --git a/(.+?) b/(.+)$", patch_text, flags=re.MULTILINE):
        headers.append(normalize_relpath(m.group(2)))

    if not headers:
        for m in re.finditer(r"^\+\+\+ b/(.+)$", patch_text, flags=re.MULTILINE):
            headers.append(normalize_relpath(m.group(1)))

    source_files: List[str] = []
    test_files: List[str] = []
    other_files: List[str] = []

    for rel in headers:
        if rel == "/dev/null":
            continue
        if is_test_file(rel):
            test_files.append(rel)
        elif is_test_or_doc_file(rel):
            other_files.append(rel)
        else:
            source_files.append(rel)

    return unique_keep_order(source_files), unique_keep_order(test_files), unique_keep_order(other_files)


def collect_files_from_metadata(meta: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for key in ["affected_source_files", "source_files_changed"]:
        out.extend(list_from_dict(meta, key))
    for section_key in ["construction", "patch", "analysis", "instance_metadata"]:
        section = meta.get(section_key)
        if isinstance(section, dict):
            for key in ["affected_source_files", "source_files_changed"]:
                out.extend(list_from_dict(section, key))
    return out


def get_affected_source_files(inst: Dict[str, Any], meta: Dict[str, Any], patch_source_files: List[str]) -> List[str]:
    candidates: List[str] = []
    candidates.extend(collect_files_from_metadata(meta))
    for key in ["affected_source_files", "source_files_changed"]:
        candidates.extend(list_from_dict(inst, key))
    if not candidates:
        candidates.extend(patch_source_files)
    return unique_keep_order(
        f for f in candidates if f and f != "/dev/null" and not is_test_or_doc_file(f)
    )


def get_install_command(args: argparse.Namespace, env: Dict[str, Any]) -> str:
    if args.install_command:
        return args.install_command
    for key in ["install", "install_repo_command"]:
        if isinstance(env.get(key), str) and env.get(key):
            return str(env[key])
    return "python -m pip install --no-deps --no-build-isolation -e ."


def get_docker_image(args: argparse.Namespace, env: Dict[str, Any]) -> str:
    return args.docker_image or str(env.get("docker_image") or "")


# -----------------------------------------------------------------------------
# Repo operations
# -----------------------------------------------------------------------------


def copy_snapshot(snapshot: Path, dst: Path) -> Path:
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(
        snapshot,
        dst,
        ignore=shutil.ignore_patterns(
            ".git", ".mypy_cache", ".pytest_cache", "__pycache__", ".tox", ".venv",
            "venv", "build", "dist", "*.egg-info",
        ),
    )
    return dst


def compare_files_between_repos(left_repo: Path, right_repo: Path, files: List[str]) -> Tuple[bool, List[str]]:
    mismatched: List[str] = []
    for rel in files:
        left = left_repo / rel
        right = right_repo / rel
        if not left.exists() or not right.exists() or sha256_file(left) != sha256_file(right):
            mismatched.append(rel)
    return len(mismatched) == 0, mismatched


def files_differ_between_repos(left_repo: Path, right_repo: Path, files: List[str]) -> List[str]:
    different: List[str] = []
    for rel in files:
        left = left_repo / rel
        right = right_repo / rel
        if not left.exists() or not right.exists() or sha256_file(left) != sha256_file(right):
            different.append(rel)
    return different


def apply_patch(
    repo: Path,
    patch_path: Path,
    *,
    reverse: bool,
    log_path: Path,
    timeout: int,
) -> Tuple[bool, str]:
    repo = repo.resolve()
    patch_path = patch_path.resolve()

    ensure_local_git_repo(repo)

    # 保险检查：确认 git 根目录就是当前临时 repo，而不是外层 benchmark repo
    rc, top, _ = run_cmd(["git", "rev-parse", "--show-toplevel"], cwd=repo, timeout=60)
    if rc != 0:
        return False, f"git repo check failed: {tail_text(top, 20)}"

    if Path(top.strip()).resolve() != repo:
        return False, (
            f"wrong git toplevel: expected {repo}, got {top.strip()}"
        )

    check_cmd = ["git", "apply", "--check"]
    if reverse:
        check_cmd.append("-R")
    check_cmd.extend(["--whitespace=nowarn", str(patch_path)])

    rc, out, _ = run_cmd(check_cmd, cwd=repo, timeout=timeout)
    write_text(log_path.with_name(log_path.stem + "_check.log"), out)

    if rc != 0:
        return False, (
            "git apply --check failed: "
            + extract_failure_reason(
                out,
                fallback=tail_text(out, 20) or "patch does not apply",
            )
        )

    apply_cmd = ["git", "apply"]
    if reverse:
        apply_cmd.append("-R")
    apply_cmd.extend(["--whitespace=nowarn", str(patch_path)])

    rc, out, _ = run_cmd(apply_cmd, cwd=repo, timeout=timeout)
    write_text(log_path, out)

    if rc != 0:
        return False, (
            "git apply failed: "
            + extract_failure_reason(
                out,
                fallback=tail_text(out, 20) or "patch does not apply",
            )
        )

    return True, "ok"


def validate_vuln_snapshot(r_vuln: Path, r_fix: Path, patch_path: Path, files: List[str], work_dir: Path, timeout: int) -> Dict[str, Any]:
    if not files:
        return make_check("vuln_snapshot", False, "no affected source files found")

    different = files_differ_between_repos(r_vuln, r_fix, files)
    if not different:
        return make_check("vuln_snapshot", False, "R_vuln and R_fix are identical on affected source files")

    reverse_repo = copy_snapshot(r_fix, work_dir / "repos" / "R_fix_minus_gold")
    ok, reason = apply_patch(
        reverse_repo,
        patch_path,
        reverse=True,
        log_path=work_dir / "logs" / "reverse_patch_apply.log",
        timeout=timeout,
    )
    if not ok:
        return make_check("vuln_snapshot", False, f"reverse gold_patch cannot be applied to R_fix: {reason}")

    same, mismatched = compare_files_between_repos(reverse_repo, r_vuln, files)
    if not same:
        return make_check(
            "vuln_snapshot",
            False,
            "R_fix - gold_patch does not match R_vuln; mismatched files: " + ", ".join(mismatched[:20]),
        )

    return make_check("vuln_snapshot", True, "R_fix - gold_patch matches R_vuln")


def validate_gold_patch(r_vuln: Path, r_fix: Path, patch_path: Path, files: List[str], work_dir: Path, timeout: int) -> Tuple[Dict[str, Any], Dict[str, Any], Path]:
    gold_repo = copy_snapshot(r_vuln, work_dir / "repos" / "R_vuln_plus_gold")

    ok, reason = apply_patch(
        gold_repo,
        patch_path,
        reverse=False,
        log_path=work_dir / "logs" / "gold_patch_apply.log",
        timeout=timeout,
    )
    if not ok:
        return (
            make_check("gold_patch_apply", False, reason),
            make_check("gold_patch_matches_fix", False, "skipped because gold_patch could not be applied"),
            gold_repo,
        )

    apply_check = make_check("gold_patch_apply", True, "gold_patch applies cleanly to R_vuln")

    if not files:
        match_check = make_check("gold_patch_matches_fix", False, "no files available for comparison")
    else:
        same, mismatched = compare_files_between_repos(gold_repo, r_fix, files)
        if same:
            match_check = make_check("gold_patch_matches_fix", True, "R_vuln + gold_patch matches R_fix")
        else:
            match_check = make_check(
                "gold_patch_matches_fix",
                False,
                "R_vuln + gold_patch does not match R_fix; mismatched files: " + ", ".join(mismatched[:20]),
            )

    return apply_check, match_check, gold_repo


# -----------------------------------------------------------------------------
# Dynamic tests
# -----------------------------------------------------------------------------


def make_command_items(args: argparse.Namespace, env: Dict[str, Any]) -> List[Dict[str, str]]:
    items: List[Dict[str, str]] = []

    functional_cmd = args.functional_test_command or env.get("functional_test")
    poc_cmd = args.poc_test_command or env.get("poc_test")
    property_cmd = args.property_test_command or env.get("property_test")

    if functional_cmd:
        items.append({
            "name": "functional_test",
            "command": str(functional_cmd),
            "expect_vuln": "PASS",
            "expect_gold": "PASS",
        })

    if poc_cmd:
        items.append({
            "name": "poc_test",
            "command": str(poc_cmd),
            "expect_vuln": "FAIL",
            "expect_gold": "PASS",
        })

    if property_cmd:
        items.append({
            "name": "property_test",
            "command": str(property_cmd),
            "expect_vuln": args.property_vuln_expected.upper(),
            "expect_gold": "PASS",
        })

    return items


def normalize_command_for_local(command: str, root: Path) -> str:
    return command.replace("/bench/", str(root.resolve()) + "/")


def run_one_test(
    *,
    args: argparse.Namespace,
    root: Path,
    repo: Path,
    image: str,
    install_command: str,
    test_command: str,
    log_path: Path,
) -> Dict[str, Any]:
    log_path.parent.mkdir(parents=True, exist_ok=True)

    if args.use_docker:
        if not image:
            return {
                "actual": "FAIL",
                "returncode": -1,
                "reason": "missing docker image; provide --docker-image or environment.docker_image",
                "log": str(log_path),
            }

        shell_cmd = f"""
set -o pipefail
cd /repo
export REPO_UNDER_TEST=/repo
({install_command})
({test_command})
"""
        docker_cmd = [
            "docker", "run", "--rm",
            "-v", f"{repo}:/repo",
            "-v", f"{root}:/bench:ro",
            "-w", "/repo",
            image,
            "bash", "-lc", shell_cmd,
        ]
        rc, out, _ = run_cmd(docker_cmd, timeout=args.docker_timeout)
    else:
        local_install = normalize_command_for_local(install_command, root)
        local_test = normalize_command_for_local(test_command, root)
        shell_cmd = f"""
set -o pipefail
cd {str(repo)!r}
export REPO_UNDER_TEST={str(repo)!r}
({local_install})
({local_test})
"""
        rc, out, _ = run_shell(shell_cmd, timeout=args.install_timeout + args.command_timeout)

    write_text(log_path, out)
    actual = status_from_rc(rc)
    reason = "ok" if rc == 0 else extract_failure_reason(out, fallback=f"command exited with code {rc}")
    return {
        "actual": actual,
        "returncode": rc,
        "reason": reason,
        "log": str(log_path),
    }


def evaluate_expected(actual: str, expected: str) -> bool:
    return expected == "ANY" or actual == expected


def run_dynamic_tests(
    *,
    args: argparse.Namespace,
    root: Path,
    image: str,
    install_command: str,
    command_items: List[Dict[str, str]],
    vuln_repo: Path,
    gold_repo: Path,
    work_dir: Path,
) -> List[Dict[str, Any]]:
    if args.skip_tests:
        return [make_check("dynamic_tests", True, "skipped because --skip-tests was set")]

    if not command_items:
        return [make_check("dynamic_tests", True, "skipped because no functional/poc/property command is configured")]

    checks: List[Dict[str, Any]] = []
    for item in command_items:
        name = item["name"]
        cmd = item["command"]
        expect_vuln = item["expect_vuln"]
        expect_gold = item["expect_gold"]

        vuln = run_one_test(
            args=args,
            root=root,
            repo=vuln_repo,
            image=image,
            install_command=install_command,
            test_command=cmd,
            log_path=work_dir / "logs" / f"R_vuln__{safe_name(name)}.log",
        )
        gold = run_one_test(
            args=args,
            root=root,
            repo=gold_repo,
            image=image,
            install_command=install_command,
            test_command=cmd,
            log_path=work_dir / "logs" / f"R_vuln_plus_gold__{safe_name(name)}.log",
        )

        vuln_ok = evaluate_expected(vuln["actual"], expect_vuln)
        gold_ok = evaluate_expected(gold["actual"], expect_gold)
        success = vuln_ok and gold_ok

        if success:
            reason = f"expected behavior observed: R_vuln={vuln['actual']} expected {expect_vuln}, gold={gold['actual']} expected {expect_gold}"
        else:
            parts: List[str] = []
            if not vuln_ok:
                parts.append(
                    f"R_vuln expected {expect_vuln} but got {vuln['actual']}: {vuln['reason']}"
                )
            if not gold_ok:
                parts.append(
                    f"R_vuln+gold expected {expect_gold} but got {gold['actual']}: {gold['reason']}"
                )
            reason = "; ".join(parts)

        checks.append(make_check(
            name,
            success,
            reason,
            command=cmd,
            R_vuln={"actual": vuln["actual"], "expected": expect_vuln, "log": vuln["log"]},
            R_vuln_plus_gold={"actual": gold["actual"], "expected": expect_gold, "log": gold["log"]},
        ))

    return checks


# -----------------------------------------------------------------------------
# Batch/reporting
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
        ids.extend(
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        )
    if args.report_csv:
        path = root / args.report_csv
        if not path.exists():
            raise FileNotFoundError(f"report csv not found: {path}")
        allowed_statuses = {"constructed", "constructed_pr_range_needs_review", "skipped_existing", "ready", "selected"}
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
        raise ValueError("No instances selected. Use --instance, --instances, --instances-file, --report-csv, or --all.")

    return out


def first_failure(checks: List[Dict[str, Any]]) -> str:
    reasons = [f"{c['name']}: {c['reason']}" for c in checks if not c.get("success")]
    return " | ".join(reasons) if reasons else ""


def process_one_instance(root: Path, instance_id: str, args: argparse.Namespace) -> Dict[str, Any]:
    instance_dir = root / "candidate_instances" / instance_id
    inst_path = instance_dir / "instance.json"
    meta_path = instance_dir / "metadata.json"

    if not inst_path.exists():
        return {
            "instance_id": instance_id,
            "success": False,
            "status": "FAIL",
            "failure_reason": f"instance.json not found: {inst_path}",
            "checks": [make_check("load_instance", False, f"instance.json not found: {inst_path}")],
        }

    inst = load_json(inst_path)
    meta = load_json_if_exists(meta_path)
    env = inst.get("environment", {}) if isinstance(inst.get("environment"), dict) else {}

    r_vuln = get_snapshot_path(root, inst, "vulnerable_snapshot", "vulnerable_snapshot_path")
    r_fix = get_snapshot_path(root, inst, "fixed_snapshot", "fixed_snapshot_path")
    patch_path = get_gold_patch_path(root, inst)

    patch_text = patch_path.read_text(encoding="utf-8", errors="ignore")
    patch_source_files, patch_test_files, _ = parse_patch_files(patch_text)
    affected_source_files = get_affected_source_files(inst, meta, patch_source_files)

    if args.compare_scope == "source":
        compare_targets = affected_source_files
    else:
        compare_targets = unique_keep_order(patch_source_files + patch_test_files)

    image = get_docker_image(args, env)
    install_command = get_install_command(args, env)
    if "/opt/pysec_install.sh" in install_command:
        install_command = "python -m pip install -e ."

    work_dir = root / "analysis" / "gold_patch_validation" / instance_id
    if work_dir.exists() and not args.keep_workdir:
        shutil.rmtree(work_dir)
    (work_dir / "logs").mkdir(parents=True, exist_ok=True)
    (work_dir / "repos").mkdir(parents=True, exist_ok=True)

    vuln_repo = copy_snapshot(r_vuln, work_dir / "repos" / "R_vuln_original")

    checks: List[Dict[str, Any]] = []
    if args.skip_vuln_validation:
        checks.append(make_check("vuln_snapshot", True, "skipped because --skip-vuln-validation was set"))
    else:
        checks.append(validate_vuln_snapshot(r_vuln, r_fix, patch_path, affected_source_files, work_dir, args.patch_timeout))

    apply_check, match_check, gold_repo = validate_gold_patch(r_vuln, r_fix, patch_path, compare_targets, work_dir, args.patch_timeout)
    checks.extend([apply_check, match_check])

    if apply_check["success"]:
        command_items = make_command_items(args, env)
        checks.extend(run_dynamic_tests(
            args=args,
            root=root,
            image=image,
            install_command=install_command,
            command_items=command_items,
            vuln_repo=vuln_repo,
            gold_repo=gold_repo,
            work_dir=work_dir,
        ))
    else:
        checks.append(make_check("dynamic_tests", False, "skipped because gold_patch could not be applied"))

    success = all(c.get("success") for c in checks)
    failure_reason = first_failure(checks)

    report = {
        "instance_id": instance_id,
        "success": success,
        "status": "PASS" if success else "FAIL",
        "failure_reason": failure_reason,
        "checks": checks,
    }

    report_path = work_dir / "validation_summary.json"
    save_json(report_path, report)

    if args.write:
        meta["validation_summary"] = {
            "status": report["status"],
            "success": success,
            "failure_reason": failure_reason,
            "report": normalize_relpath(str(report_path.relative_to(root))),
        }
        save_json(meta_path, meta)

    print(f"\n[{report['status']}] {instance_id}")
    for c in checks:
        mark = "PASS" if c.get("success") else "FAIL"
        print(f"  [{mark}] {c['name']}: {c['reason']}")
    print(f"  report: {report_path}")

    return {
        "instance_id": instance_id,
        "status": report["status"],
        "success": success,
        "failure_reason": failure_reason,
        "failed_checks": ";".join(c["name"] for c in checks if not c.get("success")),
        "report_json": normalize_relpath(str(report_path.relative_to(root))),
    }


def write_csv_report(root: Path, rows: List[Dict[str, Any]]) -> None:
    out = root / "analysis" / "gold_patch_validation_report.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    fields = ["instance_id", "status", "success", "failed_checks", "failure_reason", "report_json"]
    with out.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fields})
    print(f"\n[DONE] batch report written to: {out}")


def main() -> None:
    ap = argparse.ArgumentParser()

    ap.add_argument("--root", default=".")
    ap.add_argument("--instance", default="")
    ap.add_argument("--instances", default="", help="Comma-separated instance IDs.")
    ap.add_argument("--instances-file", default="", help="Text file containing one instance ID per line.")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--report-csv", default="")

    ap.add_argument("--use-docker", action="store_true")
    ap.add_argument("--docker-image", default="")
    ap.add_argument("--install-command", default="")
    ap.add_argument("--install-timeout", type=int, default=1800)
    ap.add_argument("--command-timeout", type=int, default=600)
    ap.add_argument("--docker-timeout", type=int, default=7200)
    ap.add_argument("--patch-timeout", type=int, default=300)

    ap.add_argument("--functional-test-command", default="")
    ap.add_argument("--poc-test-command", default="")
    ap.add_argument("--property-test-command", default="")
    ap.add_argument(
        "--property-vuln-expected",
        choices=["any", "pass", "fail"],
        default="any",
        help="Expected result of property_test on R_vuln. Default: any.",
    )

    ap.add_argument("--skip-vuln-validation", action="store_true")
    ap.add_argument("--skip-tests", action="store_true")
    ap.add_argument("--compare-scope", choices=["source", "patch"], default="source")
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--keep-workdir", action="store_true")
    ap.add_argument("--stop-on-error", action="store_true")

    args = ap.parse_args()
    root = Path(args.root).resolve()
    instance_ids = discover_instance_ids(root, args)

    rows: List[Dict[str, Any]] = []
    for idx, iid in enumerate(instance_ids, start=1):
        print("=" * 80)
        print(f"[{idx}/{len(instance_ids)}] validating {iid}")
        try:
            row = process_one_instance(root, iid, args)
        except Exception as e:
            row = {
                "instance_id": iid,
                "status": "FAIL",
                "success": False,
                "failed_checks": "exception",
                "failure_reason": str(e).replace("\n", " ")[:1200],
                "report_json": "",
            }
            print(f"[FAIL] {iid}: {row['failure_reason']}")
            if args.stop_on_error:
                rows.append(row)
                write_csv_report(root, rows)
                raise
        rows.append(row)

    write_csv_report(root, rows)

    print("\n[FINAL SUMMARY]")
    print(f"processed: {len(rows)}")
    print(f"PASS: {sum(1 for r in rows if r.get('status') == 'PASS')}")
    print(f"FAIL: {sum(1 for r in rows if r.get('status') == 'FAIL')}")

    failed = [r for r in rows if r.get("status") == "FAIL"]
    if failed:
        print("\n[FAILED]")
        for r in failed:
            print(f"- {r['instance_id']}: {r['failure_reason']}")


if __name__ == "__main__":
    main()
