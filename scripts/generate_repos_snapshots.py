#!/usr/bin/env python3
"""
Generate repos/ and snapshots/ from candidate_instances/*/instance.json.

Reads every candidate_instances/<id>/instance.json, clones/fetches each unique
repo into repos/_cache/<owner>__<repo>, then creates per-instance source
snapshots under snapshots/<id>/R_vuln and snapshots/<id>/R_fix, and writes
gold_patches/<id>.patch.

Usage:
    python scripts/generate_repos_snapshots.py --root .               # generate missing
    python scripts/generate_repos_snapshots.py --root . --overwrite   # rebuild all
    python scripts/generate_repos_snapshots.py --root . --dry-run     # show what would be done
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def run(
    cmd: List[str],
    cwd: Optional[Path] = None,
    check: bool = False,
    timeout: int = 1800,
) -> Tuple[int, str]:
    try:
        p = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
        if check and p.returncode != 0:
            raise RuntimeError(
                f"Command failed (exit {p.returncode})\n"
                f"  CMD: {' '.join(cmd)}\n"
                f"  CWD: {cwd}\n"
                f"  OUT:\n{p.stdout}"
            )
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired as e:
        return 124, f"[TIMEOUT] {' '.join(cmd)}\n{e}"


def mkdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def repo_slug(repo_url: str) -> str:
    m = re.search(r"github\.com/([^/]+)/([^/]+)$", repo_url)
    if not m:
        raise ValueError(f"Cannot parse GitHub URL: {repo_url}")
    return f"{m.group(1)}__{m.group(2).removesuffix('.git')}"


def rev_parse(repo: Path, rev: str) -> Optional[str]:
    try:
        rc, out = run(["git", "rev-parse", "--verify", f"{rev}^{{commit}}"], cwd=repo)
        return out.strip() if rc == 0 else None
    except (OSError, FileNotFoundError):
        return None


def rev_exists(repo: Path, rev: str) -> bool:
    return rev_parse(repo, rev) is not None


# ---------------------------------------------------------------------------
# Phase 1 — repo cache
# ---------------------------------------------------------------------------

def ensure_repo_cache(repo_url: str, cache_dir: Path, overwrite: bool = False) -> Path:
    dest = cache_dir / repo_slug(repo_url)

    if overwrite and dest.exists():
        shutil.rmtree(dest)

    # Abort stalled connections in ~30 s instead of waiting for the system TCP
    # timeout (~130 s), which is painful when GitHub is unreachable.
    git_net_opts = ["-c", "http.lowSpeedLimit=1000", "-c", "http.lowSpeedTime=30"]

    if not dest.exists():
        print(f"  [CLONE] {repo_url} -> {dest}")
        rc, out = run(["git", *git_net_opts, "clone", "--bare", repo_url, str(dest)])
        if rc != 0:
            if dest.exists():
                shutil.rmtree(dest)
            raise RuntimeError(f"Failed to clone {repo_url}\n{out}")
    elif any(not (dest / d).exists() for d in ("HEAD", "objects", "refs")):
        # Cache directory exists but is not a valid git repo
        shutil.rmtree(dest)
        raise RuntimeError(f"Cache directory exists but is not a valid git repository: {dest}")
    # else: cache exists and is valid — skip fetch; commits will be fetched
    # lazily on demand in Phase 2 if missing.

    return dest


# ---------------------------------------------------------------------------
# Phase 2 — snapshots
# ---------------------------------------------------------------------------

def checkout_snapshot(cache_repo: Path, rev: str, dest: Path, overwrite: bool = False) -> None:
    if dest.exists():
        if overwrite:
            shutil.rmtree(dest)
        else:
            return  # already exists, skip

    mkdir(dest.parent)

    rc, out = run(["git", "clone", "--quiet", "--no-hardlinks", str(cache_repo), str(dest)])
    if rc != 0:
        raise RuntimeError(f"Clone failed for snapshot\n{out}")

    rc, out = run(["git", "checkout", "--quiet", "--detach", rev], cwd=dest)
    if rc != 0:
        raise RuntimeError(f"Checkout of {rev} failed in {dest}\n{out}")

    run(["git", "reset", "--hard", "--quiet"], cwd=dest, check=False)
    run(["git", "clean", "-fdx", "--quiet"], cwd=dest, check=False)


# ---------------------------------------------------------------------------
# Phase 3 — gold patches
# ---------------------------------------------------------------------------

def write_patch(cache_repo: Path, vuln_rev: str, fix_rev: str, patch_path: Path) -> None:
    mkdir(patch_path.parent)
    rc, out = run(["git", "diff", "--binary", vuln_rev, fix_rev], cwd=cache_repo)
    if rc != 0:
        raise RuntimeError(f"git diff failed for {vuln_rev}..{fix_rev}\n{out}")
    patch_path.write_text(out, encoding="utf-8")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def load_candidate_instances(root: Path) -> Dict[str, dict]:
    """Return {instance_id: instance_data} for every candidate_instances subdir."""
    candidates_dir = root / "candidate_instances"
    if not candidates_dir.is_dir():
        print(f"[ERROR] candidate_instances/ not found under {root}", file=sys.stderr)
        sys.exit(1)

    instances: Dict[str, dict] = {}
    for d in sorted(candidates_dir.iterdir()):
        if not d.is_dir():
            continue
        ij = d / "instance.json"
        if not ij.exists():
            print(f"  [WARN] {d.name}: no instance.json, skipping")
            continue
        try:
            data = json.loads(ij.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            print(f"  [WARN] {d.name}: invalid JSON ({e}), skipping")
            continue

        iid = data.get("instance_id", d.name)
        instances[iid] = data

    return instances


def main():
    parser = argparse.ArgumentParser(description="Generate repos/ and snapshots/ from candidate_instances")
    parser.add_argument("--root", default=".", help="Benchmark root directory (default: .)")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing repos / snapshots / patches")
    parser.add_argument("--skip-existing", action="store_true",
                        help="Skip instances where all outputs already exist (default unless --overwrite)")
    parser.add_argument("--no-skip", action="store_true",
                        help="Process every instance; same as --overwrite for snapshots/patches (repos are always kept)")
    parser.add_argument("--dry-run", action="store_true",
                        help="List what would be done without making changes")
    parser.add_argument("--instance", default=None,
                        help="Process only this instance ID (e.g. PYSEC-2025-17)")
    args = parser.parse_args()

    root = Path(args.root).resolve()

    instances = load_candidate_instances(root)
    if not instances:
        print("[DONE] No candidate instances found.")
        return

    if args.instance:
        if args.instance in instances:
            instances = {args.instance: instances[args.instance]}
        else:
            print(f"[ERROR] Instance {args.instance} not found in candidate_instances/", file=sys.stderr)
            sys.exit(1)

    skip = args.skip_existing and not args.overwrite and not args.no_skip

    print(f"Found {len(instances)} candidate instance(s)")
    if args.dry_run:
        print("[DRY-RUN] No changes will be made.\n")

    # -----------------------------------------------------------------------
    # Build plan: group by repo URL
    # -----------------------------------------------------------------------
    repos_needed: Dict[str, str] = {}          # repo_url -> slug
    instance_plan: List[dict] = []              # per-instance work items

    for iid, data in instances.items():
        repo_url = data.get("repo_url", "")
        vuln_commit = data.get("vulnerable_commit", "")
        fix_commit = data.get("fixed_commit", "")
        vuln_snap = data.get("vulnerable_snapshot", f"snapshots/{iid}/R_vuln")
        fix_snap = data.get("fixed_snapshot", f"snapshots/{iid}/R_fix")
        gold_patch = data.get("gold_patch", f"gold_patches/{iid}.patch")

        if not repo_url or not vuln_commit or not fix_commit:
            print(f"  [SKIP] {iid}: missing repo_url / commits in instance.json")
            continue

        slug = repo_slug(repo_url)
        repos_needed[repo_url] = slug

        # Decide whether to skip this instance
        vp = root / vuln_snap
        fp = root / fix_snap
        pp = root / gold_patch
        all_exist = vp / ".git" and (vp / ".git").is_dir() and fp / ".git" and (fp / ".git").is_dir() and pp.is_file()

        if skip and all_exist:
            print(f"  [SKIP] {iid}: all outputs exist")
            continue

        instance_plan.append({
            "instance_id": iid,
            "repo_url": repo_url,
            "slug": slug,
            "vuln_commit": vuln_commit,
            "fix_commit": fix_commit,
            "vuln_snap": vuln_snap,
            "fix_snap": fix_snap,
            "gold_patch": gold_patch,
            "vuln_path": vp,
            "fix_path": fp,
            "patch_path": pp,
        })

    print(f"Unique repos to cache: {len(repos_needed)}")
    print(f"Instances to process:  {len(instance_plan)}")
    if not instance_plan:
        print("[DONE] Nothing to do.")
        return

    # -----------------------------------------------------------------------
    # Phase 1 — ensure repo cache
    # -----------------------------------------------------------------------
    cache_dir = root / "repos" / "_cache"
    mkdir(cache_dir)

    slug_to_cache: Dict[str, Path] = {}
    for repo_url, slug in sorted(repos_needed.items()):
        dest = cache_dir / slug

        if args.dry_run:
            slug_to_cache[slug] = dest
            if not dest.exists():
                print(f"[DRY-RUN] Would clone {repo_url} -> {dest}")
            continue

        try:
            ensure_repo_cache(repo_url, cache_dir, overwrite=args.overwrite)
        except Exception as e:
            print(f"  [WARN] Failed to cache {repo_url}: {e}", file=sys.stderr)
            print(f"  [WARN] Instances depending on {slug} will be skipped")
            continue

        slug_to_cache[slug] = dest

    if args.dry_run:
        print()

    # -----------------------------------------------------------------------
    # Phase 2+3 — snapshots + gold patches
    # -----------------------------------------------------------------------
    ok = 0
    fail = 0
    for plan in instance_plan:
        iid = plan["instance_id"]
        cache_path = slug_to_cache.get(plan["slug"])
        if cache_path is None:
            print(f"  [FAIL] {iid}: repo cache not available for {plan['slug']}")
            fail += 1
            continue

        if args.dry_run:
            print(f"[DRY-RUN] {iid}")
            print(f"  R_vuln: {plan['vuln_snap']}  ({plan['vuln_commit']})")
            print(f"  R_fix:  {plan['fix_snap']}  ({plan['fix_commit']})")
            print(f"  patch:  {plan['gold_patch']}")
            ok += 1
            continue

        # Validate the cache repo is on disk (works for both bare and regular clones)
        if not cache_path.is_dir() or not ((cache_path / "HEAD").exists() or (cache_path / ".git").is_dir()):
            print(f"  [FAIL] {iid}: repo cache unavailable for {plan['slug']} "
                  f"(directory missing or empty: {cache_path})")
            fail += 1
            continue

        # Validate commits exist in the cached repo; lazy-fetch if missing.
        # Only go to the network when a needed commit is absent.
        git_net_opts = ["-c", "http.lowSpeedLimit=1000", "-c", "http.lowSpeedTime=30"]

        def ensure_commit(repo: Path, commit: str, label: str) -> Optional[str]:
            """Return the full commit hash, fetching the single ref on demand."""
            full = rev_parse(repo, commit)
            if full:
                return full
            # Commit missing — try to fetch just this one object
            print(f"  [{iid}] fetching missing {label} {commit[:8]} from origin")
            rc, _ = run(["git", *git_net_opts, "fetch", "origin", commit], cwd=repo)
            if rc == 0:
                full = rev_parse(repo, commit)
                if full:
                    return full
            print(f"  [FAIL] {iid}: {label} {commit[:8]} not found (fetch failed or commit unreachable)")
            return None

        vuln_full = ensure_commit(cache_path, plan["vuln_commit"], "vulnerable_commit")
        if not vuln_full:
            fail += 1
            continue
        fix_full = ensure_commit(cache_path, plan["fix_commit"], "fixed_commit")
        if not fix_full:
            fail += 1
            continue

        overwrite = args.overwrite or args.no_skip
        try:
            # Snapshots
            print(f"  [{iid}] R_vuln <- {plan['vuln_commit'][:8]}")
            checkout_snapshot(cache_path, plan["vuln_commit"], plan["vuln_path"], overwrite=overwrite)
            print(f"  [{iid}] R_fix  <- {plan['fix_commit'][:8]}")
            checkout_snapshot(cache_path, plan["fix_commit"], plan["fix_path"], overwrite=overwrite)

            # Gold patch
            write_patch(cache_path, plan["vuln_commit"], plan["fix_commit"], plan["patch_path"])
            print(f"  [{iid}] patch written ({plan['patch_path'].stat().st_size} bytes)")

            ok += 1
        except Exception as e:
            print(f"  [FAIL] {iid}: {e}", file=sys.stderr)
            fail += 1

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    print(f"\n[DONE] {ok} ok, {fail} failed, {len(instances) - len(instance_plan)} skipped")


if __name__ == "__main__":
    main()
