#!/usr/bin/env python3
import argparse
import csv
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional


def run(cmd: List[str], cwd: Optional[Path] = None, timeout: int = 3600):
    try:
        p = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired as e:
        return 124, f"[TIMEOUT] {' '.join(cmd)}\n{e}"


def mkdir(path: Path):
    path.mkdir(parents=True, exist_ok=True)


def safe_image_part(name: str) -> str:
    name = name.lower().strip()
    name = re.sub(r"[^a-z0-9_.-]+", "-", name)
    name = name.strip(".-")
    return name or "unknown"


def docker_image_exists(image: str) -> bool:
    rc, _ = run(["docker", "image", "inspect", image], timeout=60)
    return rc == 0


def read_env_conf(env_dir: Path) -> Dict[str, str]:
    """Read key=value pairs from env.conf if present."""
    conf = {}
    conf_file = env_dir / "env.conf"
    if not conf_file.exists():
        return conf
    for line in conf_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        conf[key.strip()] = val.strip().strip("\"'")
    return conf


def find_env_dirs(env_root: Path, env_name: Optional[str] = None) -> List[Path]:
    """Discover environment directories.

    If *env_name* is given, return only that matching subdirectory.
    """
    if not env_root.exists():
        raise FileNotFoundError(f"environments directory not found: {env_root}")

    # Single named environment
    if env_name:
        env_dir = env_root / env_name
        if not env_dir.is_dir():
            raise FileNotFoundError(f"environment directory not found: {env_dir}")
        if not (env_dir / "Dockerfile").exists():
            raise FileNotFoundError(f"Dockerfile not found in: {env_dir}")
        return [env_dir]

    # All subdirectories that contain a Dockerfile
    env_dirs = []
    for p in sorted(env_root.iterdir()):
        if p.is_dir() and (p / "Dockerfile").exists():
            env_dirs.append(p)
    return env_dirs


def build_one(
    env_dir: Path,
    image_prefix: str,
    no_cache: bool,
    skip_existing: bool,
    log_dir: Path,
) -> Dict:
    env_name = env_dir.name
    image = f"{image_prefix}{safe_image_part(env_name)}:latest"
    dockerfile = env_dir / "Dockerfile"

    row = {
        "environment": env_name,
        "dockerfile": str(dockerfile),
        "image": image,
        "status": "",
        "reason": "",
        "log": "",
    }

    log_path = log_dir / f"{safe_image_part(env_name)}.log"
    row["log"] = str(log_path)

    if skip_existing and docker_image_exists(image):
        row["status"] = "skipped_existing"
        row["reason"] = "image already exists"
        log_path.write_text(f"[SKIP] {image} already exists\n", encoding="utf-8")
        return row

    # Build --build-arg flags from env.conf
    conf = read_env_conf(env_dir)
    build_args: List[str] = []
    for key, val in conf.items():
        build_args.extend(["--build-arg", f"{key}={val}"])

    cmd = [
        "docker",
        "build",
        "-t",
        image,
        "-f",
        str(dockerfile),
    ]
    # --no-cache goes right after docker build
    if no_cache:
        cmd.insert(2, "--no-cache")
    # insert build-args before the context path
    cmd.extend(build_args)
    cmd.append(str(env_dir))

    print(f"[BUILD] {env_name}")
    print(f"        image: {image}")
    for key, val in conf.items():
        print(f"        build-arg: {key}={val}")

    rc, out = run(cmd, cwd=env_dir, timeout=3600)
    log_path.write_text(out, encoding="utf-8", errors="ignore")

    if rc == 0:
        row["status"] = "built"
        row["reason"] = "ok"
        print(f"[OK] {image}")
    else:
        row["status"] = "failed"
        row["reason"] = f"docker build failed with exit code {rc}"
        print(f"[FAILED] {image}")
        print(f"         log: {log_path}")

    return row


def write_report(report_path: Path, rows: List[Dict]):
    mkdir(report_path.parent)

    fieldnames = [
        "environment",
        "dockerfile",
        "image",
        "status",
        "reason",
        "log",
    ]

    with report_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".", help="Benchmark root directory")
    parser.add_argument("--env-dir", default="environments", help="Directory containing Dockerfile folders")
    parser.add_argument("--env-name", default="", help="Build only this one environment (subdirectory name)")
    parser.add_argument("--image-prefix", default="pysec-env-", help="Docker image name prefix")
    parser.add_argument("--skip-existing", action="store_true", help="Skip if docker image already exists")
    parser.add_argument("--no-cache", action="store_true", help="Build without docker cache")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    env_root = root / args.env_dir
    log_dir = root / "analysis" / "docker_build_logs"
    report_path = root / "analysis" / "docker_build_report.csv"

    mkdir(log_dir)

    env_dirs = find_env_dirs(env_root, env_name=args.env_name or None)

    if not env_dirs:
        print(f"[ERROR] no Dockerfile found under: {env_root}")
        return

    print(f"[INFO] found {len(env_dirs)} Dockerfile(s)")

    rows = []
    for i, env_dir in enumerate(env_dirs, start=1):
        print("=" * 80)
        print(f"[{i}/{len(env_dirs)}] {env_dir.name}")

        row = build_one(
            env_dir=env_dir,
            image_prefix=args.image_prefix,
            no_cache=args.no_cache,
            skip_existing=args.skip_existing,
            log_dir=log_dir,
        )
        rows.append(row)

    write_report(report_path, rows)

    print("=" * 80)
    print(f"[DONE] report written to: {report_path}")

    built = sum(1 for r in rows if r["status"] == "built")
    skipped = sum(1 for r in rows if r["status"] == "skipped_existing")
    failed = sum(1 for r in rows if r["status"] == "failed")

    print(f"[SUMMARY] built: {built}")
    print(f"[SUMMARY] skipped_existing: {skipped}")
    print(f"[SUMMARY] failed: {failed}")


if __name__ == "__main__":
    main()
