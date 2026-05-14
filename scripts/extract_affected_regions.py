#!/usr/bin/env python3
"""
Extract line-level vulnerability regions from gold patches.

For each instance, parse the gold unified diff and extract the deleted line
ranges within affected_source_files. These are the candidate vulnerable lines.

Output: writes affected_regions into each instance's metadata.json, and prints
a summary of what would change per instance (dry-run by default).
"""

import json
import os
import re
import sys

BENCH_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTANCES_DIR = os.path.join(BENCH_DIR, "candidate_instances")
PATCHES_DIR = os.path.join(BENCH_DIR, "gold_patches")

# Match hunk header: @@ -old_start,old_count +new_start,new_count @@
HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

# Match git diff file header: diff --git a/path b/path
FILE_RE = re.compile(r"^diff --git a/(.*?) b/(.*?)$")


def parse_unified_diff(patch_text: str) -> list[dict]:
    """
    Parse a unified diff into a list of per-file changes.

    Returns list of dicts:
        {"file": "path/to/file", "is_new": bool, "is_deleted": bool,
         "hunks": [{"old_start": int, "new_start": int,
                    "deleted_lines": [int], "added_lines": [int]}]}
    """
    files = []
    current_file = None
    current_hunk = None
    old_lineno = 0
    new_lineno = 0
    in_file_header = False

    for line in patch_text.split("\n"):
        # File header
        m = FILE_RE.match(line)
        if m:
            if current_hunk and current_file:
                current_file["hunks"].append(current_hunk)
                current_hunk = None
            if current_file:
                files.append(current_file)
            current_file = {"file": m.group(1), "hunks": [], "is_new": False, "is_deleted": False}
            in_file_header = True
            continue

        # Detect new file / deleted file markers
        if in_file_header:
            if line.startswith("new file mode"):
                current_file["is_new"] = True
            elif line.startswith("deleted file mode"):
                current_file["is_deleted"] = True
            elif line.startswith("@@") or line.startswith("diff "):
                in_file_header = False
                # fall through to process as hunk/file header
            else:
                continue

        # Hunk header: reset line counters
        m = HUNK_RE.match(line)
        if m:
            if current_hunk and current_file:
                current_file["hunks"].append(current_hunk)
            old_start = int(m.group(1))
            new_start = int(m.group(3))
            current_hunk = {
                "old_start": old_start,
                "new_start": new_start,
                "deleted_lines": [],
                "added_lines": [],
            }
            old_lineno = old_start - 1
            new_lineno = new_start - 1
            continue

        # Skip non-diff lines (index lines, ---/+++ headers, etc.)
        if current_hunk is None:
            continue

        old_lineno += 1
        new_lineno += 1

        if line.startswith("-") and not line.startswith("---"):
            current_hunk["deleted_lines"].append(old_lineno)
            new_lineno -= 1  # old file advances, new file doesn't
        elif line.startswith("+") and not line.startswith("+++"):
            current_hunk["added_lines"].append(new_lineno)
            old_lineno -= 1  # new file advances, old file doesn't
        # Context lines: both advance naturally

    # Flush last hunk/file
    if current_hunk and current_file:
        current_file["hunks"].append(current_hunk)
    if current_file:
        files.append(current_file)

    return files


def merge_line_ranges(lines: list[int], max_gap: int = 3) -> list[str]:
    """
    Merge sorted line numbers into range strings.
    Lines within max_gap of each other are merged into one range.

    >>> merge_line_ranges([29])
    ['29']
    >>> merge_line_ranges([208, 209, 210, 211, 220, 221])
    ['208-211', '220-221']
    >>> merge_line_ranges([208, 209, 220, 221])  # gap=10 > max_gap=3
    ['208-209', '220-221']
    """
    if not lines:
        return []

    lines = sorted(set(lines))
    ranges = []
    start = lines[0]
    end = lines[0]

    for line in lines[1:]:
        if line <= end + max_gap:
            end = line
        else:
            ranges.append(f"{start}-{end}" if end > start else str(start))
            start = line
            end = line

    ranges.append(f"{start}-{end}" if end > start else str(start))
    return ranges


def is_blank_deletion(line_text: str) -> bool:
    """Check if a deletion line is effectively blank (whitespace only)."""
    return line_text.strip() == ""


def extract_regions_for_instance(instance_id: str, dry_run: bool = True) -> dict | None:
    """
    Extract affected_regions for a single instance.

    Returns None if no patch exists, or a dict with the proposed regions.
    """
    # Load metadata
    meta_path = os.path.join(INSTANCES_DIR, instance_id, "metadata.json")
    with open(meta_path) as f:
        metadata = json.load(f)

    patch_path = os.path.join(PATCHES_DIR, f"{instance_id}.patch")
    if not os.path.exists(patch_path):
        print(f"  [SKIP] no patch found for {instance_id}")
        return None

    with open(patch_path) as f:
        patch_text = f.read()

    source_files = set(metadata.get("affected_source_files", []))
    if not source_files:
        print(f"  [SKIP] {instance_id}: no affected_source_files")
        return None

    # Parse diff
    parsed_files = parse_unified_diff(patch_text)

    # Build affected_regions: only for files in affected_source_files
    regions = []
    skipped_non_source = []

    for pf in parsed_files:
        filename = pf["file"]

        if filename not in source_files:
            skipped_non_source.append(filename)
            continue

        # Collect deleted lines (vulnerable code in old file)
        all_deleted = []
        for hunk in pf["hunks"]:
            all_deleted.extend(hunk["deleted_lines"])

        # Collect added lines (fix code in new file)
        all_added = []
        for hunk in pf["hunks"]:
            all_added.extend(hunk["added_lines"])

        if all_deleted:
            region = {
                "file": filename,
                "lines": ", ".join(merge_line_ranges(all_deleted)),
                "kind": "modified",
            }
        elif pf["is_new"]:
            region = {
                "file": filename,
                "lines": ", ".join(merge_line_ranges(all_added)),
                "kind": "new_file",
            }
        elif all_added:
            region = {
                "file": filename,
                "lines": ", ".join(merge_line_ranges(all_added)),
                "kind": "added",
            }
        else:
            # Deleted file or truly empty — skip
            continue

        regions.append(region)

    if not dry_run:
        metadata["affected_regions"] = regions
        with open(meta_path, "w") as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
            f.write("\n")

    return {
        "instance_id": instance_id,
        "regions": regions,
        "skipped_non_source": skipped_non_source,
        "source_files_expected": sorted(source_files),
    }


def validate(result: dict) -> list[str]:
    """Run sanity checks on extracted regions. Returns list of warnings."""
    warnings = []
    regions = result["regions"]
    expected_files = set(result["source_files_expected"])
    covered_files = {r["file"] for r in regions}

    truly_missing = expected_files - covered_files - set(result["skipped_non_source"])
    if truly_missing:
        warnings.append(f"  WARN: no region for {sorted(truly_missing)}")

    return warnings


def main():
    dry_run = "--write" not in sys.argv
    mode = "DRY-RUN (use --write to persist)" if dry_run else "WRITE MODE"

    print(f"=== Extract affected_regions ({mode}) ===\n")

    instance_ids = sorted(os.listdir(INSTANCES_DIR))
    total_regions = 0
    total_instances_with_regions = 0
    all_warnings = []

    for iid in instance_ids:
        meta_path = os.path.join(INSTANCES_DIR, iid, "metadata.json")
        if not os.path.exists(meta_path):
            continue

        result = extract_regions_for_instance(iid, dry_run=dry_run)
        if result is None:
            continue

        regions = result["regions"]
        warnings = validate(result)
        all_warnings.extend(warnings)

        # Print summary for this instance
        n_regions = len(regions)
        total_regions += n_regions
        if n_regions:
            total_instances_with_regions += 1

        print(f"{iid}: {n_regions} region(s) extracted")
        for r in regions:
            kind = r.get("kind", "?")
            print(f"    [{kind}] {r['file']}: lines {r['lines']}")

        if result["skipped_non_source"]:
            for f in result["skipped_non_source"]:
                print(f"    [non-source, skipped] {f}")

        for w in warnings:
            print(w)
        print()

    print(f"--- Summary ---")
    print(f"Total instances:         {len(instance_ids)}")
    print(f"Instances with regions:  {total_instances_with_regions}")
    print(f"Total affected regions:  {total_regions}")
    if all_warnings:
        print(f"Warnings: {len(all_warnings)}")
        for w in all_warnings:
            print(w)


if __name__ == "__main__":
    main()
