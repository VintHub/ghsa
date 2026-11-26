#!/usr/bin/env python3
import json
import sys
from pathlib import Path


def iter_json_files(inputs):
    """
    Yields Path objects for JSON files from a mix of file paths and directories.
    """
    seen = set()

    for raw_path in inputs:
        path = Path(raw_path)

        if not path.exists():
            continue

        if path.is_dir():
            candidates = sorted(path.rglob("*.json"))
        else:
            candidates = [path]

        for candidate in candidates:
            if not candidate.is_file() or candidate.suffix.lower() != ".json":
                continue

            resolved = candidate.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            yield candidate


def process_advisories(inputs):
    """
    Reads JSON advisory files (from files or directories) and writes
    {ghsa_id: cve_id} mappings into <first_3_chars_of_id>/<ghsa_id>.json.
    """
    files_written = 0

    for file_path in iter_json_files(inputs):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                advisory = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(f"Error reading {file_path}: {e}")
            continue

        if not isinstance(advisory, dict):
            continue

        raw_id = advisory.get("id")
        if not isinstance(raw_id, str) or not raw_id.upper().startswith("GHSA-"):
            continue

        # Normalize GHSA prefix to uppercase while preserving the suffix case
        ghsa_id = "GHSA-" + raw_id[5:]
        id_body = ghsa_id[5:]  # e.g. "q295-vmhf-gfx2"

        if len(id_body) < 3:
            continue

        prefix_dir = id_body[:3].lower()  # e.g. "q29"

        # Extract all CVE aliases
        cve_aliases = [
            alias.strip().upper()
            for alias in advisory.get("aliases", [])
            if isinstance(alias, str) and alias.strip().upper().startswith("CVE-")
        ]

        if not cve_aliases:
            continue

        target_folder = Path(prefix_dir)
        target_folder.mkdir(parents=True, exist_ok=True)
        target_file = target_folder / f"{ghsa_id}.json"

        cve_value = cve_aliases[0] if len(cve_aliases) == 1 else cve_aliases
        mapping = {ghsa_id: cve_value}

        with open(target_file, "w", encoding="utf-8") as out_f:
            json.dump(mapping, out_f, indent=2, ensure_ascii=False)
            out_f.write("\n")

        files_written += 1

    print(f"Successfully wrote {files_written} GHSA mapping files.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 sync_advisories.py <file_or_dir> [file_or_dir ...]")
        sys.exit(1)

    process_advisories(sys.argv[1:])