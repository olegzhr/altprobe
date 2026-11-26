"""Verify vendored shared source without a sibling checkout or network access."""
import argparse
import hashlib
import json
from pathlib import Path


def hashes(directory):
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in directory.iterdir()
            if path.is_file() and path.name != "SOURCES.json"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--peer", type=Path, help="Optional other repository's src/shared")
    args = parser.parse_args()
    shared = Path(__file__).resolve().parents[1] / "shared"
    expected = json.loads((shared / "SOURCES.json").read_text(encoding="utf-8"))["files"]
    actual = hashes(shared)
    if actual != expected:
        raise SystemExit("Shared source differs from its checked-in manifest")
    if args.peer and hashes(args.peer.resolve()) != actual:
        raise SystemExit("Shared source differs between repositories")
    print(f"Shared source verified: {len(actual)} files")


if __name__ == "__main__":
    main()
