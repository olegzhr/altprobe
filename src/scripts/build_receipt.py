"""Record the exact source inputs and binary of a local Altprobe build."""
import hashlib
import json
from pathlib import Path
import sys


def source_digest(source: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(source.rglob('*'), key=lambda p: p.relative_to(source).as_posix()):
        if path.is_file() and '__pycache__' not in path.parts:
            digest.update(path.relative_to(source).as_posix().encode() + b'\0')
            digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


if __name__ == '__main__':
    source, binary, output = map(Path, sys.argv[1:])
    output.write_text(json.dumps({
        'schema': 1, 'version': '1.0.2', 'source_sha256': source_digest(source),
        'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
    }, indent=2) + '\n', encoding='utf-8')
