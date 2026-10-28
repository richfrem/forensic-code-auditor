"""Resolve bounded evidence locators. Availability/integrity is not semantic proof."""
import csv
import hashlib
import json
from pathlib import Path, PurePosixPath


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def reference(path, root, **locator):
    path, root = Path(path).resolve(), Path(root).resolve()
    return dict(path=path.relative_to(root).as_posix(), sha256=sha256(path), **locator)


def resolve(ref, root):
    raw = ref['path']
    if not isinstance(raw, str) or '\\' in raw or ':' in raw or not raw or PurePosixPath(raw).is_absolute() or any(p in ('..','.') for p in raw.split('/')):
        raise ValueError('unsafe evidence path')
    root = Path(root).resolve(); path = (root / raw).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError('evidence missing or escapes root: ' + raw)
    if sha256(path) != ref['sha256']:
        raise ValueError('evidence hash mismatch: ' + raw)
    if 'end_line' in ref and 'line' not in ref: raise ValueError('end_line requires line')
    if 'line' in ref:
        lines = path.read_text().splitlines()
        if not 1 <= ref['line'] <= ref.get('end_line',ref['line']) <= len(lines):
            raise ValueError('evidence line out of range: ' + raw)
    if 'row_key' in ref:
        if path.suffix == '.csv':
            with path.open(newline='') as stream: data = list(csv.DictReader(stream))
        elif path.suffix == '.json': data = json.loads(path.read_text())
        else: raise ValueError('row_key requires CSV/JSON')
        def keys(value):
            if isinstance(value,dict):
                for key in ('id','row_key','key'):
                    if key in value: yield str(value[key])
                for child in value.values(): yield from keys(child)
            elif isinstance(value,list):
                for child in value: yield from keys(child)
        if list(keys(data)).count(ref['row_key']) != 1:
            raise ValueError('evidence row missing or ambiguous: ' + ref['row_key'])
    return path


def all_references(value):
    if isinstance(value,dict):
        if 'path' in value and 'sha256' in value: yield value
        for item in value.values(): yield from all_references(item)
    elif isinstance(value,list):
        for item in value: yield from all_references(item)
