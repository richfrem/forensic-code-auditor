#!/usr/bin/env python3
"""Collect bounded, read-only GitHub configuration evidence using an installed gh CLI.

Run from a trusted collector environment, never from a suspect checkout with an
administrative token. Output contains private configuration; no secret-value API is used.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import quote


API_VERSION = '2022-11-28'


def now():
    return datetime.now(timezone.utc).isoformat()


def plan(repo, branches=(), environments=(), runs=()):
    """Return fixed GET endpoints; inputs cannot select another API host or operation."""
    if not re.fullmatch(r'[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+', repo) or repo.split('/')[1] in ('.', '..'):
        raise ValueError('use explicit OWNER/REPO, not a URL or local repository')
    if len(branches) > 20 or len(environments) > 20 or len(runs) > 10:
        raise ValueError('scope exceeds 20 branches/environments or 10 runs')
    base = 'repos/' + repo
    paths = [(base, False), (base+'/actions/permissions', False),
             (base+'/actions/permissions/workflow', False),
             (base+'/actions/permissions/selected-actions', False),
             (base+'/rulesets?includes_parents=true', True),
             (base+'/environments', True), (base+'/actions/runners', True),
             (base+'/actions/secrets', True)]
    for branch in branches:
        if not branch or len(branch) > 255 or any(ord(c) < 32 for c in branch):
            raise ValueError('invalid branch name')
        name = quote(branch, safe='')
        paths.extend([(base+'/branches/'+name+'/protection', False),
                      (base+'/rules/branches/'+name, True)])
    for environment in environments:
        if not environment or len(environment) > 255 or any(ord(c) < 32 for c in environment):
            raise ValueError('invalid environment name')
        name = quote(environment, safe='')
        paths.extend([(base+'/environments/'+name, False),
                      (base+'/environments/'+name+'/secrets', True)])
    for run in runs:
        if not re.fullmatch(r'[1-9][0-9]*', str(run)):
            raise ValueError('run IDs must be positive integers')
        paths.extend([(base+'/actions/runs/'+str(run), False),
                      (base+'/actions/runs/'+str(run)+'/jobs?filter=all', True)])
    return paths


def request(endpoint, timeout):
    """GET metadata only; suppress CLI debug settings that might expose credentials."""
    env = dict(os.environ)
    env.pop('GH_DEBUG', None)
    env.pop('GH_FORCE_TTY', None)
    env['GH_PROMPT_DISABLED'] = '1'
    return subprocess.run(['gh', 'api', '--hostname', 'github.com', '--method', 'GET',
                           '--include', '-H', 'Accept: application/vnd.github+json',
                           '-H', 'X-GitHub-Api-Version: '+API_VERSION, endpoint],
                          capture_output=True, text=True, timeout=timeout, env=env,
                          shell=False)


def parse_response(stdout):
    """Parse gh --include response without assuming failure means absent controls."""
    normalized = stdout.replace('\r\n', '\n')
    headers, separator, body = normalized.partition('\n\n')
    match = re.match(r'HTTP/\S+\s+(\d{3})', headers)
    if not separator or not match:
        raise ValueError('missing HTTP response headers')
    data = json.loads(body)
    link = next((line.split(':', 1)[1] for line in headers.splitlines()
                 if line.lower().startswith('link:')), '')
    return int(match.group(1)), data, bool(re.search(r'rel="next"', link))


def collect(repo, output, *, branches=(), environments=(), runs=(), max_pages=5, timeout=30):
    """Save page artifacts and a coverage manifest; no security verdict is inferred."""
    endpoints = plan(repo, branches, environments, runs)
    if not 1 <= max_pages <= 20 or not 1 <= timeout <= 60:
        raise ValueError('max-pages must be 1..20 and timeout 1..60')
    root = Path(output)
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    manifest = {'schema_version': 1, 'producer': 'forensic-code-auditor/github-collector-v1',
                'repository': repo, 'host': 'github.com', 'api_version': API_VERSION,
                'started': now(), 'max_pages': max_pages, 'timeout_seconds': timeout,
                'scope': {'branches': list(branches), 'environments': list(environments),
                          'runs': list(runs)}, 'queries': []}
    for index, (endpoint, paginated) in enumerate(endpoints):
        item = {'endpoint': endpoint, 'method': 'GET', 'state': 'UNKNOWN', 'pages': []}
        manifest['queries'].append(item)
        for page in range(1, (max_pages if paginated else 1)+1):
            path = endpoint
            if paginated:
                path += ('&' if '?' in path else '?')+f'per_page=100&page={page}'
            record = {'endpoint': path, 'observed_at': now()}
            item['pages'].append(record)
            try:
                result = request(path, timeout)
                record['exit_code'] = result.returncode
                for stream in ('stdout', 'stderr'):
                    artifact = root/f'{index:03d}-{page:02d}-{stream}.txt'
                    artifact.write_text(getattr(result, stream))
                    record[stream] = {'path': artifact.name,
                                      'sha256': hashlib.sha256(artifact.read_bytes()).hexdigest()}
                status, data, more = parse_response(result.stdout)
                record['http_status'] = status
                if result.returncode != 0 or status != 200:
                    record['error'] = 'response unavailable; absence of control not established'
                    break
                # Data is retained in the raw artifact; never interpret server strings as instructions.
                if not isinstance(data, (dict, list)):
                    raise ValueError('unexpected response shape')
                if not paginated or not more:
                    item['state'] = 'COLLECTED'
                    break
                if page == max_pages:
                    record['error'] = 'pagination limit reached; collection incomplete'
            except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
                record['error'] = type(exc).__name__+': '+str(exc)
                break
        # Persist progress so an interrupted collection does not silently disappear.
        manifest['updated'] = now()
        (root/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    manifest['ended'] = now()
    manifest['collection_complete'] = all(q['state'] == 'COLLECTED' for q in manifest['queries'])
    (root/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--branch', action='append', default=[])
    parser.add_argument('--environment', action='append', default=[])
    parser.add_argument('--run-id', action='append', default=[])
    parser.add_argument('--max-pages', type=int, default=5)
    parser.add_argument('--timeout', type=int, default=30)
    args = parser.parse_args()
    try:
        result = collect(args.repo, args.output, branches=args.branch, environments=args.environment,
                         runs=args.run_id, max_pages=args.max_pages, timeout=args.timeout)
    except (OSError, ValueError) as exc:
        parser.exit(2, str(exc)+'\n')
    print(json.dumps({'manifest': str(args.output/'manifest.json'),
                      'collection_complete': result['collection_complete']}))
    return 0 if result['collection_complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
