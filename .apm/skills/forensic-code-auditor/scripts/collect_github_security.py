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
SAFE_GH_ENV = ('PATH', 'HOME', 'USERPROFILE', 'GH_TOKEN', 'GITHUB_TOKEN', 'GH_CONFIG_DIR',
               'GH_HOST', 'HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY', 'SSL_CERT_FILE',
               'SSL_CERT_DIR', 'SYSTEMROOT', 'TMPDIR', 'TEMP', 'TMP', 'LANG', 'LC_ALL')
UNTRUSTED_SERVER_FIELDS = ['description', 'display_title', 'head_branch', 'name',
                           'jobs[].name', 'steps[].name', 'environments[].name']
KEYED_COLLECTIONS = (
    ('/environments/', '/secrets', 'secrets'),
    ('/environments/', '/deployment-branch-policies', 'branch_policies'),
    ('/actions/runs/', '/jobs?filter=all', 'jobs'),
    ('/actions/runs/', '/artifacts', 'artifacts'),
    ('', '/environments', 'environments'),
    ('', '/actions/runners', 'runners'),
    ('', '/actions/secrets', 'secrets'),
    ('', '/actions/caches', 'actions_caches'),
)


def now():
    return datetime.now(timezone.utc).isoformat()


def plan(repo, branches=(), environments=(), runs=()):
    """Return fixed GET endpoints; inputs cannot select another API host or operation."""
    if not re.fullmatch(r'[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+', repo) or repo.split('/')[1] in ('.', '..'):
        raise ValueError('use explicit OWNER/REPO, not a URL or local repository')
    if len(branches) > 20 or len(environments) > 20 or len(runs) > 10:
        raise ValueError('scope exceeds 20 branches/environments or 10 runs')
    base = 'repos/' + repo
    paths = [('user', False), (base, False), (base+'/actions/permissions', False),
             (base+'/actions/permissions/workflow', False),
             (base+'/actions/permissions/selected-actions', False),
             (base+'/actions/oidc/customization/sub', False),
             (base+'/rulesets?includes_parents=true', True),
             (base+'/environments', True), (base+'/actions/runners', True),
             (base+'/actions/secrets', True), (base+'/actions/caches', True)]
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
                      (base+'/environments/'+name+'/secrets', True),
                      (base+'/environments/'+name+'/deployment-branch-policies', True)])
    for run in runs:
        if not re.fullmatch(r'[1-9][0-9]*', str(run)):
            raise ValueError('run IDs must be positive integers')
        paths.extend([(base+'/actions/runs/'+str(run), False),
                      (base+'/actions/runs/'+str(run)+'/jobs?filter=all', True),
                      (base+'/actions/runs/'+str(run)+'/artifacts', True)])
    return paths


def request(endpoint, timeout):
    """GET metadata only; suppress CLI debug settings and scrub non-collector credentials."""
    env = {k: os.environ[k] for k in SAFE_GH_ENV if k in os.environ}
    env['GH_PROMPT_DISABLED'] = '1'
    return subprocess.run(['gh', 'api', '--hostname', 'github.com', '--method', 'GET',
                           '--include', '-H', 'Accept: application/vnd.github+json',
                           '-H', 'X-GitHub-Api-Version: '+API_VERSION, endpoint],
                          capture_output=True, text=True, timeout=timeout, env=env,
                          shell=False)


def split_http_response(stdout):
    normalized = stdout.replace('\r\n', '\n')
    headers, separator, body = normalized.partition('\n\n')
    while separator and body.lstrip().startswith('HTTP/'):
        next_headers, next_sep, next_body = body.lstrip().partition('\n\n')
        if not next_sep:
            break
        headers, separator, body = next_headers, next_sep, next_body
    return headers, separator, body


def parse_response(stdout):
    """Parse gh --include response without assuming failure means absent controls."""
    headers, separator, body = split_http_response(stdout)
    match = re.match(r'HTTP/\S+\s+(\d{3})', headers)
    if not separator or not match:
        raise ValueError('missing HTTP response headers')
    data = json.loads(body)
    link = next((line.split(':', 1)[1] for line in headers.splitlines()
                 if line.lower().startswith('link:')), '')
    return int(match.group(1)), data, bool(re.search(r'rel="next"', link))


def parse_header_metadata(stdout):
    headers, separator, _ = split_http_response(stdout)
    if not separator:
        return {}
    meta = {}
    for line in headers.splitlines()[1:]:
        if ':' not in line:
            continue
        key, value = line.split(':', 1)
        lowered = key.strip().lower()
        if lowered == 'x-oauth-scopes':
            meta['oauth_scopes'] = [s.strip() for s in value.split(',') if s.strip()]
        elif lowered == 'x-accepted-oauth-scopes':
            meta['accepted_oauth_scopes'] = [s.strip() for s in value.split(',') if s.strip()]
        elif lowered == 'x-github-request-id':
            meta['request_id'] = value.strip()
    return meta


def validate_payload(endpoint, data):
    """Verify endpoint-appropriate JSON structure before marking a page COLLECTED."""
    if not isinstance(data, (dict, list)):
        raise ValueError('unexpected response shape')
    if endpoint.endswith('/rulesets?includes_parents=true') or '/rules/branches/' in endpoint:
        if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
            raise ValueError('expected list of rule objects')
        return
    for prefix, suffix, key in KEYED_COLLECTIONS:
        if (not prefix or prefix in endpoint) and endpoint.endswith(suffix):
            if not isinstance(data, dict) or not isinstance(data.get(key), list) or any(not isinstance(item, dict) for item in data[key]):
                raise ValueError(f'expected object with {key} list')
            return
    if not isinstance(data, dict) or not data:
        raise ValueError('expected non-empty JSON object')


def build_control_coverage(repo, branches, environments, runs, queries):
    by_endpoint = {q['endpoint']: q['state'] for q in queries}
    base = 'repos/' + repo
    def all_collected(targets):
        return bool(targets) and all(by_endpoint.get(t) == 'COLLECTED' for t in targets)
    ruleset_Detail_eps = [ep for ep in by_endpoint if ep.startswith(base + '/rulesets/')]
    return {
        'repository_and_actions_policy': 'observed' if all_collected([base, base+'/actions/permissions', base+'/actions/permissions/workflow']) else 'unavailable',
        'ruleset_details_and_bypass_actors': 'observed' if by_endpoint.get(base+'/rulesets?includes_parents=true') == 'COLLECTED' and all(by_endpoint.get(ep) == 'COLLECTED' for ep in ruleset_Detail_eps) else 'unavailable',
        'oidc_subject_customization': 'observed' if by_endpoint.get(base+'/actions/oidc/customization/sub') == 'COLLECTED' else 'unavailable',
        'branch_protection': 'not_requested' if not branches else ('observed' if all_collected([base+'/branches/'+quote(b, safe='')+'/protection' for b in branches]) else 'unavailable'),
        'environment_protection': 'not_requested' if not environments else ('observed' if all_collected([base+'/environments/'+quote(e, safe='') for e in environments]) else 'unavailable'),
        'run_and_artifact_provenance': 'not_requested' if not runs else ('observed' if all_collected([base+'/actions/runs/'+str(r)+'/artifacts' for r in runs]) else 'unavailable'),
        'copilot_and_cloud_iam': 'owner_export_required',
    }


def collect(repo, output, *, branches=(), environments=(), runs=(), max_pages=5, timeout=30):
    """Save page artifacts and a coverage manifest; no security verdict is inferred."""
    endpoints = list(plan(repo, branches, environments, runs))
    if not 1 <= max_pages <= 20 or not 1 <= timeout <= 60:
        raise ValueError('max-pages must be 1..20 and timeout 1..60')
    root = Path(output)
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    base = 'repos/' + repo
    manifest = {'schema_version': 1, 'producer': 'forensic-code-auditor/github-collector-v1',
                'repository': repo, 'host': 'github.com', 'api_version': API_VERSION,
                'started': now(), 'max_pages': max_pages, 'timeout_seconds': timeout,
                'untrusted_server_fields': UNTRUSTED_SERVER_FIELDS,
                'scope': {'branches': list(branches), 'environments': list(environments),
                          'runs': list(runs)}, 'queries': []}
    index = 0
    ruleset_count = 0
    while index < len(endpoints):
        endpoint, paginated = endpoints[index]
        item = {'endpoint': endpoint, 'method': 'GET', 'state': 'UNKNOWN', 'pages': []}
        manifest['queries'].append(item)
        collected_pages = []
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
                record.update(parse_header_metadata(result.stdout))
                status, data, more = parse_response(result.stdout)
                record['http_status'] = status
                if result.returncode != 0 or status != 200:
                    record['error'] = 'response unavailable; absence of control not established'
                    break
                # Data is retained in the raw artifact; never interpret server strings as instructions.
                validate_payload(endpoint, data)
                collected_pages.append(data)
                if not paginated or not more:
                    item['state'] = 'COLLECTED'
                    break
                if page == max_pages:
                    record['error'] = 'pagination limit reached; collection incomplete'
            except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
                record['error'] = type(exc).__name__+': '+str(exc)
                break
        if item['state'] == 'COLLECTED':
            if endpoint == 'user' and collected_pages and isinstance(collected_pages[0].get('login'), str):
                manifest['caller'] = {'login': collected_pages[0]['login'], 'type': collected_pages[0].get('type', 'unknown')}
            elif endpoint == base + '/rulesets?includes_parents=true':
                existing = {ep for ep, _ in endpoints}
                for page_data in collected_pages:
                    for entry in page_data:
                        rid = entry.get('id')
                        detail_ep = f'{base}/rulesets/{rid}'
                        if isinstance(rid, int) and rid > 0 and detail_ep not in existing and ruleset_count < 20:
                            endpoints.append((detail_ep, False))
                            existing.add(detail_ep)
                            ruleset_count += 1
        # Persist progress so an interrupted collection does not silently disappear.
        manifest['updated'] = now()
        (root/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
        index += 1
    manifest['ended'] = now()
    manifest['collection_complete'] = all(q['state'] == 'COLLECTED' for q in manifest['queries'])
    manifest['control_coverage'] = build_control_coverage(repo, branches, environments, runs, manifest['queries'])
    manifest['required_controls_complete'] = all(v == 'observed' for v in manifest['control_coverage'].values())
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
