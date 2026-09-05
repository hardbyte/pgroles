#!/usr/bin/env python3
"""Sample real pod health requests during a rollout; includes API proxy overhead."""
import argparse
import json
import math
from pathlib import Path
import subprocess
import time


def run(command, timeout=5):
    return subprocess.run(command, capture_output=True, timeout=timeout, check=False)


def sample(namespace, excluded_uid, output, stop):
    with output.open('w', buffering=1) as stream:
        while not stop.exists():
            try:
                result = run(['kubectl', '-n', namespace, 'get', 'pods', '-l',
                              'app.kubernetes.io/name=pgroles-operator', '-o', 'json'])
                pods = json.loads(result.stdout).get('items', [])
                for pod in pods:
                    metadata = pod['metadata']
                    if (metadata['uid'] == excluded_uid or metadata.get('deletionTimestamp')
                            or pod.get('status', {}).get('phase') != 'Running'):
                        continue
                    for endpoint in ['livez', 'readyz']:
                        started = time.monotonic()
                        try:
                            response = run(['kubectl', '--request-timeout=2s', 'get', '--raw',
                                            f"/api/v1/namespaces/{namespace}/pods/{metadata['name']}:8080/proxy/{endpoint}"], timeout=3)
                            ok = response.returncode == 0
                        except subprocess.TimeoutExpired:
                            ok = False
                        stream.write(json.dumps({'uid': metadata['uid'], 'endpoint': endpoint,
                                                 'ok': ok, 'ms': (time.monotonic() - started) * 1000}) + '\n')
            except (subprocess.TimeoutExpired, ValueError, KeyError):
                # Pod discovery is not an HTTP health sample. The checker
                # requires samples for both endpoints, so an unavailable API
                # cannot turn an unobserved run into a pass.
                pass
            time.sleep(1)


def check(path, max_ms):
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    if len({row['uid'] for row in rows}) != 1:
        raise SystemExit('expected probes from exactly one new pod')
    for endpoint in ['livez', 'readyz']:
        samples = [row for row in rows if row['endpoint'] == endpoint]
        # Exclude startup before the endpoint first begins listening. Every
        # subsequent failure counts, even if readiness later becomes false.
        first = next((i for i, row in enumerate(samples) if row['ok']), len(samples))
        samples = samples[first:]
        if len(samples) < 3:
            raise SystemExit(f'{endpoint}: fewer than three post-startup samples')
        durations = sorted(row['ms'] for row in samples)
        failures = sum(not row['ok'] for row in samples)
        p95 = durations[math.ceil(len(durations) * .95) - 1]
        print(f'{endpoint}: samples={len(samples)} failures={failures} p95={p95:.1f}ms max={durations[-1]:.1f}ms (includes API proxy overhead)')
        if failures or durations[-1] >= max_ms:
            raise SystemExit(f'{endpoint}: exceeded the {max_ms:g}ms probe budget')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--namespace', default='pgroles-system')
    parser.add_argument('--exclude-uid')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--stop', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--max-ms', type=float, default=2000)
    args = parser.parse_args()
    if args.check:
        check(args.output, args.max_ms)
    elif args.stop is None or args.exclude_uid is None:
        parser.error('sampling requires --stop and --exclude-uid')
    else:
        sample(args.namespace, args.exclude_uid, args.output, args.stop)
