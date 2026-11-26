"""Verify OpenShell OCSF JSONL -> shipper -> Redis -> Altprobe -> OpenSearch."""
from __future__ import annotations
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

RESULTS = Path(__file__).resolve().parents[1] / 'results' / ('openshell-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
RESULTS.mkdir(parents=True, exist_ok=True)
OS = 'http://127.0.0.1:19200'
report = {'run': RESULTS.name, 'checks': []}


def check(name, detail=True):
    report['checks'].append({'name': name, 'result': detail})
    (RESULTS / 'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(name + ': PASS', flush=True)


def wait_os():
    deadline = time.time() + 180
    while time.time() < deadline:
        try:
            if requests.get(OS + '/_cluster/health', timeout=5).status_code == 200:
                return
        except Exception:
            pass
        time.sleep(4)
    raise SystemExit('OpenSearch did not become ready')


def all_docs():
    response = requests.get(OS + '/ocsf-*/_search', params={'size': 200, 'sort': 'time:desc'}, timeout=30)
    if response.status_code == 404:
        return []
    response.raise_for_status()
    return [hit.get('_source', {}) for hit in response.json().get('hits', {}).get('hits', [])]


def main():
    wait_os()
    check('OpenSearch is ready')
    docs = []
    deadline = time.time() + 120
    while time.time() < deadline:
        docs = all_docs()
        if len(docs) >= 10:
            break
        time.sleep(3)
    classes = {int(doc.get('class_uid', 0)) for doc in docs}
    required = {0, 1007, 2004, 3002, 4001, 4002, 4007, 5019, 6002, 6003}
    missing = required - classes
    assert not missing, f'OpenShell OCSF classes missing from OpenSearch: {sorted(missing)}; seen={sorted(classes)}'
    check('all OpenShell OCSF classes reached OpenSearch')

    network = [doc for doc in docs if doc.get('class_uid') == 4001]
    assert any(doc.get('action_id') == 1 for doc in network), 'allowed network event missing'
    assert any(doc.get('action_id') == 2 for doc in network), 'denied network event missing'
    check('allowed and denied OpenShell network actions are visible')

    assert any(doc.get('class_uid') == 2004 and doc.get('finding_info', {}).get('uid') == 'openshell-deny'
               for doc in docs), 'OpenShell detection finding missing'
    check('OpenShell detection finding is visible')

    report['status'] = 'PASS'
    (RESULTS / 'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print('status=PASS checks=' + str(len(report['checks'])), flush=True)


if __name__ == '__main__':
    main()
