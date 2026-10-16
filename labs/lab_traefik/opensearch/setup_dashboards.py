"""Provision lab-owned saved objects in checked batches (OpenSearch Dashboards 2.19).

Python stdlib only. Mounted as /setup/setup_dashboards.py in each complete lab.
"""
import json
import os
from pathlib import Path
import re
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent
BASE = os.getenv('OSD_URL', 'http://opensearch-dashboards:5601').rstrip('/')


def call(path, method='GET', data=None, missing_ok=False):
    raw = json.dumps(data).encode() if data is not None else None
    last = None
    for attempt in range(30):
        request = urllib.request.Request(BASE+path, data=raw, method=method,
            headers={'Content-Type':'application/json','osd-xsrf':'true'})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            if missing_ok and error.code == 404:
                return None
            if error.code not in (429, 502, 503, 504):
                raise RuntimeError(f'{method} {path}: HTTP {error.code}: {error.read(1000)!r}') from error
            last = error
        except (OSError, urllib.error.URLError) as error:
            last = error
        time.sleep(2)
    raise RuntimeError(f'{method} {path}: service unavailable: {last}')


def main():
    call('/api/status')
    # Match the same obsolete bundle IDs retired by the original APISIX script.
    original = (ROOT/'setup_dashboards.sh').read_text()
    retired = re.findall(r'^\s*"((?:dashboard|search|visualization)/[^"$]+)"', original, re.MULTILINE)
    for identifier in retired:
        call('/api/saved_objects/'+identifier, method='DELETE', missing_ok=True)
    objects = []
    for path in sorted((ROOT/'dashboards/index_patterns').glob('*.json')):
        objects.append(dict(json.loads(path.read_text()), type='index-pattern', id=path.stem))
    for path in sorted((ROOT/'dashboards/saved_objects').glob('*.json')):
        kind, identifier = path.stem.split('__', 1)
        objects.append(dict(json.loads(path.read_text()), type=kind, id=identifier))
    for offset in range(0,len(objects),20):
        batch=objects[offset:offset+20]
        result=call('/api/saved_objects/_bulk_create?overwrite=true',method='POST',data=batch)
        rows=result.get('saved_objects',[])
        if len(rows)!=len(batch) or any(row.get('error') for row in rows):
            errors=[{'type':r.get('type'),'id':r.get('id'),'error':r.get('error')} for r in rows if r.get('error')]
            raise RuntimeError(f'Saved-object batch failed: {errors}')
        expected={(row['type'],row['id']) for row in batch}
        if expected != {(row.get('type'),row.get('id')) for row in rows}:
            raise RuntimeError('Saved-object acknowledgement IDs do not match request')
        print(f'Provisioned {min(offset+20,len(objects))}/{len(objects)} saved objects',flush=True)


if __name__=='__main__':
    main()
