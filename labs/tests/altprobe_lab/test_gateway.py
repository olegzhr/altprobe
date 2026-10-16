"""Tests for this lab's real gateway -> Redis -> Altprobe -> OpenSearch pipeline."""
import json
import os
from pathlib import Path
import queue
import re
import socket
import threading
import time
import uuid

import pytest
import requests

CONFIG = {
    "gateway": os.getenv("LAB_GATEWAY", ""),
    "profile": os.getenv("LAB_PROFILE", "demo"),
    "mcp_protected": os.getenv("LAB_PROFILE", "demo") == "cloud",
    "host_name": "altprobe-" + os.getenv("LAB_GATEWAY", "") + "-lab",
}
pytestmark = pytest.mark.skipif(CONFIG["gateway"] not in ("kong", "traefik", "higress"), reason="Select LAB_GATEWAY for the extended gateway labs")
BASE = os.getenv('LAB_BASE', 'http://localhost:9080')
MOCK = os.getenv('LAB_MOCK_BASE', 'http://localhost:8000')
OS = os.getenv('LAB_OS_BASE', 'http://localhost:9200')
OSD = os.getenv('LAB_OSD_BASE', 'http://localhost:5601')
ACTIVE = {'apikey': 'lab-policy-active-key'}


def eventually(predicate, timeout=150):
    deadline = time.monotonic()+timeout
    last = None
    while time.monotonic() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(1)
    raise AssertionError(f'Condition not reached in {timeout}s; last={last!r}')


@pytest.fixture
def tap():
    """Observe RPUSH without stealing entries from the running collector."""
    connection = socket.create_connection((os.getenv('LAB_REDIS_HOST','localhost'),int(os.getenv('LAB_REDIS_PORT','16379'))), timeout=5)
    connection.settimeout(None)
    stream = connection.makefile('rb')
    connection.sendall(b'*1\r\n$7\r\nMONITOR\r\n')
    assert stream.readline() == b'+OK\r\n'
    events = queue.Queue()
    finished = threading.Event()

    def receive():
        try:
            while not finished.is_set():
                raw = stream.readline()
                if not raw:
                    break
                if b'"rpush" "log_proxy"' not in raw.lower():
                    continue
                tokens = re.findall(r'"(?:\\.|[^"\\])*"', raw.decode('utf8'))
                try:
                    events.put(json.loads(json.loads(tokens[-1])))
                except (ValueError, IndexError):
                    continue
        except OSError:
            pass

    thread = threading.Thread(target=receive, daemon=True)
    thread.start()

    def wait(uri, timeout=20):
        deadline = time.monotonic()+timeout
        while time.monotonic()<deadline:
            try:
                event = events.get(timeout=max(.1,deadline-time.monotonic()))
            except queue.Empty:
                break
            if event.get('request_uri') == uri:
                return event
        raise AssertionError(f'No Redis gateway event for {uri}')

    yield wait
    finished.set()
    connection.shutdown(socket.SHUT_RDWR)
    thread.join(timeout=3)
    stream.close()
    connection.close()


def test_01_profile_and_services():
    assert requests.get(MOCK+'/lab/profile',timeout=5).json() == {'gateway': CONFIG['gateway'], 'profile':CONFIG['profile']}
    assert requests.get(OS+'/_cluster/health',timeout=10).json()['status'] in ('yellow','green')
    assert requests.get(OSD+'/api/status',timeout=10).status_code == 200
    templates = requests.get(OS+'/_index_template',timeout=10).json()['index_templates']
    assert any('ocsf' in row['name'] for row in templates)
    assert eventually(lambda: requests.get(OSD+'/api/saved_objects/_find',params={'type':'dashboard','per_page':100},timeout=15).json().get('total',0)>0,timeout=90), 'Dashboards were not provisioned'


def test_02_capture_and_real_ocsf_ingestion(tap):
    marker=uuid.uuid4().hex
    uri='/lab/echo?case='+marker
    payload={'marker':marker,'message':'safe body capture sample'}
    response=requests.post(BASE+uri,json=payload,headers=ACTIVE,timeout=10)
    assert response.status_code==200
    assert response.json()=={'payload':payload,'apikey_forwarded':False}
    event=tap(uri)
    assert event['host_name']==CONFIG['host_name']
    assert json.loads(event['request_body'])==payload
    assert json.loads(event['response_body'])['payload']==payload
    assert 'lab-policy-active-key' not in json.dumps(event)

    def indexed():
        result=requests.post(OS+'/ocsf-*/_search',json={'size':20,'query':{'term':{'http_request.url':uri}}},timeout=10)
        assert result.status_code in (200,404), result.text[:300]
        hits=result.json().get('hits',{}).get('hits',[])
        return [hit['_source'] for hit in hits if marker in str(hit['_source'].get('http_request',{}).get('url',''))]
    docs=eventually(indexed,timeout=60)
    assert any(doc['class_uid']==4002 and doc['http_response']['code']==200 for doc in docs)
    # No handcrafted OpenSearch document is inserted by this test.


def test_03_stream_and_capture(tap):
    uri='/lab/stream?case='+uuid.uuid4().hex
    start=time.monotonic()
    with requests.get(BASE+uri,stream=True,timeout=10) as response:
        assert response.status_code==200
        lines=response.iter_lines(chunk_size=1)
        assert next(lines)==b'data: first'
        first=time.monotonic()-start
        rest=list(lines)
        total=time.monotonic()-start
    assert b'data: [DONE]' in rest
    assert total-first>.5, 'SSE buffered until completion'
    assert '[DONE]' in tap(uri)['response_body']


def test_04_large_body_is_forwarded_but_capture_is_bounded(tap):
    uri='/lab/echo?case='+uuid.uuid4().hex
    payload={'text':'x'*16000}
    response=requests.post(BASE+uri,json=payload,timeout=15)
    assert response.status_code==200 and response.json()['payload']==payload
    event=tap(uri)
    assert event['request_body_truncated'] and event['response_body_truncated']
    assert len(event['request_body'].encode())<=5000 and len(event['response_body'].encode())<=5000


def test_05_policy_authentication_and_identity(tap):
    eventually(lambda:requests.get(BASE+'/policy-check',headers=ACTIVE,timeout=5).status_code==200)
    assert requests.get(BASE+'/policy-check',timeout=5).status_code==401
    assert requests.get(BASE+'/policy-check',headers={'apikey':'invalid'},timeout=5).status_code==401
    uri='/policy-check?case='+uuid.uuid4().hex
    spoofed={'apikey':'lab-policy-blocked-key','X-Agent-Id':'policy-active','X-Consumer-Username':'policy-active'}
    response=requests.get(BASE+uri,headers=spoofed,timeout=5)
    assert response.status_code==403, response.text
    assert tap(uri)['consumer_name']=='policy-blocked'
    assert requests.get(BASE+'/policy-check',headers={'apikey':'lab-policy-unknown-key'},timeout=5).status_code==403
    assert requests.get(BASE+'/policy-unknown',headers=ACTIVE,timeout=5).status_code==403


def test_06_mcp_profile_differs():
    payload={'jsonrpc':'2.0','id':1,'method':'ping'}
    response=requests.post(BASE+'/mcp',json=payload,timeout=5)
    assert response.status_code==(401 if CONFIG['mcp_protected'] else 200)
    assert requests.post(BASE+'/mcp',json=payload,headers=ACTIVE,timeout=5).json()['result']=='pong'


@pytest.mark.slow_policy
@pytest.mark.skipif(os.getenv("LAB_LOCAL_COLLECTOR") != "1", reason="requires local mock collector")
def test_07_real_inventory_block_unblock():
    """Exercise actual polling, not a Policy emulator or a synthetic response."""
    assert os.getenv('LAB_LOCAL_COLLECTOR')=='1', 'Mutable mock Policy test requires local collector mode'
    agent=MOCK+'/lab/policy/agents/policy-active'
    target=MOCK+'/lab/policy/targets/endpoint'
    try:
        assert requests.patch(agent,json={'blockStatus':'blocked'},timeout=5).status_code==200
        assert requests.patch(target,json={'blockStatus':'blocked'},timeout=5).status_code==200
        eventually(lambda:requests.get(BASE+'/policy-other',headers=ACTIVE,timeout=5).status_code==403)
        assert requests.get(BASE+'/policy-check',headers=ACTIVE,timeout=5).status_code==403
        # Unblock the agent; endpoint remains blocked in the next inventory snapshot.
        requests.patch(agent,json={'blockStatus':'active'},timeout=5).raise_for_status()
        eventually(lambda:requests.get(BASE+'/policy-other',headers=ACTIVE,timeout=5).status_code==200)
        assert requests.get(BASE+'/policy-check',headers=ACTIVE,timeout=5).status_code==403
    finally:
        requests.patch(agent,json={'blockStatus':'active'},timeout=5).raise_for_status()
        requests.patch(target,json={'blockStatus':'active'},timeout=5).raise_for_status()
        eventually(lambda:requests.get(BASE+'/policy-check',headers=ACTIVE,timeout=5).status_code==200)
