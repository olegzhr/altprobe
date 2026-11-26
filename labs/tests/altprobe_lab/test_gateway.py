"""Tests for this lab's real gateway -> Altprobe -> OpenSearch pipeline."""
import json
import os
from pathlib import Path
import queue
import re
import socket
import subprocess
import tempfile
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
pytestmark = pytest.mark.skipif(not CONFIG["gateway"], reason="Set LAB_GATEWAY for a gateway lab")
BASE = os.getenv('LAB_BASE', 'http://localhost:9080')
MOCK = os.getenv('LAB_MOCK_BASE', 'http://localhost:8000')
OS = os.getenv('LAB_OS_BASE', 'http://localhost:9200')
ACTIVE = {}


def eventually(predicate, timeout=150):
    deadline = time.monotonic()+timeout
    last = None
    while time.monotonic() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(1)
    raise AssertionError(f'Condition not reached in {timeout}s; last={last!r}')


def _envoy_access_log_wait(uri, timeout=20):
    """Envoy lab writes JSON access logs to a volume; Redis is not used."""
    path = Path(tempfile.gettempdir()) / "altprobe-envoy-access.log"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        subprocess.run(
            ["docker", "cp", "lab-envoy-gateway:/var/log/envoy/access.log", str(path)],
            check=False, capture_output=True, text=True,
        )
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            lines = []
        for line in reversed(lines):
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if event.get("request_uri") != uri:
                continue
            request_body = event.get("request_body") or ""
            response_body = event.get("response_body") or ""
            try:
                request_size = int(event.get("http_content_length") or 0)
            except (TypeError, ValueError):
                request_size = 0
            try:
                response_size = int(event.get("body_bytes_sent") or 0)
            except (TypeError, ValueError):
                response_size = 0
            event["request_body_truncated"] = request_size > len(request_body.encode())
            event["response_body_truncated"] = response_size > len(response_body.encode())
            return event
        time.sleep(1)
    raise AssertionError(f"No Envoy access log event for {uri}")


@pytest.fixture
def tap():
    if CONFIG["gateway"] == "envoy":
        yield _envoy_access_log_wait
        return

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
    templates = requests.get(OS+'/_index_template',timeout=10).json()['index_templates']
    assert any('ocsf' in row['name'] for row in templates)


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




def test_06_mcp_profile_differs():
    payload={'jsonrpc':'2.0','id':1,'method':'ping'}
    response=requests.post(BASE+'/mcp',json=payload,timeout=5)
    assert response.status_code==(401 if CONFIG['mcp_protected'] else 200)
    assert requests.post(BASE+'/mcp',json=payload,headers=ACTIVE,timeout=5).json()['result']=='pong'
