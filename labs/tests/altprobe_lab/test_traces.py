"""Real gateway -> Altprobe -> OpenSearch OTLP coverage (no direct OS writes)."""
import os
import time
import uuid

import pytest
import requests

BASE = os.getenv('LAB_BASE', 'http://localhost:9080')
OS = os.getenv('LAB_OS_BASE', 'http://localhost:9200')
GATEWAY = os.getenv('LAB_GATEWAY', 'apisix')
INDEX = 'otel-v1-traces*'


def eventually(fn, timeout=90):
    until = time.monotonic()+timeout
    last = None
    while time.monotonic() < until:
        last = fn()
        if last:
            return last
        time.sleep(1)
    raise AssertionError(f'Trace condition not reached: {last!r}')


def search(query):
    result = requests.post(OS+'/'+INDEX+'/_search', json={'size':100,'query':query}, timeout=15)
    result.raise_for_status()
    return result.json()['hits']['hits']


def test_otel_template_and_pipeline_installed():
    result = requests.get(OS+'/_index_template/otel_traces_template', timeout=10)
    result.raise_for_status()
    template = result.json()['index_templates'][0]['index_template']['template']
    assert template['settings']['index']['default_pipeline']=='altprobe-otel-spans'
    assert requests.get(OS+'/_ingest/pipeline/altprobe-otel-spans',timeout=10).status_code==200


def test_internal_spans_for_gateway_traffic():
    marker = uuid.uuid4().hex
    response = requests.get(BASE+'/test-api/status?trace_case='+marker,timeout=10)
    assert response.status_code==200
    docs = eventually(lambda:search({'bool':{'filter':[
        {'term':{'span.source':'internal'}}, {'wildcard':{'span.http_url':'*'+marker+'*'}}]}}))
    for hit in docs:
        doc = hit['_source']
        assert doc['@timestamp']
        span = doc['span']
        assert len(span['trace_id'])==32 and len(span['span_id'])==16
        assert span['service_name']=='altprobe'
        assert span['duration_ms']>=0
        assert doc['resourceSpans'][0]['scopeSpans'][0]['spans'][0]['spanId']==span['span_id']
        assert 'class_uid' not in doc, 'OTLP must not be represented as an OCSF finding'


@pytest.mark.skipif(GATEWAY=='openresty',reason='This OpenResty build has no native OTLP module; internal spans are tested')
def test_native_gateway_preserves_w3c_trace_and_parent_ids():
    trace_id = uuid.uuid4().hex
    parent = uuid.uuid4().hex[:16]
    response=requests.post(BASE+'/mcp',json={'jsonrpc':'2.0','id':19,'method':'ping'},
        headers={'traceparent':f'00-{trace_id}-{parent}-01'},timeout=10)
    assert response.status_code==200
    docs=eventually(lambda:search({'bool':{'filter':[
        {'term':{'span.trace_id':trace_id}},{'term':{'span.source':'gateway-native'}}]}}))
    assert any(doc['_source']['span'].get('parent_span_id')==parent for doc in docs)
    assert all(doc['_source']['span']['service_name']==GATEWAY+'-native' for doc in docs)
    for hit in docs:
        doc=hit['_source'];raw=doc['resourceSpans'][0]['scopeSpans'][0]['spans'][0]
        assert raw['traceId']==trace_id
        assert raw['spanId']==doc['span']['span_id']
        assert 'class_uid' not in doc
