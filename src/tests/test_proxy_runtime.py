#!/usr/bin/env python3
"""Proxy Redis recovery/shutdown using isolated local wire servers only."""
import collections
import http.server
import json
import os
from pathlib import Path
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

class State:
    mode = 'normal'
    connects = 0
    disconnected = threading.Event()
    stalled = threading.Event()
    sink_stalled = threading.Event()
    sink_release = threading.Event()
    stall_sink = False
    release = threading.Event()
    pending = collections.deque()
    documents = []
    lock = threading.Lock()
KEY = 'review queue%literal'

class Redis(socketserver.StreamRequestHandler):
    def handle(self):
        with State.lock: State.connects += 1
        authenticated = selected = False
        while header := self.rfile.readline():
            args = []
            for _ in range(int(header[1:])):
                n = int(self.rfile.readline()[1:])
                args.append(self.rfile.read(n)); assert self.rfile.read(2) == b'\r\n'
            if not authenticated:
                assert args == [b'AUTH', b'reader', b'test password%literal'], args[0]
                authenticated = True
                self.wfile.write(b'+OK\r\n')
                continue
            if not selected:
                assert args == [b'SELECT', b'2'], args
                selected = True
                self.wfile.write(b'+OK\r\n')
                continue
            assert args == [b'LPOP',KEY.encode()], args
            with State.lock: mode = State.mode
            if mode == 'disconnect':
                State.disconnected.set()
                return
            if mode == 'stall':
                State.stalled.set(); State.release.wait(5)
                return
            with State.lock: payload = State.pending.popleft() if State.pending else None
            try:
                self.wfile.write(b'$-1\r\n' if payload is None else b'$%d\r\n'%len(payload)+payload+b'\r\n')
                self.wfile.flush()
            except OSError:
                return

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

class Sink(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        doc = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        with State.lock: State.documents.append(doc)
        if State.stall_sink:
            State.sink_stalled.set(); State.sink_release.wait(5)
        try:
            self.send_response(201); self.end_headers()
        except OSError:
            pass
    def log_message(self,*_): pass

def wait_for(predicate,timeout=8):
    until=time.monotonic()+timeout
    while time.monotonic()<until:
        if predicate(): return
        time.sleep(.03)
    raise AssertionError('proxy did not recover / reach expected test state')

def enqueue(marker):
    doc={'host_name':'review','remote_addr':'10.1.1.1','request_method':'GET',
         'request_uri':'/test-api/status?case='+marker,'status':200,'request_id':marker,
         'gateway_origin_id':'review-gateway','request_body':'','response_body':'ok'}
    with State.lock: State.pending.append(json.dumps(doc).encode())

def delivered(marker):
    with State.lock: return any(marker in json.dumps(doc) for doc in State.documents)

def main():
    root=Path(__file__).resolve().parents[1]
    binary=Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix='proxy-p1-') as directory, \
         Server(('127.0.0.1',0),Redis,bind_and_activate=False) as redis, \
         http.server.ThreadingHTTPServer(('127.0.0.1',0),Sink) as sink:
        # Bound but not listening: a real connection refusal at collector startup.
        redis.server_bind()
        threading.Thread(target=sink.serve_forever,daemon=True).start()
        sbom=Path(directory)/'sbom.yaml'; sbom.write_text('scan_interval: 0\n')
        env=dict(os.environ,TRACE_MODE='off',POLICY_ENABLED='false',SINKS_ALERTFLEX_INCIDENT_ENABLED='false',
                 ALTPROBE_GATEWAY_TYPE='apisix',
                 ALTPROBE_LOG_DEBUG='false',ALTPROBE_RULESET_PATH='',ALTPROBE_HOST_NAME='review',
                 ALTPROBE_SBOM_CONFIG=str(sbom),ALTPROBE_API_GUARD=str(root/'etc/api_guard.yaml'),
                 SINKS_AF_URL='',SINKS_AF_KEY='',SINKS_OS_URL=f'http://127.0.0.1:{sink.server_port}',
                 SINKS_OS_USER='test',SINKS_OS_PWD='test',SINKS_OS_TYPES='HTTP',
                 SINKS_TRACE_SPOOL_DIR=directory+'/traces',SOURCES_REDIS_HOST='127.0.0.1',
                 SOURCES_REDIS_PORT=str(redis.server_address[1]),SOURCES_PROXY_REDIS=KEY,SOURCES_PROXY_LOG='',
                 SOURCES_REDIS_USERNAME='reader',SOURCES_REDIS_PASSWORD='test password%literal',SOURCES_REDIS_DATABASE='2',
                 SOURCES_SURICATA_REDIS='',SOURCES_SURICATA_LOG='',
                 SOURCES_OPENSHELL_REDIS='',SOURCES_OPENSHELL_LOG='',CORRELATOR_DETECTION_ENABLED='false')
        with (Path(directory)/'collector.log').open('wb') as log:
            proc=subprocess.Popen([str(binary),'docker'],env=env,stdout=log,stderr=log)
            try:
                time.sleep(.4); assert proc.poll() is None, 'collector failed during initial Redis outage'
                redis.server_activate()
                threading.Thread(target=redis.serve_forever,daemon=True).start()
                enqueue('startup-recovered'); wait_for(lambda:delivered('startup-recovered'))
                with State.lock: State.mode='disconnect'; before=State.connects
                assert State.disconnected.wait(3)
                with State.lock: State.mode='normal'
                enqueue('connection-recovered'); wait_for(lambda:delivered('connection-recovered'))
                assert State.connects>before
                with State.lock: State.mode='stall'
                assert State.stalled.wait(3)
                started=time.monotonic(); proc.terminate(); proc.wait(timeout=3)
                assert proc.returncode==0 and time.monotonic()-started<3
                # An in-flight OpenSearch call must also observe daemon stop;
                # its ordinary 60-second request deadline must not delay join.
                State.release.set()
                with State.lock: State.mode='normal'; State.stall_sink=True
                proc=subprocess.Popen([str(binary),'docker'],env=env,stdout=log,stderr=log)
                enqueue('stalled-sink')
                assert State.sink_stalled.wait(5)
                started=time.monotonic(); proc.terminate(); proc.wait(timeout=3)
                assert proc.returncode==0 and time.monotonic()-started<3
            finally:
                State.release.set()
                State.sink_release.set()
                if proc.poll() is None: proc.kill(); proc.wait()
                redis.shutdown(); sink.shutdown()
    print('PASS Proxy: startup outage, reconnect, literal Redis key, delivery after recovery, SIGTERM during stalled LPOP and OpenSearch I/O')

if __name__=='__main__': main()
