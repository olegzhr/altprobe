"""Check the SBOM process deadline and graceful shutdown with a local fixture."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time


def wait_for(predicate, process, seconds=5):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        assert process.poll() is None, 'collector stopped unexpectedly'
        time.sleep(0.05)
    raise AssertionError('scanner did not reach expected state')


def check(binary, timeout):
    with tempfile.TemporaryDirectory(prefix='scanner-runtime-') as folder:
        work = Path(folder)
        started = work / 'started'
        config = work / 'sbom.yaml'
        config.write_text(json.dumps({
            'scan_interval': 60, 'scan_timeout_sec': timeout,
            'pipeline': [{'service_name': 'fixture', 'scan_output': str(work / 'unused.cdx.json'),
                          'scan_command': f'touch {shlex.quote(str(started))}; exec sleep 60'}],
        }), encoding='utf-8')
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(('ALTPROBE_', 'SINKS_', 'SOURCES_', 'LLM_GUARD_', 'TRACE_', 'POLICY_'))}
        env.update(ALTPROBE_SBOM_CONFIG=str(config), TRACE_MODE='off',
                   SINKS_GRAYLOG_URL='http://127.0.0.1:1/gelf', SINKS_GRAYLOG_TYPES='OCSF',
                   SINKS_TRACE_SPOOL_DIR=str(work / 'traces'))
        log = work / 'collector.log'
        with log.open('wb') as stream:
            process = subprocess.Popen([str(binary), 'docker'], env=env, stdout=stream, stderr=stream)
            try:
                wait_for(started.exists, process)
                if timeout == 1:
                    wait_for(lambda: 'scan command timed out' in log.read_text(), process)
                process.terminate()
                assert process.wait(timeout=3) == 0, log.read_text()
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
        expected = 'timed out' if timeout == 1 else 'cancelled'
        assert f'scan command {expected}' in log.read_text()


if __name__ == '__main__':
    for limit in (1, 300):
        check(Path(sys.argv[1]).resolve(), limit)
