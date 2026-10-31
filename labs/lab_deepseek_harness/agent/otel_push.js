// DSH run events + diagnostics -> OTLP/JSON logs (coexists with LoongSuite traces).
const fs = require('fs');

const endpoint = process.env.OTEL_EXPORTER_OTLP_LOGS_ENDPOINT || 'http://altprobe:4318/v1/logs';
const records = [];

function add(text, name) {
  records.push({
    timeUnixNano: String(Date.now() * 1e6),
    body: { stringValue: String(text).slice(0, 4096) },
    attributes: [
      { key: 'event.name', value: { stringValue: name } },
      { key: 'service.name', value: { stringValue: 'deepseek-harness' } },
    ],
  });
}

const eventsFile = process.argv[2] || '/home/dsh/dsh-events.jsonl';
if (fs.existsSync(eventsFile)) {
  for (const line of fs.readFileSync(eventsFile, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    let event;
    try { event = JSON.parse(line); } catch { event = { message: line }; }
    add(JSON.stringify(event), String(event.type || event.event || event.kind || 'dsh.event'));
    if (records.length >= 512) break;
  }
}
const logFile = process.argv[3] || '/home/dsh/dsh-run.log';
if (fs.existsSync(logFile)) {
  for (const line of fs.readFileSync(logFile, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    add(line, 'dsh.log');
    if (records.length >= 1024) break;
  }
}
if (!records.length) add('dsh run produced no events', 'dsh.empty');

const payload = { resourceLogs: [{ scopeLogs: [{ scope: { name: 'deepseek-harness' }, logRecords: records }] }] };
fetch(endpoint, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(payload),
}).then((response) => console.log(`[lab] OTLP logs: ${response.status} (${records.length} records)`))
  .catch((error) => console.error(`[lab] OTLP logs failed: ${error.message}`));
