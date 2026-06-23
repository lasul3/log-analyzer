'use strict';

/* ═══════════════════════════════════════════════════════════════════
   Log Analyzer — app.js
   Client-side analyzer for Java / Cloud Run logs exported via
   Google Cloud Logging. No backend required.

   Sections:
     1. Utilities
     2. Knowledge base (exception → remediation)
     3. Parser  (format detect, GCP / JSON / plaintext, stack traces)
     4. Analyzer (flags, issues, entities, traces, timing, config,
                  severity, per-entry meaning, anomalies, next steps)
     5. Narrative generator
     6. Renderers
     7. Export
     8. App controller + boot
   ═══════════════════════════════════════════════════════════════════ */


/* ═══════════════════ 1. UTILITIES ═══════════════════ */

const $  = (id) => document.getElementById(id);
const el = (sel, root = document) => root.querySelector(sel);
const els = (sel, root = document) => [...root.querySelectorAll(sel)];

function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function fmtTime(ts) { return ts ? new Date(ts).toLocaleString() : '—'; }
function fmtClock(ts) {
  return ts ? new Date(ts).toLocaleTimeString('en-US',
    { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—';
}
function fmtMs(ms) {
  if (ms == null) return '—';
  if (ms < 1000) return `${Math.round(ms)}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`;
  if (ms < 86_400_000) return `${Math.floor(ms / 3_600_000)}h ${Math.round((ms % 3_600_000) / 60_000)}m`;
  return `${Math.round(ms / 86_400_000)}d`;
}
function plural(n, w) { return `${n} ${w}${n === 1 ? '' : 's'}`; }
function pushMap(map, key, val) { (map.get(key) ?? map.set(key, []).get(key)).push(val); }


/* ═══════════════════ 2. KNOWLEDGE BASE ═══════════════════ */

const FIXES = {
  NullPointerException: [
    'Trace the null source — identify which variable or field was null at the failure point.',
    'Guard with Optional.ofNullable() or explicit null checks before dereferencing.',
    'Inspect the external API response: confirm the body and all expected fields are non-null.',
    'Add defensive logging just before processing external responses to catch nulls early.',
    'Use @NonNull annotations / bean validation to fail fast at service boundaries.',
  ],
  ConnectException: [
    'Verify the target hostname and port in application configuration.',
    'Check Cloud Run egress settings and the VPC connector for internal services.',
    'Confirm the downstream service is running and reachable from Cloud Run.',
    'Add retry with exponential backoff (e.g. Resilience4j Retry).',
  ],
  UnknownHostException: [
    'DNS resolution failed — verify the hostname is spelled correctly.',
    'Check the VPC connector / DNS settings if calling an internal service.',
    'Confirm the service domain is reachable from the Cloud Run network.',
  ],
  SocketTimeoutException: [
    'Increase the HTTP client read timeout (RestTemplate, OkHttp, WebClient, Feign).',
    'The TCP connection succeeded but no response arrived within the timeout window.',
    'Monitor downstream latency — the service may be overloaded.',
    'Consider async / reactive calls to avoid blocking threads on slow responses.',
  ],
  TimeoutException: [
    'Raise client / connection-pool timeout settings.',
    'Check whether the external service is degraded or under load.',
    'Add a circuit breaker (Resilience4j) to fail fast when the dependency is slow.',
    'Review the Cloud Run request timeout (default 300s).',
  ],
  HttpClientErrorException: [
    'Log the full 4xx response body to understand the rejection.',
    'Verify auth tokens, API keys, or OAuth credentials are valid and unexpired.',
    'Confirm the request payload matches the external API contract.',
    'Handle 429 Too Many Requests with retry-after backoff.',
  ],
  HttpServerErrorException: [
    'The dependency returned 5xx — escalate to that service team.',
    'Retry 503 Service Unavailable with exponential backoff.',
    'Add fallback / graceful degradation for this dependency.',
    'Propagate correlation IDs to aid cross-service debugging.',
  ],
  ResourceAccessException: [
    'Spring wrapped an I/O error reaching the external service — inspect the cause.',
    'Check connectivity, timeouts, and TLS/certificate validity.',
    'Verify the endpoint URL and that the service accepts the connection.',
  ],
  JsonParseException: [
    'Log the raw response string before deserialization to inspect actual content.',
    'Verify Content-Type — the response may be HTML / plain text, not JSON.',
    'Check whether the external API changed its response schema.',
    'Wrap deserialization in try-catch and log the raw payload on failure.',
  ],
  JsonMappingException: [
    'A JSON field could not map to the target type — check for schema drift.',
    'Log the raw payload and compare against your DTO definition.',
    'Make new/optional fields nullable or annotate with @JsonIgnoreProperties(ignoreUnknown=true).',
  ],
  ClassCastException: [
    'Compare the actual runtime type vs the expected type at the cast point.',
    'The external API may have changed a field type (e.g. number → string).',
    'Use instanceof before casting, or deserialize to Map<String,Object> for flexibility.',
  ],
  IllegalArgumentException: [
    'Validate all inputs before this method is invoked.',
    'Check for null, empty, or out-of-range values being passed in.',
    'Review recent config or request-format changes that could supply invalid values.',
  ],
  IllegalStateException: [
    'Trace the object lifecycle — it may be used before initialization completes.',
    'Verify Spring context / connection-pool startup and shutdown ordering.',
    'Add guards to block operations on not-yet-ready components.',
  ],
  DataAccessException: [
    'Database access failed — inspect the SQL and the underlying SQLState.',
    'Check the connection pool (HikariCP) for exhaustion or leaks.',
    'Verify DB credentials, network reachability, and Cloud SQL connector config.',
  ],
  SQLException: [
    'Inspect the SQLState / vendor error code for the precise cause.',
    'Check connection pool health and DB availability.',
    'Verify the query, schema, and constraints involved.',
  ],
  DEFAULT: [
    'Read the full error message for immediate context clues.',
    'Use the stack trace to locate the exact failing line.',
    'Search for related ERROR / WARN lines in the same timestamp window.',
    'Review recent deployments, configuration changes, or dependency upgrades.',
  ],
};

const NULL_RESPONSE_FIXES = [
  'The external system returned null / empty — check its health and logs.',
  'Add a null-safety check before processing the response object.',
  'Log the HTTP status code and raw response body for the failing request.',
  'Add a fallback value or retry strategy when a null response is received.',
  'Confirm the external service API contract has not changed.',
];

function fixesFor(type, exType) {
  if (type === 'NULL_RESPONSE') return NULL_RESPONSE_FIXES;
  if (exType) {
    for (const [key, list] of Object.entries(FIXES)) {
      if (key !== 'DEFAULT' && (exType.includes(key) || key.includes(exType))) return list;
    }
    return [
      `Inspect the full ${exType} stack trace to find the root cause.`,
      'Determine whether this is thrown by your code or a third-party library.',
      ...FIXES.DEFAULT,
    ];
  }
  return FIXES.DEFAULT;
}


/* ── Plain-language descriptions for clickable highlighted tokens. ── */

const EXCEPTION_DESC = {
  NullPointerException: 'Code tried to use an object reference that was null — for example calling a method or reading a field on a variable that held no value.',
  ConnectException: 'A TCP connection to a remote host/port could not be established. The target may be down, unreachable, or blocked by network rules.',
  UnknownHostException: 'The hostname could not be resolved to an IP address — usually a DNS or configuration problem.',
  SocketTimeoutException: 'A socket operation (connect or read) exceeded its time limit. The connection opened but no response arrived in time.',
  TimeoutException: 'An operation did not complete within its allotted time window.',
  HttpClientErrorException: 'An outbound HTTP call returned a 4xx client-error status — the request was rejected by the server.',
  HttpServerErrorException: 'An outbound HTTP call returned a 5xx server-error status — the downstream service failed.',
  ResourceAccessException: 'Spring could not reach the remote resource; this typically wraps an underlying I/O, timeout, or TLS error.',
  JsonParseException: 'The JSON payload was malformed and could not be parsed.',
  JsonMappingException: 'Valid JSON could not be mapped onto the target Java type — usually a schema mismatch.',
  ClassCastException: 'An object was cast to a type it is not an instance of.',
  IllegalArgumentException: 'A method received an argument that is invalid, out of range, or otherwise unacceptable.',
  IllegalStateException: 'An operation was invoked while the object or application was in an inappropriate state.',
  DataAccessException: 'Spring’s data-access layer reported a database failure.',
  SQLException: 'The database driver reported an error — inspect the SQLState and vendor error code.',
};

const SEVERITY_INFO = {
  ERROR: {
    icon: '🔴', accent: 'red', kicker: 'Log severity',
    desc: 'ERROR means an operation failed and the application could not complete the requested work. These entries usually need investigation and often carry a stack trace.',
    steps: [
      'Find the matching stack trace or cause in the same thread / trace ID.',
      'Inspect the entries immediately before this one for the triggering action.',
      'Check the Debug Guide to see how often this error recurs.',
    ],
    tip: 'Switch the Log Viewer to “Flagged” to isolate every ERROR-level line.',
  },
  FATAL: {
    icon: '🔴', accent: 'red', kicker: 'Log severity',
    desc: 'FATAL / SEVERE / CRITICAL marks a critical failure that may crash the process or leave the service unusable. Treat it as the highest priority.',
    steps: [
      'Determine whether the process or request was aborted.',
      'Correlate with deployment, scaling, or resource-exhaustion events.',
      'Escalate immediately if the service became unavailable.',
    ],
    tip: 'Cross-check the Timeline tab for a spike of failures around this moment.',
  },
  WARN: {
    icon: '⚠️', accent: 'yellow', kicker: 'Log severity',
    desc: 'WARN flags a recoverable or potentially harmful condition that did not stop execution but frequently precedes an error.',
    steps: [
      'Check whether warnings cluster just before an ERROR.',
      'Confirm the warned-about resource or value is within expected limits.',
      'Decide if the condition needs a config change or can be safely ignored.',
    ],
    tip: 'Repeated identical warnings often point to a misconfiguration worth fixing.',
  },
};

/** Build the detail payload shown when a highlighted token is clicked. */
function tokenDetail(type, value) {
  if (type === 'ex') {
    let key = null;
    for (const k of Object.keys(EXCEPTION_DESC)) {
      if (value === k || value.includes(k) || k.includes(value)) { key = k; break; }
    }
    const desc = key ? EXCEPTION_DESC[key]
      : /Error$/.test(value)
        ? `${value} is a Java error type. Errors usually signal serious problems an application is not expected to recover from.`
        : `${value} is a Java exception signalling an abnormal condition encountered during execution.`;
    return {
      icon: '⚡', accent: 'orange', kicker: 'Java Exception',
      title: value, desc,
      steps: fixesFor('EXCEPTION', value),
      tip: `Open the Debug Guide tab for the ranked, occurrence-aware breakdown of ${value}.`,
    };
  }
  if (type === 'null') {
    return {
      icon: '🟣', accent: 'purple', kicker: 'Null value',
      title: 'null',
      desc: 'A null appears in this entry. In logs this usually means an external system returned an empty/absent response, or a variable was unexpectedly unset before use — a common precursor to NullPointerException.',
      steps: NULL_RESPONSE_FIXES,
      tip: 'Correlate by trace ID to see what the upstream call returned just before this null.',
    };
  }
  const v = String(value).toUpperCase();
  const info = (v === 'WARN' || v === 'WARNING') ? SEVERITY_INFO.WARN
    : (v === 'FATAL' || v === 'SEVERE' || v === 'CRITICAL') ? SEVERITY_INFO.FATAL
    : SEVERITY_INFO.ERROR;
  return { ...info, title: value };
}


/* ═══════════════════ 3. PARSER ═══════════════════ */

const RX = {
  exception:  /\b([A-Za-z_$][\w$]*(?:Exception|Error|Throwable))\b/,
  bareEx:     /^(?:[\w$]+\.)*([\w$]+(?:Exception|Error))(?::|\s|$)/,
  causedBy:   /^(?:Caused by:|Suppressed:)\s/,
  stackAt:    /^\s+at\s+[\w.$<>/\[\]]+\(/,
  moreFrames: /^\s+\.\.\.\s+\d+\s+more\s*$/,
  nullResp:   /\bnull\s*(?:response|body|result|payload|return(?:ed)?|value|object)\b|\b(?:response|body|result|payload)\s+(?:was\s+|is\s+)?null\b|\b(?:received|got|returned)\s+null\b|\bresponse\s+from\s+\S+\s+(?:was|is)\s+null\b/i,
  isoTs:      /(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?)/,
  level:      /\b(TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|SEVERE|CRITICAL)\b/,
  spring:     /^(\d{4}-\d{2}-\d{2}[T ]?\d{2}:\d{2}:\d{2}[.,]\d{3})\s+(TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s+\d*\s*-+\s*\[\s*([^\]]*?)\s*\]\s+([\w.$]+)\s*:\s*(.*)$/,
  logback:    /^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[.,]\d{3})\s+(TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s+\[\s*([^\]]*?)\s*\]\s+([\w.$]+)\s*-\s*(.*)$/,
  generic:    /^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[.,]?\d*Z?)\s+(TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|SEVERE|CRITICAL)\s+(.*)$/,
};

const ERROR_LEVELS = new Set(['ERROR', 'FATAL', 'SEVERE', 'CRITICAL']);

function normLevel(l) {
  if (!l) return null;
  const u = l.toUpperCase();
  return u === 'WARNING' ? 'WARN' : u;
}

function parseTs(s) {
  if (!s) return null;
  if (typeof s === 'number') return s;
  const d = new Date(String(s).replace(' ', 'T').replace(',', '.'));
  return isNaN(d) ? null : d.getTime();
}

/** Detect overall file format. */
function detectFormat(text) {
  const t = text.trim();
  if (!t) return 'plaintext';
  if (t[0] === '[') {
    try {
      const a = JSON.parse(t);
      if (Array.isArray(a) && a.length) return isGCP(a[0]) ? 'gcp-array' : 'json-array';
    } catch { /* not a JSON array */ }
  }
  const firstObj = t.split('\n').find(l => l.trim()[0] === '{');
  if (firstObj) {
    try {
      const o = JSON.parse(firstObj);
      return isGCP(o) ? 'gcp-ndjson' : 'ndjson';
    } catch { /* not ndjson */ }
  }
  return 'plaintext';
}

function isGCP(o) {
  return !!o && typeof o === 'object' && (
    'insertId' in o ||
    ('severity' in o && ('textPayload' in o || 'jsonPayload' in o || 'protoPayload' in o)) ||
    (o.resource && o.resource.type)
  );
}

/** Build a normalized entry. `gcp` holds raw Cloud Logging metadata (or null). */
function makeEntry({ lineNumber, raw, level, ts, thread, logger, message, gcp = null, stackTrace = null }) {
  const lvl = normLevel(level);
  const flags = [];
  if (lvl && ERROR_LEVELS.has(lvl)) flags.push('ERROR');
  const exMatch = message && message.match(RX.exception);
  if (exMatch || RX.causedBy.test(message || '')) flags.push('EXCEPTION');
  if (message && RX.nullResp.test(message)) flags.push('NULL_RESPONSE');

  return {
    lineNumber, raw,
    timestamp: ts ?? null,
    level: lvl,
    thread: thread || null,
    logger: logger || null,
    message: message || '',
    gcp,
    flags,
    exceptionType: flags.includes('EXCEPTION') && exMatch ? exMatch[1] : null,
    stackTrace,
  };
}

/** Extract trace/request/da identifiers from a raw GCP record. */
function gcpMeta(rec) {
  const rl = rec.resource?.labels || {};
  const labels = rec.labels || {};
  const jp = rec.jsonPayload || {};
  const m = {
    severity:    rec.severity || null,
    serviceName: rl.service_name || rl.serviceName || null,
    revision:    rl.revision_name || rl.configuration_name || null,
    project:     rl.project_id || null,
    region:      rl.location || null,
    instanceId:  labels['run.googleapis.com/instanceId'] || labels.instanceId || null,
    traceId:     null,
    requestId:   labels['run.googleapis.com/request_id'] || labels.requestId || null,
    daId:        jp.daId || jp.da_id || jp.DA_ID || jp.daID || null,
    spanId:      rec.spanId || jp.spanId || null,
  };
  if (rec.trace) {
    const t = String(rec.trace).match(/traces\/([a-z0-9]+)/i);
    m.traceId = t ? t[1] : String(rec.trace);
  }
  if (!m.traceId) {
    const raw = jp.traceId || jp.trace_id || jp['logging.googleapis.com/trace'];
    if (raw) m.traceId = String(raw).split('/').pop();
  }
  if (!m.requestId) m.requestId = jp.requestId || jp.request_id || jp.REQ_ID || null;
  return m;
}

/** Parse a single GCP Cloud Logging record. */
function parseGCP(rec, lineNumber) {
  const meta = gcpMeta(rec);
  const ts = parseTs(rec.timestamp || rec.receiveTimestamp);
  let message = '', thread = null, logger = null, stackTrace = null;

  if (rec.jsonPayload) {
    const jp = rec.jsonPayload;
    message = jp.message ?? jp.msg ?? jp.log ?? jp.text ?? JSON.stringify(jp);
    thread  = jp.thread || jp.threadName || jp.thread_name || null;
    logger  = jp.logger || jp.loggerName || jp.logger_name || jp.class || null;
    const st = jp.stack_trace || jp.stackTrace || jp.exception || jp.stacktrace;
    if (st) stackTrace = String(st).split('\n').map(s => s.trim()).filter(Boolean);
  } else if (rec.textPayload != null) {
    message = String(rec.textPayload);
  } else if (rec.protoPayload) {
    message = rec.protoPayload.status?.message
      || rec.protoPayload.methodName
      || JSON.stringify(rec.protoPayload);
  } else {
    message = JSON.stringify(rec);
  }

  const entry = makeEntry({
    lineNumber, raw: JSON.stringify(rec),
    level: meta.severity, ts, thread, logger, message, gcp: meta, stackTrace,
  });

  // If a structured stack trace exists, ensure EXCEPTION flag + type are set.
  if (stackTrace && stackTrace.length) {
    if (!entry.flags.includes('EXCEPTION')) entry.flags.push('EXCEPTION');
    if (!entry.exceptionType) {
      const m = (stackTrace[0] || message).match(RX.exception);
      if (m) entry.exceptionType = m[1];
    }
  }
  return entry;
}

/** Parse a single generic JSON log line (non-GCP). */
function parseJSON(o, lineNumber) {
  const message = o.message ?? o.msg ?? o.log ?? o.text ?? JSON.stringify(o);
  const st = o.stack_trace || o.stackTrace || o.exception;
  const entry = makeEntry({
    lineNumber, raw: JSON.stringify(o),
    level: o.level || o.severity || o.lvl,
    ts: parseTs(o.timestamp || o.time || o['@timestamp'] || o.datetime),
    thread: o.thread || o.threadName,
    logger: o.logger || o.loggerName,
    message,
    stackTrace: st ? String(st).split('\n').map(s => s.trim()).filter(Boolean) : null,
  });
  if (entry.stackTrace?.length && !entry.flags.includes('EXCEPTION')) {
    entry.flags.push('EXCEPTION');
    const m = (entry.stackTrace[0] || message).match(RX.exception);
    if (m && !entry.exceptionType) entry.exceptionType = m[1];
  }
  return entry;
}

/** Parse one plain-text log line. Returns null for stack-trace continuation lines. */
function parsePlainLine(line, lineNumber) {
  if (RX.stackAt.test(line) || RX.causedBy.test(line) || RX.moreFrames.test(line)) return null;

  let ts = null, level = null, thread = null, logger = null, message = line, m;
  if ((m = line.match(RX.spring)))      { ts = parseTs(m[1]); level = m[2]; thread = m[3]; logger = m[4]; message = m[5]; }
  else if ((m = line.match(RX.logback))){ ts = parseTs(m[1]); level = m[2]; thread = m[3]; logger = m[4]; message = m[5]; }
  else if ((m = line.match(RX.generic))){ ts = parseTs(m[1]); level = m[2]; message = m[3]; }
  else {
    const t = line.match(RX.isoTs); if (t) ts = parseTs(t[1]);
    const l = line.match(RX.level); if (l) level = l[1];
  }
  return makeEntry({ lineNumber, raw: line, level, ts, thread, logger, message });
}

/** Parse plain-text content with multi-line stack-trace attachment. */
function parsePlaintext(text) {
  const lines = text.split('\n');
  const out = [];
  let cur = null;

  const attach = (line, exFromCausedBy) => {
    if (!cur) return;
    (cur.stackTrace ??= []).push(line.trim());
    if (exFromCausedBy && !cur.flags.includes('EXCEPTION')) {
      cur.flags.push('EXCEPTION');
      const m = line.match(RX.exception);
      if (m && !cur.exceptionType) cur.exceptionType = m[1];
    }
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) continue;

    if (RX.stackAt.test(line) || RX.moreFrames.test(line)) { attach(line, false); continue; }
    if (RX.causedBy.test(line)) { attach(line, true); continue; }

    const bare = line.match(RX.bareEx);
    if (bare && cur) {
      attach(line, false);
      if (!cur.flags.includes('EXCEPTION')) cur.flags.push('EXCEPTION');
      if (!cur.exceptionType) cur.exceptionType = bare[1];
      continue;
    }

    const entry = parsePlainLine(line, i + 1);
    if (entry) { cur = entry; out.push(entry); }
    else if (cur) { cur.message += ' ' + line.trim(); cur.raw += '\n' + line; }
  }
  return out;
}

function parseNDJSON(text) {
  return text.split('\n').filter(l => l.trim()).map((l, i) => {
    try { const o = JSON.parse(l); return isGCP(o) ? parseGCP(o, i + 1) : parseJSON(o, i + 1); }
    catch { return parsePlainLine(l, i + 1); }
  }).filter(Boolean);
}

/** Top-level parse: returns { entries, format }. */
function parseLogs(content) {
  const format = detectFormat(content);
  let entries;
  if (format === 'gcp-array' || format === 'json-array') {
    entries = JSON.parse(content.trim())
      .map((r, i) => isGCP(r) ? parseGCP(r, i + 1) : parseJSON(r, i + 1));
  } else if (format === 'gcp-ndjson' || format === 'ndjson') {
    entries = parseNDJSON(content);
  } else {
    entries = parsePlaintext(content);
  }
  return { entries, format };
}


/* ═══════════════════ 4. ANALYZER ═══════════════════ */

function computeStats(entries) {
  const stamps = entries.filter(e => e.timestamp).map(e => e.timestamp);
  return {
    total:      entries.length,
    errors:     entries.filter(e => e.flags.includes('ERROR')).length,
    exceptions: entries.filter(e => e.flags.includes('EXCEPTION')).length,
    nulls:      entries.filter(e => e.flags.includes('NULL_RESPONSE')).length,
    uniqueEx:   new Set(entries.filter(e => e.exceptionType).map(e => e.exceptionType)).size,
    firstTs:    stamps.length ? Math.min(...stamps) : null,
    lastTs:     stamps.length ? Math.max(...stamps) : null,
  };
}

function computeSeverity(entries) {
  const c = {};
  for (const e of entries) { const l = e.level || 'UNKNOWN'; c[l] = (c[l] || 0) + 1; }
  return c;
}

/** Group flagged entries into ranked issues with remediation. */
function analyzeIssues(entries) {
  const exGroups = new Map(), errGroups = new Map(), nullEntries = [];
  for (const e of entries) {
    if (e.flags.includes('NULL_RESPONSE')) nullEntries.push(e);
    if (e.flags.includes('EXCEPTION') && e.exceptionType) pushMap(exGroups, e.exceptionType, e);
    else if (e.flags.includes('ERROR')) pushMap(errGroups, `${e.level}:${e.message.slice(0, 60)}`, e);
  }

  const issues = [];
  let id = 0;
  const make = (type, severity, group, extra) => {
    const first = group[0];
    issues.push({
      id: ++id, type, severity,
      message: first.message, timestamp: first.timestamp, lineNumber: first.lineNumber,
      count: group.length, stackTrace: first.stackTrace,
      relatedLines: group.map(e => e.lineNumber),
      ...extra,
    });
  };

  for (const [exType, g] of exGroups)
    make('EXCEPTION', 'CRITICAL', g, { exceptionType: exType, title: exType, fixes: fixesFor('EXCEPTION', exType) });
  if (nullEntries.length)
    make('NULL_RESPONSE', 'HIGH', nullEntries, { exceptionType: null, title: 'Null Response from External System', fixes: fixesFor('NULL_RESPONSE') });
  for (const [, g] of errGroups) {
    const t = g[0].message.length > 90 ? g[0].message.slice(0, 90) + '…' : g[0].message;
    make('ERROR', 'MEDIUM', g, { exceptionType: null, title: t, fixes: fixesFor('ERROR') });
  }

  const rank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  issues.sort((a, b) => (rank[a.severity] - rank[b.severity]) || (b.count - a.count));
  return issues;
}

/** Aggregate GCP / structured entities across the batch. */
function extractEntities(entries) {
  const e = {
    serviceName: null, revision: null, project: null, region: null, instanceId: null,
    traceIds: new Set(), requestIds: new Set(), daIds: new Set(),
    threads: new Set(), loggers: new Set(),
  };
  for (const en of entries) {
    const g = en.gcp;
    if (g) {
      e.serviceName ||= g.serviceName;
      e.revision    ||= g.revision;
      e.project     ||= g.project;
      e.region      ||= g.region;
      e.instanceId  ||= g.instanceId;
      if (g.traceId)   e.traceIds.add(g.traceId);
      if (g.requestId) e.requestIds.add(g.requestId);
      if (g.daId)      e.daIds.add(g.daId);
    }
    if (en.thread) e.threads.add(en.thread);
    if (en.logger) e.loggers.add(en.logger);
  }
  return e;
}

/** Group entries by trace/request id, sorted chronologically. */
function groupByTrace(entries) {
  const groups = new Map();
  for (const en of entries) {
    const g = en.gcp;
    let tid = null, type = 'Trace ID';
    if (g?.traceId) { tid = g.traceId; }
    else if (g?.requestId) { tid = 'req:' + g.requestId; type = 'Request ID'; }
    if (!tid) continue;
    if (!groups.has(tid)) groups.set(tid, { type, entries: [] });
    groups.get(tid).entries.push(en);
  }
  for (const grp of groups.values())
    grp.entries.sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
  return groups;
}

/** Time-bucketed counts for the timeline chart. */
function buildTimeline(entries) {
  const stamps = entries.filter(e => e.timestamp).map(e => e.timestamp);
  if (stamps.length < 2) return null;
  const span = Math.max(...stamps) - Math.min(...stamps);
  const bucket = span <= 3e5 ? 1e4 : span <= 36e5 ? 6e4 : span <= 864e5 ? 3e5 : 36e5;

  const buckets = new Map();
  for (const e of entries) {
    if (!e.timestamp) continue;
    const k = Math.floor(e.timestamp / bucket) * bucket;
    const b = buckets.get(k) || { errors: 0, exceptions: 0, nulls: 0 };
    if (e.flags.includes('ERROR'))         b.errors++;
    if (e.flags.includes('EXCEPTION'))     b.exceptions++;
    if (e.flags.includes('NULL_RESPONSE')) b.nulls++;
    buckets.set(k, b);
  }
  const sorted = [...buckets].sort((a, b) => a[0] - b[0]);
  const label = (ts) => {
    const d = new Date(ts);
    if (bucket < 6e4) return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    if (bucket < 36e5) return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' });
    return d.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false });
  };
  return {
    labels: sorted.map(([ts]) => label(ts)),
    errors: sorted.map(([, b]) => b.errors),
    exceptions: sorted.map(([, b]) => b.exceptions),
    nulls: sorted.map(([, b]) => b.nulls),
  };
}

/** Inter-entry timing deltas; surfaces the slowest gaps. */
function buildTiming(entries) {
  const sorted = entries.filter(e => e.timestamp).sort((a, b) => a.timestamp - b.timestamp);
  if (sorted.length < 2) return { deltas: [], totalMs: 0, slowCount: 0 };
  const deltas = [];
  for (let i = 1; i < sorted.length; i++) {
    const ms = sorted[i].timestamp - sorted[i - 1].timestamp;
    deltas.push({ from: sorted[i - 1], to: sorted[i], ms, slow: ms > 2000, vSlow: ms > 10000 });
  }
  const slowCount = deltas.filter(d => d.slow).length;
  deltas.sort((a, b) => b.ms - a.ms);
  return { deltas, totalMs: sorted.at(-1).timestamp - sorted[0].timestamp, slowCount };
}

/** Extract config / feature-flag style key=value pairs from messages. */
function extractConfigs(entries) {
  const CONFIG_HINT = /config|setting|parameter|property|feature|flag|enabled|disabled|timeout|limit|threshold|url|endpoint|host|port|mode|env|version|size|count|interval|retry|batch|max|min|ttl|expiry|profile/i;
  const KV_UPPER = /\b([A-Z][A-Z0-9_]{2,})\s*[=:]\s*("[^"]*"|[^\s,;|]+)/g;
  const KV_CAMEL = /\b([a-z][a-zA-Z0-9]*(?:[A-Z][a-zA-Z0-9]*)+)\s*[=:]\s*("[^"]*"|[^\s,;|]+)/g;
  const out = [], seen = new Set();
  for (const e of entries) {
    const msg = e.message || '';
    if (!CONFIG_HINT.test(msg)) continue;
    for (const rx of [KV_UPPER, KV_CAMEL]) {
      rx.lastIndex = 0;
      let m;
      while ((m = rx.exec(msg))) {
        const key = m[1];
        const val = m[2].replace(/^"|"$/g, '').replace(/[.,;]$/, '');
        const k = `${key}=${val}`;
        if (!seen.has(k) && key.length <= 50 && val.length <= 120 && val !== '') {
          seen.add(k);
          out.push({ key, value: val, line: e.lineNumber, logger: e.logger || null, level: e.level || null, context: msg.slice(0, 110) });
        }
      }
    }
  }
  return out;
}

/** Plain-English meaning for a single log entry. */
function interpret(e) {
  const m = (e.message || '').toLowerCase();
  const log = (e.logger || '').toLowerCase();
  const lvl = (e.level || '').toUpperCase();

  const R = (re) => re.test(m);
  if (R(/started.*application|application.*started|spring.*boot.*start|in \d+\.\d+ seconds/)) return 'Spring Boot application started';
  if (R(/tomcat.*(started|initialized)|netty started|servlet.*initialized/)) return 'Embedded HTTP server ready';
  if (R(/refreshing|context.*initial|bean.*creat/)) return 'Spring context initializing';
  if (R(/hikari.*(start|pool)|connection pool/)) return 'DB connection pool activity';

  if (R(/received.*request|incoming request|request received|dispatch/)) return 'New HTTP request received';
  if (R(/\bget\b.*(\/|request)/)) return 'Handling GET request';
  if (R(/\bpost\b.*(\/|request)/)) return 'Handling POST request';
  if (R(/\bput\b.*(\/|request)/)) return 'Handling PUT request';
  if (R(/\bdelete\b.*(\/|request)/)) return 'Handling DELETE request';
  if (R(/response sent|completed.*request|request completed|status[:= ]*2\d\d/)) return 'Request completed successfully';
  if (R(/status[:= ]*4\d\d|\b4\d\d\b.*error/)) return 'Client error response (4xx)';
  if (R(/status[:= ]*5\d\d|\b5\d\d\b.*error/)) return 'Server error response (5xx)';

  if (R(/select .* from|insert into|update .* set|delete from|executing.*query/)) return 'Executing database query';
  if (R(/begin.*transaction|transaction.*start|@transactional/)) return 'Database transaction started';
  if (R(/commit/)) return 'Database transaction committed';
  if (R(/rollback/)) return 'Transaction rolled back — error occurred';

  if (R(/calling.*api|outbound|resttemplate|webclient|feign|http.?client|invoking.*service|external.*call/)) return 'Calling external API';
  if (R(/response.*(from|received).*(external|service|api)|external.*response/)) return 'Received response from external service';
  if (R(/timeout|timed out/)) return '⚠️ Operation timed out';
  if (R(/retry|attempt \d+|retrying/)) return 'Retrying failed operation';
  if (R(/circuit breaker|fallback/)) return '⚠️ Circuit breaker / fallback triggered';

  if (R(/authenticated|authentication success|login success/)) return 'Authentication succeeded';
  if (R(/unauthorized|access denied|forbidden|\b401\b|\b403\b/)) return '🔴 Access denied — auth failure';
  if (R(/token.*(valid|verify|parse)|jwt|bearer/)) return 'Validating security token';
  if (R(/token.*(expired|invalid)/)) return '🔴 Token invalid or expired';

  if (R(/cache hit|from cache/)) return 'Cache HIT';
  if (R(/cache miss|evict/)) return 'Cache MISS — fetching from source';
  if (R(/pub.?sub|published|producing/)) return 'Publishing message to queue';
  if (R(/consumed|processing.*(message|event)/)) return 'Processing message from queue';

  if (R(/null.*response|response.*null/)) return '🔴 Null response from external system';
  if (lvl === 'ERROR' || lvl === 'FATAL') return '🔴 Error — needs investigation';
  if (lvl === 'WARN') return '⚠️ Warning condition';
  if (R(/exception|failed|failure|\berror\b/)) return '🔴 Operation failure';

  if (/controller/.test(log)) return 'Controller — handling HTTP request';
  if (/service/.test(log)) return 'Service layer — business logic';
  if (/repository|dao/.test(log)) return 'Repository — database access';
  if (/scheduler|scheduled/.test(log)) return 'Scheduled job executing';
  if (/security|filter|interceptor/.test(log)) return 'Security / filter processing';

  if (lvl === 'DEBUG') return 'Debug diagnostic detail';
  if (lvl === 'INFO') return 'Informational — normal operation';
  return 'Application log entry';
}

/** Heuristic anomaly detection. */
function findAnomalies(entries, stats, timing, entities, traceGroups) {
  const a = [];
  if (stats.exceptions > 0 && stats.errors === 0)
    a.push('Exceptions detected but no ERROR-level entries — exceptions may be logged at a lower level (check logging config).');
  if (timing.slowCount > 0)
    a.push(`${plural(timing.slowCount, 'gap')} between log entries exceed 2s — possible slow operations or blocking calls.`);
  if (timing.deltas[0]?.ms > 30000)
    a.push(`Largest gap is ${fmtMs(timing.deltas[0].ms)} — investigate what happened between lines ${timing.deltas[0].from.lineNumber} and ${timing.deltas[0].to.lineNumber}.`);
  if (stats.nulls > 0)
    a.push(`${plural(stats.nulls, 'null-response event')} from external systems — a downstream dependency may be unhealthy.`);
  for (const [tid, grp] of traceGroups) {
    const hasErr = grp.entries.some(e => e.flags.length);
    const last = grp.entries.at(-1);
    if (hasErr && last && interpret(last).includes('Error'))
      a.push(`Trace ${tid.replace('req:', '').slice(0, 16)}… ends on an error — request likely did not complete successfully.`);
  }
  const noTs = entries.filter(e => !e.timestamp).length;
  if (noTs > entries.length * 0.5 && entries.length > 4)
    a.push('Over half of entries have no parseable timestamp — timeline and timing analysis may be incomplete.');
  const exTypes = new Set(entries.filter(e => e.exceptionType).map(e => e.exceptionType));
  if (exTypes.size >= 3)
    a.push(`${exTypes.size} distinct exception types in one batch — may indicate cascading failures.`);
  return a;
}

/** Prioritized, actionable next steps. */
function buildNextSteps(entities, issues, timing) {
  const steps = [];
  const proj = entities.project, svc = entities.serviceName, region = entities.region || 'us-central1';

  if (issues.some(i => i.type === 'EXCEPTION')) {
    const ex = issues.find(i => i.type === 'EXCEPTION');
    steps.push({ icon: '🐛', priority: 'CRITICAL', title: `Find the root cause of ${ex.exceptionType}`,
      detail: `Search Cloud Logging for "${ex.exceptionType}" within ±2 minutes of line ${ex.lineNumber}. Temporarily raise the log level on the affected class to DEBUG via a Cloud Run env var.` });
  }
  if (issues.some(i => i.type === 'NULL_RESPONSE')) {
    steps.push({ icon: '🌐', priority: 'HIGH', title: 'Inspect the downstream dependency',
      detail: 'Check the health and logs of the external service returning null. Log the raw HTTP status and body before parsing, and verify the API contract is unchanged.' });
  }
  if (svc && proj) {
    steps.push({ icon: '📋', priority: 'HIGH', title: 'Pull a wider log window from Cloud Logging',
      detail: `Query: resource.type="cloud_run_revision" AND resource.labels.service_name="${svc}". Widen the time range around the first error to capture preceding context.` });
  }
  if (entities.traceIds.size && proj) {
    steps.push({ icon: '🔎', priority: 'MEDIUM', title: 'Open the full distributed trace',
      detail: `Inspect spans and latency in Cloud Trace:\nhttps://console.cloud.google.com/traces/list?project=${proj}` });
  } else if (!entities.traceIds.size) {
    steps.push({ icon: '🔗', priority: 'MEDIUM', title: 'Enable distributed tracing',
      detail: 'No trace IDs were found. Add the Spring Cloud GCP Trace starter or the OpenTelemetry agent so requests can be correlated across services.' });
  }
  if (timing.slowCount > 0) {
    steps.push({ icon: '⏱️', priority: 'MEDIUM', title: `Investigate ${plural(timing.slowCount, 'slow gap')}`,
      detail: `Largest gap: ${fmtMs(timing.deltas[0]?.ms)}. Add fine-grained timing logs around the slow section and review DB query / external-call durations.` });
  }
  if (entities.daIds.size) {
    steps.push({ icon: '🆔', priority: 'MEDIUM', title: `Correlate DA_ID ${[...entities.daIds][0]}`,
      detail: 'Trace this DA_ID through upstream and downstream systems to follow the full business transaction.' });
  }
  if (svc && proj) {
    steps.push({ icon: '📊', priority: 'LOW', title: 'Review Cloud Run metrics',
      detail: `Check request latency, error rate, and instance count:\nhttps://console.cloud.google.com/run/detail/${region}/${svc}/metrics?project=${proj}` });
  }
  steps.push({ icon: '📝', priority: 'LOW', title: 'Strengthen structured logging',
    detail: 'Log request IDs, DA IDs, and operation durations on every entry. Use MDC (Mapped Diagnostic Context) for per-thread correlation to speed up future debugging.' });

  const rank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  steps.sort((a, b) => rank[a.priority] - rank[b.priority]);
  return steps;
}


/* ═══════════════════ 5. NARRATIVE GENERATOR ═══════════════════ */

function buildNarrative(entities, stats, issues, traceGroups, timing) {
  const p = [];
  const svc = entities.serviceName ? `<span class="tag">${esc(entities.serviceName)}</span>` : 'an unidentified service';
  const loc = [entities.project && `project <span class="tag">${esc(entities.project)}</span>`,
               entities.region && `region <span class="tag">${esc(entities.region)}</span>`]
               .filter(Boolean).join(', ');

  let s1 = `This batch contains <strong>${stats.total.toLocaleString()}</strong> log ${stats.total === 1 ? 'entry' : 'entries'} from ${svc}`;
  if (loc) s1 += ` (${loc})`;
  if (entities.revision) s1 += `, revision <span class="tag">${esc(entities.revision)}</span>`;
  s1 += '.';
  if (stats.firstTs && stats.lastTs && stats.lastTs > stats.firstTs)
    s1 += ` The logs span <strong>${fmtMs(stats.lastTs - stats.firstTs)}</strong> (${fmtTime(stats.firstTs)} → ${fmtTime(stats.lastTs)}).`;
  p.push(s1);

  if (traceGroups.size) {
    const reqIds = [...traceGroups].filter(([k]) => !k.startsWith('req:')).length;
    p.push(`Requests are correlated across <strong>${plural(traceGroups.size, 'trace')}</strong>${reqIds ? ` (${reqIds} via trace ID)` : ''}. See the <strong>Trace &amp; Entities</strong> tab for the chronological event sequence.`);
  }

  if (issues.length === 0) {
    p.push(`✅ No errors, exceptions, or null responses were detected — the batch looks healthy.`);
  } else {
    const parts = [];
    if (stats.exceptions) parts.push(`<strong style="color:var(--orange)">${plural(stats.exceptions, 'exception')}</strong>${stats.uniqueEx > 1 ? ` (${stats.uniqueEx} distinct types)` : ''}`);
    if (stats.errors)     parts.push(`<strong style="color:var(--red)">${plural(stats.errors, 'error')}</strong>`);
    if (stats.nulls)      parts.push(`<strong style="color:var(--purple)">${plural(stats.nulls, 'null response')}</strong>`);
    p.push(`Detected ${parts.join(', ')}. The most critical issue is <strong>${esc(issues[0].title)}</strong> (line ${issues[0].lineNumber}${issues[0].count > 1 ? `, ${issues[0].count}×` : ''}). The <strong>Debug Guide</strong> tab ranks every issue with step-by-step fixes.`);
  }

  if (timing.slowCount > 0)
    p.push(`⏱️ ${plural(timing.slowCount, 'gap')} exceeding 2s ${timing.slowCount === 1 ? 'was' : 'were'} found between entries (largest ${fmtMs(timing.deltas[0]?.ms)}) — see <strong>Timeline → Performance</strong>.`);

  return p.map(t => `<p style="margin-bottom:10px">${t}</p>`).join('');
}


/* ═══════════════════ 6. RENDERERS ═══════════════════ */

function highlight(raw, query) {
  let t = esc(raw);
  t = t.replace(/\b([A-Za-z_$][\w$]*(?:Exception|Error|Throwable))\b/g, '<span class="hl-ex hl-click" role="button" tabindex="0" data-tk="ex" data-val="$1" title="Click for details">$1</span>');
  t = t.replace(/\bnull\b/gi, '<span class="hl-null hl-click" role="button" tabindex="0" data-tk="null" data-val="null" title="Click for details">$&</span>');
  t = t.replace(/\b(ERROR|FATAL|SEVERE|CRITICAL)\b/g, '<span class="hl-err hl-click" role="button" tabindex="0" data-tk="sev" data-val="$1" title="Click for details">$1</span>');
  t = t.replace(/\b(WARN(?:ING)?)\b/g, '<span class="hl-warn hl-click" role="button" tabindex="0" data-tk="sev" data-val="$1" title="Click for details">$1</span>');
  if (query) {
    try {
      const rx = new RegExp(`(${query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
      t = t.replace(rx, '<mark>$1</mark>');
    } catch { /* ignore bad regex */ }
  }
  return t;
}

function renderCards(stats) {
  const dur = stats.firstTs && stats.lastTs && stats.lastTs > stats.firstTs ? fmtMs(stats.lastTs - stats.firstTs) : null;
  const cards = [
    { icon: '📋', value: stats.total.toLocaleString(),      label: 'Total Lines',     cls: '' },
    { icon: '🔴', value: stats.errors.toLocaleString(),     label: 'Errors',          cls: 'scard--error' },
    { icon: '⚡', value: stats.exceptions.toLocaleString(), label: 'Exceptions',      cls: 'scard--exception' },
    { icon: '🟣', value: stats.nulls.toLocaleString(),      label: 'Null Responses',  cls: 'scard--null' },
    { icon: '🔷', value: stats.uniqueEx.toLocaleString(),   label: 'Exception Types', cls: '' },
    ...(dur ? [{ icon: '⏱️', value: dur, label: 'Log Duration', cls: '' }] : []),
  ];
  $('summary-cards').innerHTML = cards.map(c => `
    <div class="scard ${c.cls}">
      <div class="scard__icon">${c.icon}</div>
      <div class="scard__value">${c.value}</div>
      <div class="scard__label">${c.label}</div>
    </div>`).join('');
}

function renderOverview() {
  $('narrative').innerHTML = `
    <div class="narrative__title">📊 Summary</div>
    <div class="narrative__body">${buildNarrative(APP.entities, APP.stats, APP.issues, APP.traceGroups, APP.timing)}</div>`;

  renderEntities();
  renderSeverity();
  renderConfig();
}

function renderEntities() {
  const e = APP.entities;
  const tagList = (vals, cls = '', max = 6, empty = 'None') => vals.length
    ? `<div class="entity__tags">${vals.slice(0, max).map(v => `<span class="chip ${cls}" title="${esc(v)}">${esc(v)}</span>`).join('')}${vals.length > max ? `<span class="chip">+${vals.length - max}</span>` : ''}</div>`
    : `<span class="entity__empty">${empty}</span>`;

  const scalar = (label, val) => `
    <div class="entity"><div class="entity__label">${label}</div>
      <div class="entity__value">${val ? esc(val) : '<span class="entity__empty">—</span>'}</div></div>`;
  const tags = (label, vals, cls, empty) => `
    <div class="entity"><div class="entity__label">${label}</div>${tagList(vals, cls, 6, empty)}</div>`;

  $('entities-grid').className = 'entities-grid';
  $('entities-grid').innerHTML =
    scalar('Service', e.serviceName) +
    scalar('Project', e.project) +
    scalar('Region', e.region) +
    scalar('Revision', e.revision) +
    tags('Trace IDs', [...e.traceIds], '', 'None detected') +
    tags('Request IDs', [...e.requestIds], '', 'None detected') +
    tags('DA IDs', [...e.daIds], 'chip--da', 'None found') +
    tags('Threads', [...e.threads], 'chip--thread', 'N/A') +
    tags('Loggers', [...e.loggers], 'chip--logger', 'N/A');
}

function renderSeverity() {
  const sev = APP.severity;
  const order = ['FATAL', 'CRITICAL', 'ERROR', 'WARN', 'INFO', 'DEBUG', 'TRACE', 'UNKNOWN'];
  const chips = order.filter(l => sev[l]).map(l => {
    const cls = ['FATAL', 'CRITICAL', 'ERROR'].includes(l) ? 'sev--error'
      : l === 'WARN' ? 'sev--warn' : l === 'INFO' ? 'sev--info' : 'sev--debug';
    return `<span class="sev ${cls}">${l} <strong>${sev[l]}</strong></span>`;
  }).join('');
  const clean = !(sev.ERROR || sev.FATAL || sev.CRITICAL || sev.WARN);
  $('severity-block').innerHTML = `
    <div class="sev-block">
      <div class="section-h">📊 Severity Breakdown</div>
      <div class="sev-chips">${chips || '<span class="entity__empty">No level information parsed</span>'}</div>
      ${clean ? '<p class="sev-ok">✅ All entries are INFO / DEBUG — no errors or warnings.</p>' : ''}
    </div>`;
}

function renderConfig() {
  const cfgs = APP.configs;
  if (!cfgs.length) { $('config-block').innerHTML = ''; return; }

  // Group settings by their source (the logger/component that emitted the line).
  const groups = new Map();
  for (const c of cfgs) {
    const src = c.logger || 'Unattributed (plain log)';
    if (!groups.has(src)) groups.set(src, []);
    groups.get(src).push(c);
  }
  // Largest groups first, then alphabetical.
  const ordered = [...groups.entries()]
    .sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));

  const sections = ordered.map(([src, items]) => {
    const short = src.includes('.') ? src.split('.').pop() : src;
    const rows = items.map(c => `
      <tr title="${esc(c.context)}">
        <td class="cell-key">${esc(c.key)}</td>
        <td class="cell-val">${esc(c.value)}</td>
        <td class="cfg-line">L${c.line}</td>
      </tr>`).join('');
    return `
      <div class="cfg-group">
        <div class="cfg-group__head">
          <span class="cfg-group__src" title="${esc(src)}">📦 ${esc(short)}</span>
          <span class="cfg-group__count">${plural(items.length, 'setting')}</span>
        </div>
        <table class="tbl cfg-tbl">
          <thead><tr><th>Parameter</th><th>Value</th><th>Line</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
  }).join('');

  $('config-block').innerHTML = `
    <div class="card">
      <div class="card__title">⚙️ Config &amp; Feature Flags · ${plural(cfgs.length, 'setting')} across ${plural(groups.size, 'source')}</div>
      <div class="cfg-groups">${sections}</div>
    </div>`;
}

function renderTimeline() {
  const t = APP.timeline;
  const empty = $('timeline-empty'), canvas = $('timeline-chart');
  if (!t || !t.labels.length) { empty.hidden = false; canvas.style.display = 'none'; }
  else {
    empty.hidden = true; canvas.style.display = '';
    APP.chart?.destroy();
    APP.chart = new Chart(canvas.getContext('2d'), {
      type: 'bar',
      data: { labels: t.labels, datasets: [
        { label: 'Errors',     data: t.errors,     backgroundColor: 'rgba(248,81,73,.8)',  stack: 's' },
        { label: 'Exceptions', data: t.exceptions, backgroundColor: 'rgba(240,136,62,.8)', stack: 's' },
        { label: 'Null Resp.', data: t.nulls,      backgroundColor: 'rgba(188,140,255,.8)',stack: 's' },
      ]},
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { labels: { color: '#e6edf3' } },
          tooltip: { backgroundColor: '#161b22', borderColor: '#30363d', borderWidth: 1, titleColor: '#e6edf3', bodyColor: '#8b949e' } },
        scales: { x: { ticks: { color: '#8b949e', maxRotation: 45 }, grid: { color: '#21262d' }, stacked: true },
                  y: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' }, beginAtZero: true, stacked: true } },
      },
    });
  }
  renderPerf();
}

function renderPerf() {
  const { deltas } = APP.timing;
  if (!deltas.length || deltas[0].ms < 500) { $('perf-block').innerHTML = ''; return; }
  const rows = deltas.slice(0, 10).map(d => {
    const cls = d.vSlow ? 'gap-vslow' : d.slow ? 'gap-slow' : 'gap-fast';
    const icon = d.vSlow ? '🔴' : d.slow ? '⚠️' : '✅';
    return `<tr>
      <td class="${cls}">${icon} ${fmtMs(d.ms)}</td>
      <td class="cell-mono">${esc((d.from.message || d.from.raw).slice(0, 64))}</td>
      <td class="cell-mono">→ ${esc((d.to.message || d.to.raw).slice(0, 64))}</td>
      <td class="cell-mono">L${d.from.lineNumber}–L${d.to.lineNumber}</td>
    </tr>`;
  }).join('');
  $('perf-block').innerHTML = `
    <div class="card">
      <div class="card__title">⏱️ Performance — Largest Gaps Between Entries</div>
      <table class="tbl"><thead><tr><th>Gap</th><th>From</th><th>To</th><th>Lines</th></tr></thead>
        <tbody>${rows}</tbody></table>
    </div>`;
}

function renderTrace() {
  const groups = APP.traceGroups;
  const empty = $('trace-empty'), container = $('trace-groups');
  if (!groups.size) { empty.hidden = false; container.innerHTML = ''; return; }
  empty.hidden = true;

  let idx = 0, html = `<div class="section-h" style="margin-bottom:16px">🔀 Request Traces (${plural(groups.size, 'group')})</div>`;
  for (const [tid, grp] of groups) {
    idx++;
    const ents = grp.entries;
    const stamps = ents.filter(e => e.timestamp).map(e => e.timestamp);
    const dur = stamps.length > 1 ? Math.max(...stamps) - Math.min(...stamps) : null;
    const flagged = ents.some(e => e.flags.length);
    const shortId = tid.replace('req:', '');
    const idLabel = shortId.length > 30 ? shortId.slice(0, 30) + '…' : shortId;

    let prev = null;
    const rows = ents.map(e => {
      const delta = prev && e.timestamp ? e.timestamp - prev : null;
      prev = e.timestamp || prev;
      const dCls = delta == null ? 't-delta--fast' : delta > 10000 ? 't-delta--vslow' : delta > 2000 ? 't-delta--slow' : 't-delta--fast';
      const dHtml = `<span class="t-delta ${dCls}">${delta == null ? '—' : '+' + fmtMs(delta)}</span>`;
      const lvl = e.level ? `<span class="lvl lvl--${e.level.toLowerCase()}">${e.level}</span>` : '';
      const logger = e.logger ? `<div class="t-logger">${esc(e.logger.split('.').pop())}</div>` : '';
      return `<tr class="${e.flags.length ? 'is-flagged' : ''}">
        <td class="t-time">${fmtClock(e.timestamp)}</td>
        <td>${dHtml}</td>
        <td>${lvl}</td>
        <td><div class="t-msg">${highlight(e.message || e.raw)}</div>
            <div class="t-meaning">${esc(interpret(e))}</div>${logger}</td>
      </tr>`;
    }).join('');

    html += `
      <div class="trace-grp">
        <div class="trace-grp__head" onclick="UI.toggleTrace(${idx})">
          <span class="trace-grp__arrow" id="tg-arr-${idx}">▼</span>
          <span class="trace-grp__id">${esc(idLabel)}</span>
          <span class="trace-grp__type">${grp.type}</span>
          <span class="trace-grp__count">${plural(ents.length, 'entry')}</span>
          ${flagged ? '<span class="trace-grp__issues">issues</span>' : ''}
          ${dur != null ? `<span class="trace-grp__dur">${fmtMs(dur)} total</span>` : ''}
        </div>
        <div id="tg-body-${idx}">
          <table class="trace-tbl">
            <thead><tr><th>Time</th><th>Gap</th><th>Level</th><th>Message &amp; Meaning</th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      </div>`;
  }
  container.innerHTML = html;
}

function renderDebug() {
  const issues = APP.issues;
  const list = $('issues-list'), emptyMsg = $('issues-empty'), badge = $('debug-badge');
  if (!issues.length) {
    list.innerHTML = ''; emptyMsg.hidden = false; badge.hidden = true;
  } else {
    emptyMsg.hidden = true;
    badge.textContent = issues.length; badge.hidden = false;
    list.innerHTML = issues.map((iss, i) => {
      const cls = iss.type === 'EXCEPTION' ? 'issue--exception' : iss.type === 'NULL_RESPONSE' ? 'issue--null' : 'issue--error';
      const label = iss.type === 'EXCEPTION' ? '⚡ Exception' : iss.type === 'NULL_RESPONSE' ? '🟣 Null Response' : '🔴 Error';
      const stack = iss.stackTrace?.length ? `
        <div class="stack-sec">
          <button class="collapse" onclick="UI.toggleStack(${iss.id})">
            <span id="st-arr-${iss.id}">▶</span> Stack Trace (${plural(iss.stackTrace.length, 'line')})
          </button>
          <pre id="st-${iss.id}" class="stack" hidden>${iss.stackTrace.map(esc).join('\n')}</pre>
        </div>` : '';
      const fixes = iss.fixes.map((f, n) => `<li class="fix"><span class="fix__num">${n + 1}</span><span>${esc(f)}</span></li>`).join('');
      return `
        <div class="issue ${cls}">
          <div class="issue__head">
            <div class="issue__step">Step ${i + 1} of ${issues.length}</div>
            <div class="issue__titlerow">
              <span class="issue__type">${label}</span>
              <h3 class="issue__title">${esc(iss.title)}</h3>
            </div>
            <div class="issue__meta">
              <span class="meta-badge">Line ${iss.lineNumber}</span>
              ${iss.count > 1 ? `<span class="meta-badge meta-badge--count">${iss.count}× occurrences</span>` : ''}
              ${iss.timestamp ? `<span class="meta-ts">First seen: ${fmtTime(iss.timestamp)}</span>` : ''}
            </div>
          </div>
          <div class="issue__msg">${highlight(iss.message)}</div>
          ${stack}
          <div class="fixes"><div class="fixes__title">🔧 Debug Steps</div><ol class="fixes__list">${fixes}</ol></div>
        </div>`;
    }).join('');
  }
  renderAnomalies();
  renderNextSteps();
}

function renderAnomalies() {
  const a = APP.anomalies;
  if (!a.length) { $('anomalies-block').innerHTML = ''; return; }
  $('anomalies-block').innerHTML = `
    <div class="anomalies">
      <div class="section-h">🚩 Anomalies &amp; Observations</div>
      ${a.map(x => `<div class="anomaly"><span class="anomaly__icon">⚠️</span><span class="anomaly__text">${esc(x)}</span></div>`).join('')}
    </div>`;
}

function renderNextSteps() {
  const steps = APP.nextSteps;
  $('next-steps-block').innerHTML = `
    <div class="next-steps">
      <div class="next-steps__title">⭐ Suggested Next Steps</div>
      ${steps.map((s, i) => `
        <div class="nstep nstep--${s.priority.toLowerCase()}">
          <div class="nstep__icon">${s.icon}</div>
          <div class="nstep__body">
            <div class="nstep__head">
              <span class="nstep__title">Step ${i + 1}: ${esc(s.title)}</span>
              <span class="prio prio--${s.priority.toLowerCase()}">${s.priority}</span>
            </div>
            <div class="nstep__detail">${esc(s.detail).replace(/\n/g, '<br>').replace(/(https?:\/\/[^\s<]+)/g, '<a href="$1" target="_blank" rel="noopener">$1</a>')}</div>
          </div>
        </div>`).join('')}
    </div>`;
}

function renderLogs() {
  const container = $('log-viewer');
  let list = APP.showAll ? APP.entries : APP.entries.filter(e => e.flags.length);
  if (APP.search) {
    const q = APP.search.toLowerCase();
    list = list.filter(e => (e.raw || '').toLowerCase().includes(q) || (e.message || '').toLowerCase().includes(q));
  }
  if (!list.length) { container.innerHTML = '<div class="empty">No entries match the current filter.</div>'; return; }

  const MAX = 2000;
  const rows = list.slice(0, MAX).map(e => {
    const has = (f) => e.flags.includes(f);
    const cls = has('EXCEPTION') ? 'log-row--exception' : has('ERROR') ? 'log-row--error' : has('NULL_RESPONSE') ? 'log-row--null' : '';
    const lvl = e.level ? `<span class="lvl lvl--${e.level.toLowerCase()}">${e.level}</span>` : '';
    const flags = e.flags.map(f => `<span class="flag flag--${f.toLowerCase()}">${f === 'NULL_RESPONSE' ? 'NULL' : f}</span>`).join('');
    const time = e.timestamp ? `<span class="log-time">${fmtClock(e.timestamp)}</span>` : '';
    return `<div class="log-row ${cls}"><span class="log-num">${e.lineNumber}</span>${time}${lvl}${flags}<span class="log-msg">${highlight(e.message || e.raw, APP.search)}</span></div>`;
  }).join('');

  container.innerHTML = `
    <div class="log-count">${list.length.toLocaleString()} ${list.length === 1 ? 'entry' : 'entries'}${APP.showAll ? '' : ' (flagged only)'}</div>
    ${rows}
    ${list.length > MAX ? `<div class="log-trunc">Showing first ${MAX.toLocaleString()} of ${list.length.toLocaleString()}</div>` : ''}`;
}


/* ═══════════════════ 7. EXPORT ═══════════════════ */

function textReport() {
  const { stats: s, issues, entities: e, filename } = APP;
  const L = '═'.repeat(54), out = [
    L, '  LOG ANALYZER REPORT',
    `  File      : ${filename}`,
    `  Generated : ${new Date().toLocaleString()}`,
    e.serviceName ? `  Service   : ${e.serviceName}` : null,
    e.project ? `  Project   : ${e.project}${e.region ? ' / ' + e.region : ''}` : null,
    L, '',
    'SUMMARY', '─'.repeat(30),
    `Total lines       : ${s.total}`,
    `Errors            : ${s.errors}`,
    `Exceptions        : ${s.exceptions}  (${s.uniqueEx} types)`,
    `Null responses    : ${s.nulls}`,
    s.firstTs ? `Time range        : ${fmtTime(s.firstTs)} → ${fmtTime(s.lastTs)}` : null,
    '', 'DEBUG GUIDE', '─'.repeat(30),
  ].filter(x => x != null);

  issues.forEach((iss, i) => {
    out.push('', `Step ${i + 1}: [${iss.type}] ${iss.title}`,
      `  Occurrences: ${iss.count} | Line: ${iss.lineNumber}${iss.timestamp ? ' | ' + fmtTime(iss.timestamp) : ''}`,
      `  Message: ${iss.message}`, '  Fixes:');
    iss.fixes.forEach((f, n) => out.push(`    ${n + 1}. ${f}`));
  });
  if (APP.anomalies.length) {
    out.push('', 'ANOMALIES', '─'.repeat(30));
    APP.anomalies.forEach(a => out.push(`  • ${a}`));
  }
  out.push('', 'NEXT STEPS', '─'.repeat(30));
  APP.nextSteps.forEach((st, i) => out.push(`  ${i + 1}. [${st.priority}] ${st.title}`, `      ${st.detail.replace(/\n/g, ' ')}`));
  return out.join('\n');
}

function copySummary() {
  const text = textReport(), btn = $('btn-copy'), orig = btn.innerHTML;
  const done = () => { btn.textContent = '✅ Copied!'; setTimeout(() => btn.innerHTML = orig, 1800); };
  const fallback = () => {
    const ta = Object.assign(document.createElement('textarea'), { value: text });
    ta.style.cssText = 'position:fixed;opacity:0'; document.body.appendChild(ta);
    ta.select(); document.execCommand('copy'); ta.remove(); done();
  };
  if (navigator.clipboard) navigator.clipboard.writeText(text).then(done).catch(fallback);
  else fallback();
}

function exportHTML() {
  const { stats: s, issues, entities: e, filename } = APP;
  const block = (iss, i) => {
    const c = iss.type === 'EXCEPTION' ? '#f0883e' : iss.type === 'NULL_RESPONSE' ? '#bc8cff' : '#f85149';
    const st = iss.stackTrace?.length
      ? `<details style="margin:8px 0"><summary style="color:#8b949e;cursor:pointer">Stack trace</summary><pre style="background:#0d1117;color:#8b949e;padding:8px;border-radius:4px;font-size:11px;overflow:auto">${esc(iss.stackTrace.join('\n'))}</pre></details>` : '';
    return `<div style="border:1px solid ${c};border-left:4px solid ${c};border-radius:8px;padding:16px 20px;margin-bottom:16px;background:#161b22">
      <div style="margin-bottom:6px"><span style="font-size:11px;font-weight:700;padding:2px 10px;border-radius:99px;background:${c}22;color:${c}">${iss.type}</span>
      <strong style="color:#e6edf3;font-size:15px;margin-left:8px">Step ${i + 1}: ${esc(iss.title)}</strong></div>
      <p style="color:#8b949e;font-size:12px;margin:0 0 8px">Line ${iss.lineNumber} · ${iss.count} occurrence(s)${iss.timestamp ? ' · First: ' + fmtTime(iss.timestamp) : ''}</p>
      <code style="display:block;background:#0d1117;color:#e6edf3;padding:8px 12px;border-radius:4px;font-size:12px;margin-bottom:8px;white-space:pre-wrap;overflow:auto">${esc(iss.message)}</code>${st}
      <p style="color:#58a6ff;font-size:12px;font-weight:700;margin:12px 0 6px">🔧 Debug Steps</p>
      <ol style="color:#e6edf3;margin:0;padding-left:20px">${iss.fixes.map(f => `<li style="margin-bottom:4px;font-size:13px">${esc(f)}</li>`).join('')}</ol></div>`;
  };
  const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Log Report — ${esc(filename)}</title>
<style>body{background:#0d1117;color:#e6edf3;font-family:-apple-system,Segoe UI,sans-serif;max-width:960px;margin:0 auto;padding:32px 16px}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin:24px 0}.c{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px 18px;min-width:130px}.v{font-size:26px;font-weight:700}.l{font-size:11px;color:#8b949e}</style></head>
<body><h1>Log Analysis Report</h1>
<p style="color:#8b949e">File: <strong>${esc(filename)}</strong> · ${new Date().toLocaleString()}${e.serviceName ? ` · Service: <strong>${esc(e.serviceName)}</strong>` : ''}${e.project ? ` · ${esc(e.project)}` : ''}</p>
<div class="cards">
  <div class="c"><div class="v">${s.total}</div><div class="l">Total Lines</div></div>
  <div class="c"><div class="v" style="color:#f85149">${s.errors}</div><div class="l">Errors</div></div>
  <div class="c"><div class="v" style="color:#f0883e">${s.exceptions}</div><div class="l">Exceptions</div></div>
  <div class="c"><div class="v" style="color:#bc8cff">${s.nulls}</div><div class="l">Null Responses</div></div>
  <div class="c"><div class="v">${s.uniqueEx}</div><div class="l">Exception Types</div></div>
</div>
<h2 style="color:#58a6ff">Debug Guide</h2>
${issues.length ? issues.map(block).join('') : '<p style="color:#3fb950">🎉 No issues detected.</p>'}
${APP.anomalies.length ? `<h2 style="color:#d29922">Anomalies</h2><ul>${APP.anomalies.map(a => `<li style="margin-bottom:6px">${esc(a)}</li>`).join('')}</ul>` : ''}
<h2 style="color:#58a6ff">Suggested Next Steps</h2>
<ol>${APP.nextSteps.map(st => `<li style="margin-bottom:8px"><strong>[${st.priority}] ${esc(st.title)}</strong><br><span style="color:#8b949e;font-size:13px">${esc(st.detail).replace(/\n/g, '<br>')}</span></li>`).join('')}</ol>
</body></html>`;
  const a = Object.assign(document.createElement('a'), {
    href: URL.createObjectURL(new Blob([html], { type: 'text/html' })),
    download: `log-report-${filename.replace(/[^a-z0-9]/gi, '-')}.html`,
  });
  document.body.appendChild(a); a.click(); a.remove();
}


/* ═══════════════════ 8. APP CONTROLLER + BOOT ═══════════════════ */

const APP = {
  entries: [], issues: [], stats: {}, severity: {}, timeline: null,
  entities: {}, traceGroups: new Map(), timing: { deltas: [], slowCount: 0 },
  configs: [], anomalies: [], nextSteps: [],
  filename: '', format: '', showAll: false, search: '', chart: null,
};

const STORE_CONTENT = 'la.content';
const STORE_FILENAME = 'la.filename';
const STORE_USE_IDB = 'la.useIdb';

/* IndexedDB load — counterpart to upload.js for oversized payloads. */
function idbLoad() {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open('logAnalyzer', 1);
    open.onupgradeneeded = () => open.result.createObjectStore('kv');
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const db = open.result;
      const tx = db.transaction('kv', 'readonly');
      const req = tx.objectStore('kv').get('payload');
      req.onsuccess = () => { db.close(); resolve(req.result || null); };
      req.onerror = () => { db.close(); reject(req.error); };
    };
  });
}

/** Resolve the stored payload from sessionStorage, or IndexedDB if oversized. */
async function loadPayload() {
  if (sessionStorage.getItem(STORE_USE_IDB) === '1') {
    const p = await idbLoad();
    if (p && p.content) return { content: p.content, filename: p.filename || 'analysis.log' };
    return null;
  }
  const content = sessionStorage.getItem(STORE_CONTENT);
  if (!content) return null;
  return { content, filename: sessionStorage.getItem(STORE_FILENAME) || 'analysis.log' };
}

/** Run the full analysis pipeline over raw log content into APP state. */
function runAnalysis(content, filename) {
  const { entries, format } = parseLogs(content);
  APP.entries  = entries;
  APP.format   = format;
  APP.filename = filename || 'analysis.log';
  APP.showAll  = false;
  APP.search   = '';

  APP.stats       = computeStats(entries);
  APP.severity    = computeSeverity(entries);
  APP.issues      = analyzeIssues(entries);
  APP.entities    = extractEntities(entries);
  APP.traceGroups = groupByTrace(entries);
  APP.timeline    = buildTimeline(entries);
  APP.timing      = buildTiming(entries);
  APP.configs     = extractConfigs(entries);
  APP.anomalies   = findAnomalies(entries, APP.stats, APP.timing, APP.entities, APP.traceGroups);
  APP.nextSteps   = buildNextSteps(APP.entities, APP.issues, APP.timing);
}

const FORMAT_LABELS = {
  'gcp-array': 'GCP JSON array', 'gcp-ndjson': 'GCP NDJSON',
  'json-array': 'JSON array', 'ndjson': 'NDJSON', 'plaintext': 'Plain text',
};

/** Render every part of the dashboard from current APP state. */
function renderAll() {
  $('source-name').textContent = APP.filename;
  const issueWord = APP.issues.length === 1 ? 'issue group' : 'issue groups';
  $('source-meta').textContent =
    `${FORMAT_LABELS[APP.format] || APP.format} · ${APP.stats.total.toLocaleString()} lines · ${APP.issues.length} ${issueWord}`;

  renderCards(APP.stats);
  renderOverview();
  renderTimeline();
  renderTrace();
  renderDebug();
  renderLogs();
}

/** Show one dashboard tab and its panel. */
function switchTab(name) {
  els('.tab').forEach(t => t.classList.toggle('is-active', t.dataset.tab === name));
  els('.panel').forEach(p => {
    const on = p.id === `panel-${name}`;
    p.classList.toggle('is-active', on);
    p.hidden = !on;
  });
  if (name === 'timeline') APP.chart?.resize();
}

/** Toggle the Flagged / All segment in the Log Viewer. */
function setSeg(showAll) {
  APP.showAll = showAll;
  $('seg-all').classList.toggle('is-active', showAll);
  $('seg-flagged').classList.toggle('is-active', !showAll);
  renderLogs();
}

/* Collapsible handlers referenced from inline onclick in renderers. */
const UI = {
  toggleTrace(idx) {
    const body = $(`tg-body-${idx}`), arr = $(`tg-arr-${idx}`);
    if (!body) return;
    const hidden = body.style.display === 'none';
    body.style.display = hidden ? '' : 'none';
    if (arr) arr.textContent = hidden ? '▼' : '▶';
  },
  toggleStack(id) {
    const pre = $(`st-${id}`), arr = $(`st-arr-${id}`);
    if (!pre) return;
    pre.hidden = !pre.hidden;
    if (arr) arr.textContent = pre.hidden ? '▶' : '▼';
  },
  openDetail(type, value) {
    const d = tokenDetail(type, value);
    const steps = d.steps?.length
      ? `<div class="md-steps__title">🔧 What to check</div>
         <ol class="md-steps">${d.steps.map(s => `<li>${esc(s)}</li>`).join('')}</ol>`
      : '';
    $('modal-content').innerHTML = `
      <div class="md-head md-head--${d.accent}">
        <span class="md-icon">${d.icon}</span>
        <div>
          <div class="md-kicker">${esc(d.kicker)}</div>
          <h3 id="modal-title" class="md-title">${esc(d.title)}</h3>
        </div>
      </div>
      <p class="md-desc">${esc(d.desc)}</p>
      ${steps}
      ${d.tip ? `<div class="md-tip">💡 ${esc(d.tip)}</div>` : ''}`;
    const m = $('detail-modal');
    m.hidden = false;
    document.body.classList.add('modal-open');
    el('.modal__close', m)?.focus();
  },
  closeDetail() {
    $('detail-modal').hidden = true;
    document.body.classList.remove('modal-open');
  },
};

/** Boot the dashboard: load stored logs, analyze, render, wire events. */
async function boot() {
  const payload = await loadPayload();
  if (!payload) { location.replace('index.html'); return; }

  try {
    runAnalysis(payload.content, payload.filename);
    renderAll();
  } catch (err) {
    console.error(err);
    alert(`Could not analyze logs: ${err.message}\nSee console for details.`);
    location.replace('index.html');
    return;
  }

  els('.tab').forEach(t => t.addEventListener('click', () => switchTab(t.dataset.tab)));

  $('btn-copy').addEventListener('click', copySummary);
  $('btn-html').addEventListener('click', exportHTML);
  $('btn-pdf').addEventListener('click', () => window.print());
  $('btn-new').addEventListener('click', () => {
    sessionStorage.removeItem(STORE_CONTENT);
    sessionStorage.removeItem(STORE_FILENAME);
    sessionStorage.removeItem(STORE_USE_IDB);
    indexedDB.deleteDatabase('logAnalyzer');
    location.href = 'index.html';
  });

  $('log-search').addEventListener('input', (e) => { APP.search = e.target.value.trim(); renderLogs(); });
  $('seg-flagged').addEventListener('click', () => setSeg(false));
  $('seg-all').addEventListener('click', () => setSeg(true));

  // Clickable highlighted tokens → detail modal (event delegation).
  document.addEventListener('click', (e) => {
    const tok = e.target.closest('.hl-click');
    if (tok) { UI.openDetail(tok.dataset.tk, tok.dataset.val); return; }
    if (e.target.closest('[data-close]')) UI.closeDetail();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { UI.closeDetail(); return; }
    const act = document.activeElement;
    if ((e.key === 'Enter' || e.key === ' ') && act?.classList.contains('hl-click')) {
      e.preventDefault();
      UI.openDetail(act.dataset.tk, act.dataset.val);
    }
  });
}

document.addEventListener('DOMContentLoaded', boot);
