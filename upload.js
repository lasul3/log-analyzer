'use strict';

/* ═══════════════════════════════════════════════════════════════════
   Log Analyzer — upload.js
   Controller for the upload page (index.html).
   Reads a file / pasted text / sample, stores it in sessionStorage,
   then navigates to dashboard.html for analysis.
   ═══════════════════════════════════════════════════════════════════ */

const $ = (id) => document.getElementById(id);

const STORE_CONTENT = 'la.content';
const STORE_FILENAME = 'la.filename';

/* Sample GCP Cloud Logging export (Java / Cloud Run) demonstrating
   trace correlation, entities, config flags, a null response, a slow gap,
   and an exception with a stack trace. */
const SAMPLE_ENTRIES = [
  { timestamp: '2026-06-18T10:15:01.120Z', severity: 'INFO', trace: 'projects/demo-prod/traces/abc123def456abc123def456abc12300', resource: { type: 'cloud_run_revision', labels: { service_name: 'order-service', revision_name: 'order-service-00042-xyz', project_id: 'demo-prod', location: 'us-central1' } }, labels: { 'run.googleapis.com/request_id': 'req-7f3a91' }, jsonPayload: { message: 'Received POST /api/orders request', thread: 'http-nio-8080-exec-3', logger: 'com.demo.order.OrderController', daId: 'DA-55012' } },
  { timestamp: '2026-06-18T10:15:01.140Z', severity: 'DEBUG', trace: 'projects/demo-prod/traces/abc123def456abc123def456abc12300', resource: { type: 'cloud_run_revision', labels: { service_name: 'order-service', revision_name: 'order-service-00042-xyz', project_id: 'demo-prod', location: 'us-central1' } }, jsonPayload: { message: 'Loaded config: MAX_RETRIES=3, TIMEOUT_MS=5000, featureFlagAsyncEnabled=true', thread: 'http-nio-8080-exec-3', logger: 'com.demo.order.OrderService' } },
  { timestamp: '2026-06-18T10:15:01.160Z', severity: 'INFO', trace: 'projects/demo-prod/traces/abc123def456abc123def456abc12300', resource: { type: 'cloud_run_revision', labels: { service_name: 'order-service', revision_name: 'order-service-00042-xyz', project_id: 'demo-prod', location: 'us-central1' } }, jsonPayload: { message: 'Calling external inventory-service API at https://inventory/api/check', thread: 'http-nio-8080-exec-3', logger: 'com.demo.order.InventoryClient' } },
  { timestamp: '2026-06-18T10:15:13.880Z', severity: 'WARN', trace: 'projects/demo-prod/traces/abc123def456abc123def456abc12300', resource: { type: 'cloud_run_revision', labels: { service_name: 'order-service', revision_name: 'order-service-00042-xyz', project_id: 'demo-prod', location: 'us-central1' } }, jsonPayload: { message: 'Response from inventory-service was null after 12s', thread: 'http-nio-8080-exec-3', logger: 'com.demo.order.InventoryClient' } },
  { timestamp: '2026-06-18T10:15:13.900Z', severity: 'ERROR', trace: 'projects/demo-prod/traces/abc123def456abc123def456abc12300', resource: { type: 'cloud_run_revision', labels: { service_name: 'order-service', revision_name: 'order-service-00042-xyz', project_id: 'demo-prod', location: 'us-central1' } }, jsonPayload: { message: 'Failed to process order', thread: 'http-nio-8080-exec-3', logger: 'com.demo.order.OrderService', stack_trace: 'java.lang.NullPointerException: Cannot invoke "InventoryResponse.getStock()" because "response" is null\n    at com.demo.order.OrderService.process(OrderService.java:88)\n    at com.demo.order.OrderController.create(OrderController.java:45)' } },
];
const SAMPLE_LOG = JSON.stringify(SAMPLE_ENTRIES, null, 2);

let payload = null; // { content, filename }

function setPayload(content, filename) {
  payload = content && content.trim() ? { content, filename } : null;
  $('analyze-btn').disabled = !payload;
}

function readFile(file) {
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    const text = String(reader.result || '');
    $('paste-input').value = text.length > 20000 ? text.slice(0, 20000) + '\n…(preview truncated)…' : text;
    setPayload(text, file.name || 'uploaded.log');
  };
  reader.readAsText(file);
}

function analyze() {
  if (!payload) return;
  sessionStorage.setItem(STORE_CONTENT, payload.content);
  sessionStorage.setItem(STORE_FILENAME, payload.filename);
  location.href = 'dashboard.html';
}

document.addEventListener('DOMContentLoaded', () => {
  const dropzone = $('dropzone');

  $('file-input').addEventListener('change', (e) => readFile(e.target.files[0]));

  $('paste-input').addEventListener('input', (e) => setPayload(e.target.value, 'pasted.log'));

  $('sample-btn').addEventListener('click', () => {
    $('paste-input').value = SAMPLE_LOG;
    setPayload(SAMPLE_LOG, 'sample.log');
  });

  $('analyze-btn').addEventListener('click', analyze);

  ['dragenter', 'dragover'].forEach((ev) =>
    dropzone.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.add('is-dragover'); }));
  ['dragleave', 'drop'].forEach((ev) =>
    dropzone.addEventListener(ev, (e) => { e.preventDefault(); dropzone.classList.remove('is-dragover'); }));
  dropzone.addEventListener('drop', (e) => {
    if (e.dataTransfer?.files?.length) readFile(e.dataTransfer.files[0]);
  });
});
