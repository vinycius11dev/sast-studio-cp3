const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const dashboard = fs.readFileSync(path.join(__dirname, "../static/js/dashboard.js"), "utf8");
const start = dashboard.indexOf("async function waitForQueuedScan(job)");
const end = dashboard.indexOf("function filteredFindings()", start);
const source = dashboard.slice(start, end).trim();
function waiter(api, statuses = []) {
  return vm.runInNewContext(`(${source})`, { api, setStatus: (text) => statuses.push(text), setTimeout: (callback) => callback(), Date });
}
test("queued scan survives HTTP 502 while polling without resubmitting", async () => {
  const requests = [], statuses = [];
  const scan = { scan_id: "scan-1", total_findings: 0 };
  let polls = 0;
  const wait = waiter(async (url) => {
    requests.push(url);
    if (url.includes("/jobs/")) {
      if (++polls === 1) throw Object.assign(new Error("HTTP 502"), { retryable: true });
      return { status: "completed", job_id: "job-1", scan_id: "scan-1" };
    }
    return scan;
  }, statuses);
  assert.strictEqual(await wait({ status: "queued", job_id: "job-1" }), scan);
  assert.deepEqual(requests, ["/api/v1/jobs/job-1", "/api/v1/jobs/job-1", "/api/v1/scans/scan-1"]);
  assert(statuses.some((text) => text.includes("Conexão interrompida")));
});
test("queued scan does not loop on authorization failures", async () => {
  let calls = 0;
  const wait = waiter(async () => { calls++; throw new Error("HTTP 401"); });
  await assert.rejects(wait({ status: "queued", job_id: "job-1" }), /401/);
  assert.equal(calls, 1);
});
test("completed job retries only its result lookup", async () => {
  let calls = 0;
  const scan = { scan_id: "scan-1" };
  const wait = waiter(async (url) => {
    assert.equal(url, "/api/v1/scans/scan-1");
    if (++calls === 1) throw Object.assign(new Error("offline"), { retryable: true });
    return scan;
  });
  assert.strictEqual(await wait({ status: "completed", job_id: "job-1", scan_id: "scan-1" }), scan);
  assert.equal(calls, 2);
});
