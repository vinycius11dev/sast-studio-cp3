"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const createConnection = require("../static/js/connection.js");
const health = { service: "sast-engine-api", status: "healthy" };
const ok = () => ({ ok: true, json: async () => health });
function setup(fetch, extra = {}) {
  const events = [], timers = new Map();
  let id = 0;
  const monitor = createConnection({ fetch, onChange: (event) => events.push(event),
    setTimeout: (callback, ms) => { timers.set(++id, { callback, ms }); return id; },
    clearTimeout: (key) => timers.delete(key), ...extra });
  return { monitor, events, timers };
}
test("HTTP 502 retries automatically and recovers without reloading", async () => {
  let calls = 0, recovered = 0;
  const { monitor, events, timers } = setup(async (url, options) => {
    assert.equal(url, "/health");
    assert.equal(options.method, undefined); // No mutation is ever replayed.
    return ++calls === 1 ? { ok: false, status: 502 } : ok();
  }, { onRecovered: () => { recovered++; } });
  monitor.start();
  await monitor.reconnect();
  assert.equal(events.at(-1).status, "disconnected");
  assert.equal(events.at(-1).message, "HTTP 502");
  assert.equal([...timers.values()][0].ms, 2000);
  [...timers.values()][0].callback();
  await monitor.reconnect();
  assert.equal(events.at(-1).status, "connected");
  assert.equal(recovered, 1);
  assert.equal(calls, 2);
  monitor.stop();
  assert.equal(timers.size, 0);
});
test("repeated clicks share a single in-flight request", async () => {
  let resolve, calls = 0;
  const { monitor } = setup(() => { calls++; return new Promise((done) => { resolve = done; }); });
  monitor.start(health);
  const first = monitor.reconnect(), second = monitor.reconnect();
  assert.strictEqual(first, second);
  resolve(ok());
  assert.equal(await first, true);
  assert.equal(calls, 1);
  monitor.stop();
});
test("HTML, another service and non-healthy JSON cannot look connected", async () => {
  for (const response of [
    { ok: true, json: async () => { throw new SyntaxError("HTML"); } },
    { ok: true, json: async () => ({ service: "another-api", status: "healthy" }) },
    { ok: true, json: async () => ({ ...health, status: "unavailable" }) },
  ]) {
    const { monitor, events } = setup(async () => response);
    monitor.start(health);
    assert.equal(await monitor.reconnect(), false);
    assert.equal(events.at(-1).status, "disconnected");
    monitor.stop();
  }
});
test("network failures back off with a 30-second cap", async () => {
  const { monitor, events } = setup(async () => { throw new TypeError("offline"); });
  monitor.start(health);
  const delays = [];
  for (let i = 0; i < 7; i++) { await monitor.reconnect(); delays.push(events.at(-1).retryMs); }
  assert.deepEqual(delays, [2000, 4000, 8000, 15000, 30000, 30000, 30000]);
  monitor.stop();
});
test("a request timeout becomes a retryable state", async () => {
  const { monitor, timers, events } = setup((_url, options) => new Promise((_resolve, reject) => {
    options.signal.addEventListener("abort", () => reject(Object.assign(new Error("timeout"), { name: "AbortError" })));
  }));
  monitor.start(health);
  const pending = monitor.reconnect();
  [...timers.values()].find((timer) => timer.ms === 6000).callback();
  assert.equal(await pending, false);
  assert.match(events.at(-1).message, /Tempo/);
  monitor.stop();
});
test("a failed scan reports disconnection but is never replayed", async () => {
  const requests = [];
  const { monitor, events } = setup(async (url) => { requests.push(url); return ok(); });
  monitor.start(health);
  monitor.reportFailure("HTTP 530");
  assert.equal(events.at(-1).status, "disconnected");
  await monitor.reconnect();
  assert.deepEqual(requests, ["/health"]);
  monitor.stop();
});
