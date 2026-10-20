/* Health checks only: reconnecting must never replay scans or AI requests. */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory;
  else root.createSastConnection = factory;
})(typeof globalThis !== "undefined" ? globalThis : this, function createSastConnection(options = {}) {
  const request = options.fetch || globalThis.fetch.bind(globalThis);
  const schedule = options.setTimeout || globalThis.setTimeout.bind(globalThis);
  const cancel = options.clearTimeout || globalThis.clearTimeout.bind(globalThis);
  const onChange = options.onChange || (() => {});
  const onRecovered = options.onRecovered || (() => {});
  const delays = options.delays || [2000, 4000, 8000, 15000, 30000];
  let timer, pending, stopped = true, failures = 0, connected = false;

  function later(ms) {
    cancel(timer);
    if (!stopped) timer = schedule(() => { void check(); }, ms);
  }
  function unavailable(message) {
    connected = false;
    failures += 1;
    const retryMs = delays[Math.min(failures - 1, delays.length - 1)];
    onChange({ status: "disconnected", message, failures, retryMs });
    later(retryMs);
  }
  function check() {
    if (stopped) return Promise.resolve(false);
    if (pending) return pending;
    cancel(timer);
    onChange({ status: "checking", failures, connected });
    pending = (async () => {
      const controller = new AbortController();
      const timeout = schedule(() => controller.abort(), options.timeoutMs || 6000);
      try {
        const response = await request("/health", { cache: "no-store", credentials: "same-origin", signal: controller.signal });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const health = await response.json();
        if (health.service !== "sast-engine-api" || health.status !== "healthy") throw new Error("Resposta de saúde inválida");
        if (stopped) return false;
        const recovered = !connected;
        connected = true;
        failures = 0;
        onChange({ status: "connected", health, failures: 0 });
        later(options.heartbeatMs || 20000);
        if (options.onHealthy) Promise.resolve().then(() => options.onHealthy(health)).catch(options.onRecoveryError || (() => {}));
        // Refresh failure is distinct from origin health and cannot create a second API request.
        if (recovered) Promise.resolve().then(() => onRecovered(health)).catch(options.onRecoveryError || (() => {}));
        return true;
      } catch (error) {
        if (!stopped) unavailable(error.name === "AbortError" ? "Tempo de conexão esgotado" : error instanceof TypeError ? "Falha de rede ao alcançar o servidor" : error.message);
        return false;
      } finally { cancel(timeout); pending = null; }
    })();
    return pending;
  }
  return {
    start(health) {
      stopped = false;
      if (health?.status === "healthy" && health.service === "sast-engine-api") {
        connected = true;
        onChange({ status: "connected", health, failures: 0 });
        later(options.heartbeatMs || 20000);
      } else { void check(); }
    },
    reconnect: check,
    reportFailure(message) { if (!stopped && !pending) unavailable(message); },
    stop() { stopped = true; cancel(timer); },
  };
});
