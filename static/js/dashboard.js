"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const escape = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]));
  const icon = (name, extra = "") => `<svg class="icon ${extra}" aria-hidden="true"><use href="#i-${name}"/></svg>`;
  const number = (value) => new Intl.NumberFormat("pt-BR").format(value || 0);
  const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const severityLabels = { CRITICAL: "Crítica", HIGH: "Alta", MEDIUM: "Média", LOW: "Baixa", INFO: "Informativa" };
  const severityColors = { CRITICAL: "#d3354b", HIGH: "#e19643", MEDIUM: "#d7b342", LOW: "#5a8fce", INFO: "#9aa8bb" };
  const languageLabels = { python: "Python", javascript: "JavaScript / TS", java: "Java" };
  const views = { overview: "Visão geral", scanner: "Scanner", findings: "Achados", history: "Histórico", rules: "Regras de análise", integrations: "Integrações" };
  const state = {
    scans: [], active: null, rules: [], capabilities: null, health: null, aiStatus: null, queueStatus: null, engineStatus: [], quality: null,
    view: "overview", mode: "files", pending: [], ignored: 0, selectionType: "file", busy: false,
    selected: null, page: 0, pageSize: 40, sources: new Map(), aiResults: new Map(), aiBusy: null, semanticBusy: null, aiBatch: null, validations: new Map(),
    overviewFilesScanId: null, overviewCompareBeforeId: null, overviewCompareAfterId: null,
  };
  let connection = null, connectionSnapshot = null, workspaceLoaded = false, workspaceLoading = null;

  function size(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  }
  function date(value, short = false) {
    if (!value) return "—";
    return new Intl.DateTimeFormat("pt-BR", { day: "2-digit", month: "2-digit", ...(short ? {} : { hour: "2-digit", minute: "2-digit" }) }).format(new Date(value));
  }
  function duration(ms) { return ms < 1000 ? `${number(Math.round(ms))} ms` : `${(ms / 1000).toFixed(1)} s`; }
  function severityBadge(value) { return `<span class="severity-badge ${value.toLowerCase()}">${escape(severityLabels[value] || value)}</span>`; }
  function owaspBadge(category, linked = true) {
    if (!category) return '<span class="owasp-tag unmapped" title="Este CWE não possui mapeamento explícito na tabela OWASP Top 10:2025">OWASP 2025 · sem mapeamento</span>';
    const label = `${category.id} · ${category.name}`;
    return linked
      ? `<a class="owasp-tag" href="${escape(category.url)}" target="_blank" rel="noopener noreferrer" title="Abrir categoria oficial OWASP Top 10:2025">${escape(label)} ${icon("external", "small")}</a>`
      : `<span class="owasp-tag" title="${escape(label)}">${escape(category.id)}</span>`;
  }
  function gateBadge(gate) {
    const status = gate?.status || "none";
    const label = { passed: "Gate aprovado", blocked: "Gate bloqueado", error: "Análise incompleta", none: "Sem análise" }[status];
    return `<span class="gate-badge ${status}">${icon(status === "passed" ? "check" : status === "none" ? "clock" : "alert")}${label}</span>`;
  }
  function empty(title, message, action = "", compact = false) {
    return `<div class="empty-state ${compact ? "compact" : ""}"><span class="empty-icon">${icon("scan")}</span><h3>${escape(title)}</h3><p>${escape(message)}</p>${action}</div>`;
  }
  function languageTags(scan) {
    return [...new Set((scan.files || []).map((file) => file.language))].map((language) => `<span class="language-tag">${escape(languageLabels[language] || language)}</span>`).join("");
  }
  function toast(message, error = false) {
    const item = document.createElement("div");
    item.className = `toast${error ? " error" : ""}`;
    item.innerHTML = icon(error ? "alert" : "check");
    const text = document.createElement("span");
    text.textContent = message;
    item.append(text);
    $("toasts").append(item);
    setTimeout(() => item.remove(), error ? 7000 : 4500);
  }
  async function api(path, options = {}) {
    let response;
    const controller = !options.signal && (!options.method || options.method === "GET") ? new AbortController() : null;
    const timeout = controller ? setTimeout(() => controller.abort(), 12000) : null;
    try {
      response = await fetch(path, controller ? { ...options, signal: controller.signal } : options);
    } catch (error) {
      if (error.name === "AbortError" && !controller) throw error;
      connection?.reportFailure("Não foi possível alcançar o servidor.");
      if (location.hostname.endsWith(".trycloudflare.com")) {
        throw Object.assign(new Error("Não foi possível alcançar a API pelo túnel. A reconexão automática está ativa; confira o estado da conexão no topo."), { retryable: true });
      }
      throw Object.assign(new Error("Não foi possível conectar à API. Confira se o servidor está iniciado e tente novamente."), { retryable: true });
    } finally { if (timeout) clearTimeout(timeout); }
    const data = await response.json().catch(() => ({}));
    if (response.redirected && new URL(response.url).hostname.endsWith("cloudflareaccess.com")) {
      throw new Error("A sessão do Cloudflare Access não está ativa para a API. Conclua o login no Cloudflare e volte ao scanner para tentar novamente.");
    }
    if (!response.ok) {
      if ([502, 503, 504, 520, 521, 522, 523, 524, 530].includes(response.status)) connection?.reportFailure(`HTTP ${response.status}`);
      const detail = Array.isArray(data.detail) ? data.detail.map((item) => item.msg).join("; ") : data.detail;
      throw Object.assign(new Error(detail || `Não foi possível completar a solicitação (HTTP ${response.status}).`), { retryable: [502, 503, 504, 520, 521, 522, 523, 524, 530].includes(response.status) });
    }
    return data;
  }
  function jsonOptions(data) { return { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) }; }
  function savePreference(key, value) { try { localStorage.setItem(key, value); } catch { /* storage may be disabled */ } }
  function preference(key) { try { return localStorage.getItem(key); } catch { return null; } }
  function removePreference(key) { try { localStorage.removeItem(key); } catch { /* storage may be disabled */ } }
  function syncClearHistoryButtons() {
    const blocked = !state.scans.length || state.busy || state.aiBusy || state.semanticBusy || (state.aiBatch && !state.aiBatch.finished);
    document.querySelectorAll("[data-clear-history]").forEach((button) => { button.disabled = Boolean(blocked); });
  }
  function setStatus(message, type = "", extra = "") {
    const node = $("scan-status");
    node.hidden = !message;
    node.className = `scan-status ${type}`;
    node.innerHTML = `${type === "loading" ? '<span class="spinner"></span>' : icon(type === "error" ? "alert" : "check")}<span>${escape(message)}</span>${extra}`;
  }

  function navigate(view) {
    if (!views[view]) view = "overview";
    if (location.hash === `#${view}`) showView();
    else location.hash = view;
  }
  function showView() {
    state.view = views[location.hash.slice(1)] ? location.hash.slice(1) : "overview";
    for (const [key] of Object.entries(views)) {
      $("view-" + key).hidden = key !== state.view;
      $("view-" + key).classList.toggle("active", key === state.view);
    }
    document.querySelectorAll("[data-view]").forEach((node) => {
      node.classList.toggle("active", node.dataset.view === state.view);
      if (node.dataset.view === state.view) node.setAttribute("aria-current", "page");
      else node.removeAttribute("aria-current");
    });
    $("breadcrumb-current").textContent = views[state.view];
    document.title = `${views[state.view]} · SAST Studio`;
    $("sidebar").classList.remove("mobile-open");
    $("menu-toggle").setAttribute("aria-expanded", "false");
    if (state.view === "overview") renderOverview();
    if (state.view === "history") renderHistory();
    if (state.view === "findings") renderFindings();
    if (state.view === "rules") renderRules();
    if (state.view === "integrations") { renderServices(); renderPolicy(); loadWorkflow(); }
    window.scrollTo({ top: 0 });
  }

  function table(items) {
    if (!items.length) return empty("Nenhuma análise por aqui", "Selecione um projeto no Scanner para começar a criar seu histórico.", '<a class="button primary small-button" href="#scanner">Nova análise</a>');
    return `<div class="table-scroll"><table class="data-table"><thead><tr><th>Projeto / análise</th><th>Política</th><th>Achados</th><th>Arquivos</th><th>Executada em</th><th></th></tr></thead><tbody>${items.map((scan) => `<tr><td><button class="project-table-name" data-open-scan="${escape(scan.scan_id)}">${icon("folder")}${escape(scan.project_name || scan.target_path)}</button><div class="table-sub">${languageTags(scan)} · ${escape(scan.scan_id.slice(0, 8))}</div></td><td>${gateBadge(scan.security_gate)}</td><td><div class="severity-counts"><span class="mini-count critical" title="Críticos">${number(scan.summary_by_severity.CRITICAL)}</span><span class="mini-count high" title="Altos">${number(scan.summary_by_severity.HIGH)}</span><span class="mini-count medium" title="Médios">${number(scan.summary_by_severity.MEDIUM)}</span><span class="table-sub">${number(scan.total_findings)} total</span></div></td><td>${number(scan.scanned_files_count)}</td><td>${date(scan.created_at)}</td><td><button class="icon-button" data-open-scan="${escape(scan.scan_id)}" aria-label="Abrir análise de ${escape(scan.project_name)}">${icon("chevron")}</button></td></tr>`).join("")}</tbody></table></div>`;
  }
  function ensureAnalyticsSelections() {
    if (!state.scans.length) return;
    const find = (id) => state.scans.find((scan) => scan.scan_id === id);
    const defaultFilesScan = state.scans.find((scan) => scan.total_findings > 0) || state.scans[0];
    state.overviewFilesScanId = find(state.overviewFilesScanId)?.scan_id || find(preference("sast-overview-files"))?.scan_id || defaultFilesScan.scan_id;
    const namedReference = state.scans.find((scan) => /vulner|antes|before|insegur/i.test(scan.project_name || ""));
    const reference = find(state.overviewCompareBeforeId) || find(preference("sast-overview-compare-before")) || namedReference || [...state.scans].sort((a, b) => b.total_findings - a.total_findings)[0];
    const namedComparison = state.scans.find((scan) => scan.scan_id !== reference.scan_id && /corrigid|depois|after|segur|secure|fix/i.test(scan.project_name || ""));
    const cleanComparison = state.scans.find((scan) => scan.scan_id !== reference.scan_id && scan.total_findings === 0);
    const fallbackComparison = state.scans.find((scan) => scan.scan_id !== reference.scan_id);
    const comparison = find(state.overviewCompareAfterId) || find(preference("sast-overview-compare-after")) || namedComparison || cleanComparison || fallbackComparison;
    state.overviewCompareBeforeId = reference.scan_id;
    state.overviewCompareAfterId = comparison?.scan_id || "";
  }
  function scanOptionLabel(scan) {
    return `${scan.project_name || scan.target_path} · ${number(scan.total_findings)} achados · ${date(scan.created_at)}`;
  }
  function trendScanLabel(scan) {
    return (scan.project_name || scan.target_path || scan.scan_id).replace(/^Demonstração\s*[·:-]\s*/i, "").replace(/correção/gi, "corr.").slice(0, 11);
  }
  function scanOptionsMarkup(selectedId) {
    return state.scans.map((scan) => `<option value="${escape(scan.scan_id)}" ${scan.scan_id === selectedId ? "selected" : ""}>${escape(scanOptionLabel(scan))}</option>`).join("");
  }
  function renderTopFiles(scan) {
    const files = scan.top_files;
    if (!Array.isArray(files)) return empty("Resumo por arquivo indisponível", "Atualize o servidor e execute ou abra novamente uma análise para carregar o ranking.", "", true);
    if (!files.length) return empty("Nenhum arquivo com achados", "Esta execução não registrou vulnerabilidades por arquivo.", "", true);
    const labels = { CRITICAL: "Críticos", HIGH: "Altos", MEDIUM: "Médios", LOW: "Baixos", INFO: "Informativos" };
    return `<div class="top-files-list">${files.map((file, index) => `<div class="top-file-row"><span class="top-file-rank">${String(index + 1).padStart(2, "0")}</span><div class="top-file-main"><button class="top-file-path" data-open-file-findings="${escape(scan.scan_id)}" data-file-path="${escape(file.path)}" title="Abrir achados deste arquivo">${icon("file")}${escape(file.path)}</button><div class="top-file-severities">${severityOrder.filter((level) => file.summary_by_severity?.[level]).map((level) => `<span class="file-severity-count ${level.toLowerCase()}" title="${labels[level]}">${labels[level]} <strong>${number(file.summary_by_severity[level])}</strong></span>`).join("")}</div></div><span class="top-file-total">${number(file.total_findings)}<small>achado${file.total_findings === 1 ? "" : "s"}</small></span></div>`).join("")}</div>`;
  }
  function severityStack(scan) {
    const total = Number(scan.total_findings) || 0;
    if (!total) return '<div class="comparison-stack empty-stack" aria-label="Nenhum achado nesta análise"></div>';
    const summary = scan.summary_by_severity || {};
    return `<div class="comparison-stack" role="img" aria-label="Distribuição de ${number(total)} achados por severidade">${severityOrder.map((level) => {
      const count = Number(summary[level]) || 0;
      return count ? `<span class="stack-segment ${level.toLowerCase()}" style="width:${count / total * 100}%" title="${severityLabels[level]}: ${number(count)}"></span>` : "";
    }).join("")}</div>`;
  }
  function renderComparison() {
    ensureAnalyticsSelections();
    if (!state.scans.length) return "";
    const before = state.scans.find((scan) => scan.scan_id === state.overviewCompareBeforeId);
    const after = state.scans.find((scan) => scan.scan_id === state.overviewCompareAfterId);
    const controls = `<div class="comparison-controls"><label><span>Análise de referência</span><select id="compare-before-select" aria-label="Análise de referência">${scanOptionsMarkup(before?.scan_id)}</select></label><label><span>Análise comparada</span><select id="compare-after-select" aria-label="Análise comparada">${state.scans.length > 1 ? scanOptionsMarkup(after?.scan_id) : '<option value="">É preciso ter duas análises</option>'}</select></label></div>`;
    if (!before || !after || before.scan_id === after.scan_id) return `<section class="panel comparison-panel"><div class="panel-heading"><div><h2>Comparação entre análises</h2><p>Compare resultados registrados no histórico desta instalação.</p></div><span class="outline-tag">Dados reais</span></div>${controls}${empty("Salve mais uma análise para comparar", "A comparação precisa de duas execuções distintas no histórico.", "", true)}</section>`;
    const delta = Number(after.total_findings) - Number(before.total_findings);
    const deltaLabel = delta < 0 ? `${number(Math.abs(delta))} achado${Math.abs(delta) === 1 ? "" : "s"} a menos` : delta > 0 ? `${number(delta)} achado${delta === 1 ? "" : "s"} a mais` : "Mesmo total de achados";
    const percent = before.total_findings ? Math.round(Math.abs(delta) / before.total_findings * 100) : null;
    const detail = percent === null ? (delta > 0 ? "A referência tinha zero achados" : "As duas análises não registraram achados") : `${percent}% de variação sobre a referência`;
    const card = (scan, label) => `<article class="comparison-scan"><div class="comparison-scan-heading"><div><span class="comparison-label">${label}</span><strong title="${escape(scan.project_name || scan.target_path)}">${escape(scan.project_name || scan.target_path)}</strong><small>${date(scan.created_at)} · ${number(scan.scanned_files_count)} arquivos</small></div>${gateBadge(scan.security_gate)}</div><div class="comparison-total"><strong>${number(scan.total_findings)}</strong><span>achados</span></div>${severityStack(scan)}<div class="comparison-severity-legend">${severityOrder.filter((level) => scan.summary_by_severity?.[level]).map((level) => `<span><i class="severity-dot ${level.toLowerCase()}"></i>${severityLabels[level]} <strong>${number(scan.summary_by_severity[level])}</strong></span>`).join("") || '<span class="comparison-no-findings">Nenhum achado registrado</span>'}</div></article>`;
    return `<section class="panel comparison-panel"><div class="panel-heading"><div><h2>Comparação entre análises</h2><p>Compare execuções reais. A diferença não atribui causalidade a uma alteração específica.</p></div><span class="outline-tag">${state.scans.length} no histórico</span></div>${controls}<div class="comparison-result"><div class="comparison-pair">${card(before, "REFERÊNCIA")}<div class="comparison-change ${delta < 0 ? "improved" : delta > 0 ? "increased" : "unchanged"}"><span>${icon(delta < 0 ? "arrow" : delta > 0 ? "alert" : "check")}</span><strong>${deltaLabel}</strong><small>${detail}</small></div>${card(after, "COMPARAÇÃO")}</div></div><div class="comparison-footnote">A distribuição considera os achados e os gates salvos em cada execução.</div></section>`;
  }
  function renderOverview() {
    syncClearHistoryButtons();
    const latest = state.scans[0];
    if (!latest) {
      $("overview-content").innerHTML = `<div class="metric-grid">${[["Análises salvas", "0", "clock"], ["Arquivos analisados", "—", "file"], ["Achados críticos", "—", "alert"], ["Regras ativas", number(state.rules.length), "rules"]].map(([label, value, symbol]) => `<div class="metric"><div class="metric-top">${label}<span class="metric-icon">${icon(symbol)}</span></div><div class="metric-number">${value}</div><div class="metric-bottom">Dados desta instalação</div></div>`).join("")}</div><div class="panel">${empty("Seu workspace está pronto", "Carregue uma pasta ou use o projeto de exemplo para executar a primeira análise.", '<a class="button primary" href="#scanner">' + icon("scan") + 'Começar análise</a>')}</div>`;
      return;
    }
    ensureAnalyticsSelections();
    const summary = latest.summary_by_severity || {};
    const metrics = [
      ["Arquivos analisados", latest.scanned_files_count, "file", "", "Na última análise"],
      ["Achados críticos", summary.CRITICAL, "alert", "critical", "Prioridade de revisão"],
      ["Achados de nível alto", summary.HIGH, "shield", "high", "Requerem atenção"],
      ["Total de achados", latest.total_findings, "bar", "total", `${state.scans.length} análise${state.scans.length === 1 ? "" : "s"} no histórico`],
    ];
    let offset = 0;
    const slices = severityOrder.map((severity) => {
      const start = offset;
      offset += latest.total_findings ? (summary[severity] || 0) / latest.total_findings * 100 : 0;
      return `${severityColors[severity]} ${start}% ${offset}%`;
    });
    const donut = latest.total_findings ? `conic-gradient(${slices.join(",")})` : "#e6f2ec";
    const trend = state.scans.slice(0, 8).reverse();
    const max = Math.max(...trend.map((item) => item.total_findings), 1);
    const filesScan = state.scans.find((scan) => scan.scan_id === state.overviewFilesScanId) || latest;
    $("overview-content").innerHTML = `<div class="metric-grid">${metrics.map(([label, value, symbol, cls, note]) => `<div class="metric ${cls}"><div class="metric-top">${label}<span class="metric-icon">${icon(symbol)}</span></div><div class="metric-number">${number(value)}</div><div class="metric-bottom">${note}</div></div>`).join("")}</div>
      ${renderComparison()}
      <div class="overview-grid"><div class="panel"><div class="panel-heading"><h2>Última análise</h2><span class="outline-tag">${icon("clock", "small")}${date(latest.created_at)}</span></div><div class="latest-scan-body"><div class="latest-scan-top"><div class="latest-header"><span class="project-icon">${icon("folder")}</span><div><div class="project-title">${escape(latest.project_name)}</div><div class="project-meta">Execução #${escape(latest.scan_id.slice(0, 8))} · Workspace local</div></div></div>${gateBadge(latest.security_gate)}</div><div class="gate-note">${escape(latest.security_gate.reason)}</div><div class="latest-stats"><div><strong>${number(latest.scanned_files_count)}</strong><span>arquivos analisados</span></div><div><strong>${duration(latest.scan_duration_ms)}</strong><span>tempo do motor</span></div><div><strong>${number(state.rules.length)}</strong><span>regras disponíveis</span></div></div><div class="latest-bottom"><div class="language-tags">${languageTags(latest)}</div><button class="text-link" data-open-scan="${escape(latest.scan_id)}">Explorar análise ${icon("arrow", "small")}</button></div></div></div>
      <div class="panel"><div class="panel-heading"><h2>Distribuição por severidade</h2><span class="outline-tag">Última análise</span></div><div class="severity-overview"><div class="severity-donut" style="background:${donut}"><div class="donut-hole"><strong>${number(latest.total_findings)}</strong><small>ACHADOS</small></div></div><div class="severity-legend">${severityOrder.filter((s) => s !== "INFO" || summary.INFO).map((severity) => `<div class="legend-row"><span><i class="severity-dot ${severity.toLowerCase()}"></i>${severityLabels[severity]}</span><strong>${number(summary[severity])}</strong></div>`).join("")}</div></div></div></div>
      <div class="analytics-grid"><section class="panel top-files-panel"><div class="panel-heading"><div><h2>Arquivos com mais achados</h2><p>Os 5 arquivos com maior concentração de ocorrências.</p></div><label class="analytics-select"><span>Análise</span><select id="overview-files-select" aria-label="Análise para o ranking dos arquivos">${scanOptionsMarkup(filesScan.scan_id)}</select></label></div>${renderTopFiles(filesScan)}<p class="panel-footnote">Selecione um arquivo para abrir a triagem já filtrada.</p></section>
      <section class="panel trend-panel"><div class="panel-heading"><div><h2>Achados por execução</h2><p>Volume total nas análises salvas mais recentes.</p></div><span class="outline-tag">Histórico real</span></div>${trend.length > 1 ? `<div class="trend-content">${trend.map((scan) => `<div class="trend-column" title="${escape(scan.project_name)} · ${date(scan.created_at)}" aria-label="${escape(scan.project_name)}: ${number(scan.total_findings)} achados em ${date(scan.created_at)}"><strong>${number(scan.total_findings)}</strong><div class="trend-bar" style="height:${Math.max(3, scan.total_findings / max * 72)}px"></div><small>${escape(trendScanLabel(scan))}</small></div>`).join("")}</div>` : empty("A evolução começa na próxima análise", "O gráfico será formado por suas próximas execuções.", "", true)}</section></div>
      <div class="panel overview-history"><div class="panel-heading"><div><h2>Análises recentes</h2><p>Histórico persistido desta instalação.</p></div><a href="#history" class="text-link">Ver histórico ${icon("arrow", "small")}</a></div>${table(state.scans.slice(0, 5))}</div><p class="section-footnote">Gráficos e indicadores são calculados a partir das análises salvas nesta instalação.</p>`;
  }
  function renderHistory() {
    syncClearHistoryButtons();
    const query = $("history-search").value.trim().toLowerCase();
    const items = state.scans.filter((scan) => `${scan.project_name} ${scan.scan_id}`.toLowerCase().includes(query));
    $("history-count").textContent = number(state.scans.length);
    $("history-table").innerHTML = items.length ? table(items) : empty("Nenhuma análise encontrada", query ? "Tente outro nome de projeto." : "Execute uma análise no Scanner para começar.", "", true);
  }
  function scanOptions() {
    $("finding-scan-select").innerHTML = state.scans.length ? state.scans.map((scan) => `<option value="${escape(scan.scan_id)}">${escape(scan.project_name)} · ${date(scan.created_at)}</option>`).join("") : '<option value="">Nenhuma análise</option>';
    if (state.active) $("finding-scan-select").value = state.active.scan_id;
    $("finding-scan-select").disabled = !state.scans.length;
  }
  async function refreshHistory() {
    const result = await api("/api/v1/scans?limit=100");
    state.scans = result.items;
    scanOptions();
    renderOverview();
    renderHistory();
  }
  function openClearHistoryDialog() {
    if (!state.scans.length || state.busy || state.aiBusy || state.semanticBusy || (state.aiBatch && !state.aiBatch.finished)) return;
    $("clear-history-confirmation").value = "";
    $("confirm-clear-history").disabled = true;
    $("clear-history-error").hidden = true;
    $("clear-history-dialog").showModal();
    $("clear-history-confirmation").focus();
  }
  async function clearHistory() {
    if ($("clear-history-confirmation").value.trim().toUpperCase() !== "ZERAR") return;
    const button = $("confirm-clear-history");
    const errorNode = $("clear-history-error");
    button.disabled = true;
    button.innerHTML = '<span class="spinner"></span>Apagando…';
    errorNode.hidden = true;
    try {
      const response = await api("/api/v1/scans", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ confirmation: "ZERAR" }) });
      state.scans = [];
      state.active = null;
      state.aiResults.clear();
      state.aiBatch = null;
      state.validations.clear();
      state.sources.clear();
      resetFilters();
      $("history-search").value = "";
      for (const key of ["sast-active-scan", "sast-overview-files", "sast-overview-compare-before", "sast-overview-compare-after"]) removePreference(key);
      scanOptions();
      renderScanOptions();
      renderOverview();
      renderHistory();
      renderFindings();
      renderPolicy();
      $("clear-history-dialog").close();
      const removedScans = response.deleted_scans ?? 0;
      const removedReviews = response.deleted_reviews ?? 0;
      toast(`${number(removedScans)} análise(s) e ${number(removedReviews)} revisão(ões) removida(s) do histórico.`);
    } catch (error) {
      errorNode.textContent = error.message;
      errorNode.hidden = false;
      toast(error.message, true);
    } finally {
      button.innerHTML = `${icon("trash")}Zerar histórico`;
      button.disabled = $("clear-history-confirmation").value.trim().toUpperCase() !== "ZERAR";
    }
  }
  function resetFilters() {
    $("findings-search").value = "";
    $("severity-filter").value = "";
    $("file-filter").value = "";
    $("semantic-filter").value = "";
    state.page = 0;
    state.selected = null;
  }
  async function openScan(id, shouldNavigate = true) {
    try {
      state.active = await api("/api/v1/scans/" + encodeURIComponent(id));
      savePreference("sast-active-scan", id);
      resetFilters();
      renderScanOptions();
      renderFindings();
      renderPolicy();
      if (shouldNavigate) navigate("findings");
    } catch (error) { toast(error.message, true); }
  }
  function renderScanOptions() {
    scanOptions();
    const paths = state.active?.files?.map((file) => file.path) || [];
    $("file-filter").innerHTML = '<option value="">Todos os arquivos</option>' + paths.map((path) => `<option value="${escape(path)}">${escape(path)}</option>`).join("");
    $("export-button").disabled = !state.active;
    $("nav-findings-count").textContent = number(state.active?.total_findings || 0);
  }

  function setMode(mode) {
    if (state.busy) return;
    state.mode = mode;
    $("files-mode").hidden = mode !== "files";
    $("editor-mode").hidden = mode !== "editor";
    document.querySelectorAll("[data-mode]").forEach((button) => {
      const active = button.dataset.mode === mode;
      button.classList.toggle("active", active);
      button.setAttribute("aria-pressed", String(active));
    });
    updateReady();
  }
  function updateEditor() {
    const text = $("code-editor").value;
    const count = text.split("\n").length;
    $("editor-lines").textContent = Array.from({ length: Math.min(count, 20000) }, (_, i) => i + 1).join("\n");
    $("editor-meta").textContent = `${number(count)} linha${count === 1 ? "" : "s"} · ${size(new Blob([text]).size)}`;
    updateReady();
  }
  function editorLanguage(filename) {
    if (/\.java$/i.test(filename)) return "java";
    if (/\.tsx?$/i.test(filename)) return "typescript";
    if (/\.jsx?$/i.test(filename)) return "javascript";
    return "python";
  }
  function setEditor(content, path) {
    $("code-editor").value = content;
    $("code-filename").value = path.split("/").pop();
    $("code-language").value = editorLanguage(path);
    updateEditor();
  }
  function updateReady() {
    const ready = state.mode === "files" ? state.pending.length > 0 : $("code-editor").value.trim().length > 0;
    $("run-scan").disabled = state.busy || !ready;
    $("scan-ready-label").textContent = state.busy ? "Análise em andamento" : state.mode === "files" ? state.pending.length ? `${state.pending.length} arquivo(s) prontos para análise` : "Selecione arquivos para começar" : ready ? "Código pronto para análise" : "Cole ou carregue um código";
  }
  function renderSelection() {
    $("selection-preview").hidden = !state.pending.length;
    if (state.pending.length) {
      const bytes = state.pending.reduce((total, item) => total + item.file.size, 0);
      $("selection-preview").innerHTML = `<div class="selection-header"><div><strong>${state.pending.length} arquivo(s) selecionado(s)</strong><small> · ${size(bytes)}${state.ignored ? ` · ${state.ignored} ignorado(s)` : ""}</small></div><button class="text-link" data-clear-selection>Limpar</button></div><div class="selected-files">${state.pending.slice(0, 16).map(({ file, path }) => `<div class="selected-file"><span>${icon("file")}<span class="selected-file-name">${escape(path)}</span></span><small>${size(file.size)}</small></div>`).join("")}${state.pending.length > 16 ? `<div class="selected-file"><small>Mais ${state.pending.length - 16} arquivos incluídos</small></div>` : ""}</div>${state.pending.length === 1 ? '<button class="text-link edit-selected" data-edit-selection>Editar código antes da análise →</button>' : ""}`;
    }
    updateReady();
  }
  async function selectFiles(files, kind) {
    if (state.busy) return;
    state.pending = [];
    state.ignored = 0;
    state.selectionType = kind;
    const extensions = state.capabilities?.extensions || [".py", ".js", ".jsx", ".ts", ".tsx", ".java"];
    const ignored = new Set(state.capabilities?.ignored_directories || ["node_modules", ".git", "venv", ".venv", "dist", "build", "target"]);
    for (const file of files) {
      const path = (file.webkitRelativePath || file.name).replace(/\\/g, "/");
      const extension = "." + path.split(".").pop().toLowerCase();
      if (!extensions.includes(extension) || path.toLowerCase().split("/").slice(0, -1).some((part) => ignored.has(part)) || !file.size) { state.ignored++; continue; }
      state.pending.push({ file, path });
    }
    const limits = state.capabilities?.limits || { project_files: 200, file_bytes: 5 * 1024 ** 2, project_bytes: 25 * 1024 ** 2 };
    const bytes = state.pending.reduce((total, item) => total + item.file.size, 0);
    let error = "";
    if (!state.pending.length) error = "Nenhum arquivo de código suportado com conteúdo foi encontrado. Selecione .py, .js, .jsx, .ts, .tsx ou .java.";
    else if (state.pending.length > limits.project_files) error = `A seleção tem ${state.pending.length} arquivos. O limite é ${limits.project_files}.`;
    else if (state.pending.some((item) => item.file.size > limits.file_bytes)) error = "Um arquivo excede o limite de 5 MB.";
    else if (bytes > limits.project_bytes) error = "A seleção excede o limite de 25 MB.";
    if (error) { state.pending = []; setStatus(error, "error"); }
    else {
      $("project-name").value = state.pending[0].path.split("/")[0];
      setStatus(`Seleção pronta. ${state.pending.length} arquivo(s) de código serão analisados.`, "");
      if (state.pending.length === 1) setEditor(await state.pending[0].file.text(), state.pending[0].path);
    }
    setMode("files");
    renderSelection();
  }
  async function loadDemo(secure = false, variant = "all") {
    if (state.busy) return;
    try {
      busy(true);
      $("run-scan").innerHTML = '<span class="spinner"></span><span>Carregando arquivos…</span>';
      const data = await api("/api/v1/samples?variant=" + encodeURIComponent(variant));
      busy(false);
      if (secure) {
        const file = data.files.find((item) => item.path.endsWith("secure_sample.py"));
        if (!file) throw new Error("Exemplo seguro indisponível.");
        setEditor(file.content, file.path);
        $("project-name").value = "Exemplo seguro";
        setMode("editor");
        setStatus("Exemplo seguro carregado. Clique em Executar análise.", "");
      } else {
        state.pending = data.files.map((item) => ({ path: item.path, file: new File([item.content], item.path.split("/").pop(), { type: "text/plain" }) }));
        state.ignored = 0;
        state.selectionType = "demo";
        $("project-name").value = data.project_name || "Projeto de demonstração";
        setMode("files");
        renderSelection();
        setStatus(`Projeto de exemplo carregado: ${state.pending.length} arquivos. Clique em Executar análise.`, "");
      }
    } catch (error) { busy(false); setStatus(error.message, "error"); }
  }
  function busy(value) {
    state.busy = value;
    ["file-upload", "folder-upload", "load-demo", "load-secure", "load-vulnerable", "load-corrected", "project-name", "gate-threshold", "code-filename", "code-language", "code-editor"].forEach((id) => { $(id).disabled = value; });
    ["choose-file", "choose-folder"].forEach((id) => $(id).setAttribute("aria-disabled", String(value)));
    document.querySelectorAll("[data-mode]").forEach((button) => { button.disabled = value; });
    $("dropzone").setAttribute("aria-busy", String(value));
    $("run-scan").innerHTML = value ? '<span class="spinner"></span><span>Analisando…</span>' : icon("scan") + "<span>Executar análise</span>";
    updateReady();
  }
  async function runScan() {
    if (state.busy) return;
    const project = $("project-name").value.trim();
    const threshold = $("gate-threshold").value;
    let path, options;
    if (state.mode === "editor") {
      const code = $("code-editor").value;
      if (!code.trim()) return;
      path = "/api/v1/scan/code";
      options = jsonOptions({ code, filename: $("code-filename").value.trim() || "snippet.py", project_name: project || null, gate_threshold: threshold });
    } else {
      if (!state.pending.length) return;
      const form = new FormData();
      form.append("project_name", project);
      form.append("gate_threshold", threshold);
      const single = state.selectionType === "file" && state.pending.length === 1;
      state.pending.forEach(({ file, path: filename }) => form.append(single ? "file" : "files", file, filename));
      path = single ? "/api/v1/scan/file" : "/api/v1/scan/project";
      options = { method: "POST", body: form };
    }
    busy(true);
    const started = Date.now();
    setStatus("Enviando fontes e executando as regras…", "loading", '<strong id="scan-elapsed">0 s</strong><progress aria-label="Análise em andamento"></progress>');
    const timer = setInterval(() => { if ($("scan-elapsed")) $("scan-elapsed").textContent = `${Math.floor((Date.now() - started) / 1000)} s`; }, 1000);
    try {
      let result = await api(path + "?queued=true", options);
      if (result.job_id) result = await waitForQueuedScan(result);
      state.active = result;
      savePreference("sast-active-scan", result.scan_id);
      resetFilters();
      await refreshHistory().catch(() => { toast("Análise concluída. O histórico não pôde ser atualizado agora.", true); });
      renderScanOptions();
      renderFindings();
      renderPolicy();
      setStatus(`Análise salva: ${result.scanned_files_count} arquivo(s), ${result.total_findings} achado(s).`, result.has_errors ? "error" : "success", '<button class="button secondary small-button" data-show-findings>Ver resultados</button>');
      toast(result.has_errors ? "Análise concluída com erros de processamento. Confira os detalhes." : `${result.scanned_files_count} arquivo(s) analisado(s) · ${result.total_findings} achado(s).`, result.has_errors);
      navigate("findings");
    } catch (error) { setStatus(error.message || "Falha de conexão com a API local.", "error"); }
    finally { clearInterval(timer); busy(false); }
  }

  async function waitForQueuedScan(job) {
    const deadline = Date.now() + 180000;
    let previous = "";
    while (Date.now() < deadline) {
      try {
        if (job.status === "completed") return await api("/api/v1/scans/" + encodeURIComponent(job.scan_id));
        if (job.status === "failed") throw new Error(job.error || "O worker não conseguiu concluir a análise.");
        if (job.status !== previous) {
          previous = job.status;
          setStatus(job.status === "queued" ? "Análise recebida na fila. Aguardando worker…" : "Worker executando os parsers e as regras…", "loading", '<strong id="scan-elapsed">0 s</strong><progress aria-label="Análise em fila"></progress>');
        }
        await new Promise((resolve) => setTimeout(resolve, 400));
        job = await api("/api/v1/jobs/" + encodeURIComponent(job.job_id));
      } catch (error) {
        if (!error.retryable) throw error;
        previous = "";
        setStatus("Conexão interrompida. Aguardando a API para consultar a análise já enviada…", "loading", '<strong id="scan-elapsed">0 s</strong>');
        await new Promise((resolve) => setTimeout(resolve, 2000));
      }
    }
    throw new Error("A análise continua na fila. Confira os workers em Integrações e tente consultar o histórico em alguns instantes.");
  }
  function filteredFindings() {
    const query = $("findings-search").value.trim().toLowerCase();
    const severity = $("severity-filter").value;
    const file = $("file-filter").value;
    const reviewFilter = $("semantic-filter").value;
    return (state.active?.findings || []).map((finding, index) => ({ finding, index })).filter(({ finding }) =>
      (!severity || finding.severity === severity) && (!file || finding.file_path === file) &&
      (!$("engine-filter")?.value || (finding.engines || ["native"]).includes($("engine-filter").value)) &&
      (!reviewFilter || (reviewFilter === "unreviewed" ? !semanticReviewFor(finding) : semanticReviewFor(finding)?.classification === reviewFilter)) &&
      (!query || [finding.rule_id, finding.rule_name, finding.file_path, finding.cwe, finding.message, finding.owasp?.id, finding.owasp?.name].join(" ").toLowerCase().includes(query))
    ).sort((a, b) => $("finding-sort").value === "file" ? a.finding.file_path.localeCompare(b.finding.file_path) || a.finding.line_number - b.finding.line_number :
      severityOrder.indexOf(a.finding.severity) - severityOrder.indexOf(b.finding.severity) || a.finding.file_path.localeCompare(b.finding.file_path) || a.finding.line_number - b.finding.line_number);
  }
  function engineRunsMarkup(scan) {
    const labels = { completed: "Concluído", skipped: "Não aplicável", unavailable: "Indisponível", timeout: "Tempo excedido", error: "Erro" };
    return (scan.engine_runs || []).length ? `<details class="engine-run-details"><summary>Execução dos motores · ${scan.engine_runs.length} registrado(s)</summary><div class="quality-table-wrap"><table class="quality-table"><thead><tr><th>Motor</th><th>Estado</th><th>Versão</th><th>Achados brutos</th><th>Tempo</th></tr></thead><tbody>${scan.engine_runs.map(run => `<tr><td>${escape(run.engine)}</td><td>${escape(labels[run.status] || run.status)}</td><td>${escape(run.version || "—")}</td><td>${number(run.findings_count)}</td><td>${duration(run.duration_ms)}</td></tr>`).join("")}</tbody></table></div><p class="field-help">Evidências do mesmo ponto de risco podem ser unidas. Os achados brutos por motor não são somados ao total.</p></details>` : "";
  }
  function renderFindings() {
    const scan = state.active;
    $("export-button").disabled = !scan;
    if (!scan) {
      $("findings-subtitle").textContent = "Execute uma análise para começar a triagem.";
      $("findings-summary").innerHTML = "";
      $("findings-filters").hidden = true;
      $("findings-list").innerHTML = empty("Sem resultados", "Os achados da análise aparecerão aqui.", "", true);
      $("filtered-count").textContent = "0 achados";
      $("finding-pagination").innerHTML = "";
      $("finding-detail").innerHTML = empty("Pronto para analisar", "Carregue uma pasta, um arquivo ou um trecho de código no Scanner.", '<a class="button primary" href="#scanner">Nova análise</a>');
      renderBatchAI(null);
      return;
    }
    $("findings-filters").hidden = false;
    $("findings-subtitle").textContent = `${scan.project_name} · #${scan.scan_id.slice(0, 8)} · ${date(scan.created_at)}`;
    $("nav-findings-count").textContent = number(scan.total_findings);
    const suggestionNotice = scan.project_name?.startsWith("Sugestão ·") ? '<div class="suggestion-scan-notice"><strong>Validação de uma correção sugerida pela IA.</strong> Este resultado verifica somente o código da sugestão. Para ver os achados originais, escolha a análise do projeto no seletor acima.</div>' : "";
    $("findings-summary").innerHTML = `<div class="scan-summary-bar"><div class="summary-left">${gateBadge(scan.security_gate)}<span>${number(scan.scanned_files_count)} arquivo(s) · ${duration(scan.scan_duration_ms)} · Gate ≥ ${severityLabels[scan.security_gate.threshold]}</span></div><div class="summary-counts">${severityOrder.slice(0, 4).map((severity) => `<span><i class="severity-dot ${severity.toLowerCase()}"></i>${number(scan.summary_by_severity[severity])}</span>`).join("")}</div></div>${suggestionNotice}${engineRunsMarkup(scan)}${scan.has_errors ? `<details class="processed-error-list" open><summary>Erros de processamento (${scan.errors.length}) — esta análise não foi aprovada</summary>${scan.errors.map((error) => escape(error)).join("<br>")}</details>` : ""}`;
    const items = filteredFindings();
    state.page = Math.min(state.page, Math.max(0, Math.ceil(items.length / state.pageSize) - 1));
    $("filtered-count").textContent = `${number(items.length)} de ${number(scan.total_findings)} achados`;
    const pageItems = items.slice(state.page * state.pageSize, (state.page + 1) * state.pageSize);
    if (!pageItems.some(({ index }) => index === state.selected)) state.selected = pageItems[0]?.index ?? null;
    const scroll = $("findings-list").scrollTop;
    $("findings-list").innerHTML = pageItems.length ? pageItems.map(({ finding, index }) => `<button class="finding-row ${state.selected === index ? "selected" : ""}" data-finding="${index}" aria-pressed="${state.selected === index}"><span class="finding-row-top">${severityBadge(finding.severity)}<code class="rule-code">${escape(finding.rule_id)}</code>${owaspBadge(finding.owasp, false)}</span><strong>${escape(finding.rule_name)}</strong><span class="finding-row-path" title="${escape(finding.file_path)}:${finding.line_number}">${icon("file")}${escape(finding.file_path)}:${finding.line_number}</span></button>`).join("") : empty(scan.total_findings ? "Nenhum resultado no filtro" : scan.has_errors ? "Análise incompleta" : "Nenhum achado", scan.total_findings ? "Tente outro termo ou limpe os filtros." : scan.has_errors ? "Confira os erros de processamento acima." : "Nenhuma regra detectou um problema no código analisado.", "", true);
    $("findings-list").scrollTop = scroll;
    $("finding-pagination").innerHTML = items.length > state.pageSize ? `<div class="pagination"><button data-page="-1" ${state.page === 0 ? "disabled" : ""}>Anterior</button><span>${state.page + 1} / ${Math.ceil(items.length / state.pageSize)}</span><button data-page="1" ${(state.page + 1) * state.pageSize >= items.length ? "disabled" : ""}>Próxima</button></div>` : "";
    renderBatchAI(scan);
    renderDetail();
  }
  function renderBatchAI(scan) {
    const toolbar = $("batch-ai-toolbar");
    const button = $("generate-all-ai");
    const status = $("ai-batch-status");
    if (!toolbar || !button || !status) return;
    toolbar.hidden = !scan;
    if (!scan) { button.disabled = true; status.hidden = true; return; }
    const findings = scan.findings || [];
    const completed = findings.reduce((total, _, index) => total + Number(state.aiResults.has(`${scan.scan_id}:${index}`)), 0);
    const pending = state.aiBatch?.scanId === scan.scan_id && !state.aiBatch.finished;
    button.disabled = findings.length === 0 || pending || Boolean(state.aiBusy || state.semanticBusy);
    button.textContent = pending ? `Gerando ${Math.min(state.aiBatch.completed + 1, state.aiBatch.total)} de ${state.aiBatch.total}…` :
      completed > 0 && completed < findings.length ? `Gerar correções restantes (${findings.length - completed})` :
        completed === findings.length && findings.length > 0 ? `Gerar novamente (${findings.length})` : `Gerar correções com IA (${findings.length})`;
    const batch = state.aiBatch?.scanId === scan.scan_id ? state.aiBatch : null;
    status.hidden = !batch;
    status.dataset.state = batch && !batch.finished ? "running" : "complete";
    if (!batch) { status.textContent = ""; renderBatchAIResults(scan, null); return; }
    if (!batch.finished) {
      const current = batch.current ? `${batch.current.rule_id} · ${batch.current.file_path}` : "preparando a fila";
      status.textContent = `A IA está gerando sugestões individuais: ${batch.completed} de ${batch.total} concluídas. Agora: ${current}. Os arquivos originais não são alterados.`;
    } else {
      const ollama = batch.ollama || 0;
      const fallback = batch.fallback || 0;
      const errors = batch.errors || 0;
      status.textContent = `${batch.completed} de ${batch.total} achados processados: ${ollama} resposta(s) do Ollama, ${fallback} fallback(s) identificados e ${errors} falha(s). As correções sugeridas aparecem abaixo, juntas e com seus diffs.`;
    }
    renderBatchAIResults(scan, batch);
  }
  function renderBatchAIResults(scan, batch) {
    const panel = $("ai-batch-results");
    if (!panel) return;
    if (!scan) { panel.hidden = true; panel.innerHTML = ""; return; }
    const failures = batch?.scanId === scan.scan_id ? (batch.failures || []) : [];
    const rows = (scan.findings || []).map((finding, index) => ({
      finding, index,
      result: state.aiResults.get(`${scan.scan_id}:${index}`),
      failure: failures.find((item) => item.index === index),
    })).filter((row) => row.result || row.failure);
    if (!rows.length) { panel.hidden = true; panel.innerHTML = ""; return; }
    const suggestions = rows.filter((row) => row.result).length;
    const failed = rows.filter((row) => row.failure).length;
    const heading = batch && !batch.finished
      ? `${suggestions} de ${number(scan.findings.length)} sugestões já aparecem aqui; a geração continua.`
      : `${suggestions} correção(ões) sugerida(s) de ${number(scan.findings.length)} achado(s)${failed ? ` · ${failed} falha(s)` : ""}.`;
    panel.hidden = false;
    panel.innerHTML = `<div class="batch-results-heading"><div><span class="eyebrow">REVISÃO EM LOTE</span><h2 id="ai-batch-results-title">Correções sugeridas pela IA</h2><p>${heading} Cada proposta precisa ser revisada; os arquivos originais continuam intactos.</p></div><span class="batch-results-count">${number(suggestions)}<small>/${number(scan.findings.length)}</small></span></div><div class="batch-results-grid">${rows.map((row) => renderBatchAIResultCard(row)).join("")}</div>`;
  }
  function renderBatchAIResultCard({ finding, index, result, failure }) {
    const realModel = result && (result.provider === "ollama" || result.model_used?.startsWith("Ollama ("));
    const manualReview = result?.patch_scope === "manual_review";
    const diff = String(result?.diff || "");
    const diffLines = diff.split("\n").map((line) => `<div class="diff-line ${line.startsWith("+") ? "add" : line.startsWith("-") ? "remove" : ""}">${escape(line) || " "}</div>`).join("");
    const generatedMarkup = manualReview
      ? `<div class="batch-result-failure"><strong>Patch não gerado — revisão necessária</strong><br>${escape(result.remediation_steps)}</div>`
      : `<div class="ai-result-label">${result.patch_scope === "file" ? "Arquivo com a correção sugerida" : "Sugestão de correção"}</div><pre class="batch-result-code">${escape(result.suggested_patch)}</pre><div class="batch-result-actions"><button class="button secondary" data-copy-batch-patch="${index}">${icon("copy")}Copiar correção</button><button class="button secondary" data-download-batch-patch="${index}">${icon("download")}Baixar diff</button><button class="button subtle" data-validate-batch-patch="${index}">${icon("scan")}Analisar sugestão</button></div><details class="diff-details"><summary>Ver diff deste achado</summary><div class="diff-code">${diffLines}</div></details><div class="ai-result-label">Orientações para aplicar</div><p class="ai-text">${escape(result.remediation_steps)}</p>${patchValidationMarkup(result)}`;
    return `<article class="batch-result-card ${failure && !result ? "failed" : ""}"><div class="batch-result-card-heading"><div class="batch-result-tags">${severityBadge(finding.severity)}<code>${escape(finding.rule_id)}</code><span class="provider-tag ${realModel ? "" : "fallback"}">${result ? `${icon(realModel ? "spark" : "rules", "small")}${escape(result.model_used)}` : "Falha na geração"}</span></div><h3>${escape(finding.rule_name)}</h3><p>${icon("file")}${escape(finding.file_path)}<strong> : ${finding.line_number}</strong></p></div>${result ? `<div class="batch-result-card-body"><div class="ai-result-label">Entenda o risco</div><p class="ai-text">${escape(result.risk_analysis)}</p>${generatedMarkup}${result.fallback_reason ? `<p class="field-help">${escape(result.fallback_reason)}</p>` : ""}${failure ? `<div class="batch-result-failure">A nova tentativa falhou; a sugestão anterior continua disponível. ${escape(failure.message)}</div>` : ""}</div>` : `<div class="batch-result-failure">${escape(failure.message || "Não foi possível gerar esta sugestão. Você pode tentar novamente pelo botão acima.")}</div>`}</article>`;
  }
  function sourceMarkup(finding) {
    const key = state.active.scan_id + ":" + finding.file_path;
    const source = state.sources.get(key);
    const lines = source ? source.split(/\r?\n/) : finding.code_snippet.split(/\r?\n/);
    const start = source ? Math.max(0, finding.line_number - 5) : Math.max(0, finding.line_number - 1);
    const context = source ? lines.slice(start, finding.line_number + 4) : lines;
    return `<div class="source-code" aria-label="Trecho de código em ${escape(finding.file_path)}">${context.map((line, index) => `<div class="source-line ${start + index + 1 === finding.line_number ? "highlight" : ""}"><span class="line-number">${start + index + 1}</span><code>${escape(line) || " "}</code></div>`).join("")}</div>`;
  }
  async function loadSource(finding) {
    const id = state.active.scan_id;
    const index = state.selected;
    const key = id + ":" + finding.file_path;
    if (state.sources.has(key)) return;
    state.sources.set(key, null);
    try {
      const data = await api(`/api/v1/scans/${encodeURIComponent(id)}/source?path=${encodeURIComponent(finding.file_path)}`);
      state.sources.set(key, data.content);
      if (state.active?.scan_id === id && state.selected === index) renderDetail();
    } catch { /* the finding snippet remains available */ }
  }
  function findingKey() { return state.active ? state.active.scan_id + ":" + state.selected : ""; }
  function semanticReviewFor(finding) {
    return (state.active?.semantic_reviews || []).find((item) => item.rule_id === finding.rule_id && item.file_path === finding.file_path && item.line_number === finding.line_number && item.column_number === finding.column_number);
  }
  function renderDetail() {
    const finding = state.active?.findings[state.selected];
    if (!finding) {
      $("finding-detail").innerHTML = empty(state.active?.has_errors ? "Confira os erros de processamento" : state.active?.total_findings ? "Selecione um achado" : "Análise concluída sem achados", state.active?.has_errors ? "Arquivos com erro não contam como analisados com sucesso." : "Os detalhes de arquivo, linha e remediação ficam disponíveis ao selecionar um achado.", '<a class="button secondary" href="#scanner">Voltar ao Scanner</a>');
      return;
    }
    const key = findingKey();
    const result = state.aiResults.get(key);
    const pending = state.aiBusy?.key === key;
    const cweId = /^CWE-(\d+)$/.exec(finding.cwe)?.[1];
    $("finding-detail").innerHTML = `<div class="detail-heading"><div class="detail-tags">${severityBadge(finding.severity)}<code>${escape(finding.rule_id)}</code><span class="outline-tag">${escape(finding.cwe)}</span>${owaspBadge(finding.owasp)}</div><h2>${escape(finding.rule_name)}</h2><div class="detail-location">${icon("file")}<span>${escape(finding.file_path)}<strong> : ${finding.line_number}</strong></span></div></div><div class="detail-body"><p class="detail-description">${escape(finding.message)}</p><div class="detail-section-title"><span>Trecho de código</span><button class="icon-button" data-copy-snippet aria-label="Copiar trecho de código">${icon("copy")}</button></div>${sourceMarkup(finding)}${detectionEvidenceMarkup(finding)}<div class="detail-section-title">Orientação da regra</div><div class="remediation-advice">${escape(finding.remediation_advice)}</div><div class="detail-meta-row"><span>Regra ${escape(finding.rule_id)} · Coluna ${finding.column_number + 1}</span>${cweId ? `<a class="text-link" href="https://cwe.mitre.org/data/definitions/${cweId}.html" target="_blank" rel="noopener">Consultar ${escape(finding.cwe)} ${icon("external", "small")}</a>` : ""}</div>${semanticMarkup(finding, key)}<section class="ai-section"><div class="ai-heading"><div><h3>${icon("spark")}Remediação assistida</h3><p>Sugestão de correção para revisão</p></div><button class="button primary small-button ai-generate" data-generate-ai ${state.aiBusy || state.semanticBusy ? "disabled" : ""}>${pending ? '<span class="spinner"></span>Gerando…' : state.aiBusy || state.semanticBusy ? "IA em uso" : result ? "Gerar novamente" : icon("spark") + "Gerar remediação"}</button></div><div class="ai-body" id="ai-body">${pending ? '<div class="ai-loading">Consultando o modelo local…<p>O primeiro uso pode levar até 90 segundos para carregar o modelo e gerar a resposta.</p><progress aria-label="Gerando remediação"></progress></div>' : result ? renderAI(result, key) : '<p class="field-help">Ollama pode propor uma correção contextual. Um validador independente verifica critérios da regra; quando não é possível comprovar uma mudança segura, a tela exige revisão manual e não oferece diff.</p>'}</div></section></div>`;
    loadSource(finding);
  }
  function semanticExtras(review) {
    const conditions = review.exploit_conditions || [];
    return `${conditions.length ? `<div class="ai-result-label">Condições necessárias para exploração</div><ul class="semantic-conditions">${conditions.map(item => `<li>${escape(item)}</li>`).join("")}</ul>` : ""}${review.remediation_recommendation ? `<div class="ai-result-label">Recomendação técnica</div><p class="ai-text">${escape(review.remediation_recommendation)}</p>` : ""}${(review.analysis_limitations || []).map(item => `<p class="field-help">${escape(item)}</p>`).join("")}${(review.validation_adjustments || []).map(item => `<p class="field-help">${escape(item)}</p>`).join("")}${review.validation_adjustments?.length && review.model_decision ? `<details class="semantic-original"><summary>Resposta original do modelo antes da validação</summary><p class="ai-text">${escape(review.model_decision.reasoning)}</p><p class="field-help">${escape(review.model_decision.classification)} · ${escape(review.model_decision.suggested_severity)}</p></details>` : ""}`;
  }
  function semanticMarkup(finding, key) {
    const review = semanticReviewFor(finding);
    const pending = state.semanticBusy?.key === key;
    const labels = { confirmed: "Risco confirmado", likely_false_positive: "Possível falso positivo", needs_review: "Potencial — requer validação" };
    const confidence = { high: "Alta", medium: "Média", low: "Baixa" };
    const source = state.sources.get(state.active.scan_id + ":" + finding.file_path)?.split(/\r?\n/) || [];
    const body = pending ? '<div class="ai-loading">Analisando contexto, severidade e possíveis falsos positivos…<progress aria-label="Revisão semântica em andamento"></progress></div>' : review ? `<span class="provider-tag ${review.provider === "ollama" ? "" : "fallback"}">${escape(review.model_used)}</span><div class="semantic-verdict ${escape(review.classification)}">${escape(labels[review.classification])}</div><p class="ai-text">${escape(review.reasoning)}</p>${semanticExtras(review)}${review.evidence_lines.length ? `<div class="semantic-severity"><span>Regra: ${severityBadge(review.original_severity)}</span><span>Revisão sugere: ${severityBadge(review.suggested_severity)}</span><span>Confiança: ${escape(confidence[review.confidence])}</span></div><div class="semantic-evidence">${review.evidence_lines.map((line) => `<div><strong>Linha ${line}</strong><code>${escape(source[line - 1] || "Fonte disponível no histórico")}</code></div>`).join("")}</div>` : ""}${review.provider !== "ollama" && review.fallback_reason ? `<p class="field-help">${escape(review.fallback_reason)}</p>` : ""}<p class="field-help">Revisão salva em ${date(review.created_at)}. O achado original e o gate foram preservados.</p>` : '<p class="field-help">A IA avalia o contexto e pode recomendar outra severidade ou indicar um possível falso positivo. A revisão fica registrada para conferência.</p>';
    return `<section class="ai-section semantic-section"><div class="ai-heading"><div><h3>${icon("spark")}Revisão semântica</h3><p>Contexto, severidade e falsos positivos</p></div><button class="button primary small-button ai-generate" data-review-semantic ${state.semanticBusy || state.aiBusy ? "disabled" : ""}>${pending ? "Analisando…" : review ? "Revisar novamente" : "Revisar com IA"}</button></div><div class="ai-body">${body}</div></section>`;
  }
  async function reviewSemantic() {
    if (state.aiBusy || state.semanticBusy || (state.aiBatch && !state.aiBatch.finished) || state.selected === null) return;
    const finding = state.active.findings[state.selected];
    const scanId = state.active.scan_id;
    const key = findingKey();
    state.semanticBusy = { key };
    renderDetail();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 110000);
    try {
      const review = await api("/api/v1/triage", { ...jsonOptions({ ...finding, scan_id: scanId }), signal: controller.signal });
      if (state.active?.scan_id === scanId) state.active.semantic_reviews = [review, ...(state.active.semantic_reviews || [])];
      toast(review.provider === "ollama" ? "Revisão semântica salva no histórico." : "A IA não concluiu a triagem. Confira o motivo exibido.", review.provider !== "ollama");
    } catch (error) { toast(error.name === "AbortError" ? "A revisão excedeu o tempo de resposta." : error.message, true); }
    finally { clearTimeout(timer); state.semanticBusy = null; renderFindings(); }
  }
  function validationSummary(validation) {
    if (validation.has_errors) return "Há erros de processamento na sugestão. Confira os detalhes antes de aplicar.";
    const rule = state.active?.findings[state.selected]?.rule_id;
    const remaining = (validation.findings || []).filter((finding) => finding.rule_id === rule).length;
    if (remaining) return `${validation.total_findings} achado(s) na sugestão. A regra ${rule} ainda foi detectada.`;
    if (validation.total_findings) return `A regra ${rule} não foi detectada na sugestão. ${validation.total_findings} achado(s) de outras regras permanecem.`;
    return "0 achado(s) na varredura estática da sugestão.";
  }
  function renderAI(result, key) {
    const realModel = result.provider === "ollama" || result.model_used.startsWith("Ollama (");
    const validation = state.validations.get(key);
    if (result.patch_scope === "manual_review") {
      return `<span class="provider-tag fallback">${icon("rules", "small")}${escape(result.model_used)}</span>${result.fallback_reason ? `<p class="field-help">${escape(result.fallback_reason)}</p>` : ""}<div class="ai-result-label">Entenda o risco</div><p class="ai-text">${escape(result.risk_analysis)}</p><div class="validation-result error"><strong>Patch não gerado — revisão necessária</strong><br>${escape(result.remediation_steps)}</div>${patchValidationMarkup(result)}`;
    }
    return `<span class="provider-tag ${realModel ? "" : "fallback"}">${icon(realModel ? "spark" : "rules", "small")}${escape(result.model_used)}</span>${result.fallback_reason ? `<p class="field-help">${escape(result.fallback_reason)}</p>` : ""}<div class="ai-result-label">Entenda o risco</div><p class="ai-text">${escape(result.risk_analysis)}</p><div class="ai-result-label">${result.patch_scope === "file" ? "Arquivo com a correção sugerida" : "Sugestão de correção"}</div><pre class="ai-code">${escape(result.suggested_patch)}</pre><div class="ai-actions"><button class="button secondary" data-copy-patch>${icon("copy")}Copiar sugestão</button><button class="button secondary" data-download-patch>${icon("download")}Baixar .patch</button><button class="button subtle" data-validate-patch ${validation?.loading ? "disabled" : ""}>${icon("scan")}${validation?.loading ? "Verificando…" : "Analisar sugestão"}</button></div><details class="diff-details"><summary aria-haspopup="dialog">Ver alterações (diff)</summary><div class="diff-code" data-diff="${escape(result.diff)}">${result.diff.split("\n").map((line) => `<div class="diff-line ${line.startsWith("+") ? "add" : line.startsWith("-") ? "remove" : ""}">${escape(line) || " "}</div>`).join("")}</div></details><div class="ai-result-label">Orientações para aplicar</div><p class="ai-text">${escape(result.remediation_steps)}</p>${patchValidationMarkup(result)}${validation && !validation.loading ? `<div class="validation-result ${validation.has_errors || validation.total_findings ? "error" : ""}">${validation.error ? escape(validation.error) : `${escape(validationSummary(validation))}<br><a class="text-link" href="#findings" data-open-scan="${escape(validation.scan_id)}">Ver análise da sugestão →</a>`}</div>` : ""}`;
  }
  async function generateAI() {
    if (state.aiBusy || state.semanticBusy || (state.aiBatch && !state.aiBatch.finished) || state.selected === null) return;
    const finding = state.active.findings[state.selected];
    const key = findingKey();
    const source = state.sources.get(state.active.scan_id + ":" + finding.file_path);
    const context = source ? source.split(/\r?\n/).slice(Math.max(0, finding.line_number - 6), finding.line_number + 5).join("\n") : null;
    state.aiBusy = { key, started: Date.now() };
    renderDetail();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 110000);
    try {
      const result = await api("/api/v1/remediate", { ...jsonOptions({ ...finding, original_code: context, scan_id: state.active.scan_id }), signal: controller.signal });
      state.aiResults.set(key, result);
      if (findingKey() !== key) toast("Remediação pronta para " + finding.rule_id + ".");
    } catch (error) {
      toast(error.name === "AbortError" ? "O modelo excedeu o tempo de resposta. Confira o serviço Ollama em Integrações." : error.message, true);
    } finally {
      clearTimeout(timeout);
      state.aiBusy = null;
      renderDetail();
      refreshServices(true);
    }
  }
  async function generateAllAI() {
    const scan = state.active;
    if (!scan || !scan.findings.length || state.aiBusy || state.semanticBusy || (state.aiBatch && !state.aiBatch.finished)) return;
    const scanId = scan.scan_id;
    let queue = scan.findings.map((finding, index) => ({ finding, index, key: `${scanId}:${index}` }))
      .filter((item) => !state.aiResults.has(item.key));
    if (!queue.length) queue = scan.findings.map((finding, index) => ({ finding, index, key: `${scanId}:${index}` }));
    const batch = state.aiBatch = { scanId, total: queue.length, completed: 0, ollama: 0, fallback: 0, errors: 0, current: null, currentIndex: null, failures: [], finished: false };
    renderFindings();
    for (const item of queue) {
      if (state.active?.scan_id !== scanId) break;
      batch.current = item.finding;
      batch.currentIndex = item.index;
      state.aiBusy = { key: item.key, started: Date.now(), batch: true };
      renderFindings();
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 110000);
      try {
        const result = await api("/api/v1/remediate", { ...jsonOptions({ ...item.finding, scan_id: scanId }), signal: controller.signal });
        state.aiResults.set(item.key, result);
        if (result.provider === "ollama" || result.model_used?.startsWith("Ollama (")) batch.ollama += 1;
        else batch.fallback += 1;
      } catch (error) {
        batch.errors += 1;
        batch.failures.push({ index: item.index, message: error.name === "AbortError" ? "O modelo excedeu o tempo limite. Tente gerar esta correção novamente." : error.message });
        toast(`${item.finding.rule_id}: ${error.name === "AbortError" ? "o modelo excedeu o tempo limite" : error.message}`, true);
      } finally {
        clearTimeout(timeout);
        state.aiBusy = null;
        batch.completed += 1;
        renderFindings();
      }
    }
    batch.current = null;
    batch.currentIndex = null;
    batch.finished = true;
    renderFindings();
    if (state.active?.scan_id === scanId) {
      $("ai-batch-results")?.scrollIntoView({ block: "start", behavior: "smooth" });
      toast(`${batch.completed} de ${batch.total} achados processados pela remediação assistida.`, batch.errors > 0);
      refreshServices(true);
    }
  }
  async function validatePatch() {
    const key = findingKey();
    const ai = state.aiResults.get(key);
    const finding = state.active?.findings[state.selected];
    if (!ai || !finding || state.validations.get(key)?.loading) return;
    state.validations.set(key, { loading: true });
    renderDetail();
    try {
      const result = await api("/api/v1/scan/code", jsonOptions({ code: ai.suggested_patch, filename: finding.file_path.split("/").pop(), project_name: `Sugestão · ${finding.rule_id}`, gate_threshold: state.active.security_gate.threshold }));
      state.validations.set(key, result);
      await refreshHistory();
    } catch (error) { state.validations.set(key, { error: error.message, has_errors: true }); }
    if (findingKey() === key) renderDetail();
  }
  function openBatchFinding(index) {
    if (!state.active?.findings[index]) return false;
    $("findings-search").value = "";
    $("severity-filter").value = "";
    $("file-filter").value = "";
    $("semantic-filter").value = "";
    state.page = 0;
    state.selected = index;
    const position = filteredFindings().findIndex((item) => item.index === index);
    if (position >= 0) state.page = Math.floor(position / state.pageSize);
    renderFindings();
    $("finding-detail").scrollIntoView({ block: "start", behavior: "smooth" });
    return true;
  }
  async function validateBatchPatch(index) {
    if (openBatchFinding(index)) await validatePatch();
  }
  function downloadText(text, filename, type = "text/plain") {
    const url = URL.createObjectURL(new Blob([text], { type }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  async function copy(text) {
    try {
      if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(text);
      else {
        const input = document.createElement("textarea");
        input.value = text;
        document.body.append(input);
        input.select();
        const success = document.execCommand("copy");
        input.remove();
        if (!success) throw new Error("Acesso à área de transferência indisponível.");
      }
      toast("Copiado para a área de transferência.");
    } catch { toast("Não foi possível copiar automaticamente. Selecione e copie o texto exibido.", true); }
  }
  function exportReport(format) {
    if (!state.active) return;
    const anchor = document.createElement("a");
    anchor.href = `/api/v1/scans/${encodeURIComponent(state.active.scan_id)}/report?format=${format}`;
    anchor.download = "";
    anchor.click();
    $("export-menu").hidden = true;
    $("export-button").setAttribute("aria-expanded", "false");
  }

  function detectionEvidenceMarkup(finding) {
    const confidence = { high: "Alta", medium: "Média", low: "Baixa" }[finding.confidence] || "Não medida";
    const engines = finding.engines || ["native"];
    const steps = finding.data_flow || [];
    const labels = { source: "Entrada", propagation: "Propagação", sink: "Operação sensível" };
    return `<section class="detection-evidence"><div class="evidence-heading"><strong>Evidências da detecção</strong><span class="outline-tag">Confiança: ${escape(confidence)}</span></div><div class="engine-tags">${engines.map(engine => `<span class="engine-tag">${escape(engine === "native" ? "Motor nativo" : engine)}</span>`).join("")}</div><p class="field-help">${steps.length ? "Fluxo local rastreado pelo motor estático." : "Padrão de risco identificado. Um caminho completo de entrada até esta operação não foi comprovado."}</p>${steps.length ? `<ol class="data-flow-list">${steps.map(step => `<li><span>${escape(labels[step.role] || step.role)}</span><small>${escape(step.file_path)}:${step.line_number}</small><code>${escape(step.code_snippet)}</code></li>`).join("")}</ol>` : ""}${(finding.evidence || []).length > 1 ? `<details><summary>${finding.evidence.length} evidências preservadas</summary><ul>${finding.evidence.map(item => `<li><strong>${escape(item.engine)} · ${escape(item.rule_id)}</strong><p>${escape(item.message)}</p></li>`).join("")}</ul></details>` : ""}${(finding.limitations || []).map(item => `<p class="field-help">${escape(item)}</p>`).join("")}</section>`;
  }
  function patchValidationMarkup(result) {
    const validation = result.validation;
    if (!validation) return "";
    const labels = { passed: "Passou", failed: "Rejeitado", not_run: "Não executado" };
    return `<section class="patch-checks"><strong>${validation.status === "passed" ? "Verificações estáticas concluídas" : "Patch rejeitado"}</strong><ul>${(validation.checks || []).map(check => `<li><span class="check-result ${escape(check.status)}">${escape(labels[check.status] || check.status)}</span><span>${escape(check.name)}<small>${escape(check.detail || "")}</small></span></li>`).join("")}</ul>${(validation.limitations || []).map(text => `<p class="field-help">${escape(text)}</p>`).join("")}</section>`;
  }
  function renderQuality() {
    const node = $("quality-dashboard");
    if (!node) return;
    const q = state.quality;
    if (!q || q.status === "unavailable") { node.innerHTML = '<p class="field-help">Métricas ainda não foram geradas nesta instalação. Consulte o relatório de validação do projeto.</p>'; return; }
    const pct = value => Number.isFinite(value) ? `${(value * 100).toLocaleString("pt-BR", {minimumFractionDigits:1,maximumFractionDigits:1})}%` : "—";
    const external = q.owasp_benchmark;
    node.innerHTML = `<div class="panel-heading"><div><h2>Cobertura e qualidade medida</h2><p>Motor nativo · corpus curado · ${number(q.case_count)} casos, ${number(q.safe_cases)} controles seguros</p></div><span class="outline-tag">${q.status === "current" ? "Medição atual" : "Medição anterior — motor alterado"}</span></div><div class="panel-body"><div class="quality-metrics"><div><small>Regras exercitadas</small><strong>${number(q.rules_exercised)} / ${number(q.rule_count)}</strong></div><div><small>Precisão no corpus</small><strong>${pct(q.precision)}</strong></div><div><small>Recall no corpus</small><strong>${pct(q.recall)}</strong></div><div><small>Erros no corpus</small><strong>${number(q.false_positives)} FP · ${number(q.false_negatives)} FN</strong></div></div><div class="quality-table-wrap"><table class="quality-table"><thead><tr><th>Linguagem</th><th>TP</th><th>FP</th><th>FN</th><th>Precisão</th><th>Recall</th></tr></thead><tbody>${Object.entries(q.by_language || {}).map(([name,item]) => `<tr><td>${escape(languageLabels[name] || name)}</td><td>${number(item.true_positives)}</td><td>${number(item.false_positives)}</td><td>${number(item.false_negatives)}</td><td>${pct(item.precision)}</td><td>${pct(item.recall)}</td></tr>`).join("")}</tbody></table></div><p class="field-help">${escape(q.scope)} A confiança de um achado é uma estimativa do motor e não uma probabilidade calibrada.</p>${external ? `<div class="external-benchmark"><strong>OWASP BenchmarkJava · avaliação externa</strong><p id="owasp-measured-summary"></p></div>` : ""}<details class="coverage-details"><summary>Detalhar métricas por CWE</summary><div class="quality-table-wrap"><table class="quality-table"><thead><tr><th>CWE</th><th>TP</th><th>FP</th><th>FN</th><th>Recall</th></tr></thead><tbody>${Object.entries(q.by_cwe || {}).map(([cwe,item]) => `<tr><td>${escape(cwe)}</td><td>${number(item.true_positives)}</td><td>${number(item.false_positives)}</td><td>${number(item.false_negatives)}</td><td>${pct(item.recall)}</td></tr>`).join("")}</tbody></table></div></details><p class="field-help">Gerado em ${date(q.generated_at)}. Casos controlados ajudam a detectar regressões; uma avaliação externa testa cenários diferentes.</p></div>`;
    if (external) {
      const metrics = external.metrics || external;
      const summary = $("owasp-measured-summary");
      const precision = metrics.precision;
      const recall = metrics.recall;
      summary.textContent = Number.isFinite(precision) && Number.isFinite(recall)
        ? `Precisão: ${pct(precision)} · Recall: ${pct(recall)}. A avaliação externa mostra limitações de fluxo de dados e falsos positivos; o corpus curado não representa cobertura universal.`
        : "Avaliação completa disponível no relatório docs/quality/owasp-native-results.md, incluindo erros e limitações por CWE.";
    }
  }
  function renderEngines() {
    const node = $("engine-status-grid");
    if (!node) return;
    node.innerHTML = (state.engineStatus || []).map(item => `<article class="engine-status-card"><div><strong>${escape(item.engine === "native" ? "Motor nativo" : item.engine)}</strong><span class="outline-tag">${item.enabled ? item.available ? "Ativo" : "Solicitado · indisponível" : "Opcional · desativado"}</span></div><p>${item.available ? "Versão " + escape(item.version || "instalada") : "Dependência não instalada"}</p><small>${item.engine === "native" ? "AST e regras por linguagem" : item.engine === "bandit" ? "Regras especializadas em Python" : "Regras locais e taint analysis da Community Edition"}</small></article>`).join("");
  }
  function renderRules() {
    renderQuality();
    $("rules-count").textContent = `${state.rules.length} regras ativas`;
    $("language-coverage").innerHTML = (state.capabilities?.languages || []).map((language) => {
      const prefix = { python: "PY", javascript: "JS", java: "JAVA" }[language.id];
      const count = state.rules.filter((rule) => rule.rule_id.split("-")[0] === prefix).length;
      return `<div class="coverage-card"><h3>${escape(language.name)}<span>${count} regras</span></h3><p>${escape(language.technique)}</p><div class="language-tags">${language.extensions.map((extension) => `<code class="language-tag">${escape(extension)}</code>`).join("")}</div></div>`;
    }).join("");
    const query = $("rules-search").value.trim().toLowerCase();
    const language = $("rule-language-filter").value;
    const rules = state.rules.filter((rule) => (!language || rule.rule_id.split("-")[0] === language) && (!query || [rule.rule_id, rule.name, rule.description, rule.cwe, rule.owasp?.id, rule.owasp?.name].join(" ").toLowerCase().includes(query)));
    $("rules-list").innerHTML = rules.length ? rules.map((rule) => `<article class="rule-card"><div class="rule-card-top"><code>${escape(rule.rule_id)} · ${escape(rule.cwe)}</code>${severityBadge(rule.severity)}</div><div class="rule-owasp">${owaspBadge(rule.owasp)}</div><h3>${escape(rule.name)}</h3><p>${escape(rule.description)}</p><details><summary>Ver orientação de remediação</summary><p>${escape(rule.remediation)}</p></details></article>`).join("") : empty("Nenhuma regra encontrada", "Tente outro termo ou linguagem.", "", true);
  }
  function renderHealth() {
    const healthy = state.health?.status === "healthy";
    const checking = connectionSnapshot?.status === "checking";
    $("api-status").innerHTML = `<span class="status-dot ${checking ? "pending" : healthy ? "" : "offline"}"></span>${checking ? "Verificando API" : healthy ? "API conectada" : "Reconectando API"}`;
    const ai = state.aiStatus;
    $("ai-status-label").textContent = ai?.model_available ? "Ollama disponível" : ai?.service_available ? "Modelo ausente" : "IA indisponível";
  }
  function renderServices() {
    renderEngines();
    const ai = state.aiStatus;
    const healthy = state.health?.status === "healthy";
    $("service-cards").innerHTML = `<div class="service-card"><div class="service-card-top"><strong>API de análise</strong><span class="outline-tag"><span class="status-dot ${healthy ? "" : "offline"}"></span>${healthy ? "Conectada" : "Indisponível"}</span></div><h3>${healthy ? escape(state.health.active_rules) + " regras ativas" : "Sem conexão"}</h3><p>FastAPI · ${healthy ? "v" + escape(state.health.version) : "Verifique o servidor local"}</p></div><div class="service-card"><div class="service-card-top"><strong>Remediação local</strong><span class="outline-tag"><span class="status-dot ${ai?.model_available ? "" : "pending"}"></span>${ai?.model_available ? "Disponível" : "Fallback disponível"}</span></div><h3>${escape(ai?.model || "Ollama")}</h3><p>${ai?.model_loaded ? "Modelo carregado em memória" : ai?.model_available ? "Modelo instalado · carrega no primeiro uso" : ai?.service_available ? "O modelo configurado não está instalado" : "Abra o Ollama para utilizar o modelo local"}</p></div><div class="service-card"><div class="service-card-top"><strong>Histórico local</strong><span class="outline-tag">SQLite</span></div><h3>${number(state.scans.length)} análises salvas</h3><p>Fontes e resultados nesta instalação · Reabertura disponível</p></div><div class="service-card"><div class="service-card-top"><strong>Fila de análises</strong><span class="outline-tag"><span class="status-dot ${state.queueStatus?.active_workers ? "" : "offline"}"></span>${state.queueStatus?.active_workers ? "Em execução" : "Sem worker ativo"}</span></div><h3>${number(state.queueStatus?.active_workers)} worker(s)</h3><p>${number(state.queueStatus?.counts?.queued)} na fila · ${number(state.queueStatus?.counts?.running)} em processamento · ${number(state.queueStatus?.counts?.completed)} concluída(s)</p></div>`;
  }
  async function refreshServices(silent = false) {
    const results = await Promise.allSettled([api("/health"), api("/api/v1/ai/status"), api("/api/v1/jobs/status"), api("/api/v1/engines")]);
    state.health = results[0].status === "fulfilled" ? results[0].value : null;
    state.aiStatus = results[1].status === "fulfilled" ? results[1].value : null;
    state.queueStatus = results[2].status === "fulfilled" ? results[2].value : null;
    state.engineStatus = results[3].status === "fulfilled" ? results[3].value.items : [];
    renderHealth();
    renderServices();
    if (!silent) toast(state.health ? "Status dos serviços atualizado." : "O servidor de análise não está respondendo.", !state.health);
  }
  function renderConnection(snapshot) {
    connectionSnapshot = snapshot;
    if (snapshot.health) state.health = snapshot.health;
    if (snapshot.status === "disconnected") { state.health = null; workspaceLoaded = false; }
    const checking = snapshot.status === "checking";
    $("reconnect-api").disabled = checking;
    $("reconnect-api").setAttribute("aria-busy", String(checking));
    $("connection-banner").hidden = snapshot.status === "connected" || (checking && snapshot.connected);
    $("connection-title").textContent = checking ? "Verificando conexão com a API" : "Conexão interrompida · reconexão automática ativa";
    $("connection-message").textContent = checking ? "Aguarde alguns segundos. Não é necessário reenviar a análise." : `${snapshot.message || "Servidor indisponível"}. Nova tentativa em ${Math.ceil((snapshot.retryMs || 2000) / 1000)} s. Use Reconectar API para tentar agora.`;
    renderHealth();
  }
  async function reconnectAPI() {
    if (!connection) return;
    const ready = await connection.reconnect();
    if (ready) {
      await loadWorkspace();
      toast(workspaceLoaded ? "API conectada. Serviços e histórico atualizados." : "API conectada; alguns dados ainda não puderam ser atualizados.", !workspaceLoaded);
    } else toast("A API ainda não respondeu. A reconexão automática continua ativa.", true);
  }
  function renderPolicy() {
    const threshold = $("policy-threshold").value;
    $("cli-command").textContent = `python cli.py scan ./src --fail-on ${threshold} -f sarif -o sast-results.sarif`;
    if (!state.active) {
      $("policy-result").innerHTML = '<div class="policy-card"><p>Selecione uma análise para avaliar esta política.</p></div>';
      return;
    }
    const scan = state.active;
    const blocking = severityOrder.slice(0, severityOrder.indexOf(threshold) + 1).reduce((sum, severity) => sum + (scan.summary_by_severity[severity] || 0), 0);
    const gate = { status: scan.has_errors ? "error" : blocking ? "blocked" : "passed" };
    $("policy-result").innerHTML = `<div class="policy-card">${gateBadge(gate)}<p>${escape(scan.project_name)} · ${scan.has_errors ? "Há erros de processamento. Saída CLI: 2." : blocking ? `${blocking} achado(s) em ${severityLabels[threshold]} ou superior. Saída CLI: 1.` : "Nenhum achado bloqueante nesta política. Saída CLI: 0."}</p></div>`;
  }
  let workflowLoaded = false;
  async function loadWorkflow() {
    if (workflowLoaded) return;
    try {
      const response = await fetch("/api/v1/integrations/workflow");
      if (!response.ok) throw new Error("Workflow indisponível nesta instalação.");
      $("workflow-code").textContent = await response.text();
      workflowLoaded = true;
    } catch (error) { $("workflow-code").textContent = error.message; }
  }

  window.addEventListener("hashchange", showView);
  $("menu-toggle").addEventListener("click", () => { const open = $("sidebar").classList.toggle("mobile-open"); $("menu-toggle").setAttribute("aria-expanded", String(open)); });
  $("guide-button").addEventListener("click", () => $("guide-dialog").showModal());
  $("close-guide").addEventListener("click", () => $("guide-dialog").close());
  $("guide-dialog").addEventListener("click", (event) => { if (event.target === $("guide-dialog")) { const rect = $("guide-dialog").getBoundingClientRect(); if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) $("guide-dialog").close(); } });
  $("file-upload").addEventListener("change", (event) => { const files = [...event.target.files]; event.target.value = ""; if (files.length) selectFiles(files, "file"); });
  $("folder-upload").addEventListener("change", (event) => { const files = [...event.target.files]; event.target.value = ""; if (files.length) selectFiles(files, "folder"); });
  ["dragenter", "dragover"].forEach((type) => $("dropzone").addEventListener(type, (event) => { event.preventDefault(); if (!state.busy) $("dropzone").classList.add("dragging"); }));
  ["dragleave", "drop"].forEach((type) => $("dropzone").addEventListener(type, (event) => { event.preventDefault(); $("dropzone").classList.remove("dragging"); }));
  $("dropzone").addEventListener("drop", (event) => {
    const files = [...(event.dataTransfer?.files || [])];
    if (files.length) selectFiles(files, "files");
    else setStatus("Para uma pasta inteira, use o botão Escolher pasta.", "error");
  });
  document.querySelectorAll("[data-mode]").forEach((button) => button.addEventListener("click", () => setMode(button.dataset.mode)));
  $("code-editor").maxLength = 500000;
  $("code-editor").addEventListener("input", updateEditor);
  $("code-editor").addEventListener("scroll", () => { $("editor-lines").scrollTop = $("code-editor").scrollTop; });
  $("code-language").addEventListener("change", () => {
    const extension = { python: ".py", javascript: ".js", typescript: ".ts", java: ".java" }[$("code-language").value];
    const base = $("code-filename").value.replace(/\.[^.]+$/, "") || "snippet";
    $("code-filename").value = base + extension;
  });
  $("code-filename").addEventListener("input", () => { $("code-language").value = editorLanguage($("code-filename").value); });
  $("load-demo").addEventListener("click", () => loadDemo());
  $("load-vulnerable").addEventListener("click", () => loadDemo(false, "vulneravel"));
  $("load-corrected").addEventListener("click", () => loadDemo(false, "corrigido"));
  $("load-secure").addEventListener("click", () => loadDemo(true));
  $("run-scan").addEventListener("click", runScan);
  ["findings-search", "severity-filter", "file-filter", "finding-sort", "semantic-filter", "engine-filter"].forEach((id) => $(id).addEventListener(id === "findings-search" ? "input" : "change", () => { state.page = 0; renderFindings(); }));
  $("finding-scan-select").addEventListener("change", (event) => { if (event.target.value) openScan(event.target.value); });
  $("generate-all-ai").addEventListener("click", generateAllAI);
  $("history-search").addEventListener("input", renderHistory);
  $("refresh-history").addEventListener("click", async () => { try { await refreshHistory(); toast("Histórico atualizado."); } catch (error) { toast(error.message, true); } });
  document.querySelectorAll("[data-clear-history]").forEach((button) => button.addEventListener("click", openClearHistoryDialog));
  $("clear-history-confirmation").addEventListener("input", () => {
    $("confirm-clear-history").disabled = $("clear-history-confirmation").value.trim().toUpperCase() !== "ZERAR";
    $("clear-history-error").hidden = true;
  });
  $("clear-history-confirmation").addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !$("confirm-clear-history").disabled) { event.preventDefault(); clearHistory(); }
  });
  $("confirm-clear-history").addEventListener("click", clearHistory);
  $("close-clear-history").addEventListener("click", () => $("clear-history-dialog").close());
  $("cancel-clear-history").addEventListener("click", () => $("clear-history-dialog").close());
  $("clear-history-dialog").addEventListener("click", (event) => { if (event.target === $("clear-history-dialog")) $("clear-history-dialog").close(); });
  $("rules-search").addEventListener("input", renderRules);
  $("overview-content").addEventListener("change", (event) => {
    const control = event.target;
    if (control.id === "overview-files-select") {
      state.overviewFilesScanId = control.value;
      savePreference("sast-overview-files", control.value);
    } else if (control.id === "compare-before-select") {
      state.overviewCompareBeforeId = control.value;
      savePreference("sast-overview-compare-before", control.value);
    } else if (control.id === "compare-after-select") {
      state.overviewCompareAfterId = control.value;
      savePreference("sast-overview-compare-after", control.value);
    } else return;
    renderOverview();
  });
  $("rule-language-filter").addEventListener("change", renderRules);
  $("policy-threshold").addEventListener("change", renderPolicy);
  $("refresh-services").addEventListener("click", reconnectAPI);
  $("reconnect-api").addEventListener("click", reconnectAPI);
  $("copy-cli").addEventListener("click", () => copy($("cli-command").textContent));
  $("copy-workflow").addEventListener("click", () => copy($("workflow-code").textContent));
  $("export-button").addEventListener("click", () => { $("export-menu").hidden = !$("export-menu").hidden; $("export-button").setAttribute("aria-expanded", String(!$("export-menu").hidden)); });
  document.addEventListener("click", async (event) => {
    const open = event.target.closest("[data-open-scan]");
    if (open) { event.preventDefault(); await openScan(open.dataset.openScan); }
    const fileFindings = event.target.closest("[data-open-file-findings]");
    if (fileFindings) {
      event.preventDefault();
      await openScan(fileFindings.dataset.openFileFindings, false);
      if (state.active?.scan_id !== fileFindings.dataset.openFileFindings) return;
      const path = fileFindings.dataset.filePath;
      if (![...$("file-filter").options].some((option) => option.value === path)) {
        toast("Esse arquivo não está disponível no detalhamento salvo.", true);
        return;
      }
      $("file-filter").value = path;
      state.page = 0;
      state.selected = null;
      navigate("findings");
      renderFindings();
    }
    const row = event.target.closest("[data-finding]");
    if (row) { state.selected = Number(row.dataset.finding); renderFindings(); if (window.innerWidth < 760) $("finding-detail").scrollIntoView({ block: "start" }); }
    const page = event.target.closest("[data-page]");
    if (page) { state.page += Number(page.dataset.page); state.selected = null; renderFindings(); $("findings-list").scrollTop = 0; }
    const exportButton = event.target.closest("[data-export]");
    if (exportButton) exportReport(exportButton.dataset.export);
    if (!event.target.closest(".export-wrapper")) { $("export-menu").hidden = true; $("export-button").setAttribute("aria-expanded", "false"); }
    if (event.target.closest("[data-clear-selection]") && !state.busy) { state.pending = []; state.ignored = 0; renderSelection(); setStatus(""); }
    if (event.target.closest("[data-edit-selection]") && state.pending[0]) { setEditor(await state.pending[0].file.text(), state.pending[0].path); setMode("editor"); }
    if (event.target.closest("[data-show-findings]")) navigate("findings");
    if (event.target.closest("[data-generate-ai]")) generateAI();
    if (event.target.closest("[data-review-semantic]")) reviewSemantic();
    if (event.target.closest("[data-copy-snippet]")) copy(state.active.findings[state.selected].code_snippet);
    if (event.target.closest("[data-copy-patch]")) copy(state.aiResults.get(findingKey()).suggested_patch);
    if (event.target.closest("[data-download-patch]")) downloadText(state.aiResults.get(findingKey()).diff, `sast-${state.active.findings[state.selected].rule_id}.patch`);
    if (event.target.closest("[data-validate-patch]")) validatePatch();
    const batchCopy = event.target.closest("[data-copy-batch-patch]");
    if (batchCopy) { const result = state.aiResults.get(`${state.active?.scan_id}:${Number(batchCopy.dataset.copyBatchPatch)}`); if (result) copy(result.suggested_patch); }
    const batchDownload = event.target.closest("[data-download-batch-patch]");
    if (batchDownload) { const index = Number(batchDownload.dataset.downloadBatchPatch); const result = state.aiResults.get(`${state.active?.scan_id}:${index}`); const finding = state.active?.findings[index]; if (result && finding) downloadText(result.diff, `sast-${finding.rule_id}-${index + 1}.patch`); }
    const batchValidate = event.target.closest("[data-validate-batch-patch]");
    if (batchValidate) validateBatchPatch(Number(batchValidate.dataset.validateBatchPatch));
    if (window.innerWidth < 761 && !event.target.closest("#sidebar") && !event.target.closest("#menu-toggle")) { $("sidebar").classList.remove("mobile-open"); $("menu-toggle").setAttribute("aria-expanded", "false"); }
  });
  document.addEventListener("keydown", (event) => { if (event.key === "Escape") { $("export-menu").hidden = true; $("export-button").setAttribute("aria-expanded", "false"); $("sidebar").classList.remove("mobile-open"); $("menu-toggle").setAttribute("aria-expanded", "false"); } });

  async function readWorkspace() {
    const results = await Promise.allSettled([api("/health"), api("/api/v1/rules"), api("/api/v1/capabilities"), api("/api/v1/scans?limit=100"), api("/api/v1/ai/status"), api("/api/v1/jobs/status"), api("/api/v1/engines"), api("/api/v1/quality")]);
    state.health = results[0].status === "fulfilled" ? results[0].value : null;
    if (results[1].status === "fulfilled") state.rules = results[1].value;
    if (results[2].status === "fulfilled") state.capabilities = results[2].value;
    if (results[3].status === "fulfilled") state.scans = results[3].value.items;
    state.aiStatus = results[4].status === "fulfilled" ? results[4].value : null;
    state.queueStatus = results[5].status === "fulfilled" ? results[5].value : null;
    state.engineStatus = results[6].status === "fulfilled" ? results[6].value.items : [];
    state.quality = results[7].status === "fulfilled" ? results[7].value : null;
    workspaceLoaded = results.slice(0, 4).every((result) => result.status === "fulfilled");
    renderHealth();
    renderOverview();
    renderHistory();
    renderRules();
    renderServices();
    renderPolicy();
    scanOptions();
    if (!state.active && state.scans.length) {
      const saved = preference("sast-active-scan");
      const id = state.scans.find((scan) => scan.scan_id === saved)?.scan_id || state.scans[0].scan_id;
      await openScan(id, false);
    } else renderFindings();
  }
  function loadWorkspace() {
    if (!workspaceLoading) workspaceLoading = readWorkspace().finally(() => { workspaceLoading = null; });
    return workspaceLoading;
  }
  async function init() {
    showView();
    connection = window.createSastConnection({
      onChange: renderConnection,
      onHealthy: () => { if (!workspaceLoaded) return loadWorkspace(); },
      onRecoveryError: (error) => toast(error.message, true),
    });
    connection.start();
    window.addEventListener("online", () => { void connection.reconnect(); });
    document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") void connection.reconnect(); });
    window.addEventListener("pagehide", () => connection.stop());
    window.addEventListener("pageshow", (event) => { if (event.persisted) connection.start(); });
    await loadWorkspace();
    updateEditor();
    setInterval(() => { if (document.visibilityState === "visible") refreshServices(true); }, 60000);
  }
  init().catch((error) => { toast(error.message, true); });
})();
