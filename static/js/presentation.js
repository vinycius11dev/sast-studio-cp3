"use strict";

(() => {
  const $ = (id) => document.getElementById(id);
  const slides = Array.from(document.querySelectorAll(".slide"));
  const notes = [
    "Apresente a proposta: detectar padrões de risco, explicar a evidência e apoiar uma correção revisada. O código do painel é ilustrativo; a demonstração real vem no slide 6.",
    "Explique a dor: um alerta isolado não informa o contexto nem a decisão de entrega. Mostre como o workspace conecta detecção, evidência e política de bloqueio.",
    "Siga as setas. A API valida a entrada; o worker usa o motor compartilhado; SQLite registra jobs e resultados. O Ollama recebe o contexto dos achados para apoiar a revisão.",
    "Alterne entre antes e depois. São resultados de referência do projeto: nove achados no exemplo vulnerável e zero no corrigido, dentro da cobertura das regras. No workspace, você vai executar essas análises novamente.",
    "Mostre que a IA não altera os arquivos automaticamente. Diferencie o selo Ollama do fallback determinístico e explique que o gate original vem da análise estática.",
    "Se desejar um ensaio limpo, abra o Histórico e use Zerar histórico. Depois carregue o exemplo vulnerável, execute a análise, revise um achado com IA e compare com o corrigido. Os atalhos preparam os arquivos; você inicia a análise no workspace.",
    "Retome as três entregas: detecção estrutural, decisão rastreável e assistência local. Explique os limites e abra o código e as evidências se houver perguntas."
  ];
  let current = 0;
  let refreshing = false;
  let messageTimer;

  function showSlide(index, updateURL = true) {
    current = Math.max(0, Math.min(slides.length - 1, index));
    let moveFocus = false;
    slides.forEach((slide, position) => {
      if (position !== current && slide.contains(document.activeElement)) moveFocus = true;
      slide.hidden = position !== current;
    });
    $("slide-number").textContent = String(current + 1).padStart(2, "0") + " / " + String(slides.length).padStart(2, "0");
    $("chapter-title").textContent = slides[current].dataset.title;
    $("notes-content").textContent = notes[current];
    $("previous-slide").disabled = current === 0;
    $("next-slide").disabled = current === slides.length - 1;
    $("deck-progress").style.width = ((current + 1) / slides.length * 100) + "%";
    document.querySelectorAll(".slide-dots [data-go]").forEach((button) => {
      if (Number(button.dataset.go) === current + 1) button.setAttribute("aria-current", "step");
      else button.removeAttribute("aria-current");
    });
    document.title = slides[current].dataset.title + " · SAST Studio";
    $("slide-stage").scrollTop = 0;
    if (moveFocus) $("slide-stage").focus({ preventScroll: true });
    if (updateURL) history.replaceState(null, "", "#slide-" + (current + 1));
  }

  function toggleNotes() {
    const open = $("speaker-notes").hidden;
    $("speaker-notes").hidden = !open;
    $("toggle-notes").setAttribute("aria-expanded", String(open));
  }

  function showMessage(text) {
    clearTimeout(messageTimer);
    $("deck-message").textContent = text;
    $("deck-message").hidden = false;
    messageTimer = setTimeout(() => { $("deck-message").hidden = true; }, 4500);
  }

  async function toggleFullscreen() {
    try {
      if (document.fullscreenElement) await document.exitFullscreen();
      else await document.documentElement.requestFullscreen();
    } catch {
      showMessage("Tela cheia indisponível neste navegador. Você também pode usar F11.");
    }
  }

  function selectEvidence(variant) {
    const after = variant === "after";
    document.querySelectorAll("[data-evidence]").forEach((button) => {
      const selected = button.dataset.evidence === variant;
      button.setAttribute("aria-selected", String(selected));
      button.tabIndex = selected ? 0 : -1;
    });
    $("evidence-panel").setAttribute("aria-labelledby", after ? "evidence-after" : "evidence-before");
    const value = document.createTextNode(after ? "0" : "9");
    const label = document.createElement("span");
    label.textContent = "achados";
    $("evidence-value").replaceChildren(value, label);
    $("evidence-value").dataset.state = after ? "passed" : "blocked";
    $("evidence-gate").textContent = after ? "Gate aprovado · limiar HIGH" : "Gate bloqueado · limiar HIGH";
    $("evidence-gate").dataset.state = after ? "passed" : "blocked";
    $("evidence-description").textContent = after ? "3 arquivos · nenhum achado pelas regras atuais no exemplo corrigido." : "3 arquivos · 6 achados críticos e 3 altos no exemplo vulnerável.";
    $("evidence-image").src = "/presentation-assets/" + (after ? "06-projeto-corrigido.png" : "02-achados-vulneraveis.png");
    $("evidence-image").alt = after ? "Exemplo corrigido com zero achados e gate aprovado" : "Exemplo vulnerável com nove achados e gate bloqueado";
    $("evidence-caption").textContent = after ? "Depois da correção · nova análise do exemplo corrigido." : "Antes da correção · achados rastreáveis por arquivo, linha e regra.";
    $("evidence-demo-link").href = "/dashboard?demo=" + (after ? "corrigido" : "vulneravel") + "#scanner";
  }

  async function requestJSON(path) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    try {
      const response = await fetch(path, { signal: controller.signal, headers: { Accept: "application/json" }, cache: "no-store" });
      if (!response.ok) throw new Error("HTTP " + response.status);
      return await response.json();
    } finally {
      clearTimeout(timeout);
    }
  }

  function runtime(id, text, ready) {
    $(id).textContent = text;
    $(id).dataset.state = ready ? "ready" : "unavailable";
  }

  async function refreshStatus() {
    if (refreshing) return;
    refreshing = true;
    $("refresh-status").disabled = true;
    $("refresh-status").textContent = "Consultando…";
    try {
      const results = await Promise.allSettled([
        requestJSON("/health"), requestJSON("/api/v1/ai/status"),
        requestJSON("/api/v1/jobs/status"), requestJSON("/api/v1/scans?limit=500")
      ]);
      const values = results.map((result) => result.status === "fulfilled" ? result.value : null);
      const [health, ai, queue, scans] = values;
      const healthy = health && health.status === "healthy";
      $("api-pill").dataset.state = healthy ? "ready" : "unavailable";
      $("api-live-status").textContent = healthy ? "API · " + health.active_rules + " regras" : "API · indisponível";
      runtime("runtime-api", healthy ? "v" + health.version + " · " + health.active_rules + " regras" : "Sem conexão", healthy);
      const aiReady = ai && ai.service_available && ai.model_available;
      $("ai-pill").dataset.state = aiReady ? "ready" : "unavailable";
      $("ai-live-status").textContent = aiReady ? "Ollama · pronto" : ai && ai.service_available ? "Ollama · falta o modelo" : "Ollama · indisponível";
      runtime("runtime-ai", aiReady ? ai.model + (ai.model_loaded ? " · carregado" : " · instalado") : ai && ai.service_available ? "Modelo não instalado" : "Serviço indisponível", aiReady);
      const workers = queue ? queue.active_workers : 0;
      runtime("runtime-worker", queue ? workers + (workers === 1 ? " worker ativo" : " workers ativos") : "Sem conexão", workers > 0);
      const count = scans && Array.isArray(scans.items) ? scans.items.length : null;
      runtime("runtime-history", count === null ? "Sem conexão" : (count === 500 ? "500 ou mais" : count) + (count === 1 ? " análise salva" : " análises salvas"), count !== null);
      $("status-updated").textContent = "Consultado às " + new Intl.DateTimeFormat("pt-BR", { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date()) + " · atualização automática a cada 30 s";
    } finally {
      refreshing = false;
      $("refresh-status").disabled = false;
      $("refresh-status").textContent = "Verificar ambiente ↻";
    }
  }

  document.querySelectorAll("[data-go]").forEach((button) => button.addEventListener("click", () => showSlide(Number(button.dataset.go) - 1)));
  $("previous-slide").addEventListener("click", () => showSlide(current - 1));
  $("next-slide").addEventListener("click", () => showSlide(current + 1));
  $("toggle-notes").addEventListener("click", toggleNotes);
  $("fullscreen").addEventListener("click", toggleFullscreen);
  $("refresh-status").addEventListener("click", refreshStatus);
  document.querySelectorAll("[data-evidence]").forEach((button) => {
    button.addEventListener("click", () => selectEvidence(button.dataset.evidence));
    button.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight"].includes(event.key)) return;
      event.preventDefault();
      event.stopPropagation();
      const variant = button.dataset.evidence === "before" ? "after" : "before";
      selectEvidence(variant);
      $("evidence-" + variant).focus();
    });
  });
  document.addEventListener("keydown", (event) => {
    if (event.altKey || event.ctrlKey || event.metaKey || event.target.closest("input, textarea, select, [contenteditable=true]")) return;
    if (event.key.toLowerCase() === "n") { event.preventDefault(); toggleNotes(); }
    else if (event.key.toLowerCase() === "f") { event.preventDefault(); toggleFullscreen(); }
    else if (event.key === "Escape") { $("speaker-notes").hidden = true; $("toggle-notes").setAttribute("aria-expanded", "false"); }
    else if (["ArrowRight", "PageDown", "ArrowLeft", "PageUp", "Home", "End"].includes(event.key)) {
      event.preventDefault();
      showSlide(event.key === "Home" ? 0 : event.key === "End" ? slides.length - 1 : current + (["ArrowRight", "PageDown"].includes(event.key) ? 1 : -1));
    } else if (event.key === " " && !event.target.closest("button, a, summary")) { event.preventDefault(); showSlide(current + 1); }
  });
  document.addEventListener("fullscreenchange", () => {
    $("fullscreen").textContent = document.fullscreenElement ? "Sair da tela cheia" : "Tela cheia";
    $("fullscreen").setAttribute("aria-label", document.fullscreenElement ? "Sair da tela cheia" : "Ativar tela cheia");
  });
  window.addEventListener("hashchange", () => showSlide((Number(location.hash.match(/^#slide-(\d+)$/)?.[1]) || 1) - 1, false));
  document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") refreshStatus(); });
  showSlide((Number(location.hash.match(/^#slide-(\d+)$/)?.[1]) || 1) - 1);
  refreshStatus();
  setInterval(() => { if (document.visibilityState === "visible") refreshStatus(); }, 30000);
})();
