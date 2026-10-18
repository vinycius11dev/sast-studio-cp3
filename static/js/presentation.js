(() => {
  const apiIndicator = document.getElementById("api-indicator");
  const aiIndicator = document.getElementById("ai-indicator");
  const apiLabel = document.getElementById("api-live-status");
  const aiLabel = document.getElementById("ai-live-status");
  const refreshButton = document.getElementById("refresh-status");

  function setStatus(indicator, label, state, text) {
    indicator.dataset.state = state;
    label.textContent = text;
  }

  async function refreshStatus() {
    refreshButton.disabled = true;
    refreshButton.textContent = "Consultando serviços locais…";
    setStatus(apiIndicator, apiLabel, "checking", "Consultando a API…");
    setStatus(aiIndicator, aiLabel, "checking", "Consultando Ollama…");

    const results = await Promise.allSettled([
      fetch("/health", { headers: { Accept: "application/json" } }).then(async (response) => {
        if (!response.ok) throw new Error("API não respondeu com sucesso");
        return response.json();
      }),
      fetch("/api/v1/ai/status", { headers: { Accept: "application/json" } }).then(async (response) => {
        if (!response.ok) throw new Error("Status da IA indisponível");
        return response.json();
      }),
    ]);

    const [apiResult, aiResult] = results;
    if (apiResult.status === "fulfilled" && apiResult.value.status === "healthy") {
      const count = Number(apiResult.value.active_rules);
      const ruleText = Number.isFinite(count) ? ` · ${count} regras carregadas` : "";
      setStatus(apiIndicator, apiLabel, "ready", `API ativa${ruleText}`);
    } else {
      setStatus(apiIndicator, apiLabel, "unavailable", "API local não está respondendo");
    }

    if (aiResult.status === "fulfilled") {
      const ai = aiResult.value;
      const model = ai.model || "modelo configurado";
      if (ai.model_available) {
        const loaded = ai.model_loaded ? "carregado na memória" : "disponível";
        setStatus(aiIndicator, aiLabel, "ready", `Ollama · ${model} · ${loaded}`);
      } else if (ai.service_available) {
        setStatus(aiIndicator, aiLabel, "unavailable", `Ollama ativo · ${model} não instalado`);
      } else {
        setStatus(aiIndicator, aiLabel, "unavailable", "Ollama não detectado · scanner SAST segue disponível");
      }
    } else {
      setStatus(aiIndicator, aiLabel, "unavailable", "Não foi possível consultar a IA local");
    }

    refreshButton.disabled = false;
    refreshButton.innerHTML = 'Atualizar estado local <span aria-hidden="true">↻</span>';
  }

  refreshButton.addEventListener("click", refreshStatus);
  refreshStatus();
})();
