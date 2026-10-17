"use strict";

(() => {
  function parseDiff(raw) {
    const lines = String(raw || "").replace(/\r\n/g, "\n").split("\n");
    if (lines.at(-1) === "") lines.pop();
    let filePath = "Correção sugerida", additions = 0, removals = 0;
    const rows = lines.map((text) => {
      let kind = "context";
      if (/^(?:--- a\/|\+\+\+ b\/|@@|diff --git |index |\\ No newline)/.test(text)) {
        kind = "meta";
        if (text.startsWith("+++ b/")) filePath = text.slice(6);
      } else if (text.startsWith("+")) { kind = "add"; additions++; }
      else if (text.startsWith("-")) { kind = "remove"; removals++; }
      return { text, kind };
    });
    return { filePath, additions, removals, rows };
  }

  function downloadName(filePath, format) {
    const name = filePath.split(/[\\/]/).pop().replace(/[<>:"|?*\x00-\x1f]/g, "_") || "correcao";
    return name + (format === "txt" ? ".diff.txt" : ".patch");
  }

  if (typeof module !== "undefined" && module.exports) module.exports = { parseDiff, downloadName };
  if (typeof document === "undefined" || document.getElementById("diff-dialog")) return;

  const dialog = document.createElement("dialog");
  dialog.id = "diff-dialog";
  dialog.setAttribute("aria-labelledby", "diff-dialog-title");
  dialog.setAttribute("aria-describedby", "diff-dialog-description");
  dialog.innerHTML = '<div class="diff-view-heading"><div><div class="eyebrow">REVISÃO DA SUGESTÃO</div><h2 id="diff-dialog-title">Comparar alterações</h2><p id="diff-dialog-path"></p></div><button class="icon-button" type="button" data-diff-close aria-label="Fechar comparação">✕</button></div><p class="diff-view-description" id="diff-dialog-description">Confira as linhas que seriam removidas e adicionadas. O arquivo original permanece como está.</p><div class="diff-view-legend"><span class="diff-legend-remove">− Removido</span><span class="diff-legend-add">+ Adicionado</span><span id="diff-dialog-count"></span></div><div class="diff-view-code" role="region" aria-label="Alterações propostas no código" tabindex="0"></div><div class="diff-view-footer"><div class="diff-view-actions"><button type="button" class="button secondary small-button" data-diff-copy>Copiar diff</button><button type="button" class="button secondary small-button" data-diff-download="patch">Baixar .patch</button><button type="button" class="button secondary small-button" data-diff-download="txt">Baixar como .txt</button></div><p>O .txt abre como texto. O .patch pode ser revisado e aplicado em ferramentas de desenvolvimento.</p><span class="diff-view-status" role="status" aria-live="polite"></span></div>';
  document.body.append(dialog);
  let activeDiff = "", activePath = "correcao", trigger = null;

  function readDiff(section) {
    const code = section?.querySelector(".diff-code");
    if (!code) return "";
    if (code.hasAttribute("data-diff")) return code.getAttribute("data-diff");
    // Compatibilidade com resultados já abertos na versão anterior da tela.
    const lines = [...code.querySelectorAll(".diff-line")].map((line) => line.textContent);
    if (lines.at(-1) === " ") lines.pop();
    return lines.length ? lines.join("\n") + "\n" : "";
  }

  function openDiff(button) {
    const details = button.closest("details");
    if (details) details.open = false;
    activeDiff = readDiff(button.closest(".ai-section"));
    const parsed = parseDiff(activeDiff);
    activePath = parsed.filePath;
    trigger = button;
    dialog.querySelector("#diff-dialog-path").textContent = activePath;
    dialog.querySelector("#diff-dialog-count").textContent = `${parsed.removals} linha(s) removida(s) · ${parsed.additions} adicionada(s)`;
    dialog.querySelector(".diff-view-status").textContent = "";
    const code = dialog.querySelector(".diff-view-code");
    code.replaceChildren();
    if (!parsed.additions && !parsed.removals) {
      const empty = document.createElement("p");
      empty.className = "diff-view-empty";
      empty.textContent = "Esta sugestão não contém alterações para comparar.";
      code.append(empty);
    } else {
      const fragment = document.createDocumentFragment();
      for (const row of parsed.rows) {
        const line = document.createElement("div");
        line.className = "diff-view-line " + row.kind;
        line.textContent = row.text || " ";
        fragment.append(line);
      }
      code.append(fragment);
    }
    dialog.querySelectorAll("[data-diff-copy], [data-diff-download]").forEach((button) => { button.disabled = !activeDiff.trim(); });
    if (!dialog.open) dialog.showModal();
    dialog.querySelector("[data-diff-close]").focus();
  }

  document.querySelectorAll(".diff-details summary").forEach((summary) => {
    summary.textContent = "Ver alterações (diff)";
    summary.setAttribute("aria-haspopup", "dialog");
  });
  document.addEventListener("click", (event) => {
    const button = event.target.closest?.("[data-view-diff], .diff-details summary");
    if (button) { event.preventDefault(); openDiff(button); }
  });
  dialog.querySelector("[data-diff-close]").addEventListener("click", () => dialog.close());
  dialog.addEventListener("close", () => { if (trigger?.isConnected) trigger.focus(); });
  dialog.addEventListener("click", (event) => {
    if (event.target !== dialog) return;
    const rect = dialog.getBoundingClientRect();
    if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) dialog.close();
  });
  dialog.querySelector("[data-diff-copy]").addEventListener("click", async () => {
    const status = dialog.querySelector(".diff-view-status");
    try {
      await navigator.clipboard.writeText(activeDiff);
      status.textContent = "Diff copiado.";
    } catch { status.textContent = "Não foi possível copiar automaticamente. Use Baixar como .txt para abrir o conteúdo."; }
  });
  dialog.querySelectorAll("[data-diff-download]").forEach((button) => button.addEventListener("click", () => {
    const url = URL.createObjectURL(new Blob([activeDiff], { type: "text/plain;charset=utf-8" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = downloadName(activePath, button.dataset.diffDownload);
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }));
})();
