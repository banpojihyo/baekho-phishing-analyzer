import { resultColumn } from "./dom.js";

export function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function severityClass(severity) {
  return `severity-${severity || "low"}`;
}

export function deriveSeverity(score) {
  if ((score ?? 0) >= 80) {
    return "critical";
  }
  if ((score ?? 0) >= 60) {
    return "high";
  }
  if ((score ?? 0) >= 30) {
    return "medium";
  }
  return "low";
}

export function createSignalChips(items = [], chipClass = "") {
  if (!items.length) {
    return '<p class="annotation-empty">표시할 신호가 없습니다.</p>';
  }
  return `
    <div class="chip-row">
      ${items
        .map((item) => `<span class="signal-chip ${chipClass}">${escapeHtml(item)}</span>`)
        .join("")}
    </div>
  `;
}

export function setResultBusy(isBusy) {
  resultColumn?.setAttribute("aria-busy", isBusy ? "true" : "false");
}
