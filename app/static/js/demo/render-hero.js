import { resultHero } from "./dom.js";
import { escapeHtml, severityClass } from "./render-utils.js";

export function renderResultHero(data) {
  const score = data.final_risk_score ?? 0;
  const severity = data.severity || "low";
  const riskSnapshot = data.explainable_report?.risk_snapshot || "";
  const nextAction = data.explainable_report?.recommended_actions?.[0] || "";
  const label = data.input_type === "eml" ? "메일 분석 완료" : "URL 분석 완료";

  resultHero.innerHTML = `
    <div class="result-hero-top">
      <div class="result-hero-heading">
        <p class="result-label">${label}</p>
        <h2>${escapeHtml(data.filename || data.url || "분석 결과")}</h2>
      </div>
      <div class="result-score-box">
        <div class="result-score-value">${score}<span>/100</span></div>
        <div class="result-score-caption">Risk Score</div>
      </div>
    </div>
    <div class="severity-chip ${severityClass(severity)}">${severity} threat</div>
    <p>${escapeHtml(data.summary || "요약이 없습니다.")}</p>
    ${
      riskSnapshot
        ? `<div class="result-evidence-box"><strong>핵심 근거</strong><p>${escapeHtml(riskSnapshot)}</p></div>`
        : ""
    }
    ${nextAction ? `<p class="result-next">다음 행동: ${escapeHtml(nextAction)}</p>` : ""}
  `;
}

export function renderPendingHero(label, description) {
  resultHero.innerHTML = `
    <p class="result-label">요청 중</p>
    <h2>${label}</h2>
    <p>${description}</p>
  `;
}

export function renderErrorHero(message) {
  resultHero.innerHTML = `
    <p class="result-label">오류</p>
    <h2>요청을 처리하지 못했습니다</h2>
    <p>${message}</p>
  `;
}
