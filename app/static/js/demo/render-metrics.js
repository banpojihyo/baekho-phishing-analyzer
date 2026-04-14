import { metricGrid } from "./dom.js";
import { createMetricCard } from "./render-cards.js";

export function renderMetricCards(data) {
  const outputs = data.mvp_outputs || {};
  const attachmentOutput = outputs.attachment_static_guard;

  metricGrid.innerHTML = "";
  metricGrid.appendChild(
    createMetricCard("최종 위험 점수", `${data.final_risk_score ?? 0}점`, `severity: ${data.severity || "low"}`)
  );
  metricGrid.appendChild(
    createMetricCard(
      "추출 URL 수",
      Array.isArray(data.extracted_urls) ? data.extracted_urls.length : 1,
      data.input_type === "url" ? "단건 URL 직접 분석" : "메일 본문에서 추출"
    )
  );
  metricGrid.appendChild(
    createMetricCard(
      "첨부파일 수",
      attachmentOutput ? attachmentOutput.attachment_count : 0,
      attachmentOutput ? `위험 첨부 ${attachmentOutput.risky_attachment_count}개` : "첨부 분석 없음"
    )
  );
  metricGrid.appendChild(
    createMetricCard(
      "본문/HTML 신호",
      outputs.email_body_risk_check?.matched_rules?.length || 0,
      outputs.email_body_risk_check?.html_present ? "HTML 본문 포함" : "텍스트 본문 중심"
    )
  );
}
