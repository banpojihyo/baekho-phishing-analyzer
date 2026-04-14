import { deriveSeverity } from "./render-utils.js";

export function collectMatchedRules(outputs = {}) {
  const headerRules = outputs.email_header_risk_check?.matched_rules || [];
  const bodyRules = outputs.email_body_risk_check?.matched_rules || [];
  const urlRules = outputs.url_suspicion_scoring?.url_results
    ? outputs.url_suspicion_scoring.url_results.flatMap((item) => item.matched_rules || [])
    : outputs.url_suspicion_scoring?.matched_rules || [];
  const attachmentRules = outputs.attachment_static_guard?.matched_rules || [];
  return [...headerRules, ...bodyRules, ...urlRules, ...attachmentRules];
}

export function createDetailCardModels(data) {
  const outputs = data.mvp_outputs || {};
  const score = data.final_risk_score ?? 0;
  const severity = data.severity || "low";
  const models = [];

  if (data.explainable_report) {
    models.push({
      title: "권장 대응",
      score,
      severity,
      evidence: data.explainable_report.recommended_actions || [],
      extra: "<p>사용자 행동 이전에 먼저 읽어야 할 다음 행동입니다.</p>",
    });
  }

  if (outputs.email_header_risk_check) {
    models.push({
      title: "헤더 분석",
      score: outputs.email_header_risk_check.score,
      severity: deriveSeverity(outputs.email_header_risk_check.score),
      evidence: outputs.email_header_risk_check.evidence,
      extra: "",
    });
  }

  if (outputs.email_body_risk_check) {
    models.push({
      title: "본문/HTML 분석",
      score: outputs.email_body_risk_check.score,
      severity: deriveSeverity(outputs.email_body_risk_check.score),
      evidence: outputs.email_body_risk_check.evidence,
      extra: "",
    });
  }

  if (outputs.url_suspicion_scoring) {
    const urlEvidence = outputs.url_suspicion_scoring.url_results
      ? outputs.url_suspicion_scoring.url_results.flatMap((item) => item.evidence || [])
      : outputs.url_suspicion_scoring.evidence || [];
    const urlScore = outputs.url_suspicion_scoring.top_risky_score ?? outputs.url_suspicion_scoring.score ?? 0;
    models.push({
      title: "URL 분석",
      score: urlScore,
      severity: deriveSeverity(urlScore),
      evidence: urlEvidence,
      extra: "",
    });
  }

  return models;
}

export function attachmentOutputFromResult(data) {
  return data.mvp_outputs?.attachment_static_guard || null;
}
