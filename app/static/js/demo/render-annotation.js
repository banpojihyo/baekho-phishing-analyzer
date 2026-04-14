import { createSignalChips } from "./render-utils.js";

export function createAnnotationBoard(data) {
  const outputs = data.mvp_outputs || {};
  const article = document.createElement("article");
  article.className = "detail-card annotation-card";

  const headerSignals = outputs.email_header_risk_check?.evidence || [];
  const bodySignals = outputs.email_body_risk_check?.evidence || [];
  const urlResults = outputs.url_suspicion_scoring?.url_results || [];
  const attachmentItems = outputs.attachment_static_guard?.attachments || [];
  const actionItems = data.explainable_report?.recommended_actions || [];
  const contextItems = data.explainable_report?.context_tags || [];

  const urlSignals = urlResults.flatMap((item) => {
    const evidence = item.evidence || [];
    return [item.url, ...evidence];
  });
  const attachmentSignals = attachmentItems.map((item) => {
    return `${item.filename} · ${item.detected_type} · ${item.score}점`;
  });

  article.innerHTML = `
    <h3>주석형 설명 보기</h3>
    <p>PhishXplain식 설명형 경고 흐름을 참고해, 어떤 부분이 왜 위험한지 컴포넌트별로 묶어 보여줍니다.</p>
    <div class="annotation-grid">
      <section class="annotation-section">
        <h4>헤더 신호</h4>
        ${createSignalChips(headerSignals, "signal-chip-header")}
      </section>
      <section class="annotation-section">
        <h4>본문/HTML 신호</h4>
        ${createSignalChips(bodySignals, "signal-chip-body")}
      </section>
      <section class="annotation-section">
        <h4>URL 신호</h4>
        ${createSignalChips(urlSignals, "signal-chip-url")}
      </section>
      <section class="annotation-section">
        <h4>탐지 문맥</h4>
        ${createSignalChips(contextItems, "signal-chip-action")}
      </section>
      <section class="annotation-section">
        <h4>첨부파일 신호</h4>
        ${createSignalChips(attachmentSignals, "signal-chip-attachment")}
      </section>
      <section class="annotation-section">
        <h4>요약 관찰</h4>
        ${createSignalChips([data.explainable_report?.risk_snapshot].filter(Boolean), "signal-chip-body")}
      </section>
      <section class="annotation-section">
        <h4>권장 대응</h4>
        ${createSignalChips(actionItems, "signal-chip-action")}
      </section>
    </div>
  `;

  return article;
}
