import { escapeHtml, severityClass } from "./render-utils.js";

export function createMetricCard(title, value, subtext = "") {
  const article = document.createElement("article");
  article.className = "metric-card";
  article.innerHTML = `
    <h3>${escapeHtml(title)}</h3>
    <div class="metric-value">${escapeHtml(value)}</div>
    ${subtext ? `<p>${escapeHtml(subtext)}</p>` : ""}
  `;
  return article;
}

export function createDetailCard(title, score, severity, evidence = [], extra = "") {
  const article = document.createElement("article");
  article.className = "detail-card";
  article.innerHTML = `
    <h3>${escapeHtml(title)}</h3>
    <p><span class="severity-chip ${severityClass(severity)}">${severity || "low"} · ${score}점</span></p>
    ${extra}
    <ul>${(evidence || []).map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
  `;
  return article;
}

export function createRuleCard(rules = []) {
  const article = document.createElement("article");
  article.className = "detail-card";
  article.innerHTML = `
    <h3>매칭 룰</h3>
    <p>점수 근거를 룰 단위로 펼쳐본 보기입니다.</p>
  `;

  if (!rules.length) {
    const empty = document.createElement("p");
    empty.className = "annotation-empty";
    empty.textContent = "표시할 룰이 없습니다.";
    article.appendChild(empty);
    return article;
  }

  const list = document.createElement("ul");
  rules.forEach((rule) => {
    const item = document.createElement("li");
    item.innerHTML = `
      <strong>${escapeHtml(rule.rule_id)}</strong> · ${escapeHtml(rule.title)}
      <div>${escapeHtml(rule.evidence || "")}</div>
    `;
    list.appendChild(item);
  });
  article.appendChild(list);
  return article;
}

export function createAttachmentCard(attachmentResult) {
  const items = attachmentResult.attachments || [];
  const article = createDetailCard(
    "첨부파일 정적 분석",
    attachmentResult.score || 0,
    attachmentResult.severity || "low",
    attachmentResult.evidence || []
  );

  if (items.length) {
    const wrapper = document.createElement("div");
    wrapper.className = "attachment-list";
    items.forEach((item) => {
      const block = document.createElement("div");
      block.className = "attachment-item";
      block.innerHTML = `
        <strong>${item.filename}</strong>
        <div>${item.content_type} · ${item.detected_type} · ${item.score}점</div>
      `;
      wrapper.appendChild(block);
    });
    article.appendChild(wrapper);
  }

  return article;
}
