import { escapeHtml } from "./render-utils.js";

export function createSampleSpotlightCards(data) {
  const cards = data.sample_spotlights || [];

  return cards.map((card) => {
    const article = document.createElement("article");
    article.className = `detail-card sample-spotlight-card sample-spotlight-${card.tone || "info"}`;
    article.innerHTML = `
      <span class="sample-spotlight-kicker">${escapeHtml(card.tone || "info")}</span>
      <h3>${escapeHtml(card.title)}</h3>
      <ul>
        ${(card.items || [])
          .map((item) => `<li>${escapeHtml(item)}</li>`)
          .join("")}
      </ul>
    `;
    return article;
  });
}
