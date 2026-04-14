import {
  createAttachmentCard,
  createDetailCard,
  createMetricCard,
  createRuleCard,
} from "./render-card-factories.js";
import {
  attachmentOutputFromResult,
  collectMatchedRules,
  createDetailCardModels,
} from "./render-result-adapters.js";

export { createMetricCard } from "./render-card-factories.js";

export function appendCoreDetailCards(detailGrid, data) {
  const outputs = data.mvp_outputs || {};
  const attachmentOutput = attachmentOutputFromResult(data);
  createDetailCardModels(data).forEach((card) => {
    detailGrid.appendChild(createDetailCard(card.title, card.score, card.severity, card.evidence, card.extra));
  });
  if (attachmentOutput) {
    detailGrid.appendChild(createAttachmentCard(attachmentOutput));
  }
  detailGrid.appendChild(createRuleCard(collectMatchedRules(outputs)));
}
