import { detailGrid, metricGrid, rawOutput, resultHero } from "./dom.js";
import { flashUpdatedSurfaces, registerMotionTargets } from "./motion.js";
import { appendCoreDetailCards } from "./render-cards.js";
import { createAnnotationBoard } from "./render-annotation.js";
import {
  renderErrorHero,
  renderPendingHero,
  renderResultHero,
} from "./render-hero.js";
import { renderMetricCards } from "./render-metrics.js";
import { createSampleSpotlightCards } from "./render-sample.js";
import { setResultBusy } from "./render-utils.js";

export function renderPending(label, description) {
  renderPendingHero(label, description);
  metricGrid.innerHTML = "";
  detailGrid.innerHTML = "";
  detailGrid.classList.remove("is-sample-layout");
  metricGrid.classList.remove("is-sample-layout");
  rawOutput.textContent = "응답을 기다리는 중입니다.";
  setResultBusy(true);
  flashUpdatedSurfaces([resultHero]);
}

export function renderResult(data) {
  const isSampleMode = data.presentation_mode === "sample";
  renderResultHero(data);
  renderMetricCards(data);

  detailGrid.innerHTML = "";
  detailGrid.classList.toggle("is-sample-layout", isSampleMode);
  metricGrid.classList.toggle("is-sample-layout", isSampleMode);

  if (isSampleMode) {
    createSampleSpotlightCards(data).forEach((card) => {
      detailGrid.appendChild(card);
    });
  } else {
    detailGrid.appendChild(createAnnotationBoard(data));
    appendCoreDetailCards(detailGrid, data);
  }

  rawOutput.textContent = JSON.stringify(data, null, 2);
  setResultBusy(false);
  registerMotionTargets([...metricGrid.children, ...detailGrid.children], {
    baseDelay: 40,
    step: 45,
  });
  flashUpdatedSurfaces([
    resultHero,
    ...metricGrid.children,
    ...detailGrid.children,
  ]);
}

export function renderError(message) {
  renderErrorHero(message);
  detailGrid.classList.remove("is-sample-layout");
  metricGrid.classList.remove("is-sample-layout");
  setResultBusy(false);
  flashUpdatedSurfaces([resultHero]);
}
