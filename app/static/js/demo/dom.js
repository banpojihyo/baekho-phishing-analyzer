export const urlForm = document.querySelector("#url-form");
export const emlForm = document.querySelector("#eml-form");
export const resultColumn = document.querySelector("#result-zone");
export const resultHero = document.querySelector("#result-hero");
export const metricGrid = document.querySelector("#metric-grid");
export const detailGrid = document.querySelector("#detail-grid");
export const rawOutput = document.querySelector("#raw-output");
export const MAX_EML_UPLOAD_BYTES = 5 * 1024 * 1024;

export function getUrlInput() {
  return document.querySelector("#url-input");
}

export function getEmlInput() {
  return document.querySelector("#eml-input");
}

export function setFormBusy(form, isBusy, busyLabel) {
  const button = form?.querySelector("button");
  const panel = form?.closest(".panel");
  if (!button) {
    return;
  }
  if (!button.dataset.defaultLabel) {
    button.dataset.defaultLabel = button.textContent;
  }
  button.disabled = isBusy;
  button.textContent = isBusy ? busyLabel : button.dataset.defaultLabel;
  panel?.classList.toggle("is-busy", isBusy);
}
