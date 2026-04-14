import { emlForm, urlForm } from "./dom.js";
import { handleEmlSubmit, handleUrlSubmit } from "./controllers.js";
import { setupStaticMotion } from "./motion.js";
import { renderResult } from "./render.js";
import { DEFAULT_SAMPLE_RESULT } from "./sample-result.js";

export function bootstrapDemoApp() {
  setupStaticMotion();
  renderResult(DEFAULT_SAMPLE_RESULT);
  urlForm?.addEventListener("submit", handleUrlSubmit);
  emlForm?.addEventListener("submit", handleEmlSubmit);
}
