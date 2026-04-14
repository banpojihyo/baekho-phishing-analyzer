import { analyzeEml, analyzeUrl } from "./api.js";
import { MAX_EML_UPLOAD_BYTES, emlForm, getEmlInput, getUrlInput, setFormBusy, urlForm } from "./dom.js";
import { renderError, renderPending, renderResult } from "./render.js";

export async function handleUrlSubmit(event) {
  event.preventDefault();
  const input = getUrlInput();
  setFormBusy(urlForm, true, "URL 분석 중...");
  renderPending("URL을 분석하고 있습니다", "구조 신호와 위험 근거를 정리한 뒤 결과를 표시합니다.");

  try {
    const data = await analyzeUrl(input?.value.trim() || "");
    renderResult(data);
  } catch (error) {
    renderError(error.message);
  } finally {
    setFormBusy(urlForm, false);
  }
}

export async function handleEmlSubmit(event) {
  event.preventDefault();
  const fileInput = getEmlInput();
  const file = fileInput?.files?.[0];
  if (!file) {
    renderError("업로드할 .eml 파일을 선택해 주세요.");
    return;
  }
  if (file.size > MAX_EML_UPLOAD_BYTES) {
    renderError("파일 크기 제한(5MB)을 초과했습니다. 민감정보를 줄이거나 개별 .eml만 추출해 다시 시도해 주세요.");
    return;
  }

  setFormBusy(emlForm, true, "메일 분석 중...");
  renderPending("메일을 분석하고 있습니다", "헤더, 본문, URL, 첨부파일 신호를 분해한 뒤 설명형 결과를 구성합니다.");

  try {
    const data = await analyzeEml(file);
    renderResult(data);
  } catch (error) {
    renderError(error.message);
  } finally {
    setFormBusy(emlForm, false);
  }
}
