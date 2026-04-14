export async function analyzeUrl(url) {
  const response = await fetch("/analyze/url", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.detail || "URL 분석 요청이 실패했습니다.");
  }
  return data;
}

export async function analyzeEml(file) {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch("/analyze/eml", {
    method: "POST",
    body: formData,
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.detail || "EML 분석 요청이 실패했습니다.");
  }
  return data;
}
