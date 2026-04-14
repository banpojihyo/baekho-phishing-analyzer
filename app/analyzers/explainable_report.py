from __future__ import annotations

from app.analyzers.rule_utils import severity_from_score
from app.analyzers.types import ExplainableReport


def to_severity(score: int) -> str:
    return severity_from_score(score)


def _unique(items: list[str]) -> list[str]:
    return list(dict.fromkeys(item for item in items if item))


def _component_labels(evidence: list[str]) -> list[str]:
    labels: list[str] = []
    for item in evidence:
        if item.startswith("[Header]"):
            labels.append("헤더")
        elif item.startswith("[Body]"):
            labels.append("본문/HTML")
        elif item.startswith("[URL]"):
            labels.append("URL")
        elif item.startswith("[Attachment]"):
            labels.append("첨부파일")
    return _unique(labels)


def _build_risk_snapshot(severity: str, evidence: list[str], context_tags: list[str]) -> str:
    components = _component_labels(evidence)
    context_text = ", ".join(context_tags[:2]) + (" 등" if len(context_tags) > 2 else "")
    component_text = "·".join(components)

    if context_text and component_text:
        return f"{context_text} 관련 문맥에서 {component_text} 신호가 함께 탐지됐습니다."
    if context_text:
        return f"{context_text} 관련 문맥이 탐지되어 업무형 사칭 가능성을 함께 살펴볼 필요가 있습니다."
    if component_text:
        return f"{component_text} 영역에서 복합 신호가 탐지됐습니다."

    if severity in {"critical", "high"}:
        return "다수의 기술적 위험 신호가 함께 탐지됐습니다."
    if severity == "medium":
        return "추가 확인이 필요한 의심 신호가 일부 탐지됐습니다."
    return "현재 기준으로는 고위험 신호가 제한적입니다."


def _recommended_actions(severity: str) -> list[str]:
    if severity == "critical":
        return [
            "해당 메일/URL을 즉시 열람 중지하고 보안 담당자에게 전달하세요.",
            "관련 계정의 비밀번호를 즉시 변경하고 MFA 적용 여부를 점검하세요.",
            "동일 발신자/도메인 메일에 대해 조직 차원의 차단 여부를 검토하세요.",
        ]
    if severity == "high":
        return [
            "링크 클릭 및 첨부파일 실행을 중단하고 별도 채널로 발신자 확인을 진행하세요.",
            "의심 징후를 팀에 공유하고 유사 메일 수신 여부를 확인하세요.",
        ]
    if severity == "medium":
        return [
            "추가 검증 전까지 링크 클릭과 민감정보 입력을 보류하세요.",
            "발신자 주소/도메인, URL 목적지를 재확인하세요.",
        ]
    return [
        "현재 기준 고위험 신호는 낮지만, 민감정보 요청은 항상 별도 검증하세요.",
    ]


def build_explainable_report(
    final_score: int,
    evidence: list[str],
    *,
    context_tags: list[str] | None = None,
) -> ExplainableReport:
    severity = to_severity(final_score)
    context_tags = _unique(context_tags or [])
    risk_snapshot = _build_risk_snapshot(severity, evidence, context_tags)
    summary = (
        f"최종 위험 점수는 {final_score}점({severity})입니다. "
        "아래 근거를 기반으로 사용자 행동 이전에 선제 대응이 권장됩니다."
    )
    return {
        "summary": summary,
        "risk_snapshot": risk_snapshot,
        "context_tags": context_tags,
        "why_risky": evidence if evidence else ["특이 탐지 근거 없음"],
        "recommended_actions": _recommended_actions(severity),
    }

