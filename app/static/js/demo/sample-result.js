export const DEFAULT_SAMPLE_RESULT = {
  presentation_mode: "sample",
  input_type: "eml",
  filename: "security-update-notice.eml",
  final_risk_score: 94,
  severity: "critical",
  summary:
    "발신자 위장, 계정 재인증 유도, 고위험 링크 신호가 동시에 감지됐습니다.",
  extracted_urls: [
    "https://xn--account-verify-7k7c.com/session/reauth?user=finance",
  ],
  explainable_report: {
    risk_snapshot:
      "발신 도메인과 링크 대상이 일치하지 않고, HTML 본문에서 즉시 로그인 재확인을 강하게 유도합니다.",
    recommended_actions: [
      "링크 접속을 중단하고, 동일 공지 여부를 별도 채널로 재확인하세요.",
      "보안 담당자 또는 메일 관리자에게 원문을 전달해 추가 검토를 요청하세요.",
      "유사한 제목의 메일이 반복 유입되는지 팀 메일함에서 함께 확인하세요.",
    ],
    context_tags: ["계정 재인증 요구", "도메인 위장", "긴급 조치 유도"],
  },
  sample_spotlights: [
    {
      tone: "critical",
      title: "핵심 근거",
      items: [
        "발신자 표시 도메인과 실제 전달 경로가 일치하지 않습니다.",
        "계정 재인증을 가장한 고위험 로그인 유도 링크가 포함됩니다.",
      ],
    },
    {
      tone: "info",
      title: "위험 신호",
      items: [
        "Punycode 기반 유사 도메인이 링크 대상에 사용됐습니다.",
        "HTML 본문이 브랜드 버튼형 CTA로 즉시 행동을 유도합니다.",
      ],
    },
    {
      tone: "success",
      title: "권장 행동",
      items: [
        "링크 접속을 중단하고 별도 채널로 공지 여부를 재확인하세요.",
        "보안 담당자에게 원문을 전달해 추가 검토를 요청하세요.",
      ],
    },
  ],
  mvp_outputs: {
    email_header_risk_check: {
      score: 88,
      evidence: [
        "From 도메인과 Return-Path 도메인이 일치하지 않습니다.",
        "Reply-To가 별도 무료메일 계정으로 지정되어 있습니다.",
      ],
      matched_rules: [
        {
          rule_id: "HDR-021",
          title: "Header identity mismatch",
          evidence: "Displayed sender and envelope sender differ.",
        },
      ],
    },
    email_body_risk_check: {
      score: 76,
      html_present: true,
      evidence: [
        "HTML 본문에 계정 잠금 해제 문구와 즉시 로그인 재요청이 반복됩니다.",
        "브랜드 스타일을 흉내 낸 버튼형 링크가 포함되어 있습니다.",
      ],
      matched_rules: [
        {
          rule_id: "BODY-014",
          title: "Urgent credential lure",
          evidence: "Urgent action phrasing combined with login CTA.",
        },
      ],
    },
    url_suspicion_scoring: {
      top_risky_score: 92,
      url_results: [
        {
          url: "https://xn--account-verify-7k7c.com/session/reauth?user=finance",
          evidence: [
            "Punycode 형태의 유사 도메인이 감지되었습니다.",
            "로그인 재인증 경로를 가장한 세션 파라미터가 포함되어 있습니다.",
          ],
          matched_rules: [
            {
              rule_id: "URL-031",
              title: "Punycode impersonation",
              evidence:
                "Unicode-like domain encoding matched impersonation pattern.",
            },
          ],
        },
      ],
    },
    attachment_static_guard: {
      score: 37,
      severity: "medium",
      evidence: ["첨부 HTML 문서가 외부 로그인 세션으로 다시 연결됩니다."],
      attachment_count: 1,
      risky_attachment_count: 1,
      attachments: [
        {
          filename: "Account_Reauth.html",
          content_type: "text/html",
          detected_type: "html",
          score: 37,
        },
      ],
      matched_rules: [
        {
          rule_id: "ATT-009",
          title: "HTML lure attachment",
          evidence: "HTML attachment redirects to remote login page.",
        },
      ],
    },
  },
};
