from __future__ import annotations


BUSINESS_CONTEXT_GROUPS = {
    "계정 인증": {
        "verify",
        "verification",
        "login",
        "password",
        "reset",
        "account",
        "credential",
        "portal",
        "인증",
        "로그인",
        "비밀번호",
        "재설정",
        "계정",
        "보안",
    },
    "결제/송금": {
        "payment",
        "invoice",
        "billing",
        "remit",
        "wire",
        "transfer",
        "receipt",
        "tax invoice",
        "결제",
        "송금",
        "입금",
        "청구서",
        "세금계산서",
        "정산",
        "납부",
    },
    "배송/주문": {
        "delivery",
        "shipping",
        "parcel",
        "shipment",
        "dispatch",
        "tracking number",
        "track shipment",
        "track package",
        "parcel tracking",
        "delivery status",
        "shipping status",
        "배송",
        "배송조회",
        "배송확인",
        "출고",
        "택배",
        "운송장",
        "주문",
        "반품",
    },
    "발주/견적": {
        "quote",
        "quotation",
        "proposal",
        "purchase order",
        "order form",
        "contract",
        "estimate",
        "견적",
        "견적서",
        "발주",
        "계약",
        "거래명세서",
        "제안서",
    },
}


def detect_business_contexts(text: str) -> list[str]:
    lowered = (text or "").lower()
    return [
        label
        for label, terms in BUSINESS_CONTEXT_GROUPS.items()
        if any(term in lowered for term in terms)
    ]
