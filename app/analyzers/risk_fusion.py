from __future__ import annotations


COMPONENT_WEIGHTS = {
    "header": 0.35,
    "body": 0.15,
    "url": 0.25,
    "attachment": 0.25,
}
CORROBORATION_THRESHOLD = 20


def combine_component_scores(
    *,
    header_score: int | None = None,
    body_score: int | None = None,
    url_score: int | None = None,
    attachment_score: int | None = None,
) -> int:
    weighted_scores: list[tuple[int, float]] = []
    if header_score is not None:
        weighted_scores.append((header_score, COMPONENT_WEIGHTS["header"]))
    if body_score is not None:
        weighted_scores.append((body_score, COMPONENT_WEIGHTS["body"]))
    if url_score is not None:
        weighted_scores.append((url_score, COMPONENT_WEIGHTS["url"]))
    if attachment_score is not None:
        weighted_scores.append((attachment_score, COMPONENT_WEIGHTS["attachment"]))

    if not weighted_scores:
        return 0

    total_weight = sum(weight for _, weight in weighted_scores)
    weighted_sum = sum(score * weight for score, weight in weighted_scores)
    weighted_average = round(weighted_sum / total_weight)
    max_component_score = max(score for score, _ in weighted_scores)
    corroborating_components = sum(1 for score, _ in weighted_scores if score >= CORROBORATION_THRESHOLD)
    corroboration_bonus = max(0, corroborating_components - 1) * 5

    return min(100, max(weighted_average, max_component_score + corroboration_bonus))
