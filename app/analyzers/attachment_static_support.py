from __future__ import annotations

from app.analyzers.types import RuleHit


def unique_items(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def unique_rule_hits(items: list[RuleHit]) -> list[RuleHit]:
    seen: set[tuple[str, str]] = set()
    unique: list[RuleHit] = []
    for item in items:
        key = (item["rule_id"], item["evidence"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique
