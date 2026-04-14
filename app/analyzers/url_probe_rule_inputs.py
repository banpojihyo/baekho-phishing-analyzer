from __future__ import annotations

from dataclasses import dataclass

from app.analyzers.types import UrlProbeResult, UrlProbeSnapshot


@dataclass(slots=True)
class ProbeRuleSignals:
    browser_snapshot: UrlProbeSnapshot
    crawler_snapshot: UrlProbeSnapshot
    client_redirect_url: str | None
    client_redirect_kind: str
    redirect_hop_count: int
    offdomain_form_action_count: int
    password_input_count: int
    hidden_iframe_count: int
    asset_reference_count: int
    external_asset_count: int
    anchor_count: int
    external_anchor_count: int
    suspicious_js_function_count: int
    suspicious_js_functions: list[str]
    suspicious_download_link_count: int


def extract_probe_rule_signals(probe_result: UrlProbeResult) -> ProbeRuleSignals:
    browser_snapshot = probe_result.get("browser") or {}
    crawler_snapshot = probe_result.get("crawler") or {}
    return ProbeRuleSignals(
        browser_snapshot=browser_snapshot,
        crawler_snapshot=crawler_snapshot,
        client_redirect_url=browser_snapshot.get("client_redirect_url"),
        client_redirect_kind=browser_snapshot.get("client_redirect_kind") or "client_side",
        redirect_hop_count=int(browser_snapshot.get("redirect_hop_count") or 0),
        offdomain_form_action_count=int(browser_snapshot.get("offdomain_form_action_count") or 0),
        password_input_count=int(browser_snapshot.get("password_input_count") or 0),
        hidden_iframe_count=int(browser_snapshot.get("hidden_iframe_count") or 0),
        asset_reference_count=int(browser_snapshot.get("asset_reference_count") or 0),
        external_asset_count=int(browser_snapshot.get("external_asset_count") or 0),
        anchor_count=int(browser_snapshot.get("anchor_count") or 0),
        external_anchor_count=int(browser_snapshot.get("external_anchor_count") or 0),
        suspicious_js_function_count=int(browser_snapshot.get("suspicious_js_function_count") or 0),
        suspicious_js_functions=browser_snapshot.get("suspicious_js_functions") or [],
        suspicious_download_link_count=int(browser_snapshot.get("suspicious_download_link_count") or 0),
    )
