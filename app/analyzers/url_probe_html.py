from __future__ import annotations

from app.analyzers.types import UrlProbeSnapshot
from app.analyzers.url_probe_html_parser import HtmlSignalParser
from app.analyzers.url_probe_html_reference import (
    count_external_references,
    count_offdomain_form_actions,
)
from app.analyzers.url_probe_html_script import count_suspicious_js_functions, extract_client_redirect
from app.analyzers.url_probe_safety import clean_probe_text


def extract_html_signals(html: str, *, base_url: str) -> UrlProbeSnapshot:
    parser = HtmlSignalParser()
    parser.feed(html)
    parser.close()

    client_redirect_url, client_redirect_kind = extract_client_redirect(html, base_url)
    asset_reference_count, external_asset_count = count_external_references(
        parser.asset_urls,
        base_url=base_url,
    )
    anchor_count, external_anchor_count = count_external_references(
        parser.anchor_urls,
        base_url=base_url,
    )
    suspicious_js_function_count, suspicious_js_functions = count_suspicious_js_functions(html)
    return {
        "title": clean_probe_text(parser.title, limit=180),
        "meta_description": clean_probe_text(parser.meta.get("description", "")),
        "meta_robots": clean_probe_text(parser.meta.get("robots", ""), limit=80),
        "client_redirect_url": client_redirect_url,
        "client_redirect_kind": client_redirect_kind,
        "form_count": len(parser.form_actions),
        "password_input_count": parser.password_input_count,
        "offdomain_form_action_count": count_offdomain_form_actions(
            parser.form_actions,
            base_url=base_url,
        ),
        "iframe_count": parser.iframe_count,
        "hidden_iframe_count": parser.hidden_iframe_count,
        "asset_reference_count": asset_reference_count,
        "external_asset_count": external_asset_count,
        "anchor_count": anchor_count,
        "external_anchor_count": external_anchor_count,
        "suspicious_js_function_count": suspicious_js_function_count,
        "suspicious_js_functions": suspicious_js_functions,
        "suspicious_download_link_count": len(parser.download_urls),
    }
