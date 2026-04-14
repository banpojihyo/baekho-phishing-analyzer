from __future__ import annotations

import re
from email.message import EmailMessage
from html import unescape
from html.parser import HTMLParser
from urllib.parse import parse_qsl, unquote, urlparse

from app.analyzers.types import EmailBodyExtractionResult


URL_PATTERN = re.compile(r"(https?://[^\s\"'<>]+)", re.IGNORECASE)
DISPLAY_URL_PATTERN = re.compile(
    r"((?:https?://|www\.)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+(?:/[^\s\"'<>]*)?)",
    re.IGNORECASE,
)
META_REFRESH_URL_PATTERN = re.compile(r"url\s*=\s*['\"]?([^'\";]+)", re.IGNORECASE)
SCRIPT_REDIRECT_URL_PATTERN = re.compile(
    r"(?:window|document)\.location(?:\.href)?\s*=\s*['\"]([^'\"]+)['\"]|"
    r"location\.replace\(\s*['\"]([^'\"]+)['\"]\s*\)",
    re.IGNORECASE,
)
NESTED_URL_PARAM_KEYS = {
    "continue",
    "continue_url",
    "dest",
    "destination",
    "destinationurl",
    "goto",
    "href",
    "link",
    "next",
    "out",
    "q",
    "r",
    "redir",
    "redirect",
    "redirect_to",
    "redirect_uri",
    "redirect_url",
    "target",
    "to",
    "u",
    "url",
}


def clean_url_candidate(candidate: str) -> str:
    return unescape(candidate or "").strip().strip("()<>[]{}\"'").rstrip(".,;:!?")


def find_urls(text: str) -> list[str]:
    if not text:
        return []
    return [clean_url_candidate(match) for match in URL_PATTERN.findall(text) if clean_url_candidate(match)]


def find_display_urls(text: str) -> list[str]:
    if not text:
        return []
    return [
        clean_url_candidate(match)
        for match in DISPLAY_URL_PATTERN.findall(text)
        if clean_url_candidate(match) and is_actionable_url(clean_url_candidate(match))
    ]


def hostname(value: str) -> str:
    try:
        candidate = value if "://" in value else f"http://{value}"
        return (urlparse(candidate).hostname or "").lower()
    except ValueError:
        return ""


def is_actionable_url(value: str) -> bool:
    candidate = clean_url_candidate(value)
    if not candidate:
        return False

    try:
        parsed = urlparse(candidate if "://" in candidate else candidate)
    except ValueError:
        return False
    if parsed.scheme:
        return parsed.scheme in {"http", "https"}

    return candidate.startswith("www.") or "." in candidate


def _iter_unquoted_variants(value: str, *, max_rounds: int = 2) -> list[str]:
    current = clean_url_candidate(value)
    variants: list[str] = []

    for _ in range(max_rounds + 1):
        if not current or current in variants:
            break
        variants.append(current)
        decoded = clean_url_candidate(unquote(current))
        if not decoded or decoded == current:
            break
        current = decoded

    return variants


def extract_nested_urls(value: str) -> list[str]:
    candidate = clean_url_candidate(value)
    if not candidate or not is_actionable_url(candidate):
        return []

    try:
        parsed = urlparse(candidate if "://" in candidate else f"http://{candidate}")
    except ValueError:
        return []

    nested_urls: list[str] = []

    for segment in parsed.path.split("/"):
        for variant in _iter_unquoted_variants(segment):
            if variant.lower().startswith(("http://", "https://")) and is_actionable_url(variant):
                nested_urls.append(clean_url_candidate(variant))
            nested_urls.extend(find_urls(variant))

    for raw_pairs in (parsed.query, parsed.fragment):
        if not raw_pairs:
            continue
        for key, raw_value in parse_qsl(raw_pairs, keep_blank_values=True):
            if key.lower() not in NESTED_URL_PARAM_KEYS:
                continue
            for variant in _iter_unquoted_variants(raw_value):
                if variant.lower().startswith(("http://", "https://")) and is_actionable_url(variant):
                    nested_urls.append(clean_url_candidate(variant))
                nested_urls.extend(find_urls(variant))

    return list(
        dict.fromkeys(
            nested
            for nested in nested_urls
            if nested and nested != candidate and is_actionable_url(nested)
        )
    )


class HtmlSignalParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchor_pairs: list[tuple[str, str]] = []
        self.form_actions: list[str] = []
        self.meta_refresh_urls: list[str] = []
        self.script_chunks: list[str] = []
        self._current_anchor_href = ""
        self._current_anchor_text: list[str] = []
        self._in_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {key.lower(): value or "" for key, value in attrs}
        normalized_tag = tag.lower()

        if normalized_tag == "a":
            self._current_anchor_href = attrs_dict.get("href", "")
            self._current_anchor_text = []
            return

        if normalized_tag == "form":
            action = clean_url_candidate(attrs_dict.get("action", ""))
            if action:
                self.form_actions.append(action)
            return

        if normalized_tag == "meta" and attrs_dict.get("http-equiv", "").lower() == "refresh":
            content = attrs_dict.get("content", "")
            match = META_REFRESH_URL_PATTERN.search(content)
            if match:
                candidate = clean_url_candidate(match.group(1))
                if candidate:
                    self.meta_refresh_urls.append(candidate)
            return

        if normalized_tag == "script":
            self._in_script = True

    def handle_endtag(self, tag: str) -> None:
        normalized_tag = tag.lower()
        if normalized_tag == "a":
            if self._current_anchor_href:
                visible_text = " ".join(self._current_anchor_text).strip()
                self.anchor_pairs.append((clean_url_candidate(self._current_anchor_href), visible_text))
            self._current_anchor_href = ""
            self._current_anchor_text = []
            return

        if normalized_tag == "script":
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._current_anchor_href:
            self._current_anchor_text.append(data)
        if self._in_script and data.strip():
            self.script_chunks.append(data)


def extract_email_body_signals(message: EmailMessage) -> EmailBodyExtractionResult:
    plain_chunks: list[str] = []
    html_chunks: list[str] = []

    if message.is_multipart():
        for part in message.walk():
            if part.get_content_maintype() == "multipart":
                continue
            try:
                content = part.get_content()
            except Exception:
                continue
            if not isinstance(content, str):
                continue
            content_type = part.get_content_type()
            if content_type == "text/plain":
                plain_chunks.append(content)
            elif content_type == "text/html":
                html_chunks.append(content)
    else:
        try:
            content = message.get_content()
        except Exception:
            content = ""
        if isinstance(content, str):
            content_type = message.get_content_type()
            if content_type == "text/html":
                html_chunks.append(content)
            else:
                plain_chunks.append(content)

    parser = HtmlSignalParser()
    html_text_chunks: list[str] = []
    extracted_urls: list[str] = []
    script_redirect_urls: list[str] = []

    for html_chunk in html_chunks:
        parser.feed(html_chunk)
        html_text_chunks.append(re.sub(r"<[^>]+>", " ", html_chunk))
        extracted_urls.extend(find_urls(html_chunk))

    extracted_urls.extend(url for url, _ in parser.anchor_pairs if is_actionable_url(url))
    extracted_urls.extend(url for url in parser.form_actions if is_actionable_url(url))
    extracted_urls.extend(url for url in parser.meta_refresh_urls if is_actionable_url(url))

    for script_chunk in parser.script_chunks:
        for match in SCRIPT_REDIRECT_URL_PATTERN.findall(script_chunk):
            candidate = clean_url_candidate(match[0] or match[1])
            if candidate:
                script_redirect_urls.append(candidate)
    extracted_urls.extend(url for url in script_redirect_urls if is_actionable_url(url))

    combined_text = "\n".join([*plain_chunks, *html_text_chunks]).strip()
    extracted_urls.extend(find_urls(combined_text))
    urls = list(dict.fromkeys(url for url in extracted_urls if url))
    expanded_urls: list[str] = []
    for url in urls:
        expanded_urls.extend(extract_nested_urls(url))
        expanded_urls.append(url)
    urls = list(dict.fromkeys(url for url in expanded_urls if url))

    return {
        "text": combined_text,
        "urls": urls,
        "anchor_pairs": list(parser.anchor_pairs),
        "form_actions": list(parser.form_actions),
        "meta_refresh_urls": list(parser.meta_refresh_urls),
        "script_redirect_urls": script_redirect_urls,
        "html_present": bool(html_chunks),
    }
