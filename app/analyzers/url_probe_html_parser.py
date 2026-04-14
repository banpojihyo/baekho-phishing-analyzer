from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urlparse


SUSPICIOUS_DOWNLOAD_EXTENSIONS = {
    ".apk",
    ".bat",
    ".cmd",
    ".com",
    ".dmg",
    ".exe",
    ".hta",
    ".iso",
    ".jar",
    ".js",
    ".lnk",
    ".msi",
    ".pkg",
    ".ps1",
    ".scr",
    ".vbs",
}


def reference_attribute_for_tag(tag_name: str) -> str | None:
    if tag_name in {"a", "link"}:
        return "href"
    if tag_name in {"audio", "embed", "img", "script", "source", "track", "video"}:
        return "src"
    if tag_name == "object":
        return "data"
    return None


def iframe_is_hidden(attrs_dict: dict[str, str | None]) -> bool:
    if "hidden" in attrs_dict:
        return True

    width = (attrs_dict.get("width") or "").strip()
    height = (attrs_dict.get("height") or "").strip()
    style = (attrs_dict.get("style") or "").replace(" ", "").lower()

    if width in {"0", "0px"} or height in {"0", "0px"}:
        return True
    return any(token in style for token in ("display:none", "visibility:hidden", "opacity:0"))


def looks_like_download_link(reference: str, attrs_dict: dict[str, str | None]) -> bool:
    if attrs_dict.get("download") is not None:
        return True

    parsed = urlparse(reference.strip())
    path = (parsed.path or "").lower()
    return any(path.endswith(ext) for ext in SUSPICIOUS_DOWNLOAD_EXTENSIONS)


class HtmlSignalParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._inside_title = False
        self._title_parts: list[str] = []
        self.meta: dict[str, str] = {}
        self.form_actions: list[str] = []
        self.password_input_count = 0
        self.iframe_count = 0
        self.hidden_iframe_count = 0
        self.asset_urls: list[str] = []
        self.anchor_urls: list[str] = []
        self.download_urls: list[str] = []

    @property
    def title(self) -> str:
        return " ".join(part.strip() for part in self._title_parts if part.strip()).strip()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {key.lower(): value for key, value in attrs if key}
        tag_name = tag.lower()
        if tag_name == "title":
            self._inside_title = True
            return

        if tag_name == "meta":
            meta_name = (
                attrs_dict.get("name")
                or attrs_dict.get("property")
                or attrs_dict.get("http-equiv")
                or ""
            ).lower()
            content = (attrs_dict.get("content") or "").strip()
            if meta_name and content and meta_name not in self.meta:
                self.meta[meta_name] = content
            return

        if tag_name == "form":
            self.form_actions.append((attrs_dict.get("action") or "").strip())
            return

        if tag_name == "input" and (attrs_dict.get("type") or "").lower() == "password":
            self.password_input_count += 1
            return

        if tag_name == "iframe":
            self.iframe_count += 1
            if iframe_is_hidden(attrs_dict):
                self.hidden_iframe_count += 1
            iframe_src = (attrs_dict.get("src") or "").strip()
            if iframe_src:
                self.asset_urls.append(iframe_src)
            return

        ref_attr = reference_attribute_for_tag(tag_name)
        if ref_attr:
            ref_value = (attrs_dict.get(ref_attr) or "").strip()
            if ref_value:
                if tag_name == "a":
                    self.anchor_urls.append(ref_value)
                    if looks_like_download_link(ref_value, attrs_dict):
                        self.download_urls.append(ref_value)
                else:
                    self.asset_urls.append(ref_value)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._inside_title = False

    def handle_data(self, data: str) -> None:
        if self._inside_title:
            self._title_parts.append(data)
