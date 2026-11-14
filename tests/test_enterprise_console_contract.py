"""Static contract checks for the browser-based Enterprise Console."""

from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]


class _IdCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.ids.extend(value for name, value in attrs if name == "id" and value)


def test_enterprise_console_has_unique_dom_ids() -> None:
    parser = _IdCollector()
    parser.feed((ROOT / "enterprise.html").read_text(encoding="utf-8"))

    duplicates = sorted(
        element_id
        for element_id, count in Counter(parser.ids).items()
        if count > 1
    )

    assert not duplicates, f"Duplicate Enterprise Console DOM IDs: {duplicates}"


def test_enterprise_javascript_static_dom_references_exist() -> None:
    html = (ROOT / "enterprise.html").read_text(encoding="utf-8")
    javascript = (ROOT / "enterprise.js").read_text(encoding="utf-8")
    parser = _IdCollector()
    parser.feed(html)

    available_ids = set(parser.ids)
    referenced_ids = set(re.findall(r'\$\(["\']([^"\']+)["\']\)', javascript))
    missing_ids = sorted(referenced_ids - available_ids)

    assert not missing_ids, f"Enterprise JavaScript references missing DOM IDs: {missing_ids}"


def test_api_token_console_is_rendered_once_with_expected_controls() -> None:
    html = (ROOT / "enterprise.html").read_text(encoding="utf-8")

    assert html.count('id="api-token-tools"') == 1
    for element_id in (
        "api-token-name",
        "api-token-expiry",
        "api-token-org-wide",
        "api-token-projects",
        "api-token-secret",
        "create-api-token",
        "copy-api-token",
        "api-token-list",
    ):
        assert html.count(f'id="{element_id}"') == 1, element_id
