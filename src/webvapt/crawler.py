import re
from urllib.parse import urljoin, urlparse


def extract_links(html: str, base_url: str) -> list[str]:
    base_host = urlparse(base_url).hostname or ""
    found: list[str] = []
    for m in re.finditer(r'href=["\']([^"\'#]+)["\']', html or "", re.I):
        absu = urljoin(base_url, m.group(1))
        u = urlparse(absu)
        if u.scheme not in ("http", "https"):
            continue
        if (u.hostname or "") != base_host:
            continue
        norm = u._replace(fragment="").geturl()
        if norm not in found:
            found.append(norm)
    return found
