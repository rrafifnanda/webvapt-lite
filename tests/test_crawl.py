from webvapt.crawler import extract_links


def test_extract_links_same_host_only():
    html = '<a href="/login">l</a><a href="https://example.com/about">a</a><a href="https://evil.com/x">e</a>'
    out = extract_links(html, "https://example.com/")
    assert "https://example.com/login" in out
    assert "https://example.com/about" in out
    assert not [u for u in out if "evil.com" in u]


def test_extract_links_dedups():
    html = '<a href="/a">1</a><a href="/a">2</a>'
    assert extract_links(html, "https://example.com/") == ["https://example.com/a"]
