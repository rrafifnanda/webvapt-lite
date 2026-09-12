from webvapt.probes.active import reflects, sqli_error


def test_reflects_detects():
    assert reflects("<xsstest>", "hello <xsstest> world")
    assert not reflects("<xsstest>", "hello clean")


def test_sqli_error_detects():
    assert sqli_error("You have an error in your SQL syntax near 'x'")
    assert not sqli_error("welcome home")
