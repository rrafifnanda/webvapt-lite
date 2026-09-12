import pytest

from webvapt.guard import GuardError, assert_authorized, enforce_scope


def test_refuses_without_authorized():
    with pytest.raises(GuardError):
        assert_authorized(False)


def test_allows_with_authorized():
    assert_authorized(True)


def test_rejects_private_by_default():
    with pytest.raises(GuardError):
        enforce_scope("http://127.0.0.1/", allow_private=False)


def test_allows_public():
    assert enforce_scope("https://example.com/", allow_private=False) == "https://example.com/"
