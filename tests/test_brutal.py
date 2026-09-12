from webvapt.probes.dirs import DIRS, is_interesting


def test_dirs_wordlist_nonempty():
    assert len(DIRS) >= 8
    assert "admin" in DIRS


def test_is_interesting():
    assert is_interesting(200)
    assert is_interesting(301)
    assert is_interesting(403)
    assert not is_interesting(404)
