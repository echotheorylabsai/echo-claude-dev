import pytest

from secure_claude import regex_engine


def test_posix_matches_simple():
    r = regex_engine.compile_rule(pattern=r"send\s+all", engine="posix", case_insensitive=True)
    assert r.search("Send all data")


def test_posix_translates_space_class():
    r = regex_engine.compile_rule(
        pattern=r"send[[:space:]]+all", engine="posix", case_insensitive=True
    )
    assert r.search("send all")
    assert r.search("send\tall")


def test_posix_translates_alnum_digit_alpha_classes():
    for cls, sample in [("alnum", "a1"), ("digit", "9"), ("alpha", "x")]:
        r = regex_engine.compile_rule(
            pattern=f"[[:{cls}:]]", engine="posix", case_insensitive=False
        )
        assert r.search(sample)


def test_posix_translates_class_inside_character_set():
    # [[:space:]] must work when wrapped in an outer [ ... ]
    r = regex_engine.compile_rule(pattern=r"[[:space:]abc]", engine="posix", case_insensitive=False)
    assert r.search(" ")
    assert r.search("a")


def test_pcre_supports_lookaround():
    r = regex_engine.compile_rule(
        pattern=r"(?i)ignore\s+previous", engine="pcre", case_insensitive=False
    )
    assert r.search("IGNORE previous")


def test_case_insensitive_flag_applied():
    r = regex_engine.compile_rule(pattern=r"HELLO", engine="posix", case_insensitive=True)
    assert r.search("hello world")


def test_compile_bad_pattern_raises():
    with pytest.raises(regex_engine.CompileError):
        regex_engine.compile_rule(pattern=r"(unterminated", engine="pcre", case_insensitive=False)


def test_compile_unknown_engine_raises():
    with pytest.raises(regex_engine.CompileError):
        regex_engine.compile_rule(pattern=r"abc", engine="foo", case_insensitive=False)


def test_compile_unknown_posix_class_raises():
    with pytest.raises(regex_engine.CompileError):
        regex_engine.compile_rule(pattern=r"[[:unknown:]]", engine="posix", case_insensitive=False)


def test_default_engine_is_posix():
    r = regex_engine.compile_rule(pattern=r"abc", engine=None, case_insensitive=False)
    assert r.search("abc")
