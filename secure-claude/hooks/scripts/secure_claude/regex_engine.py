from __future__ import annotations

import re

__all__ = ["CompileError", "compile_rule"]

# Mapping of POSIX character class names to their Python re equivalent bodies.
_POSIX_CLASS_MAP: dict[str, str] = {
    "alnum": r"A-Za-z0-9",
    "alpha": r"A-Za-z",
    "digit": r"0-9",
    "lower": r"a-z",
    "upper": r"A-Z",
    "space": r" \t\r\n\f\v",
    "blank": r" \t",
    "punct": r"!-/:-@\[-`{-~",
    "xdigit": r"0-9A-Fa-f",
    "cntrl": r"\x00-\x1f\x7f",
    "print": r" -~",
    "graph": r"!-~",
}

# Match the inner [:CLASS:] token (without the outer square brackets).
# The surrounding [ and ] of the character class remain in the pattern,
# giving correct results in both standalone and nested forms:
#   standalone:  [[:space:]]  -> [:space:] replaced by body -> [ \t\r\n\f\v]
#   nested set:  [[:space:]abc] -> [:space:] replaced by body -> [ \t\r\n\f\vabc]
_POSIX_RE = re.compile(r"\[:([a-z]+):\]")


class CompileError(ValueError):
    """Raised when a regex pattern cannot be compiled."""


def _translate(pattern: str) -> str:
    """Translate POSIX character classes to Python re equivalents.

    [[:space:]]    -> [ \\t\\r\\n\\f\\v]     (standalone — outer brackets stay)
    [[:space:]abc] -> [ \\t\\r\\n\\f\\vabc]  (inside wider set — same body)
    """

    def repl(m: re.Match) -> str:  # type: ignore[type-arg]
        cls = m.group(1)
        if cls not in _POSIX_CLASS_MAP:
            raise CompileError(f"unknown POSIX class [[:{cls}:]]")
        return _POSIX_CLASS_MAP[cls]

    return _POSIX_RE.sub(repl, pattern)


def compile_rule(
    *,
    pattern: str,
    engine: str | None,
    case_insensitive: bool,
) -> re.Pattern:  # type: ignore[type-arg]
    """Compile *pattern* into a :class:`re.Pattern`.

    Parameters
    ----------
    pattern:
        The regex pattern string.
    engine:
        ``None`` or ``"posix"`` — apply POSIX class translation before
        compiling.  ``"pcre"`` — pass through to :func:`re.compile` unchanged.
        Any other value raises :class:`CompileError`.
    case_insensitive:
        When ``True`` the compiled pattern uses :data:`re.IGNORECASE`.
    """
    flags = re.IGNORECASE if case_insensitive else 0

    if engine is None or engine == "posix":
        try:
            translated = _translate(pattern)
        except CompileError:
            raise
        try:
            return re.compile(translated, flags)
        except re.error as exc:
            raise CompileError(str(exc)) from exc

    if engine == "pcre":
        try:
            return re.compile(pattern, flags)
        except re.error as exc:
            raise CompileError(str(exc)) from exc

    raise CompileError(f"unknown engine {engine!r}; expected 'posix' or 'pcre'")
