"""NSE script catalog types and Nmap compatible script selection.

Pure logic with no file access: the Nmap adapter fills a ScriptCatalog from
script.db, and this module answers which installed scripts a --script
selection would run.
"""

from __future__ import annotations

import fnmatch
import re as _re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Categories Nmap documents as potentially disruptive. The flag is advisory:
# a script outside these categories is not guaranteed to be harmless.
INTRUSIVE_CATEGORIES = frozenset({"intrusive", "brute", "dos", "exploit", "fuzzer", "malware"})

CATEGORY_DESCRIPTIONS = {
    "auth": "Checks authentication credentials or bypasses.",
    "broadcast": "Discovers hosts by broadcasting on the local network.",
    "brute": "Guesses credentials by brute force.",
    "default": "The set run by -sC; chosen for speed and usefulness.",
    "discovery": "Queries services and registries for more information.",
    "dos": "May cause denial of service.",
    "exploit": "Actively exploits vulnerabilities.",
    "external": "Sends data to third party services on the Internet.",
    "fuzzer": "Sends unexpected input to find bugs; can crash services.",
    "intrusive": "Can crash services, use significant resources, or be seen as malicious.",
    "malware": "Tests whether the target is infected with known malware.",
    "safe": "Designed not to crash services or use excessive resources.",
    "version": "Extends service version detection; runs with -sV.",
    "vuln": "Checks for specific known vulnerabilities.",
}


@dataclass(frozen=True)
class ScriptEntry:
    name: str
    categories: tuple[str, ...]

    @property
    def is_intrusive(self) -> bool:
        return any(c in INTRUSIVE_CATEGORIES for c in self.categories)


@dataclass
class ScriptCatalog:
    scripts: list[ScriptEntry] = field(default_factory=list)
    source: Optional[Path] = None

    @property
    def categories(self) -> list[str]:
        found: set[str] = set()
        for script in self.scripts:
            found.update(script.categories)
        return sorted(found)

    def names(self) -> list[str]:
        return [s.name for s in self.scripts]

    def by_category(self, category: str) -> list[ScriptEntry]:
        return [s for s in self.scripts if category in s.categories]


# Script selection ---------------------------------------------------------
#
# Mirrors how Nmap resolves --script: each comma separated item is either a
# boolean expression over categories and script names (with "and", "or",
# "not", and parentheses), or a file or directory path. Names may use shell
# style wildcards. Evaluating this against the installed catalog tells us
# exactly which scripts a selection runs, so warnings are about real scripts
# rather than guesses from their names.

_EXPR_TOKEN = _re.compile(r"\(|\)|[^\s()]+")
_KEYWORDS = {"and", "or", "not"}


class ScriptExpressionError(ValueError):
    pass


@dataclass
class ScriptSelection:
    scripts: list[ScriptEntry] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)  # paths or names not in the catalog

    def intrusive(self, categories: frozenset[str] | set[str] = INTRUSIVE_CATEGORIES) -> list[ScriptEntry]:
        wanted = {c.lower() for c in categories}
        return [s for s in self.scripts if any(c in wanted for c in s.categories)]


def _looks_like_path(item: str) -> bool:
    return item.endswith(".nse") or "/" in item or "\\" in item or item.startswith(".")


class _Parser:
    """Recursive descent: or < and < not < term, as in Nmap's script rules."""

    def __init__(self, text: str) -> None:
        self.tokens = _EXPR_TOKEN.findall(text)
        self.position = 0

    def peek(self) -> Optional[str]:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def take(self) -> str:
        token = self.peek()
        if token is None:
            raise ScriptExpressionError("expression ends unexpectedly")
        self.position += 1
        return token

    def parse(self):
        node = self.parse_or()
        if self.peek() is not None:
            raise ScriptExpressionError(f"unexpected '{self.peek()}'")
        return node

    def parse_or(self):
        node = self.parse_and()
        while (self.peek() or "").lower() == "or":
            self.take()
            node = ("or", node, self.parse_and())
        return node

    def parse_and(self):
        node = self.parse_not()
        while (self.peek() or "").lower() == "and":
            self.take()
            node = ("and", node, self.parse_not())
        return node

    def parse_not(self):
        if (self.peek() or "").lower() == "not":
            self.take()
            return ("not", self.parse_not())
        return self.parse_term()

    def parse_term(self):
        token = self.take()
        if token == "(":
            node = self.parse_or()
            if self.take() != ")":
                raise ScriptExpressionError("missing closing parenthesis")
            return node
        if token == ")" or token.lower() in _KEYWORDS:
            raise ScriptExpressionError(f"unexpected '{token}'")
        return ("term", token)


def _terms(node) -> list[str]:
    if node[0] == "term":
        return [node[1]]
    return [t for child in node[1:] for t in _terms(child)]


def _matches(node, script: ScriptEntry, categories: set[str]) -> bool:
    kind = node[0]
    if kind == "and":
        return _matches(node[1], script, categories) and _matches(node[2], script, categories)
    if kind == "or":
        return _matches(node[1], script, categories) or _matches(node[2], script, categories)
    if kind == "not":
        return not _matches(node[1], script, categories)
    term = node[1].lower()
    if term == "all":
        return True
    if term in categories:
        return term in script.categories
    name = term[:-4] if term.endswith(".nse") else term
    return fnmatch.fnmatchcase(script.name.lower(), name)


def select_scripts(expressions: list[str], catalog: ScriptCatalog) -> ScriptSelection:
    """Resolve script expressions to installed scripts.

    Raises ScriptExpressionError for malformed boolean expressions.
    """
    selection = ScriptSelection()
    categories = set(catalog.categories)
    chosen: dict[str, ScriptEntry] = {}
    for raw in expressions:
        item = raw.strip()
        if not item:
            continue
        if _looks_like_path(item) and " " not in item:
            stem = item.replace("\\", "/").rsplit("/", 1)[-1]
            stem = stem[:-4] if stem.endswith(".nse") else stem
            match = next((s for s in catalog.scripts if s.name == stem), None)
            if match is not None and not ("/" in item or "\\" in item):
                chosen.setdefault(match.name, match)
            else:
                selection.unresolved.append(item)
            continue
        tree = _Parser(item).parse()
        for term in _terms(tree):
            lowered = term.lower()
            if lowered == "all" or lowered in categories:
                continue
            if not any(fnmatch.fnmatchcase(s.name.lower(), lowered) for s in catalog.scripts):
                selection.unresolved.append(term)
        for script in catalog.scripts:
            if _matches(tree, script, categories):
                chosen.setdefault(script.name, script)
    selection.scripts = sorted(chosen.values(), key=lambda s: s.name)
    return selection
