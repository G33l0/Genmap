"""Documentation of installed NSE scripts, read from the script files as text.

Nothing here executes Lua. The script header is scanned for the
``description`` string, the NSEdoc tags (@usage, @args, @output, @see), and
the ``author`` field, which is what the NSE page shows.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_LONG_STRING = re.compile(r"description\s*=\s*\[(=*)\[(.*?)\]\1\]", re.S)
_SHORT_STRING = re.compile(r'description\s*=\s*"((?:[^"\\\n]|\\.)*)"')
_AUTHOR = re.compile(r"^author\s*=\s*(\{[^}]*\}|\"[^\"]*\"|'[^']*')", re.M)
_QUOTED = re.compile(r"\"([^\"]*)\"|'([^']*)'")
_TAG = re.compile(r"^--\s*@(\w+)\s*(.*)$")
_DOC_LINE = re.compile(r"^--(?!\[\[)(.*)$")
_STOP = re.compile(r"^(author|license|categories|portrule|hostrule|prerule|postrule|action|dependencies)\b|^(local\s+)?function\b")
_HTML_TAGS = re.compile(r"</?(code|i|b|em|strong|ul|li|p|br)\s*/?>", re.I)

MAX_READ_BYTES = 256_000


@dataclass
class ScriptArgumentDoc:
    name: str
    description: str


@dataclass
class ScriptDocumentation:
    name: str
    path: Optional[Path] = None
    description: str = ""
    usage: list[str] = field(default_factory=list)
    arguments: list[ScriptArgumentDoc] = field(default_factory=list)
    output: str = ""
    see_also: list[str] = field(default_factory=list)
    authors: list[str] = field(default_factory=list)
    readable: bool = True

    @property
    def summary(self) -> str:
        first = self.description.strip().split("\n\n", 1)[0]
        return " ".join(first.split())


def _unescape(text: str) -> str:
    return text.replace('\\"', '"').replace("\\n", "\n").replace("\\\\", "\\")


def _clean(text: str) -> str:
    return _HTML_TAGS.sub("", text).strip()


def parse_script_documentation(name: str, text: str, path: Optional[Path] = None) -> ScriptDocumentation:
    doc = ScriptDocumentation(name=name, path=path)
    match = _LONG_STRING.search(text)
    if match:
        doc.description = _clean(match.group(2))
    else:
        match = _SHORT_STRING.search(text)
        if match:
            doc.description = _clean(_unescape(match.group(1)))

    author = _AUTHOR.search(text)
    if author:
        doc.authors = [a or b for a, b in _QUOTED.findall(author.group(1))]

    current_tag: Optional[str] = None
    buffer: list[str] = []
    started = False

    def flush() -> None:
        nonlocal buffer
        if current_tag is None:
            return
        body = "\n".join(buffer).rstrip()
        if current_tag == "usage":
            usage = "\n".join(line.strip() for line in body.splitlines()).strip()
            if usage:
                doc.usage.append(usage)
        elif current_tag == "args":
            joined = " ".join(line.strip() for line in body.splitlines() if line.strip())
            if joined:
                arg_name, _, arg_description = joined.partition(" ")
                doc.arguments.append(ScriptArgumentDoc(arg_name, _clean(arg_description)))
        elif current_tag == "output":
            doc.output = (doc.output + "\n" + body).strip("\n") if doc.output else body.strip("\n")
        elif current_tag == "see":
            doc.see_also.extend(part.strip() for part in body.split() if part.strip())
        buffer = []

    for line in text.splitlines():
        stripped = line.rstrip()
        tag = _TAG.match(stripped)
        if tag:
            flush()
            started = True
            current_tag = tag.group(1).lower()
            buffer = [tag.group(2)] if tag.group(2) else []
            continue
        doc_line = _DOC_LINE.match(stripped)
        if doc_line and current_tag is not None:
            content = doc_line.group(1)
            buffer.append(content[1:] if content.startswith(" ") else content)
            continue
        if started and (not stripped or _STOP.match(stripped) or not stripped.startswith("--")):
            flush()
            current_tag = None
            if _STOP.match(stripped):
                break
    flush()
    return doc


def load_script_documentation(data_directory: Optional[Path], name: str) -> ScriptDocumentation:
    if data_directory is None:
        return ScriptDocumentation(name=name, readable=False)
    path = data_directory / "scripts" / f"{name}.nse"
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_READ_BYTES)
    except OSError:
        return ScriptDocumentation(name=name, path=path, readable=False)
    return parse_script_documentation(name, raw.decode("utf-8", errors="replace"), path)
