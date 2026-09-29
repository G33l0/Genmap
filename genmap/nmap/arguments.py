"""Tokenising and validating free form Nmap arguments.

The advanced arguments field exists so that any Nmap option, including ones
released after this version of Genmap, can still be used. Everything ends
up in an argument list passed straight to the process; no shell is
involved, so the checks here are about catching mistakes and about keeping
options Genmap manages itself (output files, input lists) under its own
control.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from genmap.errors import ArgumentError

# Options Genmap manages on the user's behalf. Letting them through would
# either break result collection or duplicate a dedicated control.
_BLOCKED_PREFIXES: dict[str, str] = {
    "-oX": "XML output is written by Genmap so results can be parsed.",
    "-oN": "Use the export options after the scan instead of writing output files from Nmap.",
    "-oG": "Use the export options after the scan instead of writing output files from Nmap.",
    "-oS": "Use the export options after the scan instead of writing output files from Nmap.",
    "-oA": "Use the export options after the scan instead of writing output files from Nmap.",
    "--append-output": "Output files are managed by Genmap.",
    "--resume": "Resuming from an Nmap output file is not supported through Genmap.",
    "-iL": "Use the target file field on the Targets tab.",
    "--stats-every": "The statistics interval is configured in Settings and on the Output tab.",
    "--interactive": "Interactive mode was removed from Nmap and cannot run under Genmap.",
    "--iflist": "Use the Nmap diagnostics page to view interfaces.",
    "--script-help": "Script help will be available from the NSE browser; running it would replace the scan.",
    "--version": "Diagnostics already record the Nmap version.",
    "-V": "Diagnostics already record the Nmap version.",
    "--help": "This would print help instead of scanning.",
    "-h": "This would print help instead of scanning.",
}


@dataclass
class ArgumentReview:
    tokens: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def tokenize_arguments(text: str) -> list[str]:
    """Split text into arguments.

    Whitespace separates arguments unless quoted with single or double quotes.
    Backslashes are kept literally so Windows paths survive intact; this is
    deliberately not POSIX shell semantics.
    """
    tokens: list[str] = []
    current: list[str] = []
    quote: str | None = None
    in_token = False
    for ch in text:
        if quote:
            if ch == quote:
                quote = None
            else:
                current.append(ch)
            continue
        if ch in ("'", '"'):
            quote = ch
            in_token = True
            continue
        if ch.isspace():
            if in_token:
                tokens.append("".join(current))
                current = []
                in_token = False
            continue
        current.append(ch)
        in_token = True
    if quote:
        raise ArgumentError(
            "Advanced arguments contain an unterminated quote.",
            remedy="Close the quotation mark or remove it.",
        )
    if in_token:
        tokens.append("".join(current))
    return tokens


def _blocked_reason(token: str) -> str | None:
    for prefix, reason in _BLOCKED_PREFIXES.items():
        if token == prefix:
            return reason
        if prefix.startswith("--") and token.startswith(prefix + "="):
            return reason
        if not prefix.startswith("--") and len(prefix) == 3 and token.startswith(prefix) and len(token) > 3:
            # Short output options accept an attached filename, e.g. -oXscan.xml.
            return reason
    return None


def review_arguments(text: str) -> ArgumentReview:
    """Tokenise and check advanced arguments, raising ArgumentError on problems."""
    review = ArgumentReview()
    if not text.strip():
        return review
    tokens = tokenize_arguments(text)
    previous_was_option = False
    for token in tokens:
        if any(ord(c) < 32 for c in token):
            raise ArgumentError(
                "Advanced arguments contain control characters.",
                remedy="Remove line breaks and other non printable characters.",
            )
        reason = _blocked_reason(token)
        if reason:
            raise ArgumentError(
                f"The option '{token}' cannot be used in advanced arguments.",
                remedy=reason,
            )
        is_option = token.startswith("-") and len(token) > 1
        if not is_option and not previous_was_option:
            review.warnings.append(
                f"'{token}' does not look like an option. Nmap will treat it as an additional target."
            )
        previous_was_option = is_option and "=" not in token
        review.tokens.append(token)
    return review
