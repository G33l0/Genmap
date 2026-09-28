"""Assessment of how noisy or intrusive a configuration is.

Nothing here decides what is allowed. The purpose is to make sure the
person launching the scan sees what they are about to do before Nmap
starts, particularly when NSE categories that attack services are selected.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from genmap.core.nse import ScriptCatalog, ScriptExpressionError, select_scripts
from genmap.core.scan_config import ScanConfiguration, ScanMode, TcpScanTechnique
from genmap.core.targets import estimate_host_count, parse_targets

DEFAULT_INTRUSIVE_CATEGORIES = ("intrusive", "brute", "dos", "exploit", "fuzzer", "malware")
LARGE_SCOPE_THRESHOLD = 1024


@dataclass(frozen=True)
class IntrusivenessNotice:
    level: str  # "high" or "medium"
    message: str


def _script_terms(expressions: Iterable[str]) -> set[str]:
    """Positive terms of script expressions; terms directly negated by "not" are skipped."""
    terms: set[str] = set()
    for expression in expressions:
        tokens = expression.replace("(", " ( ").replace(")", " ) ").replace(",", " ").split()
        negate = False
        for token in tokens:
            lowered = token.lower()
            if lowered == "not":
                negate = True
                continue
            if lowered in ("and", "or", "(", ")"):
                if lowered != "(":
                    negate = False
                continue
            if not negate:
                terms.add(lowered)
            negate = False
    return terms


def _catalog_notices(config: ScanConfiguration, categories: set[str], catalog: ScriptCatalog) -> list[IntrusivenessNotice]:
    expressions = list(config.scripts.scripts)
    if config.aggressive and "default" not in expressions:
        expressions.append("default")
    if not expressions:
        return []
    try:
        selection = select_scripts(expressions, catalog)
    except ScriptExpressionError as exc:
        return [IntrusivenessNotice("medium", f"The script selection could not be checked: {exc}.")]
    notices: list[IntrusivenessNotice] = []
    risky = selection.intrusive(categories)
    if risky:
        names = ", ".join(s.name for s in risky[:6]) + (f" and {len(risky) - 6} more" if len(risky) > 6 else "")
        found = sorted({c for s in risky for c in s.categories if c in categories})
        notices.append(
            IntrusivenessNotice(
                "high",
                f"{len(risky)} of the {len(selection.scripts)} selected scripts are in Nmap's "
                f"{', '.join(found)} categories: {names}.",
            )
        )
    if selection.unresolved:
        notices.append(
            IntrusivenessNotice(
                "medium",
                "Not in the installed script database, so Genmap cannot check what they do: "
                + ", ".join(selection.unresolved[:6])
                + ".",
            )
        )
    return notices


def assess_intrusiveness(
    config: ScanConfiguration,
    intrusive_categories: Iterable[str] = DEFAULT_INTRUSIVE_CATEGORIES,
    catalog: Optional[ScriptCatalog] = None,
) -> list[IntrusivenessNotice]:
    """List the parts of a configuration that deserve a second look.

    With the installed script catalog the NSE check is exact: the selection
    is resolved the way Nmap resolves it and only scripts Nmap itself files
    under an intrusive category are reported. Without a catalog Genmap falls
    back to reading the expressions.
    """
    notices: list[IntrusivenessNotice] = []
    categories = {c.lower() for c in intrusive_categories}

    if catalog is not None and getattr(catalog, "scripts", None):
        notices.extend(_catalog_notices(config, categories, catalog))
    else:
        terms = _script_terms(config.scripts.scripts)
        hit_categories = sorted(t for t in terms if t in categories)
        if hit_categories:
            notices.append(
                IntrusivenessNotice(
                    "high",
                    "NSE categories selected that can crash, brute force, or exploit services: "
                    + ", ".join(hit_categories)
                    + ".",
                )
            )
        wildcard_terms = sorted(t for t in terms if t in ("all", "*") or t.endswith("*"))
        if wildcard_terms:
            notices.append(
                IntrusivenessNotice(
                    "high",
                    "Script wildcards (" + ", ".join(wildcard_terms) + ") may include intrusive scripts; "
                    "the installed script list was not available to check.",
                )
            )
        risky_names = sorted(
            t for t in terms if t.startswith(("brute", "dos", "exploit", "fuzzer")) or "-brute" in t or "-dos" in t
        )
        if risky_names:
            notices.append(
                IntrusivenessNotice("high", "Scripts selected by name look intrusive: " + ", ".join(risky_names) + ".")
            )
        if any("not" == t.lower() for e in config.scripts.scripts for t in e.split()):
            notices.append(
                IntrusivenessNotice(
                    "medium",
                    "The selection uses \"not\"; without the installed script list Genmap cannot tell what remains selected.",
                )
            )

    if config.aggressive:
        notices.append(
            IntrusivenessNotice(
                "medium",
                "Aggressive mode (-A) enables OS detection, version detection, default scripts, and traceroute.",
            )
        )

    if config.timing.template is not None and config.timing.template >= 5:
        notices.append(IntrusivenessNotice("medium", "Timing template T5 can overwhelm hosts and drop results."))
    if config.timing.min_rate and config.timing.min_rate >= 1000:
        notices.append(
            IntrusivenessNotice("medium", f"A minimum rate of {config.timing.min_rate} packets per second is very fast.")
        )

    ev = config.evasion
    if ev.decoys or ev.spoof_source or ev.spoof_mac:
        notices.append(
            IntrusivenessNotice(
                "high",
                "Decoys or spoofed addresses are configured. Responses may reach the spoofed hosts and the scan cannot be attributed cleanly.",
            )
        )
    if ev.bad_checksum or ev.fragment_packets or ev.mtu:
        notices.append(IntrusivenessNotice("medium", "Packet manipulation options are enabled (fragmentation, MTU, or bad checksums)."))
    if config.techniques.tcp == TcpScanTechnique.IDLE:
        notices.append(IntrusivenessNotice("medium", "Idle scan relays traffic through the zombie host."))
    if config.techniques.tcp == TcpScanTechnique.FTP_BOUNCE:
        notices.append(IntrusivenessNotice("high", "FTP bounce scan abuses a third party FTP server as a relay."))

    if config.techniques.mode == ScanMode.PORT_SCAN:
        try:
            targets = parse_targets(config.targets.targets)
        except Exception:
            targets = []
        estimated = estimate_host_count(targets) if targets else None
        if estimated is not None and estimated >= LARGE_SCOPE_THRESHOLD:
            notices.append(
                IntrusivenessNotice("medium", f"The target expressions cover roughly {estimated:,} addresses.")
            )
        if config.targets.random_targets:
            notices.append(
                IntrusivenessNotice("high", "Random Internet targets (-iR) will scan hosts you do not control.")
            )

    return notices


def is_high_risk(notices: list[IntrusivenessNotice]) -> bool:
    return any(n.level == "high" for n in notices)
