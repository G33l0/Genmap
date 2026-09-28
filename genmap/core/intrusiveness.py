"""Assessment of how noisy or intrusive a configuration is.

Nothing here decides what is allowed. The purpose is to make sure the
person launching the scan sees what they are about to do before Nmap
starts, particularly when NSE categories that attack services are selected.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from genmap.core.scan_config import ScanConfiguration, ScanMode, TcpScanTechnique
from genmap.core.targets import estimate_host_count, parse_targets

DEFAULT_INTRUSIVE_CATEGORIES = ("intrusive", "brute", "dos", "exploit", "fuzzer", "malware")
LARGE_SCOPE_THRESHOLD = 1024


@dataclass(frozen=True)
class IntrusivenessNotice:
    level: str  # "high" or "medium"
    message: str


def _script_terms(expressions: Iterable[str]) -> set[str]:
    terms: set[str] = set()
    for expression in expressions:
        for token in expression.replace("(", " ").replace(")", " ").replace(",", " ").split():
            lowered = token.lower()
            if lowered in ("and", "or", "not"):
                continue
            terms.add(lowered)
    return terms


def assess_intrusiveness(
    config: ScanConfiguration,
    intrusive_categories: Iterable[str] = DEFAULT_INTRUSIVE_CATEGORIES,
) -> list[IntrusivenessNotice]:
    notices: list[IntrusivenessNotice] = []
    categories = {c.lower() for c in intrusive_categories}

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
                "Script wildcards (" + ", ".join(wildcard_terms) + ") may include intrusive scripts.",
            )
        )
    risky_names = sorted(
        t for t in terms if any(t.startswith(prefix) for prefix in ("brute", "dos", "exploit", "fuzzer")) or "-brute" in t or "-dos" in t
    )
    if risky_names and not hit_categories:
        notices.append(
            IntrusivenessNotice("high", "Scripts selected by name look intrusive: " + ", ".join(risky_names) + ".")
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
