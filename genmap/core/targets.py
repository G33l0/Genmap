"""Parsing and validation of Nmap target expressions.

Nmap accepts a fairly rich target grammar: plain addresses, hostnames, CIDR
blocks for both address families, and per-octet ranges such as
10.0.0-3.1-254. This module classifies each expression so the UI can give
precise feedback and the intrusiveness checks can estimate scope.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from genmap.errors import TargetError

_HOSTNAME_LABEL = re.compile(r"^(?!-)[A-Za-z0-9_-]{1,63}(?<!-)$")
_OCTET_RANGE_PART = re.compile(r"^(\*|\d{1,3}(?:-\d{1,3})?(?:,\d{1,3}(?:-\d{1,3})?)*)$")
_FORBIDDEN = set("\"'`$;&|<>(){}\\\t\r\n")


class TargetKind(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    IPV4_NETWORK = "ipv4_network"
    IPV6_NETWORK = "ipv6_network"
    IPV4_OCTET_RANGE = "ipv4_octet_range"
    HOSTNAME = "hostname"
    HOSTNAME_NETWORK = "hostname_network"


@dataclass(frozen=True)
class Target:
    raw: str
    kind: TargetKind
    estimated_hosts: int | None

    @property
    def is_ipv6(self) -> bool:
        return self.kind in (TargetKind.IPV6, TargetKind.IPV6_NETWORK)

    @property
    def is_network(self) -> bool:
        return self.kind in (
            TargetKind.IPV4_NETWORK,
            TargetKind.IPV6_NETWORK,
            TargetKind.IPV4_OCTET_RANGE,
            TargetKind.HOSTNAME_NETWORK,
        )


def _check_characters(text: str) -> None:
    bad = sorted({c for c in text if c in _FORBIDDEN or ord(c) < 32})
    if bad:
        shown = ", ".join(repr(c) for c in bad)
        raise TargetError(
            f"Target '{text}' contains characters that are not valid in a target: {shown}.",
            remedy="Enter one address, hostname, or network per entry.",
        )


def _is_hostname(text: str) -> bool:
    if len(text) > 253 or not text:
        return False
    stripped = text[:-1] if text.endswith(".") else text
    labels = stripped.split(".")
    if not all(_HOSTNAME_LABEL.match(label) for label in labels):
        return False
    # The last label of a real name always contains a letter; anything else
    # is a malformed address or octet range rather than a hostname.
    return any(c.isalpha() for c in labels[-1])


def _octet_range_size(part: str) -> int:
    if part == "*":
        return 256
    total = 0
    for piece in part.split(","):
        if "-" in piece:
            low, high = piece.split("-", 1)
            low_i, high_i = int(low), int(high)
            if low_i > 255 or high_i > 255:
                raise ValueError("octet out of range")
            if low_i > high_i:
                raise ValueError("descending octet range")
            total += high_i - low_i + 1
        else:
            value = int(piece)
            if value > 255:
                raise ValueError("octet out of range")
            total += 1
    return total


def _try_octet_range(text: str) -> Target | None:
    parts = text.split(".")
    if len(parts) != 4:
        return None
    if not any(("-" in p) or (p == "*") or ("," in p) for p in parts):
        return None
    if not all(_OCTET_RANGE_PART.match(p) for p in parts):
        return None
    count = 1
    try:
        for part in parts:
            count *= _octet_range_size(part)
    except ValueError as exc:
        raise TargetError(
            f"Target '{text}' has an invalid octet range.",
            remedy="Each octet must be a number from 0 to 255, a range like 1-254, or *.",
        ) from exc
    return Target(text, TargetKind.IPV4_OCTET_RANGE, count)


def parse_target(text: str) -> Target:
    """Classify a single Nmap target expression or raise TargetError."""
    candidate = text.strip()
    if not candidate:
        raise TargetError("Target is empty.")
    _check_characters(candidate)
    if " " in candidate:
        raise TargetError(
            f"Target '{candidate}' contains a space.",
            remedy="Separate multiple targets with commas or new lines.",
        )
    if candidate.startswith("-"):
        raise TargetError(
            f"Target '{candidate}' starts with a dash and would be read as an option by Nmap."
        )

    if "/" in candidate:
        host_part, _, prefix = candidate.rpartition("/")
        if not prefix.isdigit():
            raise TargetError(
                f"Target '{candidate}' has an invalid network prefix.",
                remedy="Use CIDR notation such as 192.168.1.0/24 or 2001:db8::/64.",
            )
        try:
            network = ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            network = None
        if network is not None:
            kind = TargetKind.IPV6_NETWORK if network.version == 6 else TargetKind.IPV4_NETWORK
            return Target(candidate, kind, int(network.num_addresses))
        if _is_hostname(host_part) and 0 <= int(prefix) <= 32:
            return Target(candidate, TargetKind.HOSTNAME_NETWORK, 2 ** (32 - int(prefix)))
        if _try_octet_range(host_part) is not None:
            raise TargetError(
                f"Target '{candidate}' combines an octet range with a network prefix.",
                remedy="Use either an octet range or CIDR notation, not both.",
            )
        raise TargetError(
            f"Target '{candidate}' is not a valid network.",
            remedy="Use CIDR notation such as 192.168.1.0/24 or 2001:db8::/64.",
        )

    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        address = None
    if address is not None:
        kind = TargetKind.IPV6 if address.version == 6 else TargetKind.IPV4
        return Target(candidate, kind, 1)

    octet_range = _try_octet_range(candidate)
    if octet_range is not None:
        return octet_range

    if ":" in candidate:
        raise TargetError(
            f"Target '{candidate}' looks like an IPv6 address but is not valid.",
        )

    if _is_hostname(candidate):
        return Target(candidate, TargetKind.HOSTNAME, 1)

    if all(part.isdigit() or part == "" for part in candidate.split(".")):
        raise TargetError(
            f"Target '{candidate}' is not a valid IPv4 address.",
            remedy="An IPv4 address has four numbers from 0 to 255 separated by dots.",
        )

    raise TargetError(
        f"Target '{candidate}' is not a valid address, hostname, or network.",
    )


def split_target_text(text: str) -> list[str]:
    """Split free-form input on commas, whitespace, and new lines."""
    return [piece for piece in re.split(r"[,\s]+", text) if piece]


def parse_targets(text_or_items: str | Iterable[str]) -> list[Target]:
    items = split_target_text(text_or_items) if isinstance(text_or_items, str) else list(text_or_items)
    targets: list[Target] = []
    seen: set[str] = set()
    for item in items:
        target = parse_target(item)
        if target.raw not in seen:
            seen.add(target.raw)
            targets.append(target)
    return targets


def estimate_host_count(targets: Iterable[Target]) -> int | None:
    total = 0
    for target in targets:
        if target.estimated_hosts is None:
            return None
        total += target.estimated_hosts
    return total
