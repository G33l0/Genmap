"""Qt item models for scan results.

The tree model holds hosts with their ports as children. Each item carries
the searchable text for every filter field in a custom role, so the proxy
can filter on data that is not shown as a column (OS, CPE, NSE output).
"""

from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import QModelIndex, QSortFilterProxyModel, Qt
from PyQt6.QtGui import QColor, QStandardItem, QStandardItemModel

from genmap.core.results import Host, Port, ScanResult

ROLE_SEARCH = Qt.ItemDataRole.UserRole + 1
ROLE_KIND = Qt.ItemDataRole.UserRole + 2
ROLE_HOST_INDEX = Qt.ItemDataRole.UserRole + 3
ROLE_PORT_INDEX = Qt.ItemDataRole.UserRole + 4
ROLE_SORT = Qt.ItemDataRole.UserRole + 5
ROLE_STATE = Qt.ItemDataRole.UserRole + 6

FILTER_FIELDS: list[tuple[str, str]] = [
    ("all", "All fields"),
    ("host", "Host / IP"),
    ("port", "Port"),
    ("protocol", "Protocol"),
    ("state", "State"),
    ("service", "Service"),
    ("product", "Product"),
    ("version", "Version"),
    ("os", "OS"),
    ("cpe", "CPE"),
    ("nse", "NSE output"),
]

_HOST_FIELDS = {"all", "host", "os", "cpe", "nse", "state"}

STATE_COLORS = {"open": "success", "closed": "danger", "filtered": "warning"}


def _host_search(host: Host) -> dict[str, str]:
    os_text = ""
    cpes: list[str] = []
    if host.os:
        os_text = " ".join(m.name for m in host.os.matches)
        for match in host.os.matches:
            for cls in match.classes:
                os_text += " " + " ".join(p for p in (cls.vendor, cls.os_family, cls.os_generation, cls.os_type) if p)
                cpes.extend(cls.cpe)
    addresses = [a.address for a in host.addresses] + [a.vendor or "" for a in host.addresses]
    names = [h.name for h in host.hostnames]
    nse = " ".join(f"{s.script_id} {s.output}" for s in host.host_scripts)
    return {
        "host": " ".join(addresses + names),
        "os": os_text,
        "cpe": " ".join(cpes),
        "nse": nse,
        "state": host.status.state,
    }


def _port_search(host: Host, port: Port) -> dict[str, str]:
    service = port.service
    return {
        "host": " ".join([a.address for a in host.addresses] + [h.name for h in host.hostnames]),
        "port": str(port.port_id),
        "protocol": port.protocol,
        "state": port.state,
        "service": " ".join(p for p in ((service.name if service else None), (service.tunnel if service else None)) if p),
        "product": (service.product or "") + " " + (service.extra_info or "") if service else "",
        "version": service.version or "" if service else "",
        "cpe": " ".join(service.cpe) if service else "",
        "nse": " ".join(f"{s.script_id} {s.output}" for s in port.scripts),
        "os": (service.os_type or "") if service else "",
    }


def _search_blob(fields: dict[str, str]) -> dict[str, str]:
    lowered = {key: value.lower() for key, value in fields.items()}
    lowered["all"] = " ".join(lowered.values())
    return lowered


def _item(text: str, *, sort: Optional[object] = None, tooltip: Optional[str] = None) -> QStandardItem:
    item = QStandardItem(text)
    item.setEditable(False)
    if sort is not None:
        item.setData(sort, ROLE_SORT)
    if tooltip:
        item.setToolTip(tooltip)
    return item


def _ip_sort_key(host: Host) -> str:
    address = host.primary_address or ""
    try:
        import ipaddress

        parsed = ipaddress.ip_address(address)
        return f"{parsed.version}-{int(parsed):040d}"
    except ValueError:
        return f"9-{address}"


class ResultTreeModel(QStandardItemModel):
    HEADERS = ["Host / Port", "State", "Service", "Product / Version", "Details"]

    def __init__(self, palette_lookup=None, parent=None) -> None:
        super().__init__(parent)
        self.setHorizontalHeaderLabels(self.HEADERS)
        self._palette_lookup = palette_lookup
        self.result: Optional[ScanResult] = None

    def _color(self, state: str) -> Optional[QColor]:
        if self._palette_lookup is None:
            return None
        role = STATE_COLORS.get(state)
        if role is None:
            return None
        return QColor(getattr(self._palette_lookup(), role))

    def load(self, result: ScanResult) -> None:
        self.clear()
        self.setHorizontalHeaderLabels(self.HEADERS)
        self.result = result
        root = self.invisibleRootItem()
        for host_index, host in enumerate(result.hosts):
            search = _search_blob(_host_search(host))
            os_match = host.best_os_match
            details: list[str] = []
            if os_match:
                details.append(f"{os_match.name} ({os_match.accuracy}%)" if os_match.accuracy is not None else os_match.name)
            mac = host.mac_address
            if mac:
                details.append(f"MAC {mac.address}" + (f" {mac.vendor}" if mac.vendor else ""))
            open_count = len(host.open_ports)
            row = [
                _item(host.display_name, sort=_ip_sort_key(host)),
                _item(host.status.state, sort=host.status.state),
                _item(f"{open_count} open" if host.ports or open_count else "", sort=open_count),
                _item(""),
                _item("; ".join(details), tooltip="; ".join(details) or None),
            ]
            color = QColor(getattr(self._palette_lookup(), "success")) if self._palette_lookup and host.is_up else None
            if color:
                row[1].setForeground(color)
            for column, item in enumerate(row):
                item.setData("host", ROLE_KIND)
                item.setData(host_index, ROLE_HOST_INDEX)
                item.setData(search, ROLE_SEARCH)
                item.setData(host.status.state, ROLE_STATE)
            first = row[0]
            for port_index, port in enumerate(host.ports):
                port_search = _search_blob(_port_search(host, port))
                service = port.service
                name = service.name if service and service.name else ""
                if service and service.tunnel:
                    name = f"{service.tunnel}/{name}"
                product = " ".join(p for p in ((service.product if service else None), (service.version if service else None)) if p)
                extra = service.extra_info if service and service.extra_info else ""
                script_note = f"{len(port.scripts)} script result{'s' if len(port.scripts) != 1 else ''}" if port.scripts else ""
                detail = "; ".join(p for p in (extra, script_note) if p)
                children = [
                    _item(port.label, sort=(0 if port.protocol == "tcp" else 1, port.port_id)),
                    _item(port.state, sort=port.state, tooltip=f"Reason: {port.reason}" if port.reason else None),
                    _item(name, sort=name),
                    _item(product, sort=product, tooltip=product or None),
                    _item(detail, tooltip=detail or None),
                ]
                state_color = self._color(port.state.split("|")[0])
                if state_color:
                    children[1].setForeground(state_color)
                for item in children:
                    item.setData("port", ROLE_KIND)
                    item.setData(host_index, ROLE_HOST_INDEX)
                    item.setData(port_index, ROLE_PORT_INDEX)
                    item.setData(port_search, ROLE_SEARCH)
                    item.setData(port.state, ROLE_STATE)
                first.appendRow(children)
            root.appendRow(row)


class ResultFilterProxy(QSortFilterProxyModel):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setRecursiveFilteringEnabled(True)
        self.setAutoAcceptChildRows(True)
        self.setSortRole(ROLE_SORT)
        self._text = ""
        self._field = "all"
        self._state = ""
        self._hide_down = False

    def set_filter(self, text: str, field: str, state: str, hide_down: bool) -> None:
        self._text = text.strip().lower()
        self._field = field
        self._state = state
        self._hide_down = hide_down
        self.invalidateFilter()

    def _matches_text(self, search: dict[str, str]) -> bool:
        if not self._text:
            return True
        haystack = search.get(self._field, "")
        return all(term in haystack for term in self._text.split())

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        model = self.sourceModel()
        index = model.index(source_row, 0, source_parent)
        kind = index.data(ROLE_KIND)
        search = index.data(ROLE_SEARCH) or {}
        state = index.data(ROLE_STATE) or ""
        if kind == "host":
            if self._hide_down and state != "up":
                return False
            if self._state:
                # With a port state filter a host is shown only through matching ports.
                return False
            if not self._text:
                return True
            return self._field in _HOST_FIELDS and self._matches_text(search)
        if self._hide_down and source_parent.isValid() and source_parent.data(ROLE_STATE) != "up":
            return False
        if self._state and state != self._state:
            return False
        return self._matches_text(search)

    def is_filtering(self) -> bool:
        return bool(self._text or self._state or self._hide_down)

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:
        a = left.data(ROLE_SORT)
        b = right.data(ROLE_SORT)
        if a is None or b is None:
            return str(left.data() or "") < str(right.data() or "")
        try:
            return a < b
        except TypeError:
            return str(a) < str(b)


class PortTableModel(QStandardItemModel):
    HEADERS = ["Host", "Port", "Protocol", "State", "Service", "Product", "Version", "Extra info", "CPE", "Scripts"]

    def load(self, result: ScanResult) -> None:
        self.clear()
        self.setHorizontalHeaderLabels(self.HEADERS)
        for host in result.hosts:
            for port in host.ports:
                service = port.service
                values = [
                    (host.display_name, _ip_sort_key(host)),
                    (str(port.port_id), port.port_id),
                    (port.protocol, port.protocol),
                    (port.state, port.state),
                    (service.name or "" if service else "", None),
                    (service.product or "" if service else "", None),
                    (service.version or "" if service else "", None),
                    (service.extra_info or "" if service else "", None),
                    (", ".join(service.cpe) if service else "", None),
                    (", ".join(s.script_id for s in port.scripts), None),
                ]
                row = []
                for text, sort in values:
                    item = _item(text, sort=sort if sort is not None else text.lower(), tooltip=text if len(text) > 40 else None)
                    row.append(item)
                self.appendRow(row)
