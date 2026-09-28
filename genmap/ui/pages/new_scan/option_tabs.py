"""The option tabs of the New Scan page.

Each tab loads its part of a ScanConfiguration and writes it back into a
plain dict. The page validates the assembled dict in one go, so a bad value
in any tab turns into a readable validation issue instead of an exception
while the user is still typing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from PyQt6.QtCore import QStringListModel, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QCompleter,
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from genmap.core.scan_config import (
    ArpPingMode,
    DnsResolutionMode,
    PortSelectionMode,
    ScanConfiguration,
    ScanMode,
    SctpScanTechnique,
    TcpScanTechnique,
)
from genmap.core.targets import estimate_host_count, parse_targets
from genmap.errors import GenmapError
from genmap.nmap.arguments import review_arguments
from genmap.nmap.environment import NmapEnvironment
from genmap.nmap.nse import CATEGORY_DESCRIPTIONS, INTRUSIVE_CATEGORIES
from genmap.ui.widgets.common import form_layout, hint, label
from genmap.ui.widgets.inputs import EnumCombo, OptionalSpinBox, TextField, split_list


class OptionTab(QScrollArea):
    """Scrollable container for one group of options."""

    changed = pyqtSignal()
    title = ""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setFrameShape(QScrollArea.Shape.NoFrame)
        self.body = QWidget()
        self.layout_ = QVBoxLayout(self.body)
        self.layout_.setContentsMargins(18, 16, 18, 18)
        self.layout_.setSpacing(12)
        self.setWidget(self.body)

    def finish(self) -> None:
        self.layout_.addStretch(1)
        self._wire(self.body)

    def _wire(self, root: QWidget) -> None:
        for widget in root.findChildren(QLineEdit):
            widget.textChanged.connect(self.changed)
        for widget in root.findChildren(QSpinBox):
            widget.valueChanged.connect(self.changed)
        for widget in root.findChildren(QComboBox):
            widget.currentIndexChanged.connect(self.changed)
            if widget.isEditable():
                widget.editTextChanged.connect(self.changed)
        for widget in root.findChildren(QCheckBox):
            widget.toggled.connect(self.changed)
        for widget in root.findChildren(QRadioButton):
            widget.toggled.connect(self.changed)

    def group(self, title: str) -> tuple[QGroupBox, QVBoxLayout]:
        box = QGroupBox(title)
        layout = QVBoxLayout(box)
        layout.setSpacing(8)
        self.layout_.addWidget(box)
        return box, layout

    def load(self, config: ScanConfiguration) -> None:
        raise NotImplementedError

    def dump(self, data: dict[str, Any]) -> None:
        raise NotImplementedError

    def set_environment(self, env: Optional[NmapEnvironment]) -> None:
        """Optional hook for tabs that adapt to the installed Nmap."""


def _file_row(field: QLineEdit, caption: str, parent: QWidget, *, save: bool = False) -> QWidget:
    row = QWidget()
    layout = QHBoxLayout(row)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(6)
    layout.addWidget(field, 1)
    button = QPushButton("Browse...")

    def browse() -> None:
        start = field.text() or str(Path.home())
        if save:
            path, _ = QFileDialog.getSaveFileName(parent, caption, start)
        else:
            path, _ = QFileDialog.getOpenFileName(parent, caption, start, "All files (*)")
        if path:
            field.setText(path)

    button.clicked.connect(browse)
    layout.addWidget(button)
    return row


class TargetsTab(OptionTab):
    title = "Targets"

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        box, layout = self.group("Target sources")
        layout.addWidget(hint("The main target field at the top of the page takes addresses, hostnames, CIDR networks, and octet ranges such as 10.0.0-5.1-254."))
        form = form_layout()
        self.target_file = TextField("One target per line (-iL)")
        form.addRow("Target file", _file_row(self.target_file, "Choose target list", self))
        self.random_targets = OptionalSpinBox(1, 1_000_000, unset_text="Off")
        self.random_targets.setToolTip("-iR: pick random Internet hosts. Only use this where you are authorized to scan.")
        form.addRow("Random hosts", self.random_targets)
        layout.addLayout(form)

        box, layout = self.group("Exclusions")
        form = form_layout()
        self.exclusions = TextField("Addresses or networks to skip, comma separated")
        form.addRow("Exclude", self.exclusions)
        self.exclude_file = TextField("One exclusion per line (--excludefile)")
        form.addRow("Exclude file", _file_row(self.exclude_file, "Choose exclusion list", self))
        layout.addLayout(form)
        self.finish()

    def load(self, config: ScanConfiguration) -> None:
        spec = config.targets
        self.target_file.set_optional_text(spec.target_file)
        self.random_targets.set_optional_value(spec.random_targets)
        self.exclusions.setText(", ".join(spec.exclusions))
        self.exclude_file.set_optional_text(spec.exclude_file)

    def dump(self, data: dict[str, Any]) -> None:
        targets = data.setdefault("targets", {})
        targets["target_file"] = self.target_file.optional_text()
        targets["random_targets"] = self.random_targets.optional_value()
        targets["exclusions"] = split_list(self.exclusions.text())
        targets["exclude_file"] = self.exclude_file.optional_text()


_TCP_DESCRIPTIONS = {
    TcpScanTechnique.AUTO: "Nmap picks: SYN scan with raw packet access, otherwise a full TCP connect scan.",
    TcpScanTechnique.SYN: "Half open scan (-sS). Fast and the usual choice. Needs raw packet access.",
    TcpScanTechnique.CONNECT: "Full TCP handshake through the operating system (-sT). Works without special privileges.",
    TcpScanTechnique.ACK: "Maps firewall rules (-sA). Reports filtered or unfiltered, not open or closed.",
    TcpScanTechnique.WINDOW: "Like ACK but reads the TCP window to tell open from closed on some systems (-sW).",
    TcpScanTechnique.MAIMON: "FIN/ACK probe (-sM). Only meaningful against certain BSD derived stacks.",
    TcpScanTechnique.FIN: "Sends only FIN (-sF). Can pass some stateless filters; Windows replies closed for everything.",
    TcpScanTechnique.NULL: "Sends no flags (-sN). Same caveats as FIN.",
    TcpScanTechnique.XMAS: "Sends FIN, PSH, and URG (-sX). Same caveats as FIN.",
    TcpScanTechnique.CUSTOM_FLAGS: "Send any combination of TCP flags (--scanflags).",
    TcpScanTechnique.IDLE: "Blind scan through a zombie host's IP ID sequence (-sI). The zombie must be idle.",
    TcpScanTechnique.FTP_BOUNCE: "Relays the scan through an FTP server that allows PORT to third parties (-b).",
}


class TechniqueTab(OptionTab):
    title = "Scan type"

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        box, layout = self.group("What should Nmap do?")
        self.mode_group = QButtonGroup(self)
        self.mode_port = QRadioButton("Port scan: discover hosts, then scan their ports")
        self.mode_ping = QRadioButton("Host discovery only: find live hosts, no port scan (-sn)")
        self.mode_list = QRadioButton("List targets only: resolve and print targets, send nothing to them (-sL)")
        for index, button in enumerate((self.mode_port, self.mode_ping, self.mode_list)):
            self.mode_group.addButton(button, index)
            layout.addWidget(button)
        self.mode_port.setChecked(True)

        self.techniques_box, layout = self.group("Techniques")
        form = form_layout()
        items: list[tuple[str, object]] = [
            ("Nmap default", TcpScanTechnique.AUTO),
            ("SYN (-sS)", TcpScanTechnique.SYN),
            ("Connect (-sT)", TcpScanTechnique.CONNECT),
            ("ACK (-sA)", TcpScanTechnique.ACK),
            ("Window (-sW)", TcpScanTechnique.WINDOW),
            ("Maimon (-sM)", TcpScanTechnique.MAIMON),
            ("FIN (-sF)", TcpScanTechnique.FIN),
            ("NULL (-sN)", TcpScanTechnique.NULL),
            ("Xmas (-sX)", TcpScanTechnique.XMAS),
            ("Custom flags (--scanflags)", TcpScanTechnique.CUSTOM_FLAGS),
            ("Idle / zombie (-sI)", TcpScanTechnique.IDLE),
            ("FTP bounce (-b)", TcpScanTechnique.FTP_BOUNCE),
            ("No TCP scan", None),
        ]
        self.tcp = EnumCombo(items)
        form.addRow("TCP", self.tcp)
        self.tcp_description = hint("")
        form.addRow("", self.tcp_description)
        self.custom_flags = TextField("e.g. SYNFIN or 9", mono=True)
        self.custom_flags_label = label("TCP flags")
        form.addRow(self.custom_flags_label, self.custom_flags)
        self.zombie = TextField("zombie host[:probe port]", mono=True)
        self.zombie_label = label("Zombie")
        form.addRow(self.zombie_label, self.zombie)
        self.ftp_relay = TextField("[user:pass@]server[:port]", mono=True)
        self.ftp_relay_label = label("FTP relay")
        form.addRow(self.ftp_relay_label, self.ftp_relay)
        self.udp = QCheckBox("UDP scan (-sU)")
        self.udp.setToolTip("UDP scanning is slow because closed ports are rate limited by most systems. Needs raw packet access.")
        form.addRow("UDP", self.udp)
        self.sctp = EnumCombo([("Off", None), ("INIT (-sY)", SctpScanTechnique.INIT), ("COOKIE ECHO (-sZ)", SctpScanTechnique.COOKIE_ECHO)])
        form.addRow("SCTP", self.sctp)
        self.ip_protocol = QCheckBox("IP protocol scan (-sO)")
        self.ip_protocol.setToolTip("Finds which IP protocols (TCP, ICMP, IGMP...) the target supports. Port list becomes protocol numbers.")
        form.addRow("IP protocols", self.ip_protocol)
        layout.addLayout(form)
        self.capability_note = hint("")
        self.capability_note.setProperty("status", "warning")
        layout.addWidget(self.capability_note)
        self.capability_note.hide()
        self.tcp.currentIndexChanged.connect(self._update_visibility)
        self.mode_group.idToggled.connect(lambda *_: self._update_visibility())
        self._update_visibility()
        self.finish()

    def _update_visibility(self) -> None:
        technique = self.tcp.current_value()
        self.custom_flags.setVisible(technique == TcpScanTechnique.CUSTOM_FLAGS)
        self.custom_flags_label.setVisible(technique == TcpScanTechnique.CUSTOM_FLAGS)
        self.zombie.setVisible(technique == TcpScanTechnique.IDLE)
        self.zombie_label.setVisible(technique == TcpScanTechnique.IDLE)
        self.ftp_relay.setVisible(technique == TcpScanTechnique.FTP_BOUNCE)
        self.ftp_relay_label.setVisible(technique == TcpScanTechnique.FTP_BOUNCE)
        self.tcp_description.setText(_TCP_DESCRIPTIONS.get(technique, "TCP ports will not be scanned."))
        self.techniques_box.setEnabled(self.mode_port.isChecked())

    def set_environment(self, env: Optional[NmapEnvironment]) -> None:
        if env is None or not env.usable:
            self.capability_note.hide()
            return
        raw = env.capabilities.get("raw_packets")
        if raw is not None and raw.available is not True:
            self.capability_note.setText(
                "Raw packet access may be unavailable: " + raw.detail + " SYN, UDP, SCTP, stealth, and IP protocol scans can fail; TCP connect still works."
            )
            self.capability_note.show()
        else:
            self.capability_note.hide()

    def load(self, config: ScanConfiguration) -> None:
        tech = config.techniques
        {ScanMode.PORT_SCAN: self.mode_port, ScanMode.PING_ONLY: self.mode_ping, ScanMode.LIST_ONLY: self.mode_list}[tech.mode].setChecked(True)
        self.tcp.set_current_value(tech.tcp)
        self.custom_flags.set_optional_text(tech.custom_tcp_flags)
        self.zombie.set_optional_text(tech.idle_zombie)
        self.ftp_relay.set_optional_text(tech.ftp_bounce_relay)
        self.udp.setChecked(tech.udp)
        self.sctp.set_current_value(tech.sctp)
        self.ip_protocol.setChecked(tech.ip_protocol)
        self._update_visibility()

    def dump(self, data: dict[str, Any]) -> None:
        mode = ScanMode.PORT_SCAN if self.mode_port.isChecked() else ScanMode.PING_ONLY if self.mode_ping.isChecked() else ScanMode.LIST_ONLY
        technique = self.tcp.current_value()
        data["techniques"] = {
            "mode": mode.value,
            "tcp": technique.value if technique is not None else None,
            "udp": self.udp.isChecked(),
            "sctp": self.sctp.current_value().value if self.sctp.current_value() is not None else None,
            "ip_protocol": self.ip_protocol.isChecked(),
            "custom_tcp_flags": self.custom_flags.optional_text() if technique == TcpScanTechnique.CUSTOM_FLAGS else None,
            "idle_zombie": self.zombie.optional_text() if technique == TcpScanTechnique.IDLE else None,
            "ftp_bounce_relay": self.ftp_relay.optional_text() if technique == TcpScanTechnique.FTP_BOUNCE else None,
        }


class PortsTab(OptionTab):
    title = "Ports"

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        box, layout = self.group("Which ports")
        self.mode_group = QButtonGroup(self)
        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(8)
        self.mode_default = QRadioButton("Nmap default (top 1000 per protocol)")
        self.mode_specific = QRadioButton("Specific ports")
        self.mode_top = QRadioButton("Most common")
        self.mode_fast = QRadioButton("Fast: top 100 (-F)")
        self.mode_all = QRadioButton("All 65535 ports (-p-)")
        self.specification = TextField("22,80,443,8000-8100  or  T:80,U:53", mono=True)
        self.specification.setToolTip("Numbers, ranges, service names (http*), and protocol prefixes T:, U:, S:, P:.")
        self.top_ports = QSpinBox()
        self.top_ports.setRange(1, 65535)
        self.top_ports.setValue(100)
        self.top_ports.setSuffix(" ports")
        grid.addWidget(self.mode_default, 0, 0, 1, 2)
        grid.addWidget(self.mode_specific, 1, 0)
        grid.addWidget(self.specification, 1, 1)
        grid.addWidget(self.mode_top, 2, 0)
        grid.addWidget(self.top_ports, 2, 1, Qt.AlignmentFlag.AlignLeft)
        grid.addWidget(self.mode_fast, 3, 0, 1, 2)
        grid.addWidget(self.mode_all, 4, 0, 1, 2)
        grid.setColumnStretch(1, 1)
        for index, button in enumerate((self.mode_default, self.mode_specific, self.mode_top, self.mode_fast, self.mode_all)):
            self.mode_group.addButton(button, index)
        self.mode_default.setChecked(True)
        layout.addLayout(grid)

        box, layout = self.group("Refinements")
        form = form_layout()
        self.exclude = TextField("Ports to skip, e.g. 9100,515", mono=True)
        form.addRow("Exclude ports", self.exclude)
        self.sequential = QCheckBox("Scan ports in order instead of randomizing (-r)")
        form.addRow("", self.sequential)
        layout.addLayout(form)
        self.mode_group.idToggled.connect(lambda *_: self._update_enabled())
        self._update_enabled()
        self.finish()

    def _update_enabled(self) -> None:
        self.specification.setEnabled(self.mode_specific.isChecked())
        self.top_ports.setEnabled(self.mode_top.isChecked())

    def load(self, config: ScanConfiguration) -> None:
        ports = config.ports
        {
            PortSelectionMode.DEFAULT: self.mode_default,
            PortSelectionMode.SPECIFIC: self.mode_specific,
            PortSelectionMode.TOP: self.mode_top,
            PortSelectionMode.FAST: self.mode_fast,
            PortSelectionMode.ALL: self.mode_all,
        }[ports.mode].setChecked(True)
        self.specification.setText(ports.specification)
        self.top_ports.setValue(ports.top_ports)
        self.exclude.setText(ports.exclude_ports)
        self.sequential.setChecked(ports.sequential)
        self._update_enabled()

    def dump(self, data: dict[str, Any]) -> None:
        modes = [PortSelectionMode.DEFAULT, PortSelectionMode.SPECIFIC, PortSelectionMode.TOP, PortSelectionMode.FAST, PortSelectionMode.ALL]
        mode = modes[max(self.mode_group.checkedId(), 0)]
        data["ports"] = {
            "mode": mode.value,
            "specification": self.specification.text().strip() if mode == PortSelectionMode.SPECIFIC else "",
            "top_ports": self.top_ports.value(),
            "exclude_ports": self.exclude.text().strip(),
            "sequential": self.sequential.isChecked(),
        }


class DiscoveryTab(OptionTab):
    title = "Discovery"

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        box, layout = self.group("Host discovery")
        layout.addWidget(hint(
            "Before scanning ports Nmap checks which hosts are up. Leave every probe unchecked to use Nmap's defaults "
            "(ARP on local Ethernet, otherwise ICMP echo, TCP SYN 443, TCP ACK 80, and ICMP timestamp)."
        ))
        self.skip = QCheckBox("Treat all hosts as up and skip discovery (-Pn)")
        self.skip.setToolTip("Useful when hosts block ping. Every address is port scanned, which is much slower on sparse networks.")
        layout.addWidget(self.skip)
        self.probes = QWidget()
        form = form_layout()
        form.setContentsMargins(0, 0, 0, 0)
        self.probes.setLayout(form)
        icmp_row = QWidget()
        icmp_layout = QHBoxLayout(icmp_row)
        icmp_layout.setContentsMargins(0, 0, 0, 0)
        self.icmp_echo = QCheckBox("Echo (-PE)")
        self.icmp_timestamp = QCheckBox("Timestamp (-PP)")
        self.icmp_netmask = QCheckBox("Netmask (-PM)")
        for box_ in (self.icmp_echo, self.icmp_timestamp, self.icmp_netmask):
            icmp_layout.addWidget(box_)
        icmp_layout.addStretch(1)
        form.addRow("ICMP", icmp_row)
        self.tcp_syn = TextField("e.g. 22,80,443", mono=True)
        self.tcp_syn.setToolTip("-PS: send TCP SYN to these ports. Any reply means the host is up.")
        form.addRow("TCP SYN ports", self.tcp_syn)
        self.tcp_ack = TextField("e.g. 80", mono=True)
        self.tcp_ack.setToolTip("-PA: send TCP ACK to these ports. Useful against stateless firewalls.")
        form.addRow("TCP ACK ports", self.tcp_ack)
        self.udp = TextField("e.g. 53,161", mono=True)
        self.udp.setToolTip("-PU: send UDP to these ports. A port unreachable reply means the host is up.")
        form.addRow("UDP ports", self.udp)
        self.sctp = TextField("e.g. 80", mono=True)
        form.addRow("SCTP INIT ports", self.sctp)
        self.ip_protocols = TextField("e.g. 1,2,4", mono=True)
        self.ip_protocols.setToolTip("-PO: send IP packets with these protocol numbers.")
        form.addRow("IP protocols", self.ip_protocols)
        self.arp = EnumCombo([("Automatic on local networks", ArpPingMode.AUTO), ("Disabled (--disable-arp-ping)", ArpPingMode.DISABLED)])
        form.addRow("ARP / ND", self.arp)
        layout.addWidget(self.probes)
        self.traceroute = QCheckBox("Trace the network path to each host (--traceroute)")
        layout.addWidget(self.traceroute)

        box, layout = self.group("Name resolution")
        form = form_layout()
        self.dns_mode = EnumCombo([
            ("Resolve hosts that are up", DnsResolutionMode.DEFAULT),
            ("Always resolve (-R)", DnsResolutionMode.ALWAYS),
            ("Never resolve (-n)", DnsResolutionMode.NEVER),
        ])
        form.addRow("Reverse DNS", self.dns_mode)
        self.dns_servers = TextField("Custom DNS servers, comma separated", mono=True)
        form.addRow("DNS servers", self.dns_servers)
        self.system_dns = QCheckBox("Use the operating system resolver (--system-dns)")
        form.addRow("", self.system_dns)
        layout.addLayout(form)
        self.skip.toggled.connect(lambda checked: self.probes.setEnabled(not checked))
        self.finish()

    def load(self, config: ScanConfiguration) -> None:
        d = config.discovery
        self.skip.setChecked(d.skip_discovery)
        self.probes.setEnabled(not d.skip_discovery)
        self.icmp_echo.setChecked(d.icmp_echo)
        self.icmp_timestamp.setChecked(d.icmp_timestamp)
        self.icmp_netmask.setChecked(d.icmp_netmask)
        self.tcp_syn.setText(d.tcp_syn_ports)
        self.tcp_ack.setText(d.tcp_ack_ports)
        self.udp.setText(d.udp_ports)
        self.sctp.setText(d.sctp_ports)
        self.ip_protocols.setText(d.ip_protocols)
        self.arp.set_current_value(d.arp_ping)
        self.traceroute.setChecked(d.traceroute)
        self.dns_mode.set_current_value(config.dns.resolution)
        self.dns_servers.setText(", ".join(config.dns.servers))
        self.system_dns.setChecked(config.dns.use_system_resolver)

    def dump(self, data: dict[str, Any]) -> None:
        data["discovery"] = {
            "skip_discovery": self.skip.isChecked(),
            "icmp_echo": self.icmp_echo.isChecked(),
            "icmp_timestamp": self.icmp_timestamp.isChecked(),
            "icmp_netmask": self.icmp_netmask.isChecked(),
            "tcp_syn_ports": self.tcp_syn.text().strip(),
            "tcp_ack_ports": self.tcp_ack.text().strip(),
            "udp_ports": self.udp.text().strip(),
            "sctp_ports": self.sctp.text().strip(),
            "ip_protocols": self.ip_protocols.text().strip(),
            "arp_ping": self.arp.current_value().value,
            "traceroute": self.traceroute.isChecked(),
        }
        data["dns"] = {
            "resolution": self.dns_mode.current_value().value,
            "servers": split_list(self.dns_servers.text()),
            "use_system_resolver": self.system_dns.isChecked(),
        }


class DetectionTab(OptionTab):
    title = "Detection"

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        box, layout = self.group("Service and version detection")
        self.service = QCheckBox("Probe open ports to identify service, product, and version (-sV)")
        layout.addWidget(self.service)
        form = form_layout()
        self.intensity = OptionalSpinBox(0, 9)
        self.intensity.setToolTip("0 is light and fast, 9 tries every probe. Nmap's default is 7.")
        form.addRow("Intensity", self.intensity)
        self.version_trace = QCheckBox("Show version detection activity (--version-trace)")
        form.addRow("", self.version_trace)
        layout.addLayout(form)

        box, layout = self.group("Operating system detection")
        self.os = QCheckBox("Fingerprint the TCP/IP stack to guess the OS (-O)")
        self.os.setToolTip("Needs raw packet access and at least one open and one closed port for reliable results.")
        layout.addWidget(self.os)
        form = form_layout()
        self.os_limit = QCheckBox("Only fingerprint promising hosts (--osscan-limit)")
        self.os_guess = QCheckBox("Report close matches more aggressively (--osscan-guess)")
        self.os_tries = OptionalSpinBox(1, 50)
        form.addRow("", self.os_limit)
        form.addRow("", self.os_guess)
        form.addRow("Max OS tries", self.os_tries)
        layout.addLayout(form)

        box, layout = self.group("Aggressive mode")
        self.aggressive = QCheckBox("Enable OS detection, version detection, default scripts, and traceroute together (-A)")
        layout.addWidget(self.aggressive)
        layout.addWidget(hint("Aggressive mode runs the default NSE script set, which sends more traffic than a plain port scan."))
        self.finish()

    def load(self, config: ScanConfiguration) -> None:
        svc, osd = config.service_detection, config.os_detection
        self.service.setChecked(svc.enabled)
        self.intensity.set_optional_value(svc.intensity)
        self.version_trace.setChecked(svc.trace)
        self.os.setChecked(osd.enabled)
        self.os_limit.setChecked(osd.limit_to_promising)
        self.os_guess.setChecked(osd.guess_aggressively)
        self.os_tries.set_optional_value(osd.max_tries)
        self.aggressive.setChecked(config.aggressive)

    def dump(self, data: dict[str, Any]) -> None:
        data["service_detection"] = {
            "enabled": self.service.isChecked(),
            "intensity": self.intensity.optional_value(),
            "trace": self.version_trace.isChecked(),
        }
        data["os_detection"] = {
            "enabled": self.os.isChecked(),
            "limit_to_promising": self.os_limit.isChecked(),
            "guess_aggressively": self.os_guess.isChecked(),
            "max_tries": self.os_tries.optional_value(),
        }
        data["aggressive"] = self.aggressive.isChecked()


_STANDARD_CATEGORIES = sorted(CATEGORY_DESCRIPTIONS)


class ScriptsTab(OptionTab):
    title = "Scripts"

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        box, layout = self.group("Script selection")
        layout.addWidget(hint(
            "Enter script names, categories, folders, or boolean expressions such as \"default and safe\" or "
            "\"http-* and not http-brute\", separated by commas. Ticking a category adds it to the list."
        ))
        self.expressions = TextField("e.g. default, http-title, vuln", mono=True)
        self._completer_model = QStringListModel(self)
        completer = QCompleter(self._completer_model, self)
        completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        completer.setFilterMode(Qt.MatchFlag.MatchContains)
        self.expressions.setCompleter(completer)
        layout.addWidget(self.expressions)
        self.catalog_note = hint("")
        layout.addWidget(self.catalog_note)

        self.category_box = QGroupBox("Categories")
        self.category_grid = QGridLayout(self.category_box)
        self.category_grid.setHorizontalSpacing(18)
        self._category_checks: dict[str, QCheckBox] = {}
        layout.addWidget(self.category_box)
        self._build_categories(_STANDARD_CATEGORIES)

        box, layout = self.group("Script arguments")
        self.args_table = QTableWidget(0, 2)
        self.args_table.setHorizontalHeaderLabels(["Name", "Value"])
        self.args_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self.args_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.args_table.setColumnWidth(0, 220)
        self.args_table.verticalHeader().setVisible(False)
        self.args_table.setMinimumHeight(120)
        self.args_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.args_table.itemChanged.connect(lambda *_: self.changed.emit())
        layout.addWidget(self.args_table)
        buttons = QHBoxLayout()
        add = QPushButton("Add argument")
        remove = QPushButton("Remove selected")
        add.clicked.connect(self._add_argument)
        remove.clicked.connect(self._remove_argument)
        buttons.addWidget(add)
        buttons.addWidget(remove)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        form = form_layout()
        self.args_file = TextField("--script-args-file")
        form.addRow("Arguments file", _file_row(self.args_file, "Choose script arguments file", self))
        layout.addLayout(form)

        box, layout = self.group("Execution")
        form = form_layout()
        self.timeout = TextField("e.g. 2m", mono=True)
        self.timeout.setToolTip("--script-timeout: stop any single script after this long.")
        form.addRow("Script timeout", self.timeout)
        self.trace = QCheckBox("Show all data sent and received by scripts (--script-trace)")
        self.updatedb = QCheckBox("Rebuild the script database before scanning (--script-updatedb)")
        self.updatedb.setToolTip("Needs write access to the Nmap scripts folder, usually administrator rights.")
        form.addRow("", self.trace)
        form.addRow("", self.updatedb)
        layout.addLayout(form)
        self.expressions.textChanged.connect(self._sync_checks_from_text)
        self.finish()

    def _build_categories(self, categories: list[str]) -> None:
        for check in self._category_checks.values():
            check.deleteLater()
        self._category_checks.clear()
        columns = 3
        for index, category in enumerate(categories):
            intrusive = category in INTRUSIVE_CATEGORIES
            check = QCheckBox(f"{category}  (intrusive)" if intrusive else category)
            description = CATEGORY_DESCRIPTIONS.get(category, "")
            if intrusive:
                description += " Only run against systems you are authorized to test."
            check.setToolTip(description.strip())
            if intrusive:
                check.setProperty("status", "warning")
            check.toggled.connect(lambda checked, c=category: self._on_category_toggled(c, checked))
            self.category_grid.addWidget(check, index // columns, index % columns)
            self._category_checks[category] = check

    def _current_items(self) -> list[str]:
        return split_list(self.expressions.text())

    def _on_category_toggled(self, category: str, checked: bool) -> None:
        items = self._current_items()
        if checked and category not in items:
            items.append(category)
        elif not checked and category in items:
            items.remove(category)
        else:
            return
        self.expressions.blockSignals(True)
        self.expressions.setText(", ".join(items))
        self.expressions.blockSignals(False)
        self.changed.emit()

    def _sync_checks_from_text(self) -> None:
        items = set(self._current_items())
        for category, check in self._category_checks.items():
            check.blockSignals(True)
            check.setChecked(category in items)
            check.blockSignals(False)

    def _add_argument(self, name: str = "", value: str = "") -> None:
        row = self.args_table.rowCount()
        self.args_table.insertRow(row)
        self.args_table.setItem(row, 0, QTableWidgetItem(name if isinstance(name, str) else ""))
        self.args_table.setItem(row, 1, QTableWidgetItem(value))
        if not name:
            self.args_table.editItem(self.args_table.item(row, 0))
        self.changed.emit()

    def _remove_argument(self) -> None:
        rows = sorted({index.row() for index in self.args_table.selectedIndexes()}, reverse=True)
        for row in rows:
            self.args_table.removeRow(row)
        self.changed.emit()

    def set_environment(self, env: Optional[NmapEnvironment]) -> None:
        catalog = env.scripts if env is not None else None
        if catalog and catalog.scripts:
            names = catalog.names()
            self._completer_model.setStringList(names + catalog.categories)
            self.catalog_note.setText(f"{len(names)} scripts found in the installed Nmap. Start typing for suggestions.")
            categories = catalog.categories
            if categories != list(self._category_checks):
                self._build_categories(categories)
                self._sync_checks_from_text()
        else:
            self._completer_model.setStringList(_STANDARD_CATEGORIES)
            self.catalog_note.setText("The installed script list is not available, so only category suggestions are offered.")
        nse = env.capabilities.get("nse") if env is not None else None
        if nse is not None and nse.available is False:
            self.catalog_note.setText(self.catalog_note.text() + " " + nse.detail)

    def load(self, config: ScanConfiguration) -> None:
        s = config.scripts
        self.expressions.setText(", ".join(s.scripts))
        self._sync_checks_from_text()
        self.args_table.blockSignals(True)
        self.args_table.setRowCount(0)
        for argument in s.arguments:
            row = self.args_table.rowCount()
            self.args_table.insertRow(row)
            self.args_table.setItem(row, 0, QTableWidgetItem(argument.name))
            self.args_table.setItem(row, 1, QTableWidgetItem(argument.value))
        self.args_table.blockSignals(False)
        self.args_file.set_optional_text(s.arguments_file)
        self.timeout.set_optional_text(s.timeout)
        self.trace.setChecked(s.trace)
        self.updatedb.setChecked(s.update_database)

    def dump(self, data: dict[str, Any]) -> None:
        arguments = []
        for row in range(self.args_table.rowCount()):
            name_item = self.args_table.item(row, 0)
            value_item = self.args_table.item(row, 1)
            name = name_item.text().strip() if name_item else ""
            if not name:
                continue
            arguments.append({"name": name, "value": value_item.text() if value_item else ""})
        data["scripts"] = {
            "scripts": self._current_items(),
            "arguments": arguments,
            "arguments_file": self.args_file.optional_text(),
            "timeout": self.timeout.optional_text(),
            "trace": self.trace.isChecked(),
            "update_database": self.updatedb.isChecked(),
        }


class TimingTab(OptionTab):
    title = "Timing"

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        box, layout = self.group("Template")
        form = form_layout()
        self.template = EnumCombo([
            ("Nmap default (T3 Normal)", None),
            ("T0 Paranoid: IDS evasion, extremely slow", 0),
            ("T1 Sneaky: IDS evasion, very slow", 1),
            ("T2 Polite: lower bandwidth and target load", 2),
            ("T3 Normal", 3),
            ("T4 Aggressive: fast, reliable networks", 4),
            ("T5 Insane: may sacrifice accuracy", 5),
        ])
        form.addRow("Timing template", self.template)
        layout.addLayout(form)
        layout.addWidget(hint("Individual values below override the template. Times accept ms, s, m, or h, for example 250ms or 30m."))

        box, layout = self.group("Timeouts and retries")
        form = form_layout()
        self.host_timeout = TextField("e.g. 30m", mono=True)
        self.initial_rtt = TextField("e.g. 500ms", mono=True)
        self.min_rtt = TextField("e.g. 100ms", mono=True)
        self.max_rtt = TextField("e.g. 1s", mono=True)
        self.max_retries = OptionalSpinBox(0, 50)
        form.addRow("Give up on host after", self.host_timeout)
        form.addRow("Initial RTT timeout", self.initial_rtt)
        form.addRow("Minimum RTT timeout", self.min_rtt)
        form.addRow("Maximum RTT timeout", self.max_rtt)
        form.addRow("Max retries", self.max_retries)
        layout.addLayout(form)

        box, layout = self.group("Rate and parallelism")
        form = form_layout()
        self.min_rate = OptionalSpinBox(1, 1_000_000)
        self.max_rate = OptionalSpinBox(1, 1_000_000)
        self.min_rate.setSuffix(" pkt/s")
        self.max_rate.setSuffix(" pkt/s")
        self.min_hostgroup = OptionalSpinBox(1, 100_000)
        self.max_hostgroup = OptionalSpinBox(1, 100_000)
        self.min_parallelism = OptionalSpinBox(1, 10_000)
        self.max_parallelism = OptionalSpinBox(1, 10_000)
        self.scan_delay = TextField("e.g. 10ms", mono=True)
        self.max_scan_delay = TextField("e.g. 1s", mono=True)
        form.addRow("Minimum rate", self.min_rate)
        form.addRow("Maximum rate", self.max_rate)
        form.addRow("Min host group", self.min_hostgroup)
        form.addRow("Max host group", self.max_hostgroup)
        form.addRow("Min parallel probes", self.min_parallelism)
        form.addRow("Max parallel probes", self.max_parallelism)
        form.addRow("Delay between probes", self.scan_delay)
        form.addRow("Max probe delay", self.max_scan_delay)
        self.defeat_rst = QCheckBox("Ignore RST rate limiting (--defeat-rst-ratelimit)")
        self.defeat_icmp = QCheckBox("Ignore ICMP rate limiting for UDP (--defeat-icmp-ratelimit)")
        form.addRow("", self.defeat_rst)
        form.addRow("", self.defeat_icmp)
        self.nsock = EnumCombo([("Automatic", None)])
        self.nsock.setToolTip("--nsock-engine: the I/O multiplexing backend. Leave on automatic unless troubleshooting.")
        form.addRow("Nsock engine", self.nsock)
        layout.addLayout(form)
        self.finish()

    def set_environment(self, env: Optional[NmapEnvironment]) -> None:
        current = self.nsock.current_value()
        self.nsock.blockSignals(True)
        self.nsock.clear()
        self.nsock.addItem("Automatic", None)
        engines = env.version.nsock_engines if env and env.version else ()
        for engine in engines:
            self.nsock.addItem(engine, engine)
        self.nsock.set_current_value(current)
        self.nsock.blockSignals(False)
        caps = env.capabilities if env else None
        icmp = caps.get("defeat_icmp_ratelimit") if caps else None
        self.defeat_icmp.setEnabled(icmp is None or icmp.available is not False)
        if icmp is not None and icmp.available is False:
            self.defeat_icmp.setToolTip(icmp.detail)

    def load(self, config: ScanConfiguration) -> None:
        t = config.timing
        self.template.set_current_value(t.template)
        self.host_timeout.set_optional_text(t.host_timeout)
        self.initial_rtt.set_optional_text(t.initial_rtt_timeout)
        self.min_rtt.set_optional_text(t.min_rtt_timeout)
        self.max_rtt.set_optional_text(t.max_rtt_timeout)
        self.max_retries.set_optional_value(t.max_retries)
        self.min_rate.set_optional_value(t.min_rate)
        self.max_rate.set_optional_value(t.max_rate)
        self.min_hostgroup.set_optional_value(t.min_hostgroup)
        self.max_hostgroup.set_optional_value(t.max_hostgroup)
        self.min_parallelism.set_optional_value(t.min_parallelism)
        self.max_parallelism.set_optional_value(t.max_parallelism)
        self.scan_delay.set_optional_text(t.scan_delay)
        self.max_scan_delay.set_optional_text(t.max_scan_delay)
        self.defeat_rst.setChecked(t.defeat_rst_ratelimit)
        self.defeat_icmp.setChecked(t.defeat_icmp_ratelimit)
        if t.nsock_engine and self.nsock.findData(t.nsock_engine) < 0:
            self.nsock.addItem(t.nsock_engine, t.nsock_engine)
        self.nsock.set_current_value(t.nsock_engine)

    def dump(self, data: dict[str, Any]) -> None:
        data["timing"] = {
            "template": self.template.current_value(),
            "host_timeout": self.host_timeout.optional_text(),
            "initial_rtt_timeout": self.initial_rtt.optional_text(),
            "min_rtt_timeout": self.min_rtt.optional_text(),
            "max_rtt_timeout": self.max_rtt.optional_text(),
            "max_retries": self.max_retries.optional_value(),
            "min_rate": self.min_rate.optional_value(),
            "max_rate": self.max_rate.optional_value(),
            "min_hostgroup": self.min_hostgroup.optional_value(),
            "max_hostgroup": self.max_hostgroup.optional_value(),
            "min_parallelism": self.min_parallelism.optional_value(),
            "max_parallelism": self.max_parallelism.optional_value(),
            "scan_delay": self.scan_delay.optional_text(),
            "max_scan_delay": self.max_scan_delay.optional_text(),
            "defeat_rst_ratelimit": self.defeat_rst.isChecked(),
            "defeat_icmp_ratelimit": self.defeat_icmp.isChecked(),
            "nsock_engine": self.nsock.current_value(),
        }


class PacketsTab(OptionTab):
    title = "Packets"

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        layout = self.layout_
        note = hint(
            "These options change how probes look on the wire. Most need raw packet scans, many are ignored for IPv6, "
            "and spoofing can make responses go to other hosts. Use them only in environments you are authorized to test."
        )
        note.setProperty("status", "warning")
        layout.addWidget(note)

        box, layout = self.group("Fragmentation and size")
        form = form_layout()
        self.fragment = EnumCombo([("Off", 0), ("8 byte fragments (-f)", 1), ("16 byte fragments (-ff)", 2)])
        self.mtu = OptionalSpinBox(8, 65528, unset_text="Off")
        self.mtu.setSingleStep(8)
        self.mtu.setToolTip("--mtu: fragment size in bytes, must be a multiple of 8.")
        self.data_length = OptionalSpinBox(0, 1400, unset_text="Off")
        self.data_length.setToolTip("--data-length: append random bytes to probes.")
        form.addRow("Fragment packets", self.fragment)
        form.addRow("Custom MTU", self.mtu)
        form.addRow("Random payload bytes", self.data_length)
        self.data_hex = TextField("--data, e.g. 0xdeadbeef", mono=True)
        self.data_string = TextField("--data-string", mono=True)
        form.addRow("Hex payload", self.data_hex)
        form.addRow("String payload", self.data_string)
        layout.addLayout(form)

        box, layout = self.group("Addresses and headers")
        form = form_layout()
        self.decoys = TextField("e.g. RND:5, ME, 10.0.0.9", mono=True)
        self.decoys.setToolTip("-D: interleave probes from decoy addresses. ME marks your own position.")
        self.spoof_source = TextField("-S source address", mono=True)
        self.spoof_mac = TextField("--spoof-mac: 0, vendor name, or MAC", mono=True)
        self.source_port = OptionalSpinBox(0, 65535, unset_text="Off")
        self.source_port.setToolTip("-g: send probes from this source port, e.g. 53.")
        self.ttl = OptionalSpinBox(1, 255, unset_text="Off")
        self.ip_options = TextField("--ip-options, e.g. R or \"L 10.0.0.1\"", mono=True)
        self.proxies = TextField("--proxies, e.g. socks4://127.0.0.1:1080", mono=True)
        form.addRow("Decoys", self.decoys)
        form.addRow("Spoof source", self.spoof_source)
        form.addRow("Spoof MAC", self.spoof_mac)
        form.addRow("Source port", self.source_port)
        form.addRow("IP TTL", self.ttl)
        form.addRow("IP options", self.ip_options)
        form.addRow("Proxies", self.proxies)
        self.badsum = QCheckBox("Send bogus checksums (--badsum)")
        self.adler = QCheckBox("Use Adler32 for SCTP checksums (--adler32)")
        self.randomize = QCheckBox("Randomize target order (--randomize-hosts)")
        form.addRow("", self.badsum)
        form.addRow("", self.adler)
        form.addRow("", self.randomize)
        layout.addLayout(form)
        self.finish()

    def load(self, config: ScanConfiguration) -> None:
        e = config.evasion
        self.fragment.set_current_value(e.fragment_packets)
        self.mtu.set_optional_value(e.mtu)
        self.data_length.set_optional_value(e.data_length)
        self.data_hex.set_optional_text(e.data_hex)
        self.data_string.set_optional_text(e.data_string)
        self.decoys.setText(", ".join(e.decoys))
        self.spoof_source.set_optional_text(e.spoof_source)
        self.spoof_mac.set_optional_text(e.spoof_mac)
        self.source_port.set_optional_value(e.source_port)
        self.ttl.set_optional_value(e.ttl)
        self.ip_options.set_optional_text(e.ip_options)
        self.proxies.setText(", ".join(e.proxies))
        self.badsum.setChecked(e.bad_checksum)
        self.adler.setChecked(e.adler32)
        self.randomize.setChecked(e.randomize_hosts)

    def dump(self, data: dict[str, Any]) -> None:
        data["evasion"] = {
            "fragment_packets": self.fragment.current_value(),
            "mtu": self.mtu.optional_value(),
            "data_length": self.data_length.optional_value(),
            "data_hex": self.data_hex.optional_text(),
            "data_string": self.data_string.optional_text(),
            "decoys": split_list(self.decoys.text()),
            "spoof_source": self.spoof_source.optional_text(),
            "spoof_mac": self.spoof_mac.optional_text(),
            "source_port": self.source_port.optional_value(),
            "ttl": self.ttl.optional_value(),
            "ip_options": self.ip_options.optional_text(),
            "proxies": split_list(self.proxies.text()),
            "bad_checksum": self.badsum.isChecked(),
            "adler32": self.adler.isChecked(),
            "randomize_hosts": self.randomize.isChecked(),
        }


class NetworkOutputTab(OptionTab):
    title = "Network and output"

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        box, layout = self.group("Network")
        form = form_layout()
        self.interface = QComboBox()
        self.interface.setEditable(True)
        self.interface.addItem("", None)
        self.interface.lineEdit().setPlaceholderText("Automatic")
        self.interface.setToolTip("-e: send and receive through this interface.")
        form.addRow("Interface", self.interface)
        self.ipv6 = QCheckBox("Scan over IPv6 (-6)")
        form.addRow("", self.ipv6)
        self.send_mode = EnumCombo([("Automatic", "auto"), ("Raw Ethernet frames (--send-eth)", "eth"), ("Raw IP packets (--send-ip)", "ip")])
        form.addRow("Send packets as", self.send_mode)
        self.privilege = EnumCombo([
            ("Detect automatically", None),
            ("Assume privileged (--privileged)", True),
            ("Assume unprivileged (--unprivileged)", False),
        ])
        form.addRow("Privileges", self.privilege)
        layout.addLayout(form)

        box, layout = self.group("Console output")
        form = form_layout()
        self.verbosity = QSpinBox()
        self.verbosity.setRange(0, 4)
        self.verbosity.setToolTip("Verbosity 1 or higher makes Nmap report ports as they are found, which feeds the live view.")
        self.debugging = QSpinBox()
        self.debugging.setRange(0, 9)
        form.addRow("Verbosity (-v)", self.verbosity)
        form.addRow("Debugging (-d)", self.debugging)
        self.reason = QCheckBox("Show why each port has its state (--reason)")
        self.open_only = QCheckBox("Only show open ports (--open)")
        self.packet_trace = QCheckBox("Print every packet sent and received (--packet-trace)")
        form.addRow("", self.reason)
        form.addRow("", self.open_only)
        form.addRow("", self.packet_trace)
        self.stats = TextField("Genmap setting", mono=True)
        self.stats.setToolTip("--stats-every: how often Nmap prints progress. Leave empty to use the interval from Settings.")
        form.addRow("Progress interval", self.stats)
        layout.addLayout(form)
        self.finish()

    def set_environment(self, env: Optional[NmapEnvironment]) -> None:
        current = self.interface.currentText()
        self.interface.blockSignals(True)
        self.interface.clear()
        self.interface.addItem("", None)
        if env and env.interfaces:
            for iface in env.interfaces.interfaces:
                text = iface.device
                detail = ", ".join(p for p in (iface.address, iface.interface_type, "up" if iface.is_up else "down") if p)
                self.interface.addItem(text, iface.device)
                self.interface.setItemData(self.interface.count() - 1, detail, Qt.ItemDataRole.ToolTipRole)
        self.interface.setEditText(current)
        self.interface.blockSignals(False)

    def load(self, config: ScanConfiguration) -> None:
        n, o = config.network, config.output
        self.interface.setEditText(n.interface or "")
        self.ipv6.setChecked(n.ipv6)
        self.send_mode.set_current_value("eth" if n.send_ethernet else "ip" if n.send_ip else "auto")
        self.privilege.set_current_value(n.privileged)
        self.verbosity.setValue(o.verbosity)
        self.debugging.setValue(o.debugging)
        self.reason.setChecked(o.show_reason)
        self.open_only.setChecked(o.open_only)
        self.packet_trace.setChecked(o.packet_trace)
        self.stats.set_optional_text(o.stats_interval)

    def dump(self, data: dict[str, Any]) -> None:
        mode = self.send_mode.current_value()
        interface = self.interface.currentText().strip()
        data["network"] = {
            "interface": interface or None,
            "ipv6": self.ipv6.isChecked(),
            "send_ethernet": mode == "eth",
            "send_ip": mode == "ip",
            "privileged": self.privilege.current_value(),
        }
        data["output"] = {
            "verbosity": self.verbosity.value(),
            "debugging": self.debugging.value(),
            "show_reason": self.reason.isChecked(),
            "open_only": self.open_only.isChecked(),
            "packet_trace": self.packet_trace.isChecked(),
            "stats_interval": self.stats.optional_text(),
        }


class AdvancedTab(OptionTab):
    title = "Advanced"

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        box, layout = self.group("Additional Nmap arguments")
        layout.addWidget(hint(
            "Anything typed here is passed to Nmap exactly as tokenised below, after the options chosen on the other tabs. "
            "Use it for options without a dedicated control, including ones added in newer Nmap releases. "
            "Quote values that contain spaces. Output file options are managed by Genmap and are rejected."
        ))
        self.arguments = TextField("e.g. --max-os-tries 2 --script-args-file args.txt", mono=True)
        layout.addWidget(self.arguments)
        self.tokens = label("", role="mono", wrap=True, selectable=True)
        layout.addWidget(self.tokens)
        self.problem = hint("")
        layout.addWidget(self.problem)
        self.arguments.textChanged.connect(self._preview)
        self._preview()
        self.finish()

    def _preview(self) -> None:
        text = self.arguments.text()
        if not text.strip():
            self.tokens.setText("")
            self.problem.setText("")
            return
        try:
            review = review_arguments(text)
        except GenmapError as exc:
            self.tokens.setText("")
            self.problem.setText(f"{exc.message} {exc.remedy or ''}".strip())
            self.problem.setProperty("status", "error")
        else:
            self.tokens.setText("  ".join(f"[{t}]" for t in review.tokens))
            self.problem.setText(" ".join(review.warnings))
            self.problem.setProperty("status", "warning" if review.warnings else None)
        self.problem.style().unpolish(self.problem)
        self.problem.style().polish(self.problem)

    def load(self, config: ScanConfiguration) -> None:
        self.arguments.setText(config.advanced_arguments)

    def dump(self, data: dict[str, Any]) -> None:
        data["advanced_arguments"] = self.arguments.text().strip()


def describe_target_scope(text: str) -> tuple[str, Optional[str]]:
    """Return (summary, status) for the target line."""
    if not text.strip():
        return "Enter at least one target.", None
    try:
        targets = parse_targets(text)
    except GenmapError as exc:
        return exc.message, "error"
    count = estimate_host_count(targets)
    families = {"IPv6" if t.is_ipv6 else "IPv4/hostname" for t in targets}
    noun = "target" if len(targets) == 1 else "targets"
    scope = f"about {count:,} address{'es' if count != 1 else ''}" if count is not None else "unknown size"
    return f"{len(targets)} {noun}, {scope} ({', '.join(sorted(families))}).", "ok"


ALL_TABS = (
    TechniqueTab,
    PortsTab,
    DiscoveryTab,
    DetectionTab,
    ScriptsTab,
    TimingTab,
    PacketsTab,
    NetworkOutputTab,
    TargetsTab,
    AdvancedTab,
)
