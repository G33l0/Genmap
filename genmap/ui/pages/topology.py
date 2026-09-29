"""Topology page: a map of the network paths Nmap recorded."""

from __future__ import annotations

import html
import json
import math
import os
import tempfile
from pathlib import Path
from typing import Callable, Optional

from PyQt6.QtCore import QPointF, QRectF, QSize, Qt, QTimer
from PyQt6.QtGui import QBrush, QColor, QFont, QImage, QPainter, QPainterPath, QPainterPathStroker, QPen, QPolygonF
from PyQt6.QtSvg import QSvgGenerator
from PyQt6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QGraphicsItem,
    QGraphicsPathItem,
    QGraphicsRectItem,
    QGraphicsScene,
    QGraphicsSimpleTextItem,
    QGraphicsTextItem,
    QGraphicsView,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QSplitter,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from genmap.engine.run_store import RunStatus
from genmap.errors import GenmapError
from genmap.storage.models import Scan
from genmap.topology import EdgeKind, NodeKind, TopologyEdge, TopologyGraph, TopologyNode, TopologySource, build_topology, layered_layout
from genmap.topology.graph import EDGE_LABELS, NODE_LABELS, address_sort_key
from genmap.ui.app_context import AppContext
from genmap.ui.pages.base import BasePage
from genmap.ui.pages.reports import default_report_directory
from genmap.ui.tasks import run_in_background
from genmap.ui.widgets.common import Banner, PageHeader, hint, label
from genmap.ui.widgets.error_dialog import show_exception
from genmap.ui.widgets.responsive import FlowLayout

ROLE_RUN_ID = Qt.ItemDataRole.UserRole + 1
NODE_RADIUS = 15.0
MAX_EXPORT_SIDE = 16000

_USABLE = {
    RunStatus.COMPLETED.value,
    RunStatus.COMPLETED_WITH_WARNINGS.value,
    RunStatus.CANCELLED.value,
    RunStatus.TIMED_OUT.value,
    RunStatus.INTERRUPTED.value,
}


def _elide(text: str, limit: int = 30) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


class NodeItem(QGraphicsItem):
    def __init__(self, node: TopologyNode, colors: dict[str, QColor], show_hostname: bool) -> None:
        super().__init__()
        self.node = node
        self._colors = colors
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
        self.setAcceptHoverEvents(True)
        self.setZValue(2)
        self.setToolTip(f"{node.label}\n{NODE_LABELS[node.kind]}")
        lines = [node.label]
        if show_hostname and node.hostname and node.kind != NodeKind.ORIGIN:
            lines.append(_elide(node.hostname))
        self.caption = QGraphicsSimpleTextItem("\n".join(lines), self)
        self.caption.setBrush(QBrush(colors["text"]))
        font = QFont()
        font.setPointSizeF(10)
        self.caption.setFont(font)
        rect = self.caption.boundingRect()
        self.caption.setPos(-rect.width() / 2, NODE_RADIUS + 4)
        # A plate behind the caption keeps lines passing underneath from striking through it.
        plate_color = QColor(colors["background"])
        plate_color.setAlpha(210)
        self.plate = QGraphicsRectItem(self.caption.mapRectToParent(rect).adjusted(-3, -1, 3, 1), self)
        self.plate.setBrush(QBrush(plate_color))
        self.plate.setPen(QPen(Qt.PenStyle.NoPen))
        self.plate.stackBefore(self.caption)

    def boundingRect(self) -> QRectF:
        r = NODE_RADIUS + 4
        return QRectF(-r, -r, 2 * r, 2 * r)

    def shape(self) -> QPainterPath:
        path = QPainterPath()
        path.addEllipse(QPointF(0, 0), NODE_RADIUS + 2, NODE_RADIUS + 2)
        return path

    def paint(self, painter: QPainter, option, widget=None) -> None:
        c = self._colors
        kind = self.node.kind
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = NODE_RADIUS
        if kind == NodeKind.NO_REPLY:
            pen = QPen(c["muted"], 1.6, Qt.PenStyle.DashLine)
            painter.setPen(pen)
            painter.setBrush(QBrush(c["surface"]))
            painter.drawEllipse(QPointF(0, 0), r * 0.8, r * 0.8)
        elif kind == NodeKind.ORIGIN:
            painter.setPen(QPen(c["accent"].darker(130), 1.5))
            painter.setBrush(QBrush(c["accent"]))
            painter.drawRoundedRect(QRectF(-r, -r * 0.8, 2 * r, 1.6 * r), 5, 5)
        elif kind == NodeKind.TARGET:
            painter.setPen(QPen(c["info"] if self.node.relays else c["success"].darker(130), 2.5 if self.node.relays else 1.5))
            painter.setBrush(QBrush(c["success"]))
            painter.drawRoundedRect(QRectF(-r * 0.85, -r * 0.85, 1.7 * r, 1.7 * r), 4, 4)
        else:
            painter.setPen(QPen(c["info"].darker(130), 1.5))
            painter.setBrush(QBrush(c["info"]))
            painter.drawEllipse(QPointF(0, 0), r * 0.8, r * 0.8)
        if self.isSelected():
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.setPen(QPen(c["text"], 1.5, Qt.PenStyle.DotLine))
            painter.drawEllipse(QPointF(0, 0), r + 3, r + 3)


class EdgeItem(QGraphicsPathItem):
    STYLES = {
        EdgeKind.ROUTE: Qt.PenStyle.SolidLine,
        EdgeKind.GAP: Qt.PenStyle.DashLine,
        EdgeKind.INCOMPLETE: Qt.PenStyle.DashDotLine,
        EdgeKind.SCANNED: Qt.PenStyle.DotLine,
    }

    def __init__(self, edge: TopologyEdge, start: QPointF, end: QPointF, colors: dict[str, QColor]) -> None:
        super().__init__()
        self.edge = edge
        self._colors = colors
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
        self.setZValue(1)
        hosts = sorted(edge.traced_hosts, key=address_sort_key)
        tip = EDGE_LABELS[edge.kind]
        if hosts:
            tip += "\nOn the path to " + ", ".join(hosts[:8]) + (f" and {len(hosts) - 8} more" if len(hosts) > 8 else "")
        self.setToolTip(tip)
        dx, dy = end.x() - start.x(), end.y() - start.y()
        length = math.hypot(dx, dy) or 1.0
        ux, uy = dx / length, dy / length
        a = QPointF(start.x() + ux * NODE_RADIUS, start.y() + uy * NODE_RADIUS)
        b = QPointF(end.x() - ux * (NODE_RADIUS + 2), end.y() - uy * (NODE_RADIUS + 2))
        path = QPainterPath(a)
        path.lineTo(b)
        self._arrow = QPolygonF([
            b,
            QPointF(b.x() - ux * 9 - uy * 4.5, b.y() - uy * 9 + ux * 4.5),
            QPointF(b.x() - ux * 9 + uy * 4.5, b.y() - uy * 9 - ux * 4.5),
        ])
        path.addPolygon(self._arrow)
        self.setPath(path)
        self.set_highlighted(False)

    def set_highlighted(self, on: bool) -> None:
        color = self._colors["accent"] if on else self._colors["edge"]
        self.setPen(QPen(color, 2.4 if on else 1.4, self.STYLES[self.edge.kind]))
        self.setBrush(QBrush(color))

    def shape(self) -> QPainterPath:
        stroker = QPainterPathStroker()
        stroker.setWidth(10)
        return stroker.createStroke(self.path())


class GraphView(QGraphicsView):
    MIN_SCALE, MAX_SCALE = 0.05, 4.0

    def __init__(self, scene: QGraphicsScene) -> None:
        super().__init__(scene)
        self.setRenderHints(QPainter.RenderHint.Antialiasing | QPainter.RenderHint.TextAntialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorViewCenter)
        self.setAccessibleName("Topology map")

    def zoom(self, factor: float) -> None:
        current = self.transform().m11()
        target = min(self.MAX_SCALE, max(self.MIN_SCALE, current * factor))
        if target != current:
            self.scale(target / current, target / current)

    def fit(self) -> None:
        rect = self.scene().itemsBoundingRect()
        if rect.isEmpty():
            return
        self.fitInView(rect.adjusted(-40, -40, 40, 40), Qt.AspectRatioMode.KeepAspectRatio)
        # Small maps should not be blown up past a readable size.
        if self.transform().m11() > 1.4:
            self.resetTransform()
            self.scale(1.4, 1.4)
            self.centerOn(rect.center())

    def wheelEvent(self, event) -> None:
        steps = event.angleDelta().y() / 120
        if steps:
            self.zoom(1.15 ** steps)
        event.accept()

    def keyPressEvent(self, event) -> None:
        key = event.key()
        if key in (Qt.Key.Key_Plus, Qt.Key.Key_Equal):
            self.zoom(1.25)
        elif key == Qt.Key.Key_Minus:
            self.zoom(0.8)
        elif key == Qt.Key.Key_0:
            self.fit()
        else:
            super().keyPressEvent(event)


def _write_via_temp(path: Path, writer: Callable[[str], bool]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=".genmap-map-", suffix=path.suffix)
    os.close(fd)
    try:
        if not writer(temp):
            raise GenmapError(f"The map could not be written to {path}.")
        os.replace(temp, path)
    except OSError as exc:
        raise GenmapError(f"The map could not be written to {path}.", details=str(exc)) from exc
    finally:
        Path(temp).unlink(missing_ok=True)
    return path


class TopologyPage(BasePage):
    page_key = "topology"
    page_title = "Topology"

    def __init__(self, context: AppContext, parent: Optional[QWidget] = None) -> None:
        super().__init__(context, parent)
        self._scans: dict[str, Scan] = {}
        self._routed: set[str] = set()
        self._cache: dict[str, object] = {}
        self._graph: Optional[TopologyGraph] = None
        self._positions: dict[str, tuple[float, float]] = {}
        self._node_items: dict[str, NodeItem] = {}
        self._edge_items: list[EdgeItem] = []
        self._request = 0
        self._pending_selection: Optional[list[str]] = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(28, 22, 28, 18)
        outer.setSpacing(12)
        outer.addWidget(PageHeader(
            "Topology",
            "Paths drawn only from traceroute hops Nmap recorded. Hosts scanned without a traceroute connect to the scan "
            "origin with a dotted line because their path is unknown. Nothing is inferred from addresses or names.",
        ))

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        side = QSplitter(Qt.Orientation.Vertical)
        side.setChildrenCollapsible(False)
        list_box = QWidget()
        list_layout = QVBoxLayout(list_box)
        list_layout.setContentsMargins(0, 0, 0, 0)
        list_layout.addWidget(label("Scans to draw", role="section"))
        self.scan_list = QListWidget()
        self.scan_list.setAccessibleName("Scans to draw")
        list_layout.addWidget(self.scan_list, 1)
        list_layout.addWidget(hint("Scans marked 'routes' recorded traceroute hops. Choose several to merge their paths."))
        self.show_untraced = QCheckBox("Show hosts without route data")
        self.show_untraced.setChecked(True)
        self.show_names = QCheckBox("Show hostnames")
        self.show_names.setChecked(True)
        list_layout.addWidget(self.show_untraced)
        list_layout.addWidget(self.show_names)
        side.addWidget(list_box)
        side.setMinimumWidth(270)
        self.details = QTextBrowser()
        self.details.setOpenLinks(False)
        self.details.setAccessibleName("Selected node details")
        side.addWidget(self.details)
        side.setSizes([320, 300])
        splitter.addWidget(side)

        map_box = QWidget()
        map_layout = QVBoxLayout(map_box)
        map_layout.setContentsMargins(0, 0, 0, 0)
        map_layout.setSpacing(8)
        toolbar = FlowLayout()
        self.fit_button = QPushButton("Fit")
        self.fit_button.setToolTip("Show the whole map (0)")
        self.zoom_in_button = QPushButton("Zoom in")
        self.zoom_out_button = QPushButton("Zoom out")
        self.export_png_button = QPushButton("Export PNG...")
        self.export_svg_button = QPushButton("Export SVG...")
        self.export_json_button = QPushButton("Export JSON...")
        for button in (self.fit_button, self.zoom_in_button, self.zoom_out_button, self.export_png_button, self.export_svg_button, self.export_json_button):
            toolbar.addWidget(button)
        map_layout.addLayout(toolbar)
        self.legend = label("", role="small", wrap=True)
        map_layout.addWidget(self.legend)
        self.notes = Banner("info")
        map_layout.addWidget(self.notes)
        self.scene = QGraphicsScene(self)
        self.view = GraphView(self.scene)
        map_layout.addWidget(self.view, 1)
        splitter.addWidget(map_box)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 3)
        splitter.setSizes([300, 800])
        outer.addWidget(splitter, 1)
        self.status = label("", role="small", wrap=True)
        outer.addWidget(self.status)

        self._rebuild_timer = QTimer(self)
        self._rebuild_timer.setSingleShot(True)
        self._rebuild_timer.setInterval(200)
        self._rebuild_timer.timeout.connect(self.rebuild)
        self.scan_list.itemChanged.connect(lambda _item: self._rebuild_timer.start())
        self.show_untraced.toggled.connect(lambda _on: self._rebuild_timer.start())
        self.show_names.toggled.connect(lambda _on: self._draw())
        self.fit_button.clicked.connect(self.view.fit)
        self.zoom_in_button.clicked.connect(lambda: self.view.zoom(1.25))
        self.zoom_out_button.clicked.connect(lambda: self.view.zoom(0.8))
        self.export_png_button.clicked.connect(lambda: self.export("png"))
        self.export_svg_button.clicked.connect(lambda: self.export("svg"))
        self.export_json_button.clicked.connect(lambda: self.export("json"))
        self.scene.selectionChanged.connect(self._selection_changed)
        context.index_changed.connect(self._reload_if_visible)
        context.theme.theme_changed.connect(lambda _palette: self._draw())
        self._update_legend()
        self._update_buttons()

    # Scan list --------------------------------------------------------------

    def on_shown(self) -> None:
        self.reload_scans()

    def _reload_if_visible(self) -> None:
        if self.isVisible():
            self.reload_scans()

    def checked_run_ids(self) -> list[str]:
        ids = []
        for row in range(self.scan_list.count()):
            item = self.scan_list.item(row)
            if item.checkState() == Qt.CheckState.Checked:
                ids.append(item.data(ROLE_RUN_ID))
        return ids

    def reload_scans(self) -> None:
        wanted = self._pending_selection if self._pending_selection is not None else self.checked_run_ids()
        first_load = self.scan_list.count() == 0 and self._pending_selection is None
        self._pending_selection = None
        try:
            scans = [s for s in self.context.scan_index.list_scans(include_missing=False) if s.status in _USABLE]
            self._routed = self.context.scan_index.routed_scan_ids()
        except Exception as exc:
            scans = []
            self.status.setText(f"Scans could not be listed: {exc}")
        self._scans = {s.run_id: s for s in scans}
        if first_load and not wanted:
            # Start with the newest scan that recorded routes, if there is one.
            wanted = next(([s.run_id] for s in scans if s.run_id in self._routed), [])
        self.scan_list.blockSignals(True)
        self.scan_list.clear()
        for scan in scans:
            text = f"{scan.created_at.astimezone():%Y-%m-%d %H:%M}  {scan.target_summary}"
            if scan.run_id in self._routed:
                text += "  (routes)"
            item = QListWidgetItem(text)
            item.setData(ROLE_RUN_ID, scan.run_id)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked if scan.run_id in wanted else Qt.CheckState.Unchecked)
            item.setToolTip("\n".join(p for p in (text, scan.command_display) if p))
            self.scan_list.addItem(item)
        self.scan_list.blockSignals(False)
        self.rebuild()

    def show_runs(self, run_ids: list[str]) -> None:
        """Draw exactly these scans; applied now if visible, otherwise when the page is shown."""
        self._pending_selection = list(run_ids)
        if self.isVisible():
            self.reload_scans()

    # Building ---------------------------------------------------------------

    def rebuild(self) -> None:
        self._rebuild_timer.stop()
        run_ids = self.checked_run_ids()
        self._request += 1
        request = self._request
        if not run_ids:
            self._graph = None
            self._positions = {}
            self._draw()
            return
        store = self.context.run_store
        cached = {rid: self._cache[rid] for rid in run_ids if rid in self._cache}
        include_untraced = self.show_untraced.isChecked()
        labels = {rid: f"{s.created_at.astimezone():%Y-%m-%d %H:%M} {s.target_summary}" for rid, s in self._scans.items()}

        def work():
            loaded: dict[str, object] = {}
            skipped: list[str] = []
            sources = []
            for rid in run_ids:
                result = cached.get(rid)
                if result is None:
                    result = store.load_result(rid)
                    if result is None:
                        skipped.append(labels.get(rid, rid))
                        continue
                    loaded[rid] = result
                sources.append(TopologySource(result, labels.get(rid, rid), rid))
            graph = build_topology(sources, include_untraced=include_untraced)
            return graph, layered_layout(graph, column_spacing=175.0, row_spacing=74.0), loaded, skipped

        def done(outcome) -> None:
            if request != self._request:
                return
            graph, positions, loaded, skipped = outcome
            self._cache.update(loaded)
            self._graph = graph
            self._positions = positions
            if skipped:
                graph.notes.insert(0, "Skipped because their Nmap XML is missing: " + "; ".join(skipped) + ".")
            self._draw()

        def failed(exc: BaseException) -> None:
            if request != self._request:
                return
            show_exception(self, exc, "Topology could not be drawn")

        self.status.setText("Drawing...")
        run_in_background(work, done, failed)

    def _colors(self) -> dict[str, QColor]:
        p = self.context.theme.palette
        return {
            "text": QColor(p.text), "muted": QColor(p.text_muted), "accent": QColor(p.accent), "info": QColor(p.info),
            "success": QColor(p.success), "surface": QColor(p.surface), "edge": QColor(p.border_strong), "background": QColor(p.window),
        }

    def _update_legend(self) -> None:
        p = self.context.theme.palette
        dot = lambda color, glyph: f"<span style='color:{color}'>{glyph}</span>"  # noqa: E731
        self.legend.setText(
            f"{dot(p.accent, '&#9644;')} Scan origin &nbsp; {dot(p.info, '&#9679;')} Router &nbsp; "
            f"{dot(p.success, '&#9632;')} Scanned host &nbsp; {dot(p.text_muted, '&#9711;')} No reply &nbsp;&nbsp; "
            "Solid: recorded hops. Dashed: through silent hops. Dash dot: trace ended early. Dotted: no route recorded."
        )

    def _draw(self) -> None:
        self._update_legend()
        self._node_items = {}
        self._edge_items = []
        self.scene.blockSignals(True)
        self.scene.clear()
        self.scene.blockSignals(False)
        colors = self._colors()
        self.view.setBackgroundBrush(QBrush(colors["background"]))
        graph = self._graph
        if graph is None:
            self.notes.hide()
            self.details.setHtml("")
            self._message("Tick one or more scans on the left to draw their paths." if self._scans else
                          "No stored scans yet. Run a scan with 'Trace the network path' enabled on the Discovery tab.")
            self.status.setText("")
            self._update_buttons()
            return
        if graph.notes:
            self.notes.show_message("About this map", "\n".join(f"• {n}" for n in graph.notes), "info")
        else:
            self.notes.hide()
        if len(graph.nodes) <= 1:
            self._message("No host was up in the selected scans, so there is nothing to draw.")
        else:
            show_names = self.show_names.isChecked()
            for key, node in graph.nodes.items():
                item = NodeItem(node, colors, show_names)
                x, y = self._positions.get(key, (0.0, 0.0))
                item.setPos(x, y)
                self.scene.addItem(item)
                self._node_items[key] = item
            for edge in graph.edges.values():
                a, b = self._node_items.get(edge.source), self._node_items.get(edge.target)
                if a is None or b is None:
                    continue
                item = EdgeItem(edge, a.pos(), b.pos(), colors)
                self.scene.addItem(item)
                self._edge_items.append(item)
        self.scene.setSceneRect(self.scene.itemsBoundingRect().adjusted(-200, -200, 200, 200))
        self.view.fit()
        self.details.setHtml(self._summary_html())
        routers = graph.count(NodeKind.ROUTER)
        silent = graph.count(NodeKind.NO_REPLY)
        self.status.setText(
            f"{len(graph.traced_hosts)} traced host{'s' if len(graph.traced_hosts) != 1 else ''}, "
            f"{routers} router{'s' if routers != 1 else ''}, {silent} silent stretch{'es' if silent != 1 else ''}, "
            f"{len(graph.untraced_hosts)} host{'s' if len(graph.untraced_hosts) != 1 else ''} without route data."
        )
        self._update_buttons()

    def _message(self, text: str) -> None:
        item = QGraphicsTextItem()
        item.setPlainText(text)
        item.setDefaultTextColor(QColor(self.context.theme.palette.text_muted))
        item.setTextWidth(380)
        self.scene.addItem(item)

    def _update_buttons(self) -> None:
        has_map = bool(self._node_items)
        for button in (self.fit_button, self.zoom_in_button, self.zoom_out_button, self.export_png_button, self.export_svg_button, self.export_json_button):
            button.setEnabled(has_map)

    # Selection and details --------------------------------------------------

    def _selection_changed(self) -> None:
        try:
            selected = self.scene.selectedItems()
        except RuntimeError:
            return
        chosen = selected[0] if selected else None
        node_key = chosen.node.key if isinstance(chosen, NodeItem) else None
        for edge_item in self._edge_items:
            edge_item.set_highlighted(node_key is not None and node_key in (edge_item.edge.source, edge_item.edge.target) or edge_item is chosen)
        if isinstance(chosen, NodeItem):
            self.details.setHtml(self.node_html(chosen.node))
        elif isinstance(chosen, EdgeItem):
            self.details.setHtml(self.edge_html(chosen.edge))
        else:
            self.details.setHtml(self._summary_html())

    def select_node(self, key: str) -> bool:
        item = self._node_items.get(key)
        if item is None:
            return False
        self.scene.clearSelection()
        item.setSelected(True)
        self.view.centerOn(item)
        return True

    def _style(self) -> str:
        p = self.context.theme.palette
        return f"""<style>
            h3 {{ margin: 0 0 4px 0; }} h4 {{ margin: 10px 0 4px 0; }}
            .muted {{ color: {p.text_muted}; }} td {{ padding: 2px 10px 2px 0; vertical-align: top; }}
        </style>"""

    def _summary_html(self) -> str:
        graph = self._graph
        if graph is None:
            return ""
        return (self._style() + "<h3>Map</h3><p class='muted'>Select a node or a line to see what Nmap recorded about it.</p>"
                + "<p>Drawn from: " + "; ".join(html.escape(s) for s in graph.source_labels) + "</p>")

    def node_html(self, node: TopologyNode) -> str:
        e = html.escape
        graph = self._graph
        parts = [self._style(), f"<h3>{e(node.label)}</h3><p class='muted'>{e(NODE_LABELS[node.kind])}</p>"]
        if node.hostnames:
            parts.append("<p>Names: " + e(", ".join(sorted(node.hostnames))) + "</p>")
        if node.kind == NodeKind.ORIGIN:
            parts.append("<p>The computer each scan ran from. Nmap does not record its address in the XML, so it is shown without one.</p>")
        elif node.kind == NodeKind.NO_REPLY and node.ttl_range:
            start, end = node.ttl_range
            count = end - start + 1
            parts.append(
                f"<p>{count} hop{'s' if count != 1 else ''} on the path to {e(node.traced_host or '')} did not answer Nmap's traceroute probes. "
                "Which routers they were is unknown, so this stretch is not merged with any other.</p>"
            )
        else:
            parts.append(f"<p>Hop distance from the scan origin: {node.depth}</p>")
            if node.relays:
                parts.append("<p>Nmap recorded this address forwarding traffic towards other hosts.</p>")
        if node.target_summaries:
            parts.append("<h4>Scanned as a target</h4><table>" + "".join(
                f"<tr><td class='muted'>{e(src)}</td><td>{e(text)}</td></tr>" for src, text in sorted(node.target_summaries.items())
            ) + "</table>")
        if node.observations:
            rows = sorted(node.observations, key=lambda o: (o.source, address_sort_key(o.traced_host)))
            shown = rows[:40]
            parts.append("<h4>Traceroute hops recorded by Nmap</h4><table><tr><th align='left'>Path to</th><th align='left'>TTL</th><th align='left'>RTT</th></tr>")
            parts.extend(
                f"<tr><td>{e(o.traced_host)}</td><td>{o.ttl}</td><td>{f'{o.rtt:.2f} ms' if o.rtt is not None else '--'}</td></tr>" for o in shown
            )
            parts.append("</table>")
            if len(rows) > len(shown):
                parts.append(f"<p class='muted'>{len(rows) - len(shown)} more not shown.</p>")
        if graph is not None:
            before, after = graph.neighbours(node.key)
            if before:
                parts.append("<p>Reached from: " + e(", ".join(n.label for n in before)) + "</p>")
            if after:
                names = [n.label for n in after]
                parts.append("<p>Leads to: " + e(", ".join(names[:12]) + (f" and {len(names) - 12} more" if len(names) > 12 else "")) + "</p>")
        return "".join(parts)

    def edge_html(self, edge: TopologyEdge) -> str:
        e = html.escape
        graph = self._graph
        a = graph.nodes[edge.source].label if graph else edge.source
        b = graph.nodes[edge.target].label if graph else edge.target
        hosts = sorted(edge.traced_hosts, key=address_sort_key)
        parts = [self._style(), f"<h3>{e(a)} to {e(b)}</h3><p>{e(EDGE_LABELS[edge.kind])}</p>"]
        if hosts:
            parts.append("<p>On the traced path to: " + e(", ".join(hosts[:30]) + (f" and {len(hosts) - 30} more" if len(hosts) > 30 else "")) + "</p>")
        parts.append("<p class='muted'>Seen in: " + e("; ".join(sorted(edge.sources))) + "</p>")
        return "".join(parts)

    # Export -----------------------------------------------------------------

    def _default_name(self, extension: str) -> Path:
        ids = self.checked_run_ids()
        stem = "genmap-topology-" + (ids[0] if ids else "map") + (f"-and-{len(ids) - 1}-more" if len(ids) > 1 else "")
        return default_report_directory(self.context.settings.reports.default_output_directory) / f"{stem}{extension}"

    def export(self, fmt: str) -> None:
        if not self._node_items:
            return
        extension = {"png": ".png", "svg": ".svg", "json": ".json"}[fmt]
        caption = {"png": "PNG image (*.png)", "svg": "SVG drawing (*.svg)", "json": "JSON data (*.json)"}[fmt]
        path, _ = QFileDialog.getSaveFileName(self, "Export map", str(self._default_name(extension)), caption)
        if not path:
            return
        target = Path(path)
        if target.suffix.lower() != extension:
            target = target.with_suffix(extension)
        self.export_to(fmt, target)

    def export_to(self, fmt: str, path: Path) -> Optional[Path]:
        if self._graph is None or not self._node_items:
            return None
        selected = self.scene.selectedItems()
        self.scene.clearSelection()
        try:
            if fmt == "json":
                text = json.dumps(self._graph.to_dict(), indent=2)
                written = _write_via_temp(path, lambda temp: Path(temp).write_text(text, encoding="utf-8") > 0)
            elif fmt == "png":
                written = _write_via_temp(path, self._render_png)
            elif fmt == "svg":
                written = _write_via_temp(path, self._render_svg)
            else:
                raise GenmapError(f"Unknown map export format '{fmt}'.")
        except GenmapError as exc:
            show_exception(self, exc, "Export failed")
            return None
        finally:
            for item in selected:
                item.setSelected(True)
        self.status.setText(f"Saved {written}")
        return written

    def _export_rect(self) -> QRectF:
        return self.scene.itemsBoundingRect().adjusted(-30, -30, 30, 30)

    def _render_png(self, temp: str) -> bool:
        source = self._export_rect()
        scale = min(2.0, MAX_EXPORT_SIDE / max(source.width(), source.height(), 1))
        size = QSize(max(1, int(source.width() * scale)), max(1, int(source.height() * scale)))
        image = QImage(size, QImage.Format.Format_ARGB32)
        image.fill(self._colors()["background"])
        painter = QPainter(image)
        painter.setRenderHints(QPainter.RenderHint.Antialiasing | QPainter.RenderHint.TextAntialiasing)
        self.scene.render(painter, QRectF(0, 0, size.width(), size.height()), source)
        painter.end()
        return image.save(temp, "PNG")

    def _render_svg(self, temp: str) -> bool:
        source = self._export_rect()
        generator = QSvgGenerator()
        generator.setFileName(temp)
        generator.setSize(QSize(int(source.width()), int(source.height())))
        generator.setViewBox(QRectF(0, 0, source.width(), source.height()))
        generator.setTitle("Genmap topology")
        generator.setDescription("Paths from Nmap traceroute data. " + "; ".join(self._graph.source_labels if self._graph else []))
        painter = QPainter(generator)
        painter.fillRect(QRectF(0, 0, source.width(), source.height()), self._colors()["background"])
        self.scene.render(painter, QRectF(0, 0, source.width(), source.height()), source)
        return painter.end()
