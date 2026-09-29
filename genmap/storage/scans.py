"""Scan index: keeps the database in step with the run folders.

Run folders stay the source of truth (raw XML, console output, run.json).
The index adds queryable, normalised copies of their results so history,
search, reports, and later comparison do not have to reparse XML.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Optional

from sqlalchemy import delete, distinct, func, or_, select
from sqlalchemy.orm import Session, selectinload

from genmap.core.results import Host as ResultHost
from genmap.core.results import ScanResult
from genmap.engine.run_store import RunRecord, RunStatus, RunStore, summarize_result
from genmap.errors import GenmapError
from genmap.storage.database import Database
from genmap.storage.models import (
    Address,
    Cpe,
    Host,
    Hostname,
    OsClass,
    OsMatch,
    Port,
    Scan,
    ScanTarget,
    ScriptResult,
    Service,
    Tag,
    TracerouteHop,
    scan_tag,
)

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ReconcileReport:
    added: int = 0
    updated: int = 0
    indexed: int = 0
    missing: int = 0
    failed: int = 0


@dataclass(frozen=True)
class IndexStats:
    scans: int
    completed_scans: int
    distinct_hosts: int
    open_port_observations: int
    tags: int


class ScanIndex:
    def __init__(self, database: Database) -> None:
        self.db = database

    # Records -----------------------------------------------------------------

    def _apply_record(self, scan: Scan, record: RunRecord) -> None:
        scan.module_id = record.module_id
        scan.profile_name = record.profile_name
        scan.target_summary = record.target_summary[:300]
        scan.created_at = record.created_at
        scan.started_at = record.started_at
        scan.finished_at = record.finished_at
        scan.status = record.status.value
        scan.exit_code = record.exit_code
        scan.nmap_version = record.nmap_version
        scan.command_display = record.command.display if record.command else None
        scan.command_arguments = list(record.command.arguments) if record.command else None
        scan.configuration = record.configuration
        scan.error_message = record.error_message
        scan.error_remedy = record.error_remedy
        scan.warnings = list(record.warnings)
        summary = record.summary
        if summary is not None:
            scan.hosts_total = summary.hosts_total
            scan.hosts_up = summary.hosts_up
            scan.open_ports = summary.open_ports
            scan.services = summary.services
            scan.truncated = summary.truncated
        scan.folder_missing = False
        targets = record.configuration.get("targets", {}) if isinstance(record.configuration, dict) else {}
        expressions = [(t, False) for t in targets.get("targets", [])] + [(t, True) for t in targets.get("exclusions", [])]
        if [(t.expression, t.excluded) for t in scan.targets] != expressions:
            scan.targets = [ScanTarget(expression=e[:300], excluded=x) for e, x in expressions]

    def record_run(self, record: RunRecord, *, profile_id: Optional[int] = None) -> None:
        with self.db.session() as session:
            scan = session.scalar(select(Scan).where(Scan.run_id == record.run_id))
            if scan is None:
                scan = Scan(run_id=record.run_id, configuration={}, status=record.status.value, created_at=record.created_at)
                session.add(scan)
            if profile_id is not None:
                scan.profile_id = profile_id
            self._apply_record(scan, record)

    # Results -----------------------------------------------------------------

    def index_results(self, run_id: str, result: ScanResult) -> None:
        with self.db.session() as session:
            scan = session.scalar(select(Scan).where(Scan.run_id == run_id))
            if scan is None:
                raise GenmapError(f"Scan {run_id} is not in the index.")
            session.execute(delete(ScriptResult).where(ScriptResult.scan_id == scan.id))
            session.execute(delete(Host).where(Host.scan_id == scan.id))
            session.flush()
            for phase, scripts in (("pre", result.pre_scripts), ("post", result.post_scripts)):
                for script in scripts:
                    session.add(ScriptResult(scan_id=scan.id, phase=phase, script_id=script.script_id, output=script.output, structured=script.structured))
            for host in result.hosts:
                self._add_host(session, scan, host)
            summary = summarize_result(result)
            scan.hosts_total = summary.hosts_total
            scan.hosts_up = summary.hosts_up
            scan.open_ports = summary.open_ports
            scan.services = summary.services
            scan.truncated = summary.truncated
            scan.results_indexed = True
            if result.nmap_version and not scan.nmap_version:
                scan.nmap_version = result.nmap_version

    def _add_host(self, session: Session, scan: Scan, source: ResultHost) -> None:
        best = source.best_os_match
        mac = source.mac_address
        host = Host(
            scan_id=scan.id,
            state=source.status.state,
            reason=source.status.reason,
            primary_address=source.primary_address,
            primary_hostname=source.primary_hostname,
            mac_address=mac.address if mac else None,
            mac_vendor=mac.vendor if mac else None,
            distance=source.distance,
            uptime_seconds=source.uptime.seconds if source.uptime else None,
            last_boot=source.uptime.last_boot if source.uptime else None,
            os_name=best.name if best else None,
            os_accuracy=best.accuracy if best else None,
            started_at=source.start_time,
            ended_at=source.end_time,
            extra=dict(source.extra),
        )
        host.addresses = [Address(address=a.address, address_type=a.address_type, vendor=a.vendor) for a in source.addresses]
        host.hostnames = [Hostname(name=h.name, hostname_type=h.hostname_type) for h in source.hostnames]
        if source.os:
            for rank, match in enumerate(source.os.matches):
                row = OsMatch(rank=rank, name=match.name, accuracy=match.accuracy, line=match.line)
                row.classes = [
                    OsClass(os_type=c.os_type, vendor=c.vendor, family=c.os_family, generation=c.os_generation, accuracy=c.accuracy)
                    for c in match.classes
                ]
                host.os_matches.append(row)
                for cls in match.classes:
                    for value in cls.cpe:
                        host.cpes.append(Cpe(source="os", value=value))
        if source.traceroute:
            host.hops = [TracerouteHop(ttl=h.ttl, address=h.ip_address, rtt=h.rtt, hostname=h.hostname) for h in source.traceroute.hops]
        session.add(host)
        session.flush()
        for script in source.host_scripts:
            session.add(ScriptResult(scan_id=scan.id, host_id=host.id, phase="host", script_id=script.script_id, output=script.output, structured=script.structured))
        seen: set[tuple[str, int]] = set()
        for source_port in source.ports:
            key = (source_port.protocol, source_port.port_id)
            if key in seen:
                continue
            seen.add(key)
            port = Port(
                host_id=host.id,
                protocol=source_port.protocol,
                number=source_port.port_id,
                state=source_port.state,
                reason=source_port.reason,
                reason_ttl=source_port.reason_ttl,
            )
            svc = source_port.service
            if svc is not None:
                port.service = Service(
                    name=svc.name,
                    product=svc.product,
                    version=svc.version,
                    extra_info=svc.extra_info,
                    method=svc.method,
                    confidence=svc.confidence,
                    tunnel=svc.tunnel,
                    os_type=svc.os_type,
                    device_type=svc.device_type,
                    hostname=svc.hostname,
                    fingerprint=svc.service_fingerprint,
                    extra=dict(svc.extra),
                )
            session.add(port)
            session.flush()
            if svc is not None:
                for value in svc.cpe:
                    session.add(Cpe(host_id=host.id, port_id=port.id, source="service", value=value))
            for script in source_port.scripts:
                session.add(ScriptResult(scan_id=scan.id, host_id=host.id, port_id=port.id, phase="port", script_id=script.script_id, output=script.output, structured=script.structured))

    # Reconciliation ------------------------------------------------------------

    def reconcile(self, store: RunStore, *, active_run_ids: Iterable[str] = ()) -> ReconcileReport:
        """Bring the index in line with the run folders on disk."""
        active = set(active_run_ids)
        added = updated = indexed = missing = failed = 0
        records = {r.run_id: r for r in store.list_runs()}
        with self.db.session() as session:
            known = {s.run_id: s for s in session.scalars(select(Scan))}
            for run_id, scan in known.items():
                flag = run_id not in records
                if flag and not scan.folder_missing:
                    missing += 1
                scan.folder_missing = flag
        for run_id, record in records.items():
            scan = known.get(run_id)
            if scan is None:
                added += 1
            elif scan.status != record.status.value or scan.finished_at != record.finished_at:
                updated += 1
            try:
                self.record_run(record)
                if run_id in active or not record.status.is_terminal:
                    continue
                if scan is not None and scan.results_indexed and scan.finished_at == record.finished_at:
                    continue
                result = store.load_result(run_id)
                if result is not None:
                    self.index_results(run_id, result)
                    indexed += 1
            except Exception as exc:
                failed += 1
                log.warning("Could not index run %s: %s", run_id, exc)
        return ReconcileReport(added, updated, indexed, missing, failed)

    def index_finished_run(self, store: RunStore, record: RunRecord) -> bool:
        """Record a finished run and index its XML. Returns True when results were indexed."""
        self.record_run(record)
        try:
            result = store.load_result(record.run_id)
        except GenmapError as exc:
            log.warning("Run %s XML not indexed: %s", record.run_id, exc.message)
            return False
        if result is None:
            return False
        self.index_results(record.run_id, result)
        return True

    def mark_all_for_reindex(self) -> int:
        """Flag every scan so the next reconcile parses its XML again."""
        from sqlalchemy import update

        with self.db.session() as session:
            return session.execute(update(Scan).values(results_indexed=False)).rowcount or 0

    # Queries -----------------------------------------------------------------

    def get(self, run_id: str) -> Optional[Scan]:
        with self.db.session() as session:
            return session.scalar(
                select(Scan).where(Scan.run_id == run_id).options(selectinload(Scan.tags), selectinload(Scan.targets))
            )

    def list_scans(
        self,
        *,
        search: str = "",
        status: Optional[str] = None,
        tag: Optional[str] = None,
        include_missing: bool = True,
        limit: Optional[int] = None,
    ) -> list[Scan]:
        query = select(Scan).options(selectinload(Scan.tags), selectinload(Scan.targets)).order_by(Scan.created_at.desc())
        if status:
            query = query.where(Scan.status == status)
        if tag:
            query = query.where(Scan.tags.any(Tag.name == tag))
        if not include_missing:
            query = query.where(Scan.folder_missing.is_(False))
        for term in search.split():
            like = f"%{term}%"
            query = query.where(
                or_(
                    Scan.target_summary.ilike(like),
                    Scan.profile_name.ilike(like),
                    Scan.command_display.ilike(like),
                    Scan.status.ilike(like),
                    Scan.run_id.ilike(like),
                    Scan.tags.any(Tag.name.ilike(like)),
                    Scan.targets.any(ScanTarget.expression.ilike(like)),
                    Scan.hosts.any(or_(Host.primary_address.ilike(like), Host.primary_hostname.ilike(like))),
                )
            )
        if limit:
            query = query.limit(limit)
        with self.db.session() as session:
            return list(session.scalars(query))

    def delete(self, run_id: str) -> None:
        with self.db.session() as session:
            scan = session.scalar(select(Scan).where(Scan.run_id == run_id))
            if scan is not None:
                session.delete(scan)

    def set_tags(self, run_id: str, names: Iterable[str]) -> list[str]:
        cleaned: list[str] = []
        for name in names:
            tag = " ".join(name.split())[:60]
            if tag and tag.lower() not in {c.lower() for c in cleaned}:
                cleaned.append(tag)
        with self.db.session() as session:
            scan = session.scalar(select(Scan).where(Scan.run_id == run_id))
            if scan is None:
                raise GenmapError(f"Scan {run_id} is not in the index.")
            existing = {t.name.lower(): t for t in session.scalars(select(Tag))}
            tags = []
            for name in cleaned:
                tag = existing.get(name.lower())
                if tag is None:
                    tag = Tag(name=name)
                    session.add(tag)
                    existing[name.lower()] = tag
                tags.append(tag)
            scan.tags = tags
            session.flush()
            # Tags exist only while some scan uses them.
            session.execute(delete(Tag).where(~Tag.id.in_(select(scan_tag.c.tag_id))))
        return cleaned

    def all_tags(self) -> list[str]:
        with self.db.session() as session:
            return list(session.scalars(select(Tag.name).order_by(Tag.name)))

    def routed_scan_ids(self) -> set[str]:
        """Run ids of scans whose indexed results include traceroute hops."""
        query = select(Scan.run_id).join(Host, Host.scan_id == Scan.id).join(TracerouteHop, TracerouteHop.host_id == Host.id).distinct()
        with self.db.session() as session:
            return set(session.scalars(query))

    def recent_targets(self, limit: int = 30) -> list[tuple[str, datetime, int]]:
        """Target expressions used in scans, most recent first, with use counts."""
        query = (
            select(ScanTarget.expression, func.max(Scan.created_at), func.count(ScanTarget.id))
            .join(Scan)
            .where(ScanTarget.excluded.is_(False))
            .group_by(ScanTarget.expression)
            .order_by(func.max(Scan.created_at).desc())
            .limit(limit)
        )
        with self.db.session() as session:
            return [(e, when, count) for e, when, count in session.execute(query)]

    def stats(self) -> IndexStats:
        with self.db.session() as session:
            scans = session.scalar(select(func.count(Scan.id))) or 0
            completed = session.scalar(
                select(func.count(Scan.id)).where(Scan.status.in_([RunStatus.COMPLETED.value, RunStatus.COMPLETED_WITH_WARNINGS.value]))
            ) or 0
            hosts = session.scalar(select(func.count(distinct(Host.primary_address))).where(Host.state == "up")) or 0
            ports = session.scalar(select(func.count(Port.id)).where(Port.state == "open")) or 0
            tags = session.scalar(select(func.count(Tag.id))) or 0
        return IndexStats(scans, completed, hosts, ports, tags)
