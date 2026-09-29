"""SQLAlchemy models for Genmap's local database.

The schema is normalised so results can be queried across scans (every
host that ever exposed 3389, every scan that saw a given CPE) without
parsing XML again. Raw material is still preserved: the configuration a
scan ran with is kept verbatim, the raw Nmap XML stays in the run folder,
and fields Genmap does not model yet are kept in ``extra`` columns.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    TypeDecorator,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

# Stable constraint names keep Alembic migrations reproducible on SQLite.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class UTCDateTime(TypeDecorator):
    """Stores timestamps as naive UTC and returns timezone aware UTC values."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: Optional[datetime], dialect) -> Optional[datetime]:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.astimezone()
        return value.astimezone(timezone.utc).replace(tzinfo=None)

    def process_result_value(self, value: Optional[datetime], dialect) -> Optional[datetime]:
        if value is None:
            return None
        return value.replace(tzinfo=timezone.utc)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
    type_annotation_map = {dict[str, Any]: JSON, list[Any]: JSON}


scan_tag = Table(
    "scan_tag",
    Base.metadata,
    Column("scan_id", ForeignKey("scan.id", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", ForeignKey("tag.id", ondelete="CASCADE"), primary_key=True),
)


class Profile(Base):
    __tablename__ = "profile"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    configuration: Mapped[dict[str, Any]] = mapped_column(JSON)
    builtin_key: Mapped[Optional[str]] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)


class TargetGroup(Base):
    __tablename__ = "target_group"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)
    entries: Mapped[list["TargetGroupEntry"]] = relationship(
        back_populates="group", cascade="all, delete-orphan", order_by="TargetGroupEntry.position"
    )


class TargetGroupEntry(Base):
    __tablename__ = "target_group_entry"

    id: Mapped[int] = mapped_column(primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("target_group.id", ondelete="CASCADE"), index=True)
    expression: Mapped[str] = mapped_column(String(300))
    excluded: Mapped[bool] = mapped_column(Boolean, default=False)
    position: Mapped[int] = mapped_column(Integer, default=0)
    group: Mapped[TargetGroup] = relationship(back_populates="entries")


class Tag(Base):
    __tablename__ = "tag"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(60), unique=True)


class Scan(Base):
    __tablename__ = "scan"

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[str] = mapped_column(String(64), unique=True)
    module_id: Mapped[str] = mapped_column(String(64), default="nmap", index=True)
    profile_id: Mapped[Optional[int]] = mapped_column(ForeignKey("profile.id", ondelete="SET NULL"))
    profile_name: Mapped[Optional[str]] = mapped_column(String(120))
    target_summary: Mapped[str] = mapped_column(String(300), default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(UTCDateTime)
    finished_at: Mapped[Optional[datetime]] = mapped_column(UTCDateTime)
    status: Mapped[str] = mapped_column(String(32), index=True)
    exit_code: Mapped[Optional[int]] = mapped_column(Integer)
    nmap_version: Mapped[Optional[str]] = mapped_column(String(40))
    command_display: Mapped[Optional[str]] = mapped_column(Text)
    command_arguments: Mapped[Optional[list[Any]]] = mapped_column(JSON)
    configuration: Mapped[dict[str, Any]] = mapped_column(JSON)
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    error_remedy: Mapped[Optional[str]] = mapped_column(Text)
    warnings: Mapped[list[Any]] = mapped_column(JSON, default=list)
    hosts_total: Mapped[int] = mapped_column(Integer, default=0)
    hosts_up: Mapped[int] = mapped_column(Integer, default=0)
    open_ports: Mapped[int] = mapped_column(Integer, default=0)
    services: Mapped[int] = mapped_column(Integer, default=0)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    results_indexed: Mapped[bool] = mapped_column(Boolean, default=False)
    folder_missing: Mapped[bool] = mapped_column(Boolean, default=False)

    profile: Mapped[Optional[Profile]] = relationship()
    targets: Mapped[list["ScanTarget"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    hosts: Mapped[list["Host"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    scripts: Mapped[list["ScriptResult"]] = relationship(
        primaryjoin="and_(Scan.id == ScriptResult.scan_id, ScriptResult.host_id.is_(None))",
        viewonly=True,
    )
    tags: Mapped[list[Tag]] = relationship(secondary=scan_tag, order_by=Tag.name)
    reports: Mapped[list["Report"]] = relationship(back_populates="scan")


class ScanTarget(Base):
    __tablename__ = "scan_target"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan.id", ondelete="CASCADE"), index=True)
    expression: Mapped[str] = mapped_column(String(300), index=True)
    excluded: Mapped[bool] = mapped_column(Boolean, default=False)
    scan: Mapped[Scan] = relationship(back_populates="targets")


class Host(Base):
    __tablename__ = "host"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan.id", ondelete="CASCADE"), index=True)
    state: Mapped[str] = mapped_column(String(20), index=True)
    reason: Mapped[Optional[str]] = mapped_column(String(60))
    primary_address: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    primary_hostname: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    mac_address: Mapped[Optional[str]] = mapped_column(String(32))
    mac_vendor: Mapped[Optional[str]] = mapped_column(String(120))
    distance: Mapped[Optional[int]] = mapped_column(Integer)
    uptime_seconds: Mapped[Optional[int]] = mapped_column(Integer)
    last_boot: Mapped[Optional[str]] = mapped_column(String(60))
    os_name: Mapped[Optional[str]] = mapped_column(String(255), index=True)
    os_accuracy: Mapped[Optional[int]] = mapped_column(Integer)
    started_at: Mapped[Optional[datetime]] = mapped_column(UTCDateTime)
    ended_at: Mapped[Optional[datetime]] = mapped_column(UTCDateTime)
    extra: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="hosts")
    addresses: Mapped[list["Address"]] = relationship(cascade="all, delete-orphan")
    hostnames: Mapped[list["Hostname"]] = relationship(cascade="all, delete-orphan")
    ports: Mapped[list["Port"]] = relationship(back_populates="host", cascade="all, delete-orphan")
    os_matches: Mapped[list["OsMatch"]] = relationship(cascade="all, delete-orphan", order_by="OsMatch.rank")
    cpes: Mapped[list["Cpe"]] = relationship(cascade="all, delete-orphan")
    hops: Mapped[list["TracerouteHop"]] = relationship(cascade="all, delete-orphan", order_by="TracerouteHop.ttl")
    scripts: Mapped[list["ScriptResult"]] = relationship(
        primaryjoin="and_(Host.id == ScriptResult.host_id, ScriptResult.port_id.is_(None))",
        viewonly=True,
    )


class Address(Base):
    __tablename__ = "address"

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("host.id", ondelete="CASCADE"), index=True)
    address: Mapped[str] = mapped_column(String(64), index=True)
    address_type: Mapped[str] = mapped_column(String(10))
    vendor: Mapped[Optional[str]] = mapped_column(String(120))


class Hostname(Base):
    __tablename__ = "hostname"

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("host.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    hostname_type: Mapped[Optional[str]] = mapped_column(String(20))


class Port(Base):
    __tablename__ = "port"
    __table_args__ = (UniqueConstraint("host_id", "protocol", "number", name="uq_port_host_protocol_number"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("host.id", ondelete="CASCADE"), index=True)
    protocol: Mapped[str] = mapped_column(String(8))
    number: Mapped[int] = mapped_column(Integer, index=True)
    state: Mapped[str] = mapped_column(String(24), index=True)
    reason: Mapped[Optional[str]] = mapped_column(String(60))
    reason_ttl: Mapped[Optional[int]] = mapped_column(Integer)

    host: Mapped[Host] = relationship(back_populates="ports")
    service: Mapped[Optional["Service"]] = relationship(back_populates="port", cascade="all, delete-orphan", uselist=False)
    scripts: Mapped[list["ScriptResult"]] = relationship(viewonly=True, primaryjoin="Port.id == ScriptResult.port_id")


class Service(Base):
    __tablename__ = "service"

    id: Mapped[int] = mapped_column(primary_key=True)
    port_id: Mapped[int] = mapped_column(ForeignKey("port.id", ondelete="CASCADE"), unique=True)
    name: Mapped[Optional[str]] = mapped_column(String(80), index=True)
    product: Mapped[Optional[str]] = mapped_column(String(200), index=True)
    version: Mapped[Optional[str]] = mapped_column(String(120))
    extra_info: Mapped[Optional[str]] = mapped_column(String(255))
    method: Mapped[Optional[str]] = mapped_column(String(16))
    confidence: Mapped[Optional[int]] = mapped_column(Integer)
    tunnel: Mapped[Optional[str]] = mapped_column(String(16))
    os_type: Mapped[Optional[str]] = mapped_column(String(80))
    device_type: Mapped[Optional[str]] = mapped_column(String(80))
    hostname: Mapped[Optional[str]] = mapped_column(String(255))
    fingerprint: Mapped[Optional[str]] = mapped_column(Text)
    extra: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    port: Mapped[Port] = relationship(back_populates="service")


class Cpe(Base):
    __tablename__ = "cpe"

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("host.id", ondelete="CASCADE"), index=True)
    port_id: Mapped[Optional[int]] = mapped_column(ForeignKey("port.id", ondelete="CASCADE"))
    source: Mapped[str] = mapped_column(String(10))  # "service" or "os"
    value: Mapped[str] = mapped_column(String(255), index=True)


class OsMatch(Base):
    __tablename__ = "os_match"

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("host.id", ondelete="CASCADE"), index=True)
    rank: Mapped[int] = mapped_column(Integer, default=0)
    name: Mapped[str] = mapped_column(String(255))
    accuracy: Mapped[Optional[int]] = mapped_column(Integer)
    line: Mapped[Optional[int]] = mapped_column(Integer)
    classes: Mapped[list["OsClass"]] = relationship(cascade="all, delete-orphan")


class OsClass(Base):
    __tablename__ = "os_class"

    id: Mapped[int] = mapped_column(primary_key=True)
    os_match_id: Mapped[int] = mapped_column(ForeignKey("os_match.id", ondelete="CASCADE"), index=True)
    os_type: Mapped[Optional[str]] = mapped_column(String(80))
    vendor: Mapped[Optional[str]] = mapped_column(String(120))
    family: Mapped[Optional[str]] = mapped_column(String(120))
    generation: Mapped[Optional[str]] = mapped_column(String(60))
    accuracy: Mapped[Optional[int]] = mapped_column(Integer)


class ScriptResult(Base):
    __tablename__ = "script_result"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scan.id", ondelete="CASCADE"), index=True)
    host_id: Mapped[Optional[int]] = mapped_column(ForeignKey("host.id", ondelete="CASCADE"), index=True)
    port_id: Mapped[Optional[int]] = mapped_column(ForeignKey("port.id", ondelete="CASCADE"), index=True)
    phase: Mapped[str] = mapped_column(String(8))  # pre, host, port, post
    script_id: Mapped[str] = mapped_column(String(120), index=True)
    output: Mapped[str] = mapped_column(Text, default="")
    structured: Mapped[Optional[Any]] = mapped_column(JSON)


class TracerouteHop(Base):
    __tablename__ = "traceroute_hop"

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("host.id", ondelete="CASCADE"), index=True)
    ttl: Mapped[int] = mapped_column(Integer)
    address: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    rtt: Mapped[Optional[float]] = mapped_column(Float)
    hostname: Mapped[Optional[str]] = mapped_column(String(255))


class Report(Base):
    __tablename__ = "report"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[Optional[int]] = mapped_column(ForeignKey("scan.id", ondelete="SET NULL"), index=True)
    run_id: Mapped[Optional[str]] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(300), default="")
    format: Mapped[str] = mapped_column(String(10))
    path: Mapped[str] = mapped_column(Text)
    options: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    scan: Mapped[Optional[Scan]] = relationship(back_populates="reports")
