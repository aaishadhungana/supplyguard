import uuid

from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Dependency(Base):
    __tablename__ = "dependencies"
    __table_args__ = (
        UniqueConstraint("scan_id", "ecosystem", "name", "version", name="uq_dependencies_component"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    ecosystem: Mapped[str] = mapped_column(String(20))
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(String(100))
    purl: Mapped[str] = mapped_column(String(700))
    is_direct: Mapped[bool]
    scope: Mapped[str] = mapped_column(String(20))


class DependencyEdge(Base):
    __tablename__ = "dependency_edges"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dependencies.id", ondelete="CASCADE"), nullable=True
    )
    child_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("dependencies.id", ondelete="CASCADE"))