import enum
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, Enum, String, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from models.base import Base


class ClientType(str, enum.Enum):
    PUBLIC = "public"
    CONFIDENTIAL = "confidential"


class TrustLevel(str, enum.Enum):
    FIRST_PARTY = "first_party"
    EXTERNAL = "external"


class SSOClient(Base):
    __tablename__ = "sso_clients"
    __table_args__ = (CheckConstraint(
        "(client_type = 'public' AND secret_hash IS NULL) OR (client_type = 'confidential' AND secret_hash IS NOT NULL)",
        name="ck_sso_clients_secret_type",
    ),)

    client_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    client_type: Mapped[ClientType] = mapped_column(Enum(ClientType, name="sso_client_type", values_callable=lambda e: [v.value for v in e]), nullable=False)
    trust_level: Mapped[TrustLevel] = mapped_column(Enum(TrustLevel, name="sso_trust_level", values_callable=lambda e: [v.value for v in e]), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"), nullable=False)
    redirect_uris: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    allowed_scopes: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    secret_hash: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
