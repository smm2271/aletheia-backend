import enum
import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Enum, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from models.base import Base


class EligibilityStatus(str, enum.Enum):
    ELIGIBLE = "eligible"
    INELIGIBLE = "ineligible"
    UNKNOWN = "unknown"


class VerificationStatus(str, enum.Enum):
    TEST = "test"
    UNVERIFIED = "unverified"
    VERIFIED = "verified"


class StudentEligibility(Base):
    __tablename__ = "student_eligibility"
    __table_args__ = (
        CheckConstraint("valid_until IS NULL OR valid_until > updated_at", name="ck_eligibility_validity"),
        CheckConstraint("(source = 'test_fixture') = (verification_status = 'test')", name="ck_eligibility_test_source"),
    )
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    status: Mapped[EligibilityStatus] = mapped_column(Enum(EligibilityStatus, name="eligibility_status", values_callable=lambda e: [v.value for v in e]))
    source: Mapped[str] = mapped_column(String(128), nullable=False)
    verification_status: Mapped[VerificationStatus] = mapped_column(Enum(VerificationStatus, name="eligibility_verification_status", values_callable=lambda e: [v.value for v in e]))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
