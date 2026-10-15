"""Independent student eligibility evidence and provenance."""
from alembic import op
import sqlalchemy as sa

revision = "20261015_0007"
down_revision = "20261015_0006"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "student_eligibility",
        sa.Column("user_id", sa.UUID(), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("status", sa.Enum("eligible", "ineligible", "unknown", name="eligibility_status"), nullable=False),
        sa.Column("source", sa.String(128), nullable=False),
        sa.Column("verification_status", sa.Enum("test", "unverified", "verified", name="eligibility_verification_status"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True)),
        sa.CheckConstraint("valid_until IS NULL OR valid_until > updated_at", name="ck_eligibility_validity"),
        sa.CheckConstraint("(source = 'test_fixture') = (verification_status = 'test')", name="ck_eligibility_test_source"),
    )


def downgrade():
    op.drop_table("student_eligibility")
    sa.Enum(name="eligibility_verification_status").drop(op.get_bind())
    sa.Enum(name="eligibility_status").drop(op.get_bind())
