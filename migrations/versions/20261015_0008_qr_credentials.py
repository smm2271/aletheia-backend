"""One bounded-lifetime static QR credential per user."""
from alembic import op
import sqlalchemy as sa

revision = "20261015_0008"
down_revision = "20261015_0007"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "qr_credentials",
        sa.Column("user_id", sa.UUID(), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("credential_id", sa.String(43), unique=True, nullable=False),
        sa.Column("token", sa.Text(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("expires_at > issued_at", name="ck_qr_credential_validity"),
    )


def downgrade():
    op.drop_table("qr_credentials")
