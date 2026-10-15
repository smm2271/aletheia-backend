from datetime import datetime, timezone

from fastapi import HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from models import QRCredential, User
from qr.tokens import QRIssuer, QRValidationError
from signing_keys import KeyManagementError


class CredentialResponse(BaseModel):
    token: str
    credential_id: str
    format_version: int = 1
    issued_at: datetime
    expires_at: datetime


def get_or_issue(engine, user_id, issuer: QRIssuer) -> CredentialResponse:
    try:
        with Session(engine) as session, session.begin():
            # Lock the stable user row, including first issuance with no credential row.
            user = session.scalar(select(User).where(User.id == user_id).with_for_update())
            if user is None or user.disabled_at is not None:
                raise HTTPException(401, "Unauthenticated")
            record = session.get(QRCredential, user_id)
            if record is not None and datetime.now(timezone.utc) < record.expires_at:
                try:
                    claims = issuer.validate(record.token)
                    if (claims["cid"] != record.credential_id
                            or claims["iat"] != int(record.issued_at.timestamp())
                            or claims["exp"] != int(record.expires_at.timestamp())):
                        raise QRValidationError()
                except QRValidationError:
                    raise HTTPException(409, "Current QR credential is unavailable; retry after its expiry") from None
            else:
                token, claims = issuer.issue()
                values = dict(credential_id=claims["cid"], token=token,
                              issued_at=datetime.fromtimestamp(claims["iat"], timezone.utc),
                              expires_at=datetime.fromtimestamp(claims["exp"], timezone.utc))
                if record is None:
                    record = QRCredential(user_id=user_id, **values)
                    session.add(record)
                else:
                    for key, value in values.items():
                        setattr(record, key, value)
            return CredentialResponse(token=record.token, credential_id=record.credential_id,
                                      issued_at=record.issued_at, expires_at=record.expires_at)
    except KeyManagementError:
        raise HTTPException(503, "QR signing keys unavailable") from None
