"""Operator-only test evidence; never creates officially verified enrollment records."""
import argparse
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from database import create_database_engine
from models import EligibilityStatus, StudentEligibility, User, VerificationStatus


def main():
    parser = argparse.ArgumentParser(description="Set clearly marked TEST student eligibility evidence")
    parser.add_argument("user_id", type=uuid.UUID)
    parser.add_argument("status", choices=[s.value for s in EligibilityStatus])
    args = parser.parse_args()
    engine = create_database_engine()
    try:
        with Session(engine) as session:
            if session.get(User, args.user_id) is None:
                parser.exit(1, "User not found\n")
            previous = session.get(StudentEligibility, args.user_id)
            if previous is not None and previous.source != "test_fixture":
                parser.exit(1, "Refusing to overwrite non-test evidence\n")
            now = datetime.now(timezone.utc)
            session.merge(StudentEligibility(
                user_id=args.user_id, status=EligibilityStatus(args.status), source="test_fixture",
                verification_status=VerificationStatus.TEST, updated_at=now, valid_until=now + timedelta(hours=1),
            ))
            session.commit()
        print("Test fixture saved (not an official enrollment verification)")
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
