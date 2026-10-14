"""Deployment-owned affiliation policy for first-time Google sign-ins.

Edit determine_affiliation to use your campus rules or roster. It receives only
cryptographically verified Google claims. Return None to refuse provisioning.
Existing users retain their locally managed affiliation.
"""

import re
from collections.abc import Mapping

from models import Affiliation


def determine_affiliation(claims: Mapping) -> Affiliation | None:
    local_part = claims.get("email", "").partition("@")[0]
    if re.fullmatch(r"[sj][0-9]{7}", local_part):
        return Affiliation.STUDENT
    return Affiliation.TEACHER
