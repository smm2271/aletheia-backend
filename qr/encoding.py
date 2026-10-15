"""Pure QR encoding; callers separately authenticate tokens with QRValidator."""
from io import BytesIO

import segno

from qr.tokens import QRValidationError, check_compact_token

MAX_VERSION = 26


def encode_png(token: str) -> bytes:
    check_compact_token(token)
    try:
        code = segno.make_qr(token, mode="byte", encoding="ascii", error="m", boost_error=False)
        if code.version > MAX_VERSION:
            raise ValueError()
        output = BytesIO()
        code.save(output, kind="png", scale=4, border=4)
        return output.getvalue()
    except (ValueError, segno.DataOverflowError):
        raise QRValidationError("Token exceeds supported QR capacity") from None
