from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from fastapi.security import HTTPBearer
from pydantic import BaseModel

from qr.verification import VerificationRequest, VerificationResponse
from qr.verification_flow import verify_with_nonce


class NoStoreRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def no_store(request: Request):
            try:
                response = await handler(request)
            except RequestValidationError:
                # Validation errors can contain the submitted bearer credential.
                response = JSONResponse({"detail": "Invalid verification request"}, status_code=422)
            except HTTPException as error:
                error.headers = {**(error.headers or {}), "Cache-Control": "no-store"}
                raise
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
            return response

        return no_store


class VerificationError(BaseModel):
    detail: str


router = APIRouter(tags=["Static QR verification"], route_class=NoStoreRoute)


@router.post("/api/v1/qr/static/verify", response_model=VerificationResponse,
             dependencies=[Depends(HTTPBearer(auto_error=False))],
             summary="Verify a current static QR credential",
             description=("Requires an SSO Access Token for the configured resource audience with "
                          "qr:static:verify scope and a currently enabled user and client. "
                          "Checks signature and current credential mapping, then atomically consumes a required "
                          "client-scoped transaction nonce. A new nonce permits another scan of the same QR. "
                          "Does not authorize admission or prevent copying a static QR."),
             responses={code: {"model": VerificationError, "description": description} for code, description in (
                 (400, "Invalid QR credential, invalid or expired nonce, or unsupported query parameters"),
                 (401, "Invalid Access Token or disabled scanner/client"),
                 (403, "Required scope missing or no longer granted to client"),
                 (409, "Verification request nonce already consumed"),
                 (422, "Invalid request body"), (503, "Verification keys or stores unavailable"))})
async def verify_credential(request: Request, body: VerificationRequest):
    if request.query_params:
        raise HTTPException(400, "Query parameters are unsupported")
    await verify_with_nonce(request, body.token, body.nonce)
    return VerificationResponse()
