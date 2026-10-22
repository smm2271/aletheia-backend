from fastapi import APIRouter, Body, Depends, HTTPException, Request
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
                          "Nonce TTL is QR_NONCE_TTL_SECONDS (default 300, range 1-600 seconds); clocks must be synchronized. "
                          "Bearer audience is SSO_ACCESS_AUDIENCE (default argus-api). In Authorize paste only the "
                          "Access Token; cookies, ID Tokens and QR tokens cannot authorize this operation. "
                          "A Redis timeout may have consumed the nonce: start a new transaction with a fresh nonce. "
                          "All responses are no-store. Does not authorize admission or prevent copying a static QR. "
                          "Example token is a placeholder and example nonce is stale; replace both before Try it out."),
             responses={
                 200: {"description": "Current QR verified and nonce claimed; no identity or eligibility disclosed.",
                       "content": {"application/json": {"example": {"valid": True}}}},
                 **{code: {"model": VerificationError, "description": description,
                           "content": {"application/json": {"example": {"detail": detail}}}}
                    for code, description, detail in (
                        (400, "Invalid QR, malformed/expired/future nonce or query parameters", "Invalid QR credential"),
                        (401, "Invalid/missing Access Token or deleted/disabled scanner/client", "Invalid access token"),
                        (403, "Required scope missing or no longer granted to client", "Required scope missing"),
                        (409, "This client already consumed the nonce, even for another QR", "Verification request already consumed"),
                        (422, "Invalid body; submitted credential is not echoed", "Invalid verification request"),
                        (503, "Verification configuration, keys, database or Redis unavailable; fails closed", "Verification request store unavailable"))}})
async def verify_credential(request: Request, body: VerificationRequest = Body(openapi_examples={
    "scan": {"summary": "Synthetic example: replace token and generate a fresh nonce",
             "value": {"token": "<signed-static-qr-jwt>", "nonce": "v1.1792022400." + "A" * 43}},
})):
    if request.query_params:
        raise HTTPException(400, "Query parameters are unsupported")
    await verify_with_nonce(request, body.token, body.nonce)
    return VerificationResponse()
