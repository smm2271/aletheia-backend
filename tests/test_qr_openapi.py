"""Public documentation contracts; no signing keys, database or Redis required."""
from fastapi.testclient import TestClient

from main import app


def test_swagger_and_openapi_are_available_without_authentication():
    client = TestClient(app)  # Do not enter lifespan: docs do not need backing services.
    response = client.get("/docs")
    assert response.status_code == 200
    assert "/openapi.json" in response.text and "SwaggerUIBundle" in response.text
    assert client.get("/openapi.json").status_code == 200


def test_qr_openapi_distinguishes_browser_cookie_from_scanner_bearer():
    schema = app.openapi()
    issue = schema["paths"]["/api/v1/qr/credentials"]["post"]
    verify = schema["paths"]["/api/v1/qr/static/verify"]["post"]
    schemes = schema["components"]["securitySchemes"]
    assert issue["security"] == [{"APIKeyCookie": []}]
    assert schemes["APIKeyCookie"]["in"] == "cookie"
    assert schemes["APIKeyCookie"]["name"] == "aletheia_session"
    assert verify["security"] == [{"HTTPBearer": []}]
    assert schemes["HTTPBearer"]["scheme"] == "bearer"
    assert "qr:static:verify" in verify["description"]
    origin = next(p for p in issue["parameters"] if p["name"] == "Origin")
    assert origin["in"] == "header" and origin["required"]
    assert "required" not in issue["requestBody"]  # Omitted body is allowed.
    assert verify["requestBody"]["required"]
    assert issue["requestBody"]["content"]["application/json"]["examples"]["self"]["value"] == {}


def test_qr_openapi_request_and_minimal_response_contracts():
    schema = app.openapi()
    models = schema["components"]["schemas"]
    request = models["VerificationRequest"]
    assert set(request["required"]) == {"token", "nonce"}
    assert request["additionalProperties"] is False
    assert request["properties"]["token"]["maxLength"] == 1024
    assert request["properties"]["nonce"]["maxLength"] == 64
    assert models["CredentialRequest"]["additionalProperties"] is False
    assert set(models["CredentialResponse"]["properties"]) == {
        "token", "credential_id", "format_version", "issued_at", "expires_at"}
    assert set(models["VerificationResponse"]["properties"]) == {"valid"}
    assert models["VerificationResponse"]["properties"]["valid"]["const"] is True
    operation = schema["paths"]["/api/v1/qr/static/verify"]["post"]
    example = operation["requestBody"]["content"]["application/json"]["examples"]["scan"]["value"]
    assert set(example) == {"token", "nonce"}


def test_qr_openapi_error_schemas_match_distinct_validation_formats():
    schema = app.openapi()
    for path, validation_model in (("/api/v1/qr/credentials", "HTTPValidationError"),
                                   ("/api/v1/qr/static/verify", "VerificationError")):
        responses = schema["paths"][path]["post"]["responses"]
        assert set(responses) == {"200", "400", "401", "403", "409", "422", "503"}
        assert responses["422"]["content"]["application/json"]["schema"]["$ref"] == (
            "#/components/schemas/" + validation_model)
        for status, response in responses.items():
            content = response["content"]["application/json"]
            assert "example" in content
            if status != "200":
                assert set(content["example"]) == {"detail"}
        # Each generated local schema reference must resolve.
        for response in responses.values():
            ref = response["content"]["application/json"]["schema"]["$ref"]
            assert ref.rsplit("/", 1)[1] in schema["components"]["schemas"]
