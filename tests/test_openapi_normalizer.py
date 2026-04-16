from backend.models.recon import EndpointSurface, OpenAPIReconRequest, OpenAPIReconResponse
from backend.services.openapi_normalizer import OpenAPINormalizer


def test_normalizer_extracts_path_query_body_and_auth() -> None:
    request = OpenAPIReconRequest(
        target_url="http://example.com",
        openapi_spec_text="""
openapi: 3.0.3
paths:
  /users/{id}:
    get:
      operationId: getUser
      summary: Get user
      tags: [users]
      security:
        - bearerAuth: []
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
        - name: search
          in: query
          required: false
          schema:
            type: string
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                note:
                  type: string
                role:
                  type: string
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
""",
    )
    parsed_surface = OpenAPIReconResponse(
        target_url="http://example.com",
        surface_summary="stub",
        endpoints=[],
        auth_schemes=["bearerAuth"],
        schemas=[],
        raw_metadata={},
    )

    result = OpenAPINormalizer().normalize(request, parsed_surface)

    assert len(result.endpoints) == 1
    endpoint = result.endpoints[0]
    assert endpoint.path == "/users/{id}"
    assert endpoint.method == "GET"
    assert endpoint.operation_id == "getUser"
    assert endpoint.summary == "Get user"
    assert endpoint.path_params == ["id"]
    assert endpoint.query_params == ["search"]
    assert endpoint.body_fields == ["note", "role"]
    assert endpoint.auth_required is True
    assert endpoint.security_schemes == ["bearerAuth"]
    assert endpoint.tags == ["users"]


def test_normalizer_classifies_authorization_and_injection_signals() -> None:
    request = OpenAPIReconRequest(
        target_url="http://example.com",
        openapi_spec_text="""
openapi: 3.0.3
paths:
  /accounts/{accountId}:
    get:
      summary: Get account profile
      security:
        - bearerAuth: []
      parameters:
        - name: accountId
          in: path
          required: true
          schema:
            type: string
        - name: search
          in: query
          required: false
          schema:
            type: string
""",
    )
    parsed_surface = OpenAPIReconResponse(
        target_url="http://example.com",
        surface_summary="stub",
        endpoints=[],
        auth_schemes=["bearerAuth"],
        schemas=[],
        raw_metadata={},
    )

    result = OpenAPINormalizer().normalize(request, parsed_surface)
    endpoint = result.endpoints[0]

    assert endpoint.resource_signals.has_object_id is True
    assert endpoint.resource_signals.has_sensitive_keywords is True
    assert endpoint.candidate_scores.authorization >= 0.55
    assert endpoint.candidate_scores.injection >= 0.45
    assert "authorization" in endpoint.candidate_classes
    assert "injection" in endpoint.candidate_classes


def test_normalizer_can_fallback_to_flat_surface() -> None:
    request = OpenAPIReconRequest(target_url="http://example.com", openapi_url="http://example.com/openapi.json")
    parsed_surface = OpenAPIReconResponse(
        target_url="http://example.com",
        surface_summary="stub",
        endpoints=[
            EndpointSurface(
                path="/orders/{orderId}",
                methods=["GET"],
                auth_required=True,
                path_params=["orderId"],
                query_params=[],
                body_fields=[],
                auth_hints=["bearerAuth"],
            )
        ],
        auth_schemes=["bearerAuth"],
        schemas=[],
        raw_metadata={},
    )

    result = OpenAPINormalizer().normalize(request, parsed_surface)

    assert len(result.endpoints) == 1
    endpoint = result.endpoints[0]
    assert endpoint.path == "/orders/{orderId}"
    assert endpoint.auth_required is True
    assert endpoint.candidate_scores.authorization >= 0.55
