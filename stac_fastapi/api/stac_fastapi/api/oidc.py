"""Optional OIDC bearer authentication for any STAC API backend."""

import logging
from typing import Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.routing import APIRoute
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from stac_fastapi.api.routes import add_route_dependencies

logger = logging.getLogger(__name__)
bearer = HTTPBearer(auto_error=False)


class OIDCTokenAuth:
    """Validate tokens using a cached JWKS client in FastAPI's worker pool."""

    def __init__(
        self,
        issuer: str,
        audience: str,
        jwks_url: str,
    ):
        if not issuer or not audience or not jwks_url:
            raise ValueError("OIDC issuer, audience and JWKS URL are required")
        self.issuer = issuer
        self.audience = audience
        self.jwks = jwt.PyJWKClient(jwks_url, timeout=3)

    def __call__(
        self,
        request: Request,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
    ) -> dict:
        if credentials is None:
            raise HTTPException(
                status_code=401,
                detail="missing bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        try:
            key = self.jwks.get_signing_key_from_jwt(credentials.credentials).key
            claims = jwt.decode(
                credentials.credentials,
                key,
                algorithms=["EdDSA"],
                issuer=self.issuer,
                audience=self.audience,
                leeway=60,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.PyJWKClientConnectionError as exc:
            logger.warning("OIDC signing keys unavailable: %s", exc)
            raise HTTPException(
                status_code=503, detail="authentication unavailable"
            ) from exc
        except (jwt.InvalidTokenError, jwt.PyJWKClientError) as exc:
            logger.warning("OIDC token validation failed: %s", exc)
            raise HTTPException(
                status_code=401,
                detail="invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc
        request.state.auth = claims
        products = claims.get("hiddenProductSlugs", [])
        if not isinstance(products, list) or any(
            not isinstance(value, str) for value in products
        ):
            logger.warning("Invalid OIDC product entitlement claims")
            raise HTTPException(status_code=403, detail="invalid product entitlements")
        request.scope["allowed_products"] = set(products)
        return claims

    def install(self, app: FastAPI) -> None:
        """Protect registered API routes after all extensions have registered."""
        prefix = getattr(app.state, "router_prefix", "")
        for route in app.routes:
            if not isinstance(route, APIRoute) or route.path == f"{prefix}/_mgmt/ping":
                continue
            if any(dependency.dependency is self for dependency in route.dependencies):
                continue
            # One matching method attaches the dependency to the whole route.
            add_route_dependencies(
                [route],
                [{"path": route.path, "method": next(iter(route.methods))}],
                [Depends(self)],
            )
        app.openapi_schema = None
