# OIDC authentication

Install the optional dependency:

```bash
pip install "stac-fastapi.api[oidc]"
```

Enable authentication after registering the API routes:

```python
from stac_fastapi.api.oidc import OIDCTokenAuth

OIDCTokenAuth(
    issuer="https://issuer.example/realms/example",
    audience="stac",
    jwks_url="https://issuer.example/realms/example/protocol/openid-connect/certs",
).install(api.app)
```

Validation uses EdDSA, 60 seconds of clock leeway and a 3-second JWKS timeout.
Tokens must contain `exp`, `iat`, `iss`, `aud` and `sub`.

The dependency validates bearer tokens and makes the token claims available
through `request.state.auth`. The `hiddenProductSlugs` claim is exposed as
`request.scope["allowed_products"]`. The management ping endpoint remains
public; all other registered API routes require a valid token.
