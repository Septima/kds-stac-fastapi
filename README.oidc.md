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
    algorithms=("EdDSA",),
).install(api.app)
```

Validation defaults to EdDSA, with 60 seconds of clock leeway and a 3-second
JWKS timeout. Pass accepted JWT algorithms through `algorithms`. Tokens must
contain `exp`, `iat`, `iss`, `aud` and `sub`.

The dependency validates bearer tokens and makes the token claims available
through `request.state.auth`. Product access is derived from the
`hiddenProductSlugs` claim: an absent or empty claim selects the standard
profile, while the defence marker selects the defence profile. Unsupported
values are rejected. `request.scope["allowed_products"]` contains the
resulting product allowlist. SQLAlchemy item queries also include rows whose
`product_id` is NULL, making public items available to any authenticated user.
The management ping endpoint remains public; all other registered API routes
require a valid token.
