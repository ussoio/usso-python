# 🛡️ USSO Python Client SDK

The **USSO Python Client SDK** (`usso`) provides a universal, secure JWT authentication layer for Python microservices and web frameworks.  
It’s designed to integrate seamlessly with the [USSO Identity Platform](https://github.com/ussoio/usso) — or any standards-compliant token issuer.

---

## 🔗 Relationship to the USSO Platform

This SDK is the official verification client for the **USSO** identity service, which provides multi-tenant authentication, RBAC, token flows, and more.  
You can use the SDK with:
- Self-hosted USSO via Docker
- Any identity provider that issues signed JWTs (with proper config)

---

## ✨ Features

- ✅ **Token verification** for EdDSA, RS256, HS256, and more
- ✅ **Claim validation** (`exp`, `nbf`, `aud`, `iss`)
- ✅ **Remote JWK support** for key rotation
- ✅ **Typed payload parsing** via `UserData` (Pydantic)
- ✅ **Token extraction** from:
  - `Authorization` header
  - Cookies
  - Custom headers
- ✅ **FastAPI integration** with dependency injection
- ✅ **Django middleware** for request-based user resolution
- 🧪 90% tested with `pytest` and `tox`

---

## 📦 Installation

```bash
pip install usso
````

With framework extras:

```bash
pip install "usso[fastapi]"     # for FastAPI integration
pip install "usso[django]"      # for Django integration
```

---

## 🚀 Quick Start (FastAPI)

```python
from usso.fastapi.integration import get_authenticator
from usso.schemas import JWTConfig, JWTHeaderConfig, UserData
from usso.jwt.enums import Algorithm

config = JWTConfig(
    key="your-ed25519-public-key",
    issuer="https://sso.example.com",
    audience="api.example.com",
    type=Algorithm.EdDSA,
    header=JWTHeaderConfig(type="Authorization")
)

authenticator = get_authenticator(config)

@app.get("/me")
def get_me(user: UserData = Depends(authenticator)):
    return {"user_id": user.sub, "roles": user.roles}
```

---

## 🧱 Project Structure

```
src/usso/
├── fastapi/            # FastAPI adapter
├── django/             # Django middleware
├── jwt/                # Core JWT logic and algorithms
├── session/            # Stateless session support
├── models/             # JWTConfig, UserData, etc.
├── exceptions/         # Shared exceptions
├── authenticator.py    # High-level API (token + user resolution)
```

---

## 🐳 Integrate with USSO (Docker)

Run your own identity provider:

```bash
docker run -p 8000:8000 ghcr.io/ussoio/usso:latest
```

Then configure your app to verify tokens issued by this service, using its public JWKS endpoint:

```python
JWTConfig(
    jwk_url="http://localhost:8000/.well-known/jwks.json",
    ...
)
```

---

## 🧪 Testing

```bash
pytest
tox
```

---

## 🤝 Contributing

We welcome contributions! 

---

## 📝 License

MIT License © \[mahdikiani]

