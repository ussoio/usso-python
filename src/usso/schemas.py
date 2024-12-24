import uuid

import cachetools.func
from pydantic import BaseModel, model_validator

from . import b64tools


class UserData(BaseModel):
    user_id: str
    workspace_id: str | None = None
    workspace_ids: list[str] = []
    token_type: str = "access"

    email: str | None = None
    phone: str | None = None
    username: str | None = None

    authentication_method: str | None = None
    is_active: bool = False

    jti: str | None = None
    data: dict | None = None

    token: str | None = None

    @property
    def uid(self) -> uuid.UUID:
        user_id = self.user_id

        if user_id.startswith("u_"):
            user_id = user_id[2:]
        if 22 <= len(user_id) <= 24:
            user_id = b64tools.b64_decode_uuid(user_id)

        return uuid.UUID(user_id)

    @property
    def b64id(self) -> uuid.UUID:
        return b64tools.b64_encode_uuid_strip(self.uid)


class JWTConfig(BaseModel):
    """Configuration for JWT processing."""

    jwk_url: str | None = None
    secret: str | None = None
    algorithm: str = "RS256"
    header: dict[str, str] = {"type": "Cookie", "name": "usso_access_token"}

    def __hash__(self):
        return hash(self.model_dump_json())

    @model_validator(mode="before")
    def validate_config(cls, data: dict):
        if not data.get("jwk_url") and not data.get("secret"):
            raise ValueError("Either jwk_url or secret must be provided")
        return data

    @cachetools.func.ttl_cache(maxsize=128, ttl=600)
    def decode(self, token: str):
        """Decode a token using the configured method."""
        from .core import decode_token, decode_token_with_jwk

        if self.jwk_url:
            return decode_token_with_jwk(self.jwk_url, token)
        return decode_token(self.secret, token, algorithms=[self.algorithm])
