import uuid

from pydantic import BaseModel

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
