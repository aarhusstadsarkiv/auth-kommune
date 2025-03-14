from typing import Any

from starlette.authentication import BaseUser


class User(BaseUser):
    key_id: str = "id"
    key_name: str = "name"
    key_email: str = "email"
    key_roles: str = "role"

    def __init__(self, userinfo: dict[str, Any]):
        self.id: str = userinfo[self.key_id]
        self.name: str = userinfo[self.key_name]
        self.email: str = userinfo[self.key_email]
        self.roles: list[str] = userinfo[self.key_roles]

    @property
    def is_authenticated(self):
        return True

    @property
    def display_name(self) -> str:
        return self.name

    @property
    def identity(self) -> str:
        return self.id
