from typing import Any

from starlette.authentication import BaseUser


class User(BaseUser):
    def __init__(self, userinfo: dict[str, Any]):
        self.id: str = userinfo["id"]
        self.name: str = userinfo["name"]
        self.email: str = userinfo["email"]
        self.roles: list[str] = userinfo["access_groups"]

    @property
    def is_authenticated(self):
        return True

    @property
    def display_name(self) -> str:
        return self.name

    @property
    def identity(self) -> str:
        return self.id
