from typing import Any

from starlette.authentication import BaseUser


class User(BaseUser):
    """
    Base class for authenticated users.

    :cvar key_id: Key to use to get id from userinfo object.
    :cvar key_name: Key to use to get name from userinfo object.
    :cvar key_email: Key to use to get email from userinfo object.
    :cvar key_roles: Key to use to get roles from userinfo object.
    :cvar email_id: Whether to use the email name as ID.


    :ivar id: User ID.
    :ivar name: User name.
    :ivar email: User email.
    :ivar roles: User roles.
    """

    key_id: str = "id"
    key_name: str = "name"
    key_email: str = "email"
    key_roles: str = "role"
    email_id: bool = False

    def __init__(self, userinfo: dict[str, Any]):
        """

        :param userinfo: Userinfo objected returned by OpenID interface.
        """
        self.id: str = (userinfo[self.key_email].split("@")[0]) if self.email_id else userinfo[self.key_id]
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
