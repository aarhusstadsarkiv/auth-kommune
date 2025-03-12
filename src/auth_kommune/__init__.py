from starlette.routing import Route

from .authentication import create_oauth_state
from .authentication import get_oauth_state
from .authentication import handler_auth
from .authentication import handler_login
from .authentication import handler_logout
from .middleware import AccessLogMiddleware
from .middleware import PostgreConnectionWrapper
from .middleware import PostgresAuthenticationBackend
from .user import User

__all__ = [
    "AccessLogMiddleware",
    "PostgreConnectionWrapper",
    "PostgresAuthenticationBackend",
    "User",
    "authentication_routes",
    "create_oauth_state",
    "get_oauth_state",
    "handler_auth",
    "handler_login",
    "handler_logout",
]

authentication_routes: list[Route] = [
    Route("/login", handler_login),
    Route("/login/auth", handler_auth, name="auth"),
    Route("/logout", handler_logout),
]
