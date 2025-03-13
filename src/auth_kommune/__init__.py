from starlette.routing import Route

from .middleware import AccessLogMiddleware
from .middleware import PostgreConnectionWrapper
from .middleware import PostgresAuthenticationBackend
from .routes import create_oauth_state
from .routes import get_oauth_state
from .routes import handler_auth
from .routes import handler_login
from .routes import handler_logout
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
    Route("/login", handler_login, name="login"),
    Route("/login/auth", handler_auth, name="auth"),
    Route("/logout", handler_logout, name="logout"),
]
