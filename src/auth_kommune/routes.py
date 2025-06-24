from authlib.integrations.starlette_client import OAuth
from authlib.integrations.starlette_client import StarletteOAuth2App
from starlette.config import Config
from starlette.datastructures import URL
from starlette.requests import Request
from starlette.responses import RedirectResponse

from .user import DefaultUser


def create_oauth_state(config: Config) -> OAuth:
    oauth = OAuth(config)
    oauth.register(
        "microsoft",
        server_metadata_url=config.get("MICROSOFT_CONFIG_URL"),
        client_kwargs={"scope": "openid"},
    )

    return oauth


def get_oauth_state(request: Request) -> OAuth:
    return request.state.oauth


async def handler_login(request: Request):
    """
    Redirect the user to Microsoft's authentication page and store the next page as a cookie named ``next``.
    """
    if not isinstance(request.user, DefaultUser) and request.user.is_authenticated:
        return RedirectResponse(request.query_params.get("next", request.session.get("next", "/")))

    ms_client: StarletteOAuth2App = get_oauth_state(request).create_client("microsoft")
    redirect_uri: URL = request.url_for("auth")
    if redirect := request.query_params.get("next"):
        request.session["next"] = redirect
    return await ms_client.authorize_redirect(request, redirect_uri)


async def handler_auth(request: Request):
    """
    Authentication backend to confirm the access token with Microsoft OAuth2.

    If the authentication succeeds, store the user's JWT in a ``user`` cookie and redirect to the next page.

    The next page is implied to be "/login" unless a ``next`` cookie is present.
    """
    ms_client: StarletteOAuth2App = get_oauth_state(request).create_client("microsoft")
    token = await ms_client.authorize_access_token(request)
    redirect: str = "/login"
    if user := token.get("userinfo"):
        request.session["user"] = user
        redirect = request.session.get("next", "/")
        request.session.pop("next", None)
    return RedirectResponse(redirect)


async def handler_logout(request: Request):
    """
    Logout the user by removing the ``user`` cookie from the session.
    """
    request.session.pop("user", None)
    return RedirectResponse("/")
