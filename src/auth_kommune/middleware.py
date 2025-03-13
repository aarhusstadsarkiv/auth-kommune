from datetime import datetime
from datetime import timezone

from psycopg import AsyncConnection
from psycopg.types.json import Jsonb
from starlette.applications import Starlette
from starlette.authentication import AuthCredentials
from starlette.authentication import AuthenticationBackend
from starlette.authentication import BaseUser
from starlette.authentication import UnauthenticatedUser
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.base import RequestResponseEndpoint
from starlette.requests import HTTPConnection
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import BaseRoute

from .user import User


class PostgreConnectionWrapper:
    def __init__(self, conninfo: str = ""):
        self.conninfo: str = conninfo
        self.connection: AsyncConnection | None = None

    async def connect(self):
        if self.connection is None:
            self.connection = await AsyncConnection.connect(self.conninfo)

    async def close(self):
        if self.connection is not None:
            await self.connection.close()


class AccessLogMiddleware(BaseHTTPMiddleware):
    """
    Middleware for logging access to routes.

    :param app: The Starlette application.
    :param connection_wrapper: The database connection used for logging.
    :param routes: List of BaseRoute or string representing routes to log access for.
    :param query_routes: List of BaseRoute or string representing routes to log access for including query parameters.
    :param status_codes: List of HTTP status codes to log access for.

    :ivar app: The Starlette application instance.
    :ivar connection_wrapper: The database connection instance used for logging.
    :ivar routes: Set of routes to log access for.
    :ivar query_routes: Set of routes to log access for including query parameters.
    :ivar status_codes: Set of status codes to log access for.
    """

    def __init__(
        self,
        app: Starlette,
        *,
        connection_wrapper: PostgreConnectionWrapper,
        routes: list[BaseRoute | str] | None = None,
        query_routes: list[BaseRoute | str] | None = None,
        status_codes: list[int] | None = None,
    ):
        super().__init__(app)
        self.connection_wrapper: PostgreConnectionWrapper = connection_wrapper
        self.routes: set[str] = {
            path
            for r in routes or []
            if (path := (r if isinstance(r, str) else getattr(r, "path", "")).strip("/").split("/")[0])
            and not (path.startswith("{") and path.endswith("}"))
        }
        self.query_routes: set[str] = {
            path
            for r in query_routes or []
            if (path := (r if isinstance(r, str) else getattr(r, "path", "")).strip("/").split("/")[0])
            and not (path.startswith("{") and path.endswith("}"))
        }
        self.status_codes: set[int] = set(status_codes or [])

    def match_route(self, request: Request) -> tuple[bool, bool]:
        """
        Determine if the provided request matches a route and/or query route.

        :param request: The Request object.
        :return: A tuple containing two booleans indicating whether the request path matches
                 any of the defined routes and query routes, respectively.
        """
        path: str = request.url.path.strip("/").split("/", 1)[0]
        return path in self.routes, path in self.query_routes

    async def log_access(
        self,
        time: datetime,
        user: User,
        request: Request,
        response: Response,
        query_params: bool = False,
    ) -> None:
        """
        This method is used to log access to the system in the access_logs table. The user ID, request method, request
        path (including query parameters if specified), and response status code are recorded in the log entry. The
        time of the access is set to the current datetime in UTC.

        :param time: The time the request has been received.
        :param user: The user object representing the user who accessed the system.
        :param request: The request object representing the incoming request.
        :param response: The response object representing the outgoing response.
        :param query_params: A boolean indicating whether to include the query parameters in the request path.
        Defaults to False.
        """
        async with self.connection_wrapper.connection.cursor() as cur:
            await cur.execute(
                "insert into access_logs"
                " (time, user_id, request_method, path, response)"
                " values (%s, %s, %s, %s, %s)".encode(),
                [
                    time.astimezone(timezone.utc),
                    user.id,
                    request.method,
                    request.url.path + (f"?{request.url.query}" if request.url.query and query_params else ""),
                    response.status_code,
                ],
            )
            await self.connection_wrapper.connection.commit()

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """
        Dispatch the request to the appropriate endpoint for processing.

        The dispatch method checks if the user is authenticated and matches the request route. If the user is
        authenticated and the route is matched, it calls the next middleware to process the request and stores the
        response. If the response status code is less than or equal to 404, it logs the user's access in the database.
        If the user is not authenticated or the route does not match, it bypasses the logging step and directly calls
        the next middleware to process the request.

        :param request: The request object containing the client's HTTP request.
        :param call_next: The next request-response endpoint in the middleware chain.
        :return: The response object generated by the endpoint or the next middleware.
        """
        if not self.routes and not self.query_routes:
            return await call_next(request)
        if request.user.is_authenticated and (route_match := self.match_route(request))[0]:
            time: datetime = datetime.now(timezone.utc)
            response: Response = await call_next(request)
            if not self.status_codes or response.status_code in self.status_codes:
                await self.log_access(time, request.user, request, response, route_match[1])
            return response
        else:
            return await call_next(request)


class PostgresAuthenticationBackend(AuthenticationBackend):
    """
    Authentication backend that uses an OpenID payload and a PostgreSQL database to authenticate users.

    The ``authenticate`` method uses the JWT stored in the ``user`` cookie. If the token is not available in the
    session or if is expired (``exp`` value contains the timestamp of expiration) has expired, an Unauthenticated User
    is returned. Else, the method interacts with the database to create, read, or update the user details which are
    then returned.

    :param connection_wrapper: An instance of the ``PostgreConnectionWrapper`` class used for authentication.

    :ivar connection_wrapper: The database connection used for authentication.
    """

    def __init__(self, connection_wrapper: PostgreConnectionWrapper):
        self.connection_wrapper: PostgreConnectionWrapper = connection_wrapper

    async def update_user(self, user: User) -> None:
        async with self.connection_wrapper.connection.cursor() as cursor:
            await cursor.execute(
                """
                insert into users (id, name, email, roles) values (%s, %s, %s, %s)
                on conflict (id) do update set name = excluded.name, email = excluded.email, roles = excluded.roles
                """,
                [user.id, user.name, user.email, Jsonb(user.roles)],
            )
            await self.connection_wrapper.connection.commit()

    async def authenticate(self, conn: HTTPConnection) -> tuple[AuthCredentials, BaseUser] | None:
        """
        Authenticates the user based on the provided HTTP connection and the JWT stored in the ``user`` cookie. If the
        token is not available in the session or if is expired (``exp`` value contains the timestamp of expiration) has
        expired, an Unauthenticated User is returned. Else, the method interacts with the database to create, read, or
        update the user details which are then returned.

        :param conn: The HTTP connection object.
        :return: A tuple containing the authenticated user's credentials and base user information,
            or None if authentication fails.
        """
        if not (userinfo := conn.session.get("user")):
            return AuthCredentials(), UnauthenticatedUser()
        elif datetime.now(timezone.utc).timestamp() >= userinfo["exp"]:
            conn.session.pop("user", None)
            return AuthCredentials(), UnauthenticatedUser()

        user = User(userinfo)
        await self.update_user(user)
        return AuthCredentials(["authenticated", *user.roles]), user
