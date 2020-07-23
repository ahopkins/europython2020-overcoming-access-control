import os
import typing as t
from base64 import b64decode, b64encode
from datetime import datetime, timedelta

from cryptography.fernet import Fernet, InvalidToken
from sanic_jwt import Initialize

from sanic import Sanic
from sanic.exceptions import Forbidden, Unauthorized
from sanic.log import logger
from sanic.request import Request
from sanic.response import HTTPResponse, json
from sscopes import validate

# These are the HTTP methods that we want to enforce CSRF upon
HTTP_UNSAFE_METHODS = ("POST", "PUT", "PATCH", "DELETE")

# We will be encrypting a bit of random text as our CSRF key using some bytes
CSRF_REF_BYTES = 16


app = Sanic("EuroPython2020")
app.config.JWT_SECRET = "NextYearInDublin"
app.config.CSRF_SECRET = Fernet.generate_key()


def authenticate(request: Request) -> t.Dict[str, int]:
    return {"user_id": 1}


def scope_extender(*args) -> str:
    return "top_secret:read:write"


sanicjwt = Initialize(
    app,
    authenticate=authenticate,
    add_scopes_to_payload=scope_extender,
    cookie_set=True,
    cookie_split=True,
)


@app.exception(Forbidden, Unauthorized)
async def handle_exceptions(request: Request, exception: Exception) -> HTTPResponse:
    """We want to override the default exception handler to return a JSON message as opposed to some HTML"""
    return json(
        {"error": exception.__class__.__name__, "message": str(exception)},
        status=exception.status_code,
    )


@app.middleware("request")
async def do_csrf_request(request: Request) -> None:
    if request.path != "/auth":
        if not is_pass_csrf(request):
            raise Forbidden("You CSRF thief!")


@app.middleware("response")
async def do_csrf_response(request: Request, response: HTTPResponse) -> None:
    if request.path == "/auth":
        set_cookie(
            response, "csrf_token", generate_csrf_token(), httponly=False,
        )


@app.middleware("request")
def log_request(request: Request) -> None:
    """In production, do not commit this stuff to your logs without filtering out tokens and other sensitive stuff"""
    logger.info(f"Incoming request headers: {request.headers}")
    logger.info(f"Incoming request cookies: {request.cookies}")


def generate_csrf_token() -> str:
    global app

    cipher = Fernet(app.config.CSRF_SECRET)

    # Some random bytes of a known length
    csrf_ref = os.urandom(CSRF_REF_BYTES)

    # Encrypt those bytes with our secret
    token = cipher.encrypt(csrf_ref)

    # Append the reference and base64 encode for transport, so that when we
    # decode the token later (again using our secret) we can verify that
    # (1) it is authentic, and (2) it has not been tampered with
    csrf_token = b64encode(csrf_ref + token)

    return csrf_token.decode("utf-8")


def verify_csrf_token(csrf_token: str, ttl: int = None) -> bool:
    """Run the generate_csrf_token function in reverse"""
    global app

    cipher = Fernet(app.config.CSRF_SECRET)

    try:
        raw = b64decode(csrf_token)

        # Break the raw bytes based upon our known length
        csrf_ref = raw[:CSRF_REF_BYTES]
        token = raw[CSRF_REF_BYTES:]

        # decode the token
        decoded = cipher.decrypt(token)

        # Make sure the token matches our original reference
        return decoded == csrf_ref

    except InvalidToken as e:
        logger.error(e)
        return False


def is_pass_csrf(request: Request) -> bool:
    if request.method in HTTP_UNSAFE_METHODS:
        return verify_csrf_token(request.headers.get("x-xsrf-token", ""))
    return True


def set_cookie(response, key, value, httponly=None):
    response.cookies[key] = value
    response.cookies[key]["httponly"] = httponly
    response.cookies[key]["path"] = "/"
    response.cookies[key]["expires"] = datetime.now() + timedelta(hours=1)

    # These are disabled here for demo purposes. They should be used
    # for additional security in production.
    # response.cookies[key]["samesite"] = "lax"
    # response.cookies[key]["domain"] = "foo.bar"
    # response.cookies[key]["secure"] = True

    # See server1.py for more info.


@app.get("/protected")
@sanicjwt.protected()
async def top_secret(request: Request) -> HTTPResponse:
    return json({"foo": "bar"})


@app.get("/scoped")
@sanicjwt.scoped("top_secret:read")
async def scoped(request: Request) -> HTTPResponse:
    return json({"fizz": "buzz"})


@app.post("/do")
@sanicjwt.scoped("top_secret:write")
async def do_secret(request: Request) -> HTTPResponse:
    return json({"self_destruct": True})


app.run(debug=True, port=7777)
