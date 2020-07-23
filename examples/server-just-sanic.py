import os
import typing as t
from base64 import b64decode, b64encode
from datetime import datetime, timedelta

from cryptography.fernet import Fernet, InvalidToken

import jwt
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


@app.exception(Forbidden, Unauthorized)
async def handle_exceptions(request: Request, exception: Exception) -> HTTPResponse:
    """We want to override the default exception handler to return a JSON message as opposed to some HTML"""
    return json(
        {"error": exception.__class__.__name__, "message": str(exception)},
        status=exception.status_code,
    )


# This is an alternative strategy to providing protection to endpoints
# instead of using the decorators
# @app.middleware("request")
# async def global_authentication(request: Request) -> None:
#     if request.path != request.app.url_for("do_auth"):
#         do_protection(request)


@app.middleware("request")
def log_request(request: Request) -> None:
    """In production, do not commit this stuff to your logs without filtering out tokens and other sensitive stuff"""
    logger.info(f"Incoming request headers: {request.headers}")
    logger.info(f"Incoming request cookies: {request.cookies}")


def extract_token(request: Request) -> str:
    """Reconstruct the "split" JWT cookies"""
    access_token = request.cookies.get("access_token")
    access_token_signature = request.cookies.get("access_token_signature")
    return f"{access_token}.{access_token_signature}"


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


def is_authenticated(request: Request) -> bool:
    token = extract_token(request)
    try:
        # This will attempt to decode the JWT and will also apply any known
        # claims that are on it. Since our example only uses exp,
        # the only claim to test against is expiration
        jwt.decode(token, request.app.config.JWT_SECRET)
    except Exception as e:
        logger.error(e)
        return False
    else:
        return True


def is_authorized(request: Request, base_scope: t.Optional[str]) -> bool:
    if base_scope:
        token = extract_token(request)
        try:
            # Get the encrypted payload. If it fails to decrypt, or it fails
            # a claim (like expiration) then this will raise an exception
            payload = jwt.decode(token, request.app.config.JWT_SECRET)
        except Exception as e:
            logger.error(e)
            return False
        else:
            # Check to see if the known base scope criteria has been met
            return validate(base_scope, payload.get("scopes", ""))
    return True


def is_pass_csrf(request: Request) -> bool:
    if request.method in HTTP_UNSAFE_METHODS:
        return verify_csrf_token(request.headers.get("x-xsrf-token", ""))
    return True


def do_protection(request: Request, scoped: t.Optional[str] = None) -> None:
    """This method does all of our auth checks and raises exceptions upon failure"""

    if not is_authenticated(request):
        raise Unauthorized("Who are you?")

    if not is_authorized(request, scoped):
        raise Forbidden("You are not allowed")

    if not is_pass_csrf(request):
        raise Forbidden("You CSRF thief!")


def protected(wrapped: t.Optional[t.Union[t.Callable, str]] = None) -> t.Callable:
    """
    This decorator is setup to be used in one of the following ways:

    @app.get("/")
    @protected
    async def my_route(request):
        ...

    @app.get("/")
    @protected()
    async def my_route(request):
        ...

    @app.get("/")
    @protected("foo:bar")
    async def my_route(request):
        ...
    """
    scoped = None

    # If we passed a string, then we know that we are trying to scope
    # our endpoint
    if wrapped is not None and isinstance(wrapped, str):
        scoped, wrapped = wrapped, scoped

    def decorator(handler: t.Callable) -> t.Callable:
        async def decorated_function(request: Request, *args, **kwargs) -> HTTPResponse:

            # Run our protection
            do_protection(request, scoped)

            # Assuming no exception has been raised, we can proceed with
            # our handler
            return await handler(request, *args, **kwargs)

        return decorated_function

    return decorator if wrapped is None else decorator(wrapped)


def make_auth_response(token: bytes) -> HTTPResponse:
    """
    Our login response will provide the access token in the body.
    It also needs to setup our "split" JWT cookies, and a CSRF cookie
    """

    token = token.decode("utf-8")

    # Split the JWT
    header_payload, signature = token.rsplit(".", maxsplit=1)

    # Setup the response. We are putting the token in the body. But
    # DO NOT store that token in the web client.
    response = json({"access_token": token})

    # We are allowing httponly to be False so that the payload can be
    # grabbed from the web client and deserialized
    set_cookie(response, "access_token", header_payload, httponly=False)

    # This is SUPER important. The security of our authentication scheme
    # hinges upon httponly being True. DO NOT forget this.
    set_cookie(
        response, "access_token_signature", signature, httponly=True,
    )

    # Setup a csrf_token. In order for this to work, we are going to expect
    # that any incoming requests have a HEADER called X-XSRF-TOKEN.
    # To allow that to happen, httponly needs to be False
    set_cookie(
        response, "csrf_token", generate_csrf_token(), httponly=False,
    )

    return response


def set_cookie(response, key, value, httponly=None):
    response.cookies[key] = value
    response.cookies[key]["httponly"] = httponly
    response.cookies[key]["path"] = "/"
    response.cookies[key]["expires"] = datetime.now() + timedelta(hours=1)
    response.cookies[key]["samesite"] = "lax"

    # These are disabled here for demo purposes. They should be used
    # for additional security in production.
    # response.cookies[key]["samesite"] = "lax"
    # response.cookies[key]["domain"] = "foo.bar"
    # response.cookies[key]["secure"] = True

    # What about SameSite cookies? Indeed, they are meant as a protection from
    # CSRF attaches and can help. But, you need to determine if they are
    # appropriate. It you set SameSite=Strict (and apply to the JWT cookies)
    # then anyone that visits a secured link (regardless if they have already
    # logged in) from outside of your site will be denied access. But, that only
    # is until they refresh their browser. Which might also lead to weird and
    # unexpected behavior. This may be OK. But it may not. Should protected
    # resources be sharable? Even when using it, there are instances where
    # CSRF may still be bypassed. We default our cookies to SameSite=Lax.
    # This means that GET requests coming from third-parties can still pass the
    # cookie. So, links will still be shareable as the user would still appear
    # logged in. However, with SameSite=Lax, non safe HTTP methods from third
    # parties will not submit the cookies. Authentication type cookies should
    # ALWAYS carry SameSite=Lax (which is default behavior on modern browsers).
    # And, you should decide if SameSite=Strict makes sense for you. Regardless,
    # CSRF tokens are a proven and simple method. And, given there are still
    # known methods to circumvent these cookie restrictions, I still believe
    # that an effective anti-CSRF strategy includes tokens. SameSite tokens
    # do not YET appear to be a full-proof solution.


@app.post("/auth")
async def do_auth(request: Request) -> HTTPResponse:
    """This is our "login" method. Hitting it sets the cookies."""

    # Setup the times for the JWT expiration claim
    iat = datetime.now()
    exp = datetime.now() + timedelta(hours=1)

    # Encode our payload into a JWT
    token = jwt.encode(
        {
            "iat": iat.timestamp(),
            "exp": exp.timestamp(),
            "scopes": "top_secret:read:write",
        },
        request.app.config.JWT_SECRET,
        algorithm="HS256",
    )

    # Generate our authentication response
    response = make_auth_response(token)

    return response


@app.get("/protected")
@protected
async def top_secret(request: Request) -> HTTPResponse:
    return json({"foo": "bar"})


@app.get("/scoped")
@protected("top_secret:read")
async def scoped(request: Request) -> HTTPResponse:
    return json({"fizz": "buzz"})


@app.post("/do")
@protected("top_secret:write")
async def do_secret(request: Request) -> HTTPResponse:
    return json({"self_destruct": True})


app.run(debug=True, port=7777)
