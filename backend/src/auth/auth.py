# ---------------------------------------------------------------------------#
# Imports
# ---------------------------------------------------------------------------#


import json
from flask import request, _request_ctx_stack, abort
from functools import wraps
from jose import jwt
from urllib.request import urlopen


# ---------------------------------------------------------------------------#
# API Config
# ---------------------------------------------------------------------------#


AUTH0_DOMAIN = 'nacler.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'coffee'


# ---------------------------------------------------------------------------#
# Helpers
# ---------------------------------------------------------------------------#


# AuthError Exception
class AuthError(Exception):
    '''
    AuthError exception to standardize auth failures
    '''
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


# Get Token from Auth Header
def get_token_auth_header():
    '''
    Get the auth token from the auth header, and return AuthErrors if header
    is missing or type is not bearer
    '''
    auth = request.headers.get('Authorization', None)
    if not auth:
        raise AuthError({
            'code': 'authorization_header_missing',
            'description': 'Authorization header is expected.'
        }, 401)

    parts = auth.split()
    if parts[0].lower() != 'bearer':
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must start with "Bearer".'
        }, 401)

    elif len(parts) == 1:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Token not found.'
        }, 401)

    elif len(parts) > 2:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must be bearer token.'
        }, 401)

    token = parts[1]
    return token


# Check Permissions
def check_permissions(permission, payload):
    '''
    Check that permissions is in the payload
    '''
    if 'permissions' not in payload:
        raise AuthError({
            'code': 'invalid_claims',
            'description': 'Permissions not included in JWT.'
        }, 400)

    if permission not in payload['permissions']:
        raise AuthError({
            'code': 'unauthorized',
            'description': 'Permission not found.'
        }, 401)

    return True


# Verify and Decode the JWT
def verify_decode_jwt(token):
    '''
    Given a token, validate using auto0 endpoint. Decode the payload and
    validate the claims. Return the decoded payload.
    '''
    jsonurl = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    jwks = json.loads(jsonurl.read())
    unverified_header = jwt.get_unverified_header(token)
    rsa_key = {}

    if 'kid' not in unverified_header:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization malformed.'
        }, 401)

    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }

    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer='https://' + AUTH0_DOMAIN + '/'
            )

            return payload

        except jwt.ExpiredSignatureError:
            raise AuthError({
                'success': False,
                'message': 'Token expired',
                'error': 401,
            }, 401)

        except jwt.JWTClaimsError:
            raise AuthError({
                'success': False,
                'message': 'Incorrect claims. Please, check the audience \
                            and issuer',
                'error': 401,
            }, 401)

        except Exception:
            raise AuthError({
                'success': False,
                'message': 'Unable to parse authentication token',
                'error': 400,
            }, 400)

    raise AuthError({
        'success': False,
        'message': 'Unable to find the appropriate key',
        'error': 401,
    }, 401)


# Require Auth + Decordator
def requires_auth(permission=''):
    '''
    Get the token, verify it, check the user's permissions and return
    the auth decorator
    '''
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            payload = verify_decode_jwt(token)
            check_permissions(permission, payload)
            return f(payload, *args, **kwargs)

        return wrapper
    return requires_auth_decorator
