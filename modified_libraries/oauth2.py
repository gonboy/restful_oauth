# coding: utf-8
"""
    flask_oauthlib.provider.oauth2
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    Implemnts OAuth2 provider support for Flask.

    :copyright: (c) 2013 - 2014 by Hsiaoming Yang.
"""

import os
import logging
import datetime
from functools import wraps
from flask import request, url_for
from flask import redirect, abort
from werkzeug import cached_property
from werkzeug.utils import import_string
from oauthlib import oauth2
from oauthlib.oauth2 import RequestValidator, Server
from oauthlib.common import to_unicode
from ..utils import extract_params, decode_base64, create_response

__all__ = ('OAuth2Provider', 'OAuth2RequestValidator')

log = logging.getLogger('flask_oauthlib')


class OAuth2Provider(object):
    """Provide secure services using OAuth2.

    The server should provide an authorize handler and a token hander,
    But before the handlers are implemented, the server should provide
    some getters for the validation.

    Like many other Flask extensions, there are two usage modes. One is
    binding the Flask app instance::

        app = Flask(__name__)
        oauth = OAuth2Provider(app)

    The second possibility is to bind the Flask app later::

        oauth = OAuth2Provider()

        def create_app():
            app = Flask(__name__)
            oauth.init_app(app)
            return app

    Configure :meth:`tokengetter` and :meth:`tokensetter` to get and
    set tokens. Configure :meth:`grantgetter` and :meth:`grantsetter`
    to get and set grant tokens. Configure :meth:`clientgetter` to
    get the client.

    Configure :meth:`usergetter` if you need password credential
    authorization.

    With everything ready, implement the authorization workflow:

        * :meth:`authorize_handler` for consumer to confirm the grant
        * :meth:`token_handler` for client to exchange access token

    And now you can protect the resource with scopes::

        @app.route('/api/user')
        @oauth.require_oauth('email', 'username')
        def user(oauth):
            return jsonify(oauth.user)
    """

    def __init__(self, app=None):
        self._before_request_funcs = []
        self._after_request_funcs = []
        if app:
            self.init_app(app)

    def init_app(self, app):
        """
        This callback can be used to initialize an application for the
        oauth provider instance.
        """
        self.app = app
        app.extensions = getattr(app, 'extensions', {})
        app.extensions['oauthlib.provider.oauth2'] = self

    @cached_property
    def error_uri(self):
        """The error page URI.

        When something turns error, it will redirect to this error page.
        You can configure the error page URI with Flask config::

            OAUTH2_PROVIDER_ERROR_URI = '/error'

        You can also define the error page by a named endpoint::

            OAUTH2_PROVIDER_ERROR_ENDPOINT = 'oauth.error'
        """
        error_uri = self.app.config.get('OAUTH2_PROVIDER_ERROR_URI')
        if error_uri:
            return error_uri
        error_endpoint = self.app.config.get('OAUTH2_PROVIDER_ERROR_ENDPOINT')
        if error_endpoint:
            return url_for(error_endpoint)
        return '/oauth/errors'

    @cached_property
    def server(self):
        """
        All in one endpoints. This property is created automaticly
        if you have implemented all the getters and setters.

        However, if you are not satisfied with the getter and setter,
        you can create a validator with :class:`OAuth2RequestValidator`::

            class MyValidator(OAuth2RequestValidator):
                def validate_client_id(self, client_id):
                    # do something
                    return True

        And assign the validator for the provider::

            oauth._validator = MyValidator()
        """
        expires_in = self.app.config.get('OAUTH2_PROVIDER_TOKEN_EXPIRES_IN')
        token_generator = self.app.config.get(
            'OAUTH2_PROVIDER_TOKEN_GENERATOR', None
        )
        if token_generator and not callable(token_generator):
            token_generator = import_string(token_generator)

        if hasattr(self, '_validator'):
            return Server(
                self._validator,
                token_expires_in=expires_in,
                token_generator=token_generator,
            )

        if hasattr(self, '_clientgetter') and \
           hasattr(self, '_tokengetter') and \
           hasattr(self, '_tokensetter') and \
           hasattr(self, '_grantgetter') and \
           hasattr(self, '_grantsetter'):

            usergetter = None
            if hasattr(self, '_usergetter'):
                usergetter = self._usergetter

            validator = OAuth2RequestValidator(
                clientgetter=self._clientgetter,
                tokengetter=self._tokengetter,
                grantgetter=self._grantgetter,
                usergetter=usergetter,
                tokensetter=self._tokensetter,
                grantsetter=self._grantsetter,
            )
            self._validator = validator
            return Server(
                validator,
                token_expires_in=expires_in,
                token_generator=token_generator,
            )
        raise RuntimeError('application not bound to required getters')

    def before_request(self, f):
        """Register functions to be invoked before accessing the resource.

        The function accepts nothing as parameters, but you can get
        information from `Flask.request` object. It is usually useful
        for setting limitation on the client request::

            @oauth.before_request
            def limit_client_request():
                client_id = request.values.get('client_id')
                if not client_id:
                    return
                client = Client.get(client_id)
                if over_limit(client):
                    return abort(403)

                track_request(client)
        """
        self._before_request_funcs.append(f)
        return f

    def after_request(self, f):
        """Register functions to be invoked after accessing the resource.

        The function accepts ``valid`` and ``request`` as parameters,
        and it should return a tuple of them::

            @oauth.after_request
            def valid_after_request(valid, oauth):
                if oauth.user in black_list:
                    return False, oauth
                return valid, oauth
        """
        self._after_request_funcs.append(f)
        return f

    def clientgetter(self, f):
        """Register a function as the client getter.

        The function accepts one parameter `client_id`, and it returns
        a client object with at least these information:

            - client_id: A random string
            - client_secret: A random string
            - client_type: A string represents if it is `confidential`
            - redirect_uris: A list of redirect uris
            - default_redirect_uri: One of the redirect uris
            - default_scopes: Default scopes of the client

        The client may contain more information, which is suggested:

            - allowed_grant_types: A list of grant types
            - allowed_response_types: A list of response types
            - validate_scopes: A function to validate scopes

        Implement the client getter::

            @oauth.clientgetter
            def get_client(client_id):
                client = get_client_model(client_id)
                # Client is an object
                return client
        """
        self._clientgetter = f
        return f

    def usergetter(self, f):
        """Register a function as the user getter.

        This decorator is only required for password credential
        authorization::

            @oauth.usergetter
            def get_user(username=username, password=password,
                         *args, **kwargs):
                return get_user_by_username(username, password)
        """
        self._usergetter = f
        return f

    def tokengetter(self, f):
        """Register a function as the token getter.

        The function accepts an `access_token` or `refresh_token` parameters,
        and it returns a token object with at least these information:

            - access_token: A string token
            - refresh_token: A string token
            - client_id: ID of the client
            - scopes: A list of scopes
            - expires: A `datetime.datetime` object
            - user: The user object

        The implementation of tokengetter should accepts two parameters,
        one is access_token the other is refresh_token::

            @oauth.tokengetter
            def bearer_token(access_token=None, refresh_token=None):
                if access_token:
                    return get_token(access_token=access_token)
                if refresh_token:
                    return get_token(refresh_token=refresh_token)
                return None
        """
        self._tokengetter = f
        return f

    def tokensetter(self, f):
        """Register a function to save the bearer token.

        The setter accepts two parameters at least, one is token,
        the other is request::

            @oauth.tokensetter
            def set_token(token, request, *args, **kwargs):
                save_token(token, request.client, request.user)

        The parameter token is a dict, that looks like::

            {
                u'access_token': u'6JwgO77PApxsFCU8Quz0pnL9s23016',
                u'token_type': u'Bearer',
                u'expires_in': 3600,
                u'scope': u'email address'
            }

        The request is an object, that contains an user object and a
        client object.
        """
        self._tokensetter = f
        return f

    def grantgetter(self, f):
        """Register a function as the grant getter.

        The function accepts `client_id`, `code` and more::

            @oauth.grantgetter
            def grant(client_id, code):
                return get_grant(client_id, code)

        It returns a grant object with at least these information:

            - delete: A function to delete itself
        """
        self._grantgetter = f
        return f

    def grantsetter(self, f):
        """Register a function to save the grant code.

        The function accepts `client_id`, `code`, `request` and more::

            @oauth.grantsetter
            def set_grant(client_id, code, request, *args, **kwargs):
                save_grant(client_id, code, request.user, request.scopes)
        """
        self._grantsetter = f
        return f

    def authorize_handler(self, f):
        """Authorization handler decorator.

        This decorator will sort the parameters and headers out, and
        pre validate everything::

            @app.route('/oauth/authorize', methods=['GET', 'POST'])
            @oauth.authorize_handler
            def authorize(*args, **kwargs):
                if request.method == 'GET':
                    # render a page for user to confirm the authorization
                    return render_template('oauthorize.html')

                confirm = request.form.get('confirm', 'no')
                return confirm == 'yes'
        """
        @wraps(f)
        def decorated(*args, **kwargs):
            # raise if server not implemented
            server = self.server
            uri, http_method, body, headers = extract_params()

            if request.method == 'GET':
                redirect_uri = request.args.get('redirect_uri', None)
                log.debug('Found redirect_uri %s.', redirect_uri)
                try:
                    ret = server.validate_authorization_request(
                        uri, http_method, body, headers
                    )
                    scopes, credentials = ret
                    kwargs['scopes'] = scopes
                    kwargs.update(credentials)
                    return f(*args, **kwargs)
                except oauth2.FatalClientError as e:
                    log.debug('Fatal client error %r', e)
                    return redirect(e.in_uri(self.error_uri))

            if request.method == 'POST':
                redirect_uri = request.values.get('redirect_uri', None)
                if not f(*args, **kwargs):
                    # denied by user
                    e = oauth2.AccessDeniedError()
                    return redirect(e.in_uri(redirect_uri))
                return self.confirm_authorization_request()
        return decorated

    def confirm_authorization_request(self):
        """When consumer confirm the authrozation."""
        server = self.server
        scope = request.values.get('scope') or ''
        scopes = scope.split()
        credentials = dict(
            client_id=request.values.get('client_id'),
            redirect_uri=request.values.get('redirect_uri', None),
            response_type=request.values.get('response_type', None),
            state=request.values.get('state', None)
        )
        log.debug('Fetched credentials from request %r.', credentials)
        redirect_uri = credentials.get('redirect_uri')
        log.debug('Found redirect_uri %s.', redirect_uri)

        uri, http_method, body, headers = extract_params()
        try:
            ret = server.create_authorization_response(
                uri, http_method, body, headers, scopes, credentials)
            log.debug('Authorization successful.')
            return create_response(*ret)
        except oauth2.FatalClientError as e:
            return redirect(e.in_uri(self.error_uri))
        except oauth2.OAuth2Error as e:
            return redirect(e.in_uri(redirect_uri))

    def token_handler(self, f):
        """Access/refresh token handler decorator.

        The decorated function should return an dictionary or None as
        the extra credentials for creating the token response.

        You can control the access method with standard flask route mechanism.
        If you only allow the `POST` method::

            @app.route('/oauth/token', methods=['POST'])
            @oauth.token_handler
            def access_token():
                return None
        """
        @wraps(f)
        def decorated(*args, **kwargs):
            server = self.server
            uri, http_method, body, headers = extract_params()
            credentials = f(*args, **kwargs) or {}
            log.debug('Fetched extra credentials, %r.', credentials)
            ret = server.create_token_response(
                uri, http_method, body, headers, credentials
            )
            return create_response(*ret)
        return decorated

    def require_oauth(self, *scopes):
        """Protect resource with specified scopes."""
        def wrapper(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                for func in self._before_request_funcs:
                    func()

                server = self.server
                uri, http_method, body, headers = extract_params()
                valid, req = server.verify_request(
                    uri, http_method, body, headers, scopes
                )

                for func in self._after_request_funcs:
                    valid, req = func(valid, req)

                if not valid:
                    return abort(403)
                return f(*((req,) + args), **kwargs)
            return decorated
        return wrapper


class OAuth2RequestValidator(RequestValidator):
    """Subclass of Request Validator.

    :param clientgetter: a function to get client object
    :param tokengetter: a function to get bearer token
    :param tokensetter: a function to save bearer token
    :param grantgetter: a function to get grant token
    :param grantsetter: a function to save grant token
    """
    def __init__(self, clientgetter, tokengetter, grantgetter,
                 usergetter=None, tokensetter=None, grantsetter=None):
        self._clientgetter = clientgetter
        self._tokengetter = tokengetter
        self._usergetter = usergetter
        self._tokensetter = tokensetter
        self._grantgetter = grantgetter
        self._grantsetter = grantsetter

    def client_authentication_required(self, request, *args, **kwargs):
        return request.grant_type in ('password', 'refresh_token')

    def authenticate_client(self, request, *args, **kwargs):
        """Authenticate itself in other means.

        Other means means is described in `Section 3.2.1`_.

        .. _`Section 3.2.1`: http://tools.ietf.org/html/rfc6749#section-3.2.1
        """
        auth = request.headers.get('Authorization', None)
        log.debug('Authenticate client %r', auth)
        if auth:
            try:
                _, s = auth.split(' ')
                client_id, client_secret = decode_base64(s).split(':')
                client_id = to_unicode(client_id, 'utf-8')
                client_secret = to_unicode(client_secret, 'utf-8')
            except Exception as e:
                log.debug('Authenticate client failed with exception: %r', e)
                return False
        else:
            client_id = request.client_id
            client_secret = request.client_secret

        client = self._clientgetter(client_id)
        if not client:
            log.debug('Authenticate client failed, client not found.')
            return False

        request.client = client
        if client.client_secret != client_secret:
            log.debug('Authenticate client failed, secret not match.')
            return False

        if client.client_type != 'confidential':
            log.debug('Authenticate client failed, not confidential.')
            return False
        log.debug('Authenticate client success.')
        return True

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        """Authenticate a non-confidential client.

        :param client_id: Client ID of the non-confidential client
        :param request: The Request object passed by oauthlib
        """
        log.debug('Authenticate client %r.', client_id)
        client = request.client or self._clientgetter(client_id)
        if not client:
            log.debug('Authenticate failed, client not found.')
            return False

        # attach client on request for convenience
        request.client = client

        # authenticate non-confidential client_type only
        # most of the clients are of public client_type
        # haseeb: removing this check - doesn't make sense
        if False: #client.client_type == 'confidential':
            log.debug('Authenticate client failed, confidential client.')
            return False
        return True

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client,
                             *args, **kwargs):
        """Ensure client is authorized to redirect to the redirect_uri.

        This method is used in the authorization code grant flow. It will
        compare redirect_uri and the one in grant token strictly, you can
        add a `validate_redirect_uri` function on grant for a customized
        validation.
        """
        log.debug('Confirm redirect uri for client %r and code %r.',
                  client_id, code)
        grant = self._grantgetter(client_id=client_id, code=code)
        if not grant:
            log.debug('Grant not found.')
            return False
        if hasattr(grant, 'validate_redirect_uri'):
            return grant.validate_redirect_uri(redirect_uri)
        log.debug('Compare redirect uri for grant %r and %r.',
                  grant.redirect_uri, redirect_uri)

        if os.environ.get('DEBUG') and redirect_uri is None:
            # For testing
            return True
        print (grant.redirect_uri, redirect_uri)
        return grant.redirect_uri == redirect_uri

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        """Get the list of scopes associated with the refresh token.

        This method is used in the refresh token grant flow.  We return
        the scope of the token to be refreshed so it can be applied to the
        new access token.
        """
        log.debug('Obtaining scope of refreshed token.')
        tok = self._tokengetter(refresh_token=refresh_token)
        return tok.scopes

    def confirm_scopes(self, refresh_token, scopes, request, *args, **kwargs):
        """Ensures the requested scope matches the scope originally granted
        by the resource owner. If the scope is omitted it is treated as equal
        to the scope originally granted by the resource owner.

        DEPRECATION NOTE: This method will cease to be used in oauthlib>0.4.2,
        future versions of ``oauthlib`` use the validator method
        ``get_original_scopes`` to determine the scope of the refreshed token.
        """
        if not scopes:
            log.debug('Scope omitted for refresh token %r', refresh_token)
            return True
        log.debug('Confirm scopes %r for refresh token %r',
                  scopes, refresh_token)
        tok = self._tokengetter(refresh_token=refresh_token)
        return set(tok.scopes) == set(scopes)

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        """Default redirect_uri for the given client."""
        request.client = request.client or self._clientgetter(client_id)
        redirect_uri = request.client.default_redirect_uri
        log.debug('Found default redirect uri %r', redirect_uri)
        return redirect_uri

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        """Default scopes for the given client."""
        request.client = request.client or self._clientgetter(client_id)
        scopes = request.client.default_scopes
        log.debug('Found default scopes %r', scopes)
        return scopes

    def invalidate_authorization_code(self, client_id, code, request,
                                      *args, **kwargs):
        """Invalidate an authorization code after use.

        We keep the temporary code in a grant, which has a `delete`
        function to destroy itself.
        """
        log.debug('Destroy grant token for client %r, %r', client_id, code)
        grant = self._grantgetter(client_id=client_id, code=code)
        if grant:
            grant.delete()

    def save_authorization_code(self, client_id, code, request,
                                *args, **kwargs):
        """Persist the authorization code."""
        log.debug(
            'Persist authorization code %r for client %r',
            code, client_id
        )
        request.client = request.client or self._clientgetter(client_id)
        self._grantsetter(client_id, code, request, *args, **kwargs)
        return request.client.default_redirect_uri

    def save_bearer_token(self, token, request, *args, **kwargs):
        """Persist the Bearer token."""
        log.debug('Save bearer token %r', token)
        self._tokensetter(token, request, *args, **kwargs)
        return request.client.default_redirect_uri

    def validate_bearer_token(self, token, scopes, request):
        """Validate access token.

        :param token: A string of random characters
        :param scopes: A list of scopes
        :param request: The Request object passed by oauthlib

        The validation validates:

            1) if the token is available
            2) if the token has expired
            3) if the scopes are available
        """
        log.debug('Validate bearer token %r', token)
        tok = self._tokengetter(access_token=token)
        if not tok:
            log.debug('Bearer token not found.')
            return False

        # validate expires
        if datetime.datetime.utcnow() > tok.expires:
            log.debug('Bearer token is expired.')
            return False

        # validate scopes
        if not set(tok.scopes).issuperset(set(scopes)):
            log.debug('Bearer token scope not valid.')
            return False

        request.access_token = tok
        request.user = tok.user
        request.scopes = scopes

        if hasattr(tok, 'client'):
            request.client = tok.client
        elif hasattr(tok, 'client_id'):
            request.client = self._clientgetter(tok.client_id)
        return True

    def validate_client_id(self, client_id, request, *args, **kwargs):
        """Ensure client_id belong to a valid and active client."""
        log.debug('Validate client %r', client_id)
        client = request.client or self._clientgetter(client_id)
        if client:
            # attach client to request object
            request.client = client
            return True
        return False

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        """Ensure the grant code is valid."""
        log.debug(
            'Validate code for client %r and code %r', client_id, code
        )
        grant = self._grantgetter(client_id=client_id, code=code)
        if not grant:
            log.debug('Grant not found.')
            return False
        if hasattr(grant, 'expires') and \
           datetime.datetime.utcnow() > grant.expires:
            log.debug('Grant is expired.')
            return False

        request.state = kwargs.get('state')
        request.user = grant.user
        request.scopes = grant.scopes
        return True

    def validate_grant_type(self, client_id, grant_type, client, request,
                            *args, **kwargs):
        """Ensure the client is authorized to use the grant type requested.

        It will allow any of the four grant types (`authorization_code`,
        `password`, `client_credentials`, `refresh_token`) by default.
        Implemented `allowed_grant_types` for client object to authorize
        the request.

        It is suggested that `allowed_grant_types` should contain at least
        `authorization_code` and `refresh_token`.
        """
        if self._usergetter is None and grant_type == 'password':
            log.debug('Password credential authorization is disabled.')
            return False

        if grant_type not in ('authorization_code', 'password',
                              'client_credentials', 'refresh_token'):
            return False

        if hasattr(client, 'allowed_grant_types'):
            return grant_type in client.allowed_grant_types

        if grant_type == 'client_credentials':
            if hasattr(client, 'user'):
                request.user = client.user
                return True
            log.debug('Client should has a user property')
            return False

        return True

    def validate_redirect_uri(self, client_id, redirect_uri, request,
                              *args, **kwargs):
        """Ensure client is authorized to redirect to the redirect_uri.

        This method is used in the authorization code grant flow and also
        in implicit grant flow. It will detect if redirect_uri in client's
        redirect_uris strictly, you can add a `validate_redirect_uri`
        function on grant for a customized validation.
        """
        request.client = request.client = self._clientgetter(client_id)
        client = request.client
        if hasattr(client, 'validate_redirect_uri'):
            return client.validate_redirect_uri(redirect_uri)
        return redirect_uri in client.redirect_uris

    def validate_refresh_token(self, refresh_token, client, request,
                               *args, **kwargs):
        """Ensure the token is valid and belongs to the client

        This method is used by the authorization code grant indirectly by
        issuing refresh tokens, resource owner password credentials grant
        (also indirectly) and the refresh token grant.
        """

        token = self._tokengetter(refresh_token=refresh_token)

        if token and token.client_id == client.client_id:
            # Make sure the request object contains user and client_id
            request.client_id = token.client_id
            request.user = token.user
            return True
        return False

    def validate_response_type(self, client_id, response_type, client, request,
                               *args, **kwargs):
        """Ensure client is authorized to use the response type requested.

        It will allow any of the two (`code`, `token`) response types by
        default. Implemented `allowed_response_types` for client object
        to authorize the request.
        """
        if response_type not in ('code', 'token'):
            return False

        if hasattr(client, 'allowed_response_types'):
            return response_type in client.allowed_response_types
        return True

    def validate_scopes(self, client_id, scopes, client, request,
                        *args, **kwargs):
        """Ensure the client is authorized access to requested scopes."""
        if hasattr(client, 'validate_scopes'):
            return client.validate_scopes(scopes)
        return set(client.default_scopes).issuperset(set(scopes))

    def validate_user(self, username, password, client, request,
                      *args, **kwargs):
        """Ensure the username and password is valid.

        Attach user object on request for later using.
        """
        log.debug('Validating username %r and password %r',
                  username, password)
        if self._usergetter is not None:
            user = self._usergetter(
                username, password, client, request, *args, **kwargs
            )
            if user:
                request.user = user
                return True
            return False
        log.debug('Password credential authorization is disabled.')
        return False
