import urllib, ast
from urlparse import urlparse, parse_qs
from datetime import datetime, timedelta

from manage import oauth2, app
from settings import TOKEN_EXPIRES_IN, WEB_APP_REDIRECT_URL, API_BASE_URL, WEB_APP_SCOPES, \
                     WEB_APP_CLIENT_ID, WEB_APP_CLIENT_SECRET
from myapi.user.models import User
from models import Client, Token, Grant
from flask.ext.restful import Resource, reqparse
from flask import jsonify, session, abort, redirect, request

def current_user():
    if 'id' in session:
        id = str(session['id'])
        return User.objects(id=id)[0]
    return None

def login(error=None, user_id=None, registered=False):
    if error:
        return redirect('%s?error=%s' %(WEB_APP_REDIRECT_URL, error))
    elif user_id:
        data = {
                "user_id": user_id,
                "client_id": WEB_APP_CLIENT_ID,
                "client_secret": WEB_APP_CLIENT_SECRET,
                "redirect_uri": API_BASE_URL,
                "response_type": "code",
                "scope": WEB_APP_SCOPES,
                "thirdparty": "true",
        }
        client = app.test_client()
        check = False
        try:
            resp = client.post('/oauth/authorize', data=data)
        except:
            pass
        try:            
            code = parse_qs(urlparse(resp.location).query)['code'][0]
            check = True
        except:
            pass
        if not check:
            return redirect('%s?error=Something went wrong - Please try again later!' %WEB_APP_REDIRECT_URL)
        resp = None
        data = {
                "grant_type": "authorization_code",
                "code": code,
                "client_id": WEB_APP_CLIENT_ID,
                "client_secret": WEB_APP_CLIENT_SECRET,
                "redirect_uri": API_BASE_URL,
        }
        try:
            resp = client.get('/oauth/access_token?%s' %urllib.urlencode(data))
        except:
            pass
        try:
            data = ast.literal_eval(resp.data)
            if registered:
                user_id = '?user_id=%s&' %data['user_id']
            else:
                user_id = '?'
            url = '%s%saccess_token=%s&refresh_token=%s' %(WEB_APP_REDIRECT_URL, user_id, data['access_token'], data['refresh_token'])
            return redirect(url)
        except:
            return redirect('%s?error=Something went wrong - Please try again later!' %WEB_APP_REDIRECT_URL)
    else:
        return jsonify({'error': 'Something went wrong - Please try again later!'})

def home():
    json = dict(request.args)
    json_dict = {}
    for k, v in json.items():
        if type(v) is list and len(v) == 1:
            json_dict[k] = v[0]
        else:
            json_dict[k] = v
    if json_dict:
        return jsonify(json_dict)
    return jsonify({'message': 'Welcome to My API!'})

@oauth2.clientgetter
def load_client(client_id):
    client = Client.objects(client_id=client_id)
    if client:
        client = client[0]
    else:
        client = None
    return client

@oauth2.grantgetter
def load_grant(client_id, code):
    return Grant.objects(client=client_id)[0]

@oauth2.grantsetter
def save_grant(client_id, code, request):
    # decide the expires time yourself
    user = current_user()
    expires = datetime.utcnow() + timedelta(seconds=TOKEN_EXPIRES_IN)
    Grant.objects(client=str(client_id), user=user, _scopes=request.scopes).delete()
    if user.is_admin:
        request.scopes.append('admin')
    grant = Grant(
        client=str(client_id),
        code=code['code'],
        redirect_uri=request.redirect_uri,
        _scopes=request.scopes,
        user=user,
        expires=expires
    )
    grant.save()
    return grant

@oauth2.tokengetter
def load_token(access_token=None, refresh_token=None):
    token = None
    if access_token:
        try:
            token = Token.objects(access_token=access_token)[0]
        except:
            pass
    elif refresh_token:
        try:
            token = Token.objects(refresh_token=refresh_token, expires__gt=datetime.utcnow())[0]
        except:
            pass
    return token

@oauth2.tokensetter
def save_token(token, request):
    toks = Token.objects(client=request.client.id, user=request.user.id).delete()
    # make sure that every client has only one token connected to a user

    expires_in = token.pop('expires_in')
    expires = datetime.utcnow() + timedelta(seconds=expires_in)

    tok = Token(**token)
    tok.expires = expires
    tok.client = request.client
    tok.user = request.user
    tok._scopes = token['scope'].split()
    tok.save()
    token['expires'] = str(expires)
    token['user_id'] = str(request.user.id)
    return tok

class Authorize(Resource):

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('user_id', type=str, required=False)
        self.reqparse.add_argument('client_id', type=str, required=True)
        self.reqparse.add_argument('client_secret', type=str, required=True)
        self.reqparse.add_argument('username', type=str, required=False)
        self.reqparse.add_argument('password', type=str, required=False)
        self.reqparse.add_argument('redirect_uri', type=str, required=True)
        self.reqparse.add_argument('response_type', type=str, required=True)
        self.reqparse.add_argument('scope', type=str, required=True)
        self.reqparse.add_argument('thirdparty', type=str, required=False)
        super(Authorize, self).__init__()

    def post(self):
        @oauth2.authorize_handler
        def apply_decorator(self):
            return True
        args = self.reqparse.parse_args()
        session.clear()
        response_type = args['response_type'].strip().lower()
        thirdparty_check = False
        if request.form.has_key('thirdparty'):
            thirdparty_check = True
        username = args.get('username', None)
        password = args.get('password', None)
        user_id = str(args.get('user_id', None)).strip()
        client_id = str(args['client_id'])
        client_secret = str(args['client_secret'])
        client = Client.objects(client_id=client_id, client_secret=client_secret)
        if not client:
            return {'message': 'Invalid Client ID and Secret!'}, 403
        if not thirdparty_check:
            try:
                usr = User.objects(username=username)[0]
            except:
                return {'message': 'Invalid Username or Password!'}, 403
        else:
            try:
                usr = User.objects(id=user_id)[0]
                session['id'] = str(user_id)
            except:
                return {'message': 'Invalid user_id'}, 403
        if not thirdparty_check:
            from werkzeug import check_password_hash
            stored_password = str(usr.password)
            check = check_password_hash(stored_password, password)
            if check:
                user = usr
                session['id'] = str(user.id)
            else:
                 return {'message': 'Invalid Username or Password!'}, 403
        return apply_decorator(self)

class AccessToken(Resource):

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('grant_type', type=str, required=True)
        self.reqparse.add_argument('client_id', type=str, required=True)
        self.reqparse.add_argument('client_secret', type=str, required=True)
        self.reqparse.add_argument('code', type=str, required=False)
        self.reqparse.add_argument('redirect_uri', type=str, required=False)
        super(AccessToken, self).__init__()
        
    def get(self):
        @oauth2.token_handler
        def apply_decorator(self):
            return {}
        args = self.reqparse.parse_args()
        if args['grant_type'] == 'refresh_token':
            pass
        else:
            client_id = str(args['client_id'])
            client_secret = str(args['client_secret'])
            code = args.get('code', None)
            redirect_uri = args.get('redirect_uri', None)
            if code:
                code = str(code)
            if redirect_uri:
                redirect_uri = str(redirect_uri)
            if not code:
                return {'message': 'Please provide authorization code!'}, 403
            if not redirect_uri:
                return {'message': 'Please provide redirect_uri!'}, 403
            client = Client.objects(client_id=client_id, client_secret=client_secret)
            if not client:
                return {'message': 'Invalid Client ID and Secret!'}, 403
            now = datetime.utcnow()
            grant = Grant.objects(client=client[0], code=code, expires__gt=now)
            if not grant:
                return {'message': 'Grant code invalid or expired!'}, 403
        return apply_decorator(self)

    def post(self):
        return self.get()

class DeAuthorize(Resource):
    decorators = [oauth2.require_oauth("normal-user")]
    def get(self, request):
        user = User.objects(id=request.user.id)[0]
        client = Client.objects(client_id=request.client.id)[0]
        Token.objects(client=client, user=user).delete()
        return {'status': 'success'}