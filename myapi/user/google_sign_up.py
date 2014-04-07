from datetime import datetime, timedelta

from settings import GOOGLE_APP_ID, GOOGLE_APP_SECRET, GOOGLE_APP_SCOPES, GOOGLE_PLUS_API_URL, \
                     GOOGLE_API_URL, GOOGLE_ACCESS_TOKEN_URL, GOOGLE_AUTHORIZE_URL
from manage import oauth2_client, app
from models import User, GoogleOAuth, GENDERS, THIRD_PARTY_DATA
from myapi.oauth.views import login

from flask import url_for, session, request
from flask.ext.restful import Resource
from flask_oauthlib.client import OAuthException

FIELDS_TO_FETCH = {
                   'email':         'email',
                   'first_name':    'given_name',
                   'last_name':     'family_name',
                   'gender':        'gender',
                   'dob':           'birthday',
                   'location':      ['location', 'placesLived', 'hometown'],
                   'picture':       'picture',
                  }

google = oauth2_client.remote_app(
    'google',
    consumer_key=GOOGLE_APP_ID,
    consumer_secret=GOOGLE_APP_SECRET,
    request_token_params={'scope': GOOGLE_APP_SCOPES},
    base_url=GOOGLE_API_URL,
    request_token_url=None,
    access_token_url=GOOGLE_ACCESS_TOKEN_URL,
    authorize_url=GOOGLE_AUTHORIZE_URL,
    access_token_method='POST',
)

class ThirdPartySignUpGoogle(Resource):
    def get(self):
        return google.authorize(callback=url_for('google_authorized', _external=True, _scheme='https'))

@app.route('/login/authorized/google')
@google.authorized_handler
def google_authorized(resp):
    if resp is None:
        return login(error='%s, error_description=%s' %(request.args['error_reason'], request.args['error_description']))
    if isinstance(resp, OAuthException):
        return login(error=resp.message)

    session['google_token'] = (resp['access_token'], '')
    access_token = session['google_token'][0]
    expires = resp.get('expires_in', None)
    (me, me_plus, data, data_plus) = (None, None, {}, {})
    if access_token and expires:
        expires = datetime.utcnow() + timedelta(seconds=long(expires))
        try:
            me = google.get('userinfo')
        except:
            pass
        try:
            me_plus = google.get(GOOGLE_PLUS_API_URL+'people/me')
        except:
            pass
    else:
        return login(error='Something went wrong - Could not fetch data from Google')
    if hasattr(me, 'data'):
        data = me.data
    if hasattr(me_plus, 'data'):
        data_plus = me_plus.data
    if not data and not data_plus:
        return login(error='Something went wrong - Could not fetch data from Google')
    data.update(data_plus)
    for k, v in dict(data).items():
        v = str(v).strip()
        if not v:
            data.pop(k)
    google_id = data['id']
    oauth_object = GoogleOAuth.objects(google_id=google_id)
    if oauth_object:
        oauth_object = oauth_object[0]
        user = User.objects(id=oauth_object.user.id)[0]
    else:
        user = User()
    third_party_data = {v:k for k, v in THIRD_PARTY_DATA.items()}
    fields_to_fetch = [third_party_data[k] for k, v in FIELDS_TO_FETCH.items()]
    fields_to_update = list(set(fields_to_fetch) - set(user.fields_updated))
    for field in fields_to_update:
        db_field = THIRD_PARTY_DATA[field]
        if db_field == 'location':
            location = None
            try:
                location = data['location']
            except:
                pass
            try:
                for x in data['placesLived']:
                    location = x['value']
                    if x['primary']:
                        break
            except:
                pass
            try:
                location = data['hometown']['name']
            except:
                pass
            if location:
                user.location = location
        elif db_field == 'gender':
            genders = {v:k for k, v in GENDERS.items()}
            try:
                gender = genders[data[FIELDS_TO_FETCH[db_field]]]
                user.gender = gender
            except:
                pass
        else:
            try:
                exec "user.%s = '%s'" %(db_field, data[FIELDS_TO_FETCH[db_field]]) in locals()
            except:
                pass
    user.is_active = True
    user.save()
    if not oauth_object:
        oauth_object = GoogleOAuth()
    oauth_object.google_id = google_id
    oauth_object.user = user
    oauth_object.access_token = access_token
    oauth_object.expires = expires
    oauth_object.created_at = datetime.utcnow()
    oauth_object.save()
    registered = False
    if user.password:
        registered = True
    user_id = str(user.id)
    return login(user_id=user_id, registered=registered)

@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')