from datetime import datetime, timedelta

from settings import INSTAGRAM_APP_ID, INSTAGRAM_APP_SECRET, INSTAGRAM_APP_SCOPES, \
                     INSTAGRAM_API_URL, INSTAGRAM_ACCESS_TOKEN_URL, INSTAGRAM_AUTHORIZE_URL
from manage import oauth2_client, app
from models import User, InstagramOAuth, THIRD_PARTY_DATA
from myapi.oauth.views import authenticate_web_user

from flask import url_for, session, request
from flask.ext.restful import Resource
from flask_oauthlib.client import OAuthException

FIELDS_TO_FETCH = {
                   'first_name':    'full_name',
                   'last_name':     'full_name',
                   'picture':       'profile_picture',
                  }

instagram = oauth2_client.remote_app(
    'instagram',
    consumer_key=INSTAGRAM_APP_ID,
    consumer_secret=INSTAGRAM_APP_SECRET,
    request_token_params={'scope': INSTAGRAM_APP_SCOPES},
    base_url=INSTAGRAM_API_URL,
    request_token_url=None,
    access_token_url=INSTAGRAM_ACCESS_TOKEN_URL,
    authorize_url=INSTAGRAM_AUTHORIZE_URL,
    access_token_method='POST',
)

class ThirdPartySignUpInstagram(Resource):
    def get(self):
        callback = url_for(
            'instagram_authorized',
            next=request.args.get('next') or request.referrer or None,
            _external=True, _scheme='https'
        )
        return instagram.authorize(callback=callback)

@app.route('/login/authorized/instagram')
@instagram.authorized_handler
def instagram_authorized(resp):
    error = 'Something went wrong - Could not fetch data from Instagram'
    if resp is None:
        return authenticate_web_user(error='%s, error_description=%s' %(request.args['error_reason'], request.args['error_description']))
    if isinstance(resp, OAuthException):
        return authenticate_web_user(error=resp.message)
    (access_token, data) = (None, None)
    session['instagram_token'] = (resp['access_token'], '')
    try:
        access_token = resp['access_token']
        expires = datetime.utcnow() + timedelta(days=90)
    except:
        pass
    try:
        data = resp['user']
        instagram_id = resp['user']['id']
    except:
        pass
    if not access_token or not data:
        return authenticate_web_user(error=error)
    for k, v in dict(data).items():
        v = str(v).strip()
        if not v:
            data.pop(k)
    oauth_object = InstagramOAuth.objects(instagram_id=instagram_id)
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
        if db_field == 'first_name':
            split_name = data[FIELDS_TO_FETCH[db_field]].split()
            if len(split_name) > 1:
                user.first_name = split_name[0]
            else:
                user.first_name = ' '.join(split_name)
        elif db_field == 'last_name':
            split_name = data[FIELDS_TO_FETCH[db_field]].split()
            if len(split_name) > 1:
                user.last_name = ' '.join(split_name[1:])
        else:
            try:
                exec "user.%s = '%s'" %(db_field, data[FIELDS_TO_FETCH[db_field]]) in locals()
            except:
                pass
    user.is_active = True
    user.save()
    if not oauth_object:
        oauth_object = InstagramOAuth()
    oauth_object.instagram_id = instagram_id
    oauth_object.user = user
    oauth_object.access_token = access_token
    oauth_object.expires = expires
    oauth_object.created_at = datetime.utcnow()
    oauth_object.save()
    registered = False
    if user.password:
        registered = True
    return authenticate_web_user(user=user, registered=registered)

@instagram.tokengetter
def get_instagram_oauth_token():
    return session.get('instagram_token')