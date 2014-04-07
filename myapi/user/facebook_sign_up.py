import requests
from datetime import datetime, timedelta

from settings import FACEBOOK_APP_ID, FACEBOOK_APP_SECRET, FACEBOOK_APP_SCOPES, \
                     FACEBOOK_API_URL, FACEBOOK_ACCESS_TOKEN_URL, FACEBOOK_AUTHORIZE_URL
from manage import oauth2_client, app
from models import User, FaceBookOAuth, GENDERS, THIRD_PARTY_DATA
from myapi.oauth.views import login

from flask import url_for, session, request
from flask.ext.restful import Resource
from flask_oauthlib.client import OAuthException

FIELDS_TO_FETCH = {
                   'email':         'email',
                   'first_name':    'first_name',
                   'last_name':     ['middle_name', 'last_name'],
                   'gender':        'gender',
                   'dob':           'birthday',
                   'location':      ['location', 'hometown'],
                   'picture':       'picture',
                  }

facebook = oauth2_client.remote_app(
    'facebook',
    consumer_key=FACEBOOK_APP_ID,
    consumer_secret=FACEBOOK_APP_SECRET,
    request_token_params={'scope': FACEBOOK_APP_SCOPES},
    base_url=FACEBOOK_API_URL,
    request_token_url=None,
    access_token_url=FACEBOOK_ACCESS_TOKEN_URL,
    authorize_url=FACEBOOK_AUTHORIZE_URL,
)

class ThirdPartySignUpFacebook(Resource):
    def get(self):
        callback = url_for(
            'facebook_authorized',
            next=request.args.get('next') or request.referrer or None,
            _external=True, _scheme='https'
        )
        return facebook.authorize(callback=callback)

@app.route('/login/authorized/facebook')
@facebook.authorized_handler
def facebook_authorized(resp):
    if resp is None:
        return login(error='%s, error_description=%s' %(request.args['error_reason'], request.args['error_description']))
    if isinstance(resp, OAuthException):
        return login(error=resp.message)

    session['oauth_token'] = (resp['access_token'], '')
    access_token = session['oauth_token'][0]
    expires = resp.get('expires', None)
    (me, data) = (None, {})
    if access_token and expires:
        expires = datetime.utcnow() + timedelta(seconds=long(expires))
        try:
            me = facebook.get('/me')
        except:
            pass
    else:
        return login(error='Something went wrong - Could not fetch data from Facebook')
    if hasattr(me, 'data'):
        data = me.data
    if not data:
        return login(error='Something went wrong - Could not fetch data from Facebook')
    for k, v in dict(data).items():
        v = str(v).strip()
        if not v:
            data.pop(k)
    fb_id = data['id']
    oauth_object = FaceBookOAuth.objects(fb_id=fb_id)
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
        if db_field == 'last_name':
            for x in FIELDS_TO_FETCH[db_field]:
                try:
                    last_name += '%s ' %data[x]
                    user.last_name = last_name.strip()
                except:
                    pass
        elif db_field == 'location':
            for x in FIELDS_TO_FETCH[db_field]:
                try:
                    location = data[x]['name']
                    user.location = location
                except:
                    pass
        elif db_field == 'gender':
            genders = {v:k for k, v in GENDERS.items()}
            try:
                gender = genders[data[FIELDS_TO_FETCH[db_field]]]
                user.gender = gender
            except:
                pass
        elif db_field == 'dob':
            try:
                dob = data[FIELDS_TO_FETCH[db_field]]
                dob = dob.split('/')
                dob = '%s-%s-%s' %(dob[2], dob[0], dob[1])
                user.dob = dob
            except:
                pass
        elif db_field == 'picture':
            try:
                picture = requests.get('%s/%s/picture?type=large' %(FACEBOOK_API_URL, fb_id)).url
                user.picture = picture
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
        oauth_object = FaceBookOAuth()
    oauth_object.fb_id = fb_id
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

@facebook.tokengetter
def get_facebook_oauth_token():
    return session.get('oauth_token')