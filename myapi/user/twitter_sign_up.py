from datetime import datetime, timedelta

from settings import TWITTER_APP_ID, TWITTER_APP_SECRET, TWITTER_REQUEST_TOKEN_URL, \
                     TWITTER_API_URL, TWITTER_ACCESS_TOKEN_URL, TWITTER_AUTHORIZE_URL
from manage import oauth2_client, app
from models import User, TwitterOAuth, THIRD_PARTY_DATA
from myapi.oauth.views import authenticate_web_user

from flask import url_for, session, request
from flask.ext.restful import Resource
from flask_oauthlib.client import OAuthException

FIELDS_TO_FETCH = {
                   'first_name':    'name',
                   'last_name':     'name',
                   'location':      'location',
                   'picture':       'profile_image_url',
                  }

twitter = oauth2_client.remote_app(
    'twitter',
    consumer_key=TWITTER_APP_ID,
    consumer_secret=TWITTER_APP_SECRET,
    base_url=TWITTER_API_URL,
    request_token_url=TWITTER_REQUEST_TOKEN_URL,
    access_token_url=TWITTER_ACCESS_TOKEN_URL,
    authorize_url=TWITTER_AUTHORIZE_URL,
)

class ThirdPartySignUpTwitter(Resource):
    def get(self):
        callback = url_for(
            'twitter_authorized',
            next=request.args.get('next') or request.referrer or None,
            _external=True, _scheme='https'
        )
        return twitter.authorize(callback=callback)

@app.route('/login/authorized/twitter')
@twitter.authorized_handler
def twitter_authorized(resp):
    error = 'Something went wrong - Could not fetch data from Twitter'
    if resp is None:
        return authenticate_web_user(error='%s, error_description=%s' %(request.args['error_reason'], request.args['error_description']))
    if isinstance(resp, OAuthException):
        return authenticate_web_user(error=resp.message)
    (access_token, me, data) = (None, None, None)
    session['twitter_oauth'] = resp
    try:
        access_token = resp['oauth_token']
        expires = datetime.utcnow() + timedelta(days=90)
    except:
        pass
    if access_token:
        twt_id = resp['user_id']
        screen_name = resp['screen_name']
        try:
            me = twitter.get('users/show.json?screen_name=%s' %screen_name)
        except:
            pass
        try:
            error = me.data['error']['message']
        except:
            pass
    else:
        return authenticate_web_user(error=error)
    if hasattr(me, 'data'):
        data = me.data
    if not data:
        return authenticate_web_user(error=error)
    for k, v in dict(data).items():
        v = str(v).strip()
        if not v:
            data.pop(k)
    oauth_object = TwitterOAuth.objects(twt_id=twt_id)
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
        oauth_object = TwitterOAuth()
    oauth_object.twt_id = twt_id
    oauth_object.user = user
    oauth_object.access_token = access_token
    oauth_object.expires = expires
    oauth_object.created_at = datetime.utcnow()
    oauth_object.save()
    registered = False
    if user.password:
        registered = True
    return authenticate_web_user(user=user, registered=registered)

@twitter.tokengetter
def get_twitter_token():
    if 'twitter_oauth' in session:
        resp = session['twitter_oauth']
        return resp['oauth_token'], resp['oauth_token_secret']
    else:
        return None, None