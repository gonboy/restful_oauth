from flask import Flask
from flask.ext.restful import Api
from settings import API_SETUP_VERSION

app = Flask(__name__)

api = Api(app)

# oauth
from myapi.oauth.views import Authorize, AccessToken, DeAuthorize
from myapi.oauth.views import home
api.add_resource(Authorize, '/oauth/authorize', endpoint='authorize')
api.add_resource(AccessToken, '/oauth/access_token', endpoint='access_token')
api.add_resource(DeAuthorize, '/oauth/deauthorize', endpoint='deauthorize')
app.add_url_rule('/', view_func=home, methods=['GET', 'POST'])

# native sign up
from myapi.user.views import SignUp, SignUpThirdParty, UsernameAvailability
api.add_resource(SignUp, '/user/sign_up', endpoint='sign_up')
api.add_resource(SignUpThirdParty, '/user/sign_up/third_party', endpoint='sign_up_third_party')
api.add_resource(UsernameAvailability, '/user/sign_up/username_available', endpoint='username_available')

# third party sign ups
from myapi.user.facebook_sign_up import ThirdPartySignUpFacebook
from myapi.user.google_sign_up import ThirdPartySignUpGoogle
from myapi.user.twitter_sign_up import ThirdPartySignUpTwitter
from myapi.user.instagram_sign_up import ThirdPartySignUpInstagram
api.add_resource(ThirdPartySignUpFacebook, '/user/sign_up/facebook', endpoint='sign_up_facebook')
api.add_resource(ThirdPartySignUpGoogle, '/user/sign_up/google', endpoint='sign_up_google')
api.add_resource(ThirdPartySignUpTwitter, '/user/sign_up/twitter', endpoint='sign_up_twitter')
api.add_resource(ThirdPartySignUpInstagram, '/user/sign_up/instagram', endpoint='sign_up_instagram')

# sign in
from myapi.user.views import SignIn
api.add_resource(SignIn, '/user/sign_in', endpoint='sign_in')

# user - profile
from myapi.user.views import GetSetProfile, GetProfileOther
api.add_resource(GetSetProfile, '/%s/users' %API_SETUP_VERSION, endpoint='profile')
api.add_resource(GetProfileOther, '/%s/users/<string:username>' %API_SETUP_VERSION, endpoint='profile_other')