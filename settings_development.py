# Project settings
DEBUG = True
API_BASE_URL = ''

# Web App Settings
WEB_APP_REDIRECT_URL = ''
WEB_APP_SCOPES = 'profile'
WEB_APP_CLIENT_ID = ''
WEB_APP_CLIENT_SECRET = ''

# MongoDB Connection
MONGODB_DB = ''
MONGODB_USERNAME = ''
MONGODB_PASSWORD = ''
MONGODB_HOST = '127.0.0.1'
MONGODB_PORT = 27017

# Session Expire Time (in seconds)
TOKEN_EXPIRES_IN = 36000

# API setup version - API versioning should be handled in the web server dynamically
API_SETUP_VERSION = 'v1'

# SMTP Settings
MAIL_SERVER = 'localhost'
MAIL_PORT = 25
MAIL_USE_TLS = False
MAIL_USE_SSL = False
MAIL_DEBUG = DEBUG
MAIL_USERNAME = None
MAIL_PASSWORD = None
DEFAULT_MAIL_SENDER = None

# Facebook OAuth Settings
FACEBOOK_APP_ID = ''
FACEBOOK_APP_SECRET = ''
FACEBOOK_APP_SCOPES = 'email user_birthday'
FACEBOOK_API_URL = 'https://graph.facebook.com'
FACEBOOK_ACCESS_TOKEN_URL = '/oauth/access_token'
FACEBOOK_AUTHORIZE_URL = 'https://www.facebook.com/dialog/oauth'

# Google OAuth Settings
GOOGLE_APP_ID = ''
GOOGLE_APP_SECRET = ''
GOOGLE_APP_SCOPES = 'https://www.googleapis.com/auth/plus.me https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email'
GOOGLE_API_URL = 'https://www.googleapis.com/oauth2/v1/'
GOOGLE_PLUS_API_URL = 'https://www.googleapis.com/plus/v1/'
GOOGLE_ACCESS_TOKEN_URL = 'https://accounts.google.com/o/oauth2/token'
GOOGLE_AUTHORIZE_URL = 'https://accounts.google.com/o/oauth2/auth'

# Twitter OAuth Settings
TWITTER_APP_ID = ''
TWITTER_APP_SECRET = ''
TWITTER_API_URL = 'https://api.twitter.com/1.1/'
TWITTER_ACCESS_TOKEN_URL = 'https://api.twitter.com/oauth/access_token'
TWITTER_REQUEST_TOKEN_URL = 'https://api.twitter.com/oauth/request_token'
TWITTER_APP_ONLY_AUTHENTICATION = 'https://api.twitter.com/oauth2/token'
TWITTER_AUTHORIZE_URL = 'https://api.twitter.com/oauth/authorize'

# Instagram OAuth Settings
INSTAGRAM_APP_ID = ''
INSTAGRAM_APP_SECRET = ''
INSTAGRAM_APP_SCOPES = 'basic'
INSTAGRAM_API_URL = 'https://api.instagram.com/v1/'
INSTAGRAM_AUTHORIZE_URL = 'https://api.instagram.com/oauth/authorize'
INSTAGRAM_ACCESS_TOKEN_URL = 'https://api.instagram.com/oauth/access_token'