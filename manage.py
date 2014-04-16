import os, sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from settings import DEBUG, MAIL_SERVER, MAIL_PORT, MAIL_USE_TLS, MAIL_USE_SSL, MAIL_DEBUG,\
                     MAIL_USERNAME, MAIL_PASSWORD, DEFAULT_MAIL_SENDER
from flask.ext.script import Manager, Server
from flask.ext.mail import Mail, Message
from flask import jsonify, make_response
from flask_oauthlib.provider import OAuth2Provider
from flask_oauthlib.client import OAuth
from urls import api, app

app.secret_key = ''

app.config.update({
    'OAUTH2_PROVIDER_ENFORCE_SSL': True,
    'OAUTH2_PROVIDER_KEY_LENGTH': (10, 100),
    'OAUTH2_PROVIDER_ERROR_URI': '/',
    'PREFERRED_URL_SCHEME': 'https',
})

oauth2 = OAuth2Provider(app)

oauth2_client = OAuth(app)

# SMTP Setup
mail = Mail(app)
app.config.update({
    'MAIL_SERVER': MAIL_SERVER,
    'MAIL_PORT': MAIL_PORT,
    'MAIL_USE_TLS': MAIL_USE_TLS,
    'MAIL_USE_SSL': MAIL_USE_SSL,
    'MAIL_DEBUG': MAIL_DEBUG,
    'MAIL_USERNAME': MAIL_USERNAME,
    'MAIL_PASSWORD': MAIL_PASSWORD,
    'DEFAULT_MAIL_SENDER': DEFAULT_MAIL_SENDER,
})
@app.errorhandler(404)
def page_not_found(e):
    return make_response(jsonify({'message': '%s - Invalid API Call!' %e}), 404)

project_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '.'))

if __name__ == "__main__":
    app.config['DEBUG'] = True
    app.run(
            host='0.0.0.0', port=80, threaded=True, \
            ssl_context = (project_path+'/conf/server.crt', project_path+'/conf/server.key'),
            use_reloader = True,
           )