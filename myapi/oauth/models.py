from connection import db
from myapi.user.models import User

class Client(db.Document):
    client_id = db.StringField(max_length=40, primary_key=True)
    client_secret = db.StringField(max_length=50, required=True)
    user = db.ReferenceField(User)
    # public or confidential
    is_confidential = db.BooleanField(default=True)
    _redirect_uris = db.ListField(required=False)
    _default_scopes = db.ListField(required=False)

    meta = {
        'indexes': [
                    {'fields': ['client_secret'], 'unique': True, 'index_options': {'hashed': True}}
                   ],
            }

    @property
    def client_type(self):
        if self.is_confidential:
            return 'confidential'
        return 'public'

    @property
    def redirect_uris(self):
        if self._redirect_uris:
            return self._redirect_uris
        return []

    @property
    def default_redirect_uri(self):
        if self.redirect_uris:
            return self.redirect_uris[0]
        else:
            return None

    @property
    def default_scopes(self):
        if self._default_scopes:
            return self._default_scopes
        return []

class Token(db.Document):
    user = db.ReferenceField(User)
    client = db.ReferenceField(Client)
    # currently only Bearer is supported
    token_type = db.StringField(max_length=25, default='Bearer')
    access_token = db.StringField(max_length=255, unique=True)
    refresh_token = db.StringField(max_length=255, required=False)
    expires = db.DateTimeField()
    _scopes = db.ListField(required=False)

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes
        return []

    @property
    def client_id(self):
        return str(self.client.id)

class Grant(db.Document):
    user = db.ReferenceField(User)
    client = db.ReferenceField(Client)
    code = db.StringField(max_length=50, required=True)
    redirect_uri = db.URLField(required=False)
    expires = db.DateTimeField()
    _scopes = db.ListField(required=False)

    meta = {
        'indexes': [
                    {'fields': ['code'], 'unique': True, 'index_options': {'hashed': True}}
                   ],
            }

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes
        return []