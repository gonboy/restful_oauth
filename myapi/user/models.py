import re
from connection import db
from datetime import datetime, date

# DO NOT change these dictionaries
THIRD_PARTY_DATA = {
                    1: 'email',
                    2: 'first_name',
                    3: 'last_name',
                    4: 'gender',
                    5: 'dob',
                    6: 'location',
                    7: 'picture',
                 }
GENDERS = {
           'm': 'male',
           'f': 'female',
           }

CONFIRM_FOR = {
               'email': 1,
               'forgot_password': 2,
              }

USERNAME_REGEX = re.compile('^[a-zA-Z0-9][a-zA-Z0-9_]*[a-zA-Z0-9]$')

class User(db.Document):
    username = db.StringField(max_length=50, required=False)
    password = db.StringField(max_length=150, required=False)
    first_name = db.StringField(max_length=50, required=False)
    last_name = db.StringField(max_length=50, required=False)
    email = db.EmailField(max_length=50, required=False)
    location = db.StringField(max_length=255, required=False)
    joined_at = db.DateTimeField(default=datetime.utcnow)
    is_active = db.BooleanField(default=False)
    is_admin = db.BooleanField(default=False)
    gender = db.StringField(max_length=1, required=False)
    dob = db.StringField(max_length=10, required=False)
    rating = db.IntField(required=False)
    picture = db.StringField(max_length=255, required=False)
    fields_updated = db.ListField(required=False)

    meta = {
        'indexes': [
                    {'fields': ['username'], 'unique': True, 'sparse': True, 'index_options': {'hashed': True}},
                    ],
            }

    @property
    def user_id(self):
        return self.id

    def get_gender(self):
        if self.gender:
            return GENDERS[self.gender]
        else:
            return None

    def get_dob(self):
        dob = None
        if self.dob:
            dob = dob.split('-')
            try:
                dob = date(int(dob[0]), int(dob[1]), int(dob[2]))
            except:
                dob = None
        return dob

    @staticmethod
    def validate_username(username):
        try:
            username = username.strip().lower()
        except:
            return "Invalid characters in username"
        if len(username) < 4:
            return "Username should be atleast 4 characters long"
        if len(username) > 15:
            return "Username could be atmost 15 characters long"
        if username.find('__') != -1 or not USERNAME_REGEX.match(username):
            return "Username not allowed"
        exists = User.objects(username__iexact=username)
        if exists:
            return "Username already taken"
        return None

class Confirm(db.Document):
    from myapi.user.models import User
    user = db.ReferenceField(User, required=True)
    code = db.StringField(max_length=50, required=True)
    confirmation_for = db.IntField(required=True)
    confirmation_value = db.StringField(max_length=100, required=True)
    created_at = db.DateTimeField(default=datetime.utcnow)

    def confirm_for(self):
        return CONFIRM_FOR[self.confirmation_for]

class GoogleOAuth(db.Document):
    from myapi.user.models import User
    google_id = db.StringField(max_length=50, primary_key=True)
    user = db.ReferenceField(User, required=True)
    access_token = db.StringField(max_length=255, required=True)
    created_at = db.DateTimeField()
    expires = db.DateTimeField()
    meta = {'collection': 'google_oauth'}

class FaceBookOAuth(db.Document):
    from myapi.user.models import User
    fb_id = db.StringField(max_length=50, primary_key=True)
    user = db.ReferenceField(User, required=True)
    access_token = db.StringField(max_length=255, required=True)
    created_at = db.DateTimeField()
    expires = db.DateTimeField()
    meta = {'collection': 'facebook_oauth'}

class TwitterOAuth(db.Document):
    from myapi.user.models import User
    twt_id = db.StringField(max_length=50, primary_key=True)
    user = db.ReferenceField(User, required=True)
    access_token = db.StringField(max_length=255, required=True)
    created_at = db.DateTimeField()
    expires = db.DateTimeField()
    meta = {'collection': 'twitter_oauth'}

class InstagramOAuth(db.Document):
    from myapi.user.models import User
    instagram_id = db.StringField(max_length=50, primary_key=True)
    user = db.ReferenceField(User, required=True)
    access_token = db.StringField(max_length=255, required=True)
    created_at = db.DateTimeField()
    expires = db.DateTimeField()
    meta = {'collection': 'instagram_oauth'}