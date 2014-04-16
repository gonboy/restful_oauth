from datetime import date

from settings import API_BASE_URL
from models import User, Confirm, CONFIRM_FOR, THIRD_PARTY_DATA
from manage import oauth2, mail
from myapi.oauth.views import authenticate_web_user

from flask.ext.restful import Resource, reqparse, fields, marshal
from flask.ext.mail import Mail, Message
from mongoengine.fields import EmailField
from werkzeug.security import gen_salt
from werkzeug import generate_password_hash, check_password_hash

def send_verification_email(user, confirm):
    msg = Message("MyAPI - Verify your email!",
                  sender="welcome@myapi.com",
                  recipients=[confirm.confirmation_value])
    msg.body = "Please confirm your email. Follow the link -</br>"
    msg.html = API_BASE_URL + 'sign_up/confirm_email/?code=%s' %confirm.code
    mail.send(msg)

class GetSetProfile(Resource):
    decorators = [oauth2.require_oauth("profile")]

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        request_type = reqparse.request.method
        if request_type == 'GET':
            self.reqparse.add_argument('field', type=str, required=True, location='args', action='append')
        if request_type == 'PUT':
            self.reqparse.add_argument('fields', type=dict, required=True, location='json')
        super(GetSetProfile, self).__init__()

    def get(self, request):
        user = request.user
        args = self.reqparse.parse_args()
        fields = args['field']
        allowed_fields = {
                          'username': user.username, 'first_name': user.first_name, \
                          'last_name': user.last_name, 'email': user.email, 'location': user.location, \
                          'gender': user.gender, 'dob': user.dob, 'rating': user.rating, \
                          'picture': user.picture, 'user_id': str(user.id),
                         }
        return_json = {}
        for field in fields:
            field = field.strip().lower()
            try:
                return_json[field] = allowed_fields[field]
            except:
                pass
        if not return_json:
            return {'message': 'Please select valid allowed fields'}, 404
        return return_json

    def put(self, request):
        args = self.reqparse.parse_args()
        user = request.user
        db_fields = {
                     'username': fields.String,
                     'first_name': fields.String,
                     'last_name': fields.String,
                     'location': fields.String,
                     'gender': fields.String,
                     'dob': fields.String,
                     'picture': fields.String,
                    }
        try:
            db_fields = marshal(args['fields'], db_fields)
        except:
            return {'message': 'Please send the json in correct format'}, 404
        result = {}
        for k, v in dict(db_fields).items():
            k = k.lower().strip()
            if v is not None:
                if k == 'username':
                    error = User.validate_username(v)
                    if error:
                        result[k] = error
                        continue
                elif k == 'gender':
                    if v.lower().strip() not in ['m', 'f']:
                        result[k] = 'invalid'
                        continue
                elif k == 'dob':
                    try:
                        x = v.strip().split('-')
                        v = '-'.join(x)
                        date(int(x[0]), int(x[1]), int(x[2]))
                    except:
                        result[k] = 'invalid'
                        continue
                try:
                    setattr(user, k, v)
                    result[k] = 'success'
                except:
                    setattr(user, k, 'invalid')
        if result:
            fields_updated = list(user.fields_updated)
            third_party_data = {v: k for k, v in THIRD_PARTY_DATA.items()}
            for key in result:
                try:
                    fields_updated.append(third_party_data[key])
                except:
                    pass
            fields_updated = list(set(fields_updated))
            user.fields_updated = fields_updated
            user.save()
            return result
        else:
            return {'message': 'nothing to save'}, 404

class GetProfileOther(Resource):
    decorators = [oauth2.require_oauth("profile", "surrogate-authenticated")]

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('field', type=str, required=True, location='args', action='append')
        super(GetProfileOther, self).__init__()

    def get(self, request, username):
        try:
            user = User.objects(username=username.strip())[0]
        except:
            return {'message': 'User does not exist!'}, 404
        args = self.reqparse.parse_args()
        fields = args['field']
        allowed_fields = {
                          'username': user.username, 'first_name': user.first_name, \
                          'last_name': user.last_name, 'location': user.location, \
                          'gender': user.gender, 'dob': user.dob, 'rating': user.rating, \
                          'picture': user.picture
                         }
        return_json = {}
        for field in fields:
            field = field.strip().lower()
            try:
                return_json[field] = allowed_fields[field]
            except:
                pass
        if not return_json:
            return {'message': 'Please select valid allowed fields'}, 404
        return return_json

class SignUp(Resource):
    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('username', type=str, required=True)
        self.reqparse.add_argument('email', type=str, required=True)
        self.reqparse.add_argument('password', type=str, required=True)
        self.reqparse.add_argument('gender', type=str, required=True)
        self.reqparse.add_argument('first_name', type=str, required=False)
        self.reqparse.add_argument('last_name', type=str, required=False)
        self.reqparse.add_argument('location', type=str, required=False)
        self.reqparse.add_argument('dob', type=str, required=False)
        super(SignUp, self).__init__()

    def get(self):
        args = self.reqparse.parse_args()
        email = args['email']
        try:
            email = email.strip().lower()
        except:
            return {'message': 'Invalid email address'}, 400
        if not EmailField.EMAIL_REGEX.match(email):
            return {'message': 'Invalid email address'}, 400
        password = ''.encode("utf-8")
        password += args['password']
        if len(password) < 6:
            return {'message': 'Password should be atleast 6 characters long'}, 400
        if len(password) > 150:
            return {'message': 'Password too long - keep it below 150 characters'}, 400
        password = generate_password_hash(password)
        gender = args['gender'].lower().strip()
        if gender not in ['m', 'f']:
            return {'message': 'Invalid value for gender selected'}, 400
        check = args.get('first_name', None)
        first_name = None
        if check:
            first_name = ''.encode('utf-8')
            first_name += check
            first_name = first_name.strip()
            if not first_name:
                first_name = None
        check = args.get('last_name', None)
        last_name = None
        if check:
            last_name = ''.encode('utf-8')
            last_name += check
            last_name = last_name.strip()
            if not last_name:
                last_name = None
        check = args.get('location', None)
        location = None
        if check:
            location = ''.encode('utf-8')
            location += check
            location = location.strip()
            if not location:
                location = None
        dob = args.get('dob', None)
        if dob:
            dob = dob.strip()
            if not dob:
                dob = None
            else:
                check = dob.split('-')
                try:
                    check = date(int(dob[0]), int(dob[1]), int(dob[2]))
                except:
                    return {'message': 'Invalid date format'}, 400
        check = Confirm.objects(confirmation_value=email)
        if check:
            return {'message': "You have already registered with this email address and haven't confirmed it yet"}, 400
        username = args['username']
        error = User.validate_username(username)
        if error:
            return {'message': error}, 400
        user = User(username=username, password=password, gender=gender)
        if first_name:
            user.first_name = first_name
        if last_name:
            user.last_name = last_name
        if location:
            user.location = location
        if dob:
            user.dob = dob
        user.save()
        email_confirm = Confirm(user=user, code=gen_salt(50), confirmation_for=CONFIRM_FOR['email'], \
                                confirmation_value=email)
        email_confirm.save()
        #send_verification_email(user, email_confirm)
        return {'status': 'success'}

    def post(self):
        return self.get(request)

class SignUpThirdParty(Resource):
    decorators = [oauth2.require_oauth("profile")]

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('username', type=str, required=True)
        self.reqparse.add_argument('password', type=str, required=True)
        super(SignUpThirdParty, self).__init__()

    def get(self, request):
        args = self.reqparse.parse_args()
        user = request.user
        if user.password:
            return {'message': 'User already registered!'}, 403
        password = ''.encode("utf-8")
        password += args['password']
        if len(password) < 6:
            return {'message': 'Password should be atleast 6 characters long'}, 400
        if len(password) > 150:
            return {'message': 'Password too long - keep it below 150 characters'}, 400
        username = args['username']
        error = User.validate_username(username)
        if error:
            return {'message': error}, 400
        password = generate_password_hash(password)
        user.username = username
        user.password = password
        try:
            user.save()
        except:
            return {'message': 'Something went wrong - Please try again later!'}, 500
        return {'user_id': str(user.id)}

    def post(self, request):
        return self.get(request)

class UsernameAvailability(Resource):
    decorators = [oauth2.require_oauth("profile")]

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('username', type=str, required=True)
        super(UsernameAvailability, self).__init__()

    def get(self, request):
        args = self.reqparse.parse_args()
        username = args['username']
        error = User.validate_username(username)
        if error:
            return {'message': error}, 400
        return {'status': 'available'}

class SignIn(Resource):

    def __init__(self):
        self.reqparse = reqparse.RequestParser()
        self.reqparse.add_argument('username', type=str, required=True)
        self.reqparse.add_argument('password', type=str, required=True)
        super(SignIn, self).__init__()

    def get(self):
        args = self.reqparse.parse_args()
        password = ''.encode("utf-8")
        password += args['password']
        username = args['username'].strip()
        if not username:
            return {'message': 'Username missing!'}, 403
        if not password:
            return {'message': 'Password missing!'}, 403
        user = User.objects(username=username)
        if not user:
            return {'message': 'Invalid username or password'}, 403
        user = user[0]
        stored_password = user.password
        check = check_password_hash(stored_password, password)
        if check:
            return authenticate_web_user(user=user, sign_in=True)
        else:
            return {'message': 'Invalid username or password'}, 403

    def post(self):
        return self.get()