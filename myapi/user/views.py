from datetime import date

from settings import API_BASE_URL
from models import User, Confirm, CONFIRM_FOR
from manage import oauth2, mail

from flask.ext.restful import Resource, reqparse
from flask.ext.mail import Mail, Message
from mongoengine.fields import EmailField
from werkzeug.security import gen_salt
from werkzeug import generate_password_hash

def send_verification_email(user, confirm):
    msg = Message("MyAPI - Verify your email!",
                  sender="welcome@my.api.com",
                  recipients=[confirm.confirmation_value])
    msg.body = "Please confirm your email. Follow the link -</br>"
    msg.html = API_BASE_URL + 'confirm_email/?code=%s' %confirm.code
    mail.send(msg)

class UserProfile(Resource):
    decorators = [oauth2.require_oauth("normal-user")]

    def get(self, request):
        user = User.objects(id=request.user.id)[0]
        data = {}
        for key, value in user.__dict__['_data'].items():
            if value:
                data[key] = str(value)
        return data

    def post(self, request):
        return self.get(request)

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
        check = User.objects(email=email)
        if check:
            return {'message': "An account is already associated with this email address"}, 400
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
        send_verification_email(user, email_confirm)
        return {'status': 'success'}

    def post(self):
        return self.get(request)

class SignUpThirdParty(Resource):
    decorators = [oauth2.require_oauth("normal-user")]

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
    decorators = [oauth2.require_oauth("normal-user")]

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

    def post(self, request):
        return self.get(request)