from myapi.oauth.models import Client
from myapi.user.models import User, Confirm

def create_users():
    from werkzeug import generate_password_hash
    User.objects().delete()
    user = User(username='test', password=generate_password_hash('123456'), email='test@foo.com')
    user.save()

def create_client():
    from werkzeug.security import gen_salt
    Client.objects().delete()
    user = User.objects(username='test')[0]
    client = Client(_default_scopes=['profile'], client_id=gen_salt(40), 
                    client_secret=gen_salt(50), user=user, _redirect_uris=['https://foo.com/', 'https://www.foo.com/'])
    client.save()