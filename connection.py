from flask import Flask
from flask.ext.mongoengine import MongoEngine
from settings import MONGODB_DB, MONGODB_USERNAME, MONGODB_PASSWORD, MONGODB_HOST, MONGODB_PORT

app = Flask(__name__)
app.config["MONGODB_SETTINGS"] = {"DB": MONGODB_DB, "USERNAME": MONGODB_USERNAME,
                                  "PASSWORD": MONGODB_PASSWORD, "HOST": MONGODB_HOST,
                                  "PORT": MONGODB_PORT}
db = MongoEngine(app)