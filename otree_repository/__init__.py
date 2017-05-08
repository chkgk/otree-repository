#!/usr/bin/python3 

from flask import Flask

from flask_sqlalchemy import SQLAlchemy

from flask_security import Security, SQLAlchemyUserDatastore
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail
from flask_uploads import * 

import datetime, os

app = Flask(__name__)
app.config.from_envvar('OTREE_REPOSITORY_SETTINGS')

csrf = CSRFProtect(app)
mail = Mail(app)
db = SQLAlchemy(app)
packages = UploadSet('packages', ARCHIVES)
configure_uploads(app, packages)


if not os.path.isdir(app.config['UPLOADED_PACKAGES_DEST']):
	os.mkdir(app.config['UPLOADED_PACKAGES_DEST'])

from otree_repository.models import *

user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

import otree_repository.views

if __name__ == "__main__":
	app.run()