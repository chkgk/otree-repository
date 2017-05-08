#!/usr/bin/python3 

from flask import Flask

from flask_security import UserMixin, RoleMixin
from flask_security import Security, SQLAlchemyUserDatastore
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail
from flask_uploads import * 

import datetime, os

app = Flask(__name__)

PACKAGES_LIST_FILE = "packages.list"
MANIFEST_FILE_NAME = "package-manifest.json"
CLAMD_SOCKET = os.environ['CLAMDSOCKET']



app.config['UPLOADED_PACKAGES_DEST'] = os.environ["UPLOADED_PACKAGES_DEST"]
app.config['DEBUG'] = True

app.config['SECRET_KEY'] = 'super-secret'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ["DB_URI"]
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SECURITY_PASSWORD_HASH'] = 'bcrypt'
app.config['SECURITY_PASSWORD_SALT'] = 'super_secret_salt'
app.config['SECURITY_EMAIL_SENDER'] = 'no-reply-otree-repo@ckgk.de'
app.config['SECURITY_CONFIRMABLE'] = True
app.config['SECURITY_REGISTERABLE'] = True
app.config['SECURITY_RECOVERABLE'] = True
app.config['SECURITY_CHANGEABLE'] = True
app.config['SECURITY_TRACKABLE'] = True
app.config['SECURITY_POST_LOGOUT_VIEW'] = 'login'
app.config['SECURITY_POST_REGISTER_VIEW'] = 'list'
app.config['SECURITY_POST_CONFIRM_VIEW'] = 'list'


app.config['MAIL_SERVER'] = 'ckgk.de'
app.config['MAIL_PORT'] = 25
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USE_TSL'] = True
app.config['MAIL_USERNAME'] = 'no-reply-otree-repo@ckgk.de'
app.config['MAIL_PASSWORD'] = '7Wd-BvU-4cq-n8V'


if not os.path.isdir(app.config['UPLOADED_PACKAGES_DEST']):
	os.mkdir(app.config['UPLOADED_PACKAGES_DEST'])

if not os.path.isfile(PACKAGES_LIST_FILE):
	open(PACKAGES_LIST_FILE, 'a').close()


csrf = CSRFProtect(app)
mail = Mail(app)
db = SQLAlchemy(app)


packages = UploadSet('packages', ARCHIVES)
configure_uploads(app, packages)


# Models

roles_users = db.Table('roles_users',
		db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
		db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))


packages_versions = db.Table('packages_versions',
	db.Column('package_id', db.Integer(), db.ForeignKey('package.id')),
	db.Column('version_id', db.Integer(), db.ForeignKey('version.id')))


class Role(db.Model, RoleMixin):
	id = db.Column(db.Integer(), primary_key=True)
	name = db.Column(db.String(80), unique=True)
	description = db.Column(db.String(255))


class User(db.Model, UserMixin):
	id = db.Column(db.Integer(), primary_key=True)
	email = db.Column(db.String(255), unique=True)
	password = db.Column(db.String(255))
	name = db.Column(db.String(255))
	active = db.Column(db.Boolean())
	confirmed_at = db.Column(db.DateTime())
	last_login_at = db.Column(db.DateTime())
	current_login_at = db.Column(db.DateTime())
	last_login_ip = db.Column(db.String(46))
	current_login_ip = db.Column(db.String(46))
	login_count = db.Column(db.Integer())

	roles = db.relationship('Role', secondary=roles_users, 
		backref=db.backref('users', lazy='dynamic'))

	packages = db.relationship('Package',
		backref=db.backref('creator'))


class Version(db.Model):
	id = db.Column(db.Integer(), primary_key=True)
	version = db.Column(db.String(32))
	filename = db.Column(db.String(255), unique=True)
	created = db.Column(db.DateTime())
	package = db.relationship('Package', secondary=packages_versions)


	def __init__(self, version, filename):
		self.version = version
		self.filename = filename
		self.created = datetime.datetime.utcnow()

	def __repr__(self):
		return "<Package version %r, filename %r>" % (self.version, self.filename)


class Package(db.Model):
	id = db.Column(db.Integer(), primary_key=True)
	name = db.Column(db.String(255), unique=True)
	description = db.Column(db.Text)
	created = db.Column(db.DateTime())
	user_id = db.Column(db.Integer(), db.ForeignKey("user.id"))
	versions = db.relationship('Version', secondary=packages_versions, order_by=Version.version)

	def __init__(self, name, user_id, description=""):
		self.name = name
		self.description = description
		self.user_id = user_id
		self.created = datetime.datetime.utcnow()

	def __repr__(self):
		return "<Package %r by user id %r>" % (self.name, self.user_id)


user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

import otree_repository.views


if __name__ == "__main__":
	app.run()