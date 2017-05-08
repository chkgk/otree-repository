#!/usr/bin/python3 

from flask import Flask

from flask_security import UserMixin, RoleMixin
from flask_security import Security, SQLAlchemyUserDatastore
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail
from flask_uploads import * 

import datetime, os

import otree_repository.default_config as config


app = Flask(__name__)
app.config.from_object(config)


if not os.path.isdir(app.config['UPLOADED_PACKAGES_DEST']):
	os.mkdir(app.config['UPLOADED_PACKAGES_DEST'])


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