#!/usr/bin/python3 

from flask import Flask, request, url_for, render_template
from flask_uploads import * 

from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, \
	UserMixin, RoleMixin, login_required, user_registered, login_user, auth_token_required

from flask_security.confirmable import requires_confirmation
from flask_security.utils import verify_and_update_password
from flask_security.views import _render_json

from flask_security.forms import LoginForm

from flask_mail import Mail

from flask_wtf.csrf import CSRFProtect
from werkzeug.datastructures import MultiDict

import os
import json
import pyclamd
from zipfile import ZipFile

import datetime


PACKAGES_LIST_FILE = "packages.list"
MANIFEST_FILE_NAME = "package-manifest.json"
CLAMD_SOCKET = os.environ['CLAMDSOCKET']


app = Flask(__name__)
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

csrf = CSRFProtect(app)
mail = Mail(app)
db = SQLAlchemy(app)


packages = UploadSet('packages', ARCHIVES)
configure_uploads(app, packages)



if not os.path.isdir(app.config['UPLOADED_PACKAGES_DEST']):
	os.mkdir(app.config['UPLOADED_PACKAGES_DEST'])

if not os.path.isfile(PACKAGES_LIST_FILE):
	open(PACKAGES_LIST_FILE, 'a').close()


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


class Package(db.Model):
	id = db.Column(db.Integer(), primary_key=True)
	name = db.Column(db.String(255), unique=True)
	description = db.Column(db.Text)
	created = db.Column(db.DateTime())
	user_id = db.Column(db.Integer(), db.ForeignKey("user.id"))

	def __init__(self, name, description, user_id):
		self.name = name
		self.description = description
		self.user_id = user_id
		self.created = datetime.datetime.utcnow()

	def __repr__(self):
		return "<Package %r by user id %r>" % (self.name, self.user_id)


class Version(db.Model):
	id = db.Column(db.Integer(), primary_key=True)
	version = db.Column(db.String(32))
	filename = db.Column(db.String(255), unique=True)
	created = db.Column(db.DateTime())

	def __init__(self, version, filename):
		self.version = version
		self.filename = filename
		self.created = datetime.datetime.utcnow()

	def __repr__(self):
		return "<Package version %r, filename %r>" % (self.version, self.filename)


user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)


@user_registered.connect_via(app)
def on_registration(sender, user, confirm_token):
	default_role = user_datastore.find_role('user')
	user_datastore.add_role_to_user(user, default_role)
	db.session.commit()



# create user to test with
@app.before_first_request
def create_user():
	db.create_all()
	user_datastore.find_or_create_role(name='admin', description='Administrator')
	user_datastore.find_or_create_role(name='user', description='User')
	db.session.commit()


# views

@app.route("/api/login", methods=["POST"])
@csrf.exempt
def api_login():
	if request.method == "POST":
		form_class = security.login_form
		form = form_class(MultiDict(request.json))
		user = user_datastore.get_user(form.email.data)
		if _is_valid_user(user, form.password.data):
			login_user(user)
			form.user = user
			return _render_json(form, include_auth_token=True)
	return "bad request\n", 400


def _is_valid_user(user, password):
	if user is None:
		print("a")
		return False
	if not user.password:
		print("b")
		return False
	if not verify_and_update_password(password, user):
		print("c")
		return False
	if requires_confirmation(user):
		print("d")
		return False
	if not user.is_active:
		print("e")
		return False
	return True



@app.route("/")
def index():
	return "all good", 200


@app.route("/api/put", methods=['POST'])
@auth_token_required
def put():
	# needs to be re-written for th packages database. currently works with files.
	cd = pyclamd.ClamdUnixSocket(CLAMD_SOCKET)

	if request.method == 'POST' and 'package' in request.files:
		try:
			filename = packages.save(request.files['package'])
			if cd.scan_file(os.getcwd()+ "/" + app.config['UPLOADED_PACKAGES_DEST'] + "/" + filename) != None:
				os.remove(os.getcwd()+ "/" + app.config['UPLOADED_PACKAGES_DEST'] + "/" + filename)
				return "virus detected, file rejected\n", 400

		except UploadNotAllowed:
			return "wrong filetype\n", 415

		manifest = _read_manifest(app.config['UPLOADED_PACKAGES_DEST'] + "/" + filename)
		package_list = _read_package_list()
		new_package_list = _add_or_update(package_list, manifest, filename)
		_write_package_list(new_package_list)

		return "all good\n", 200
	return "bad request\n", 400


@app.route("/api/get/<package_name>")
def get(package_name):
	# needs to be re-written for th packages database. currently works with files.
	package_list = _read_package_list()
	filename = _get_filename(package_name, package_list)
	path = app.config['UPLOADED_PACKAGES_DEST'] + "/" + filename
	if os.path.isfile(path):
		return send_from_directory(app.config['UPLOADED_PACKAGES_DEST'], filename)
	return "file not found\n", 404


@app.route("/api/list")
def api_list():
	# needs to be re-written for th packages database. currently works with files.
	package_list = _read_package_list()
	clean_list = []
	for package in package_list:
		p_object = {}
		for key in package.keys():
			if key != "filename":
				p_object[key] = package[key]
		clean_list.append(p_object)
	return json.dumps(clean_list)


@app.route("/api/detail/<package_name>")
def detail(package_name):
	# needs to be re-written for th packages database. currently works with files.
	package_list = _read_package_list()
	pos = _get_package_pos(package_name, package_list)
	if pos == -1:
		return "not found\n", 404
	else:
		detail_object = {}
		for key in package_list[pos].keys():
			if key != "filename":
				detail_object[key] = package_list[pos][key]
		return json.dumps(detail_object)


def _get_package_pos(package_name, package_list):
	package_names = [package["package-name"] for package in package_list]
	if not package_name in package_names:
		pos = -1
	else:
		pos = next(index for (index, d) in enumerate(package_list) if d["package-name"] == package_name)
	return pos


def _get_filename(package_name, package_list):
	pos = _get_package_pos(package_name, package_list)
	if pos != -1:
		return package_list[pos]["filename"]
	else:
		raise FileNotFoundError(package_name)


def _write_package_list(packages_list):
	return json.dump(packages_list, open(PACKAGES_LIST_FILE, 'w'))


def _read_package_list():
	# probably not necessary anymore after switch to database
	try:
		package_list = json.load(open('packages.list', 'r'))
	except ValueError:
		package_list = []
	return package_list


def _read_manifest(zip_filepath):
	if not os.path.isfile(zip_filepath):
		raise FileNotFoundError(zip_filepath)

	with ZipFile(zip_filepath, 'r') as zip_file:
		return json.loads(zip_file.read(MANIFEST_FILE_NAME).decode())


def _add_or_update(package_list, manifest, filename):
	# needs to be updated for the database
	pos = _get_package_pos(manifest["package-name"], package_list)
	package_object = {
				"package-name": manifest["package-name"],
				"package-author": manifest["package-author"],
				"created": manifest["created"],
				"filename": filename
			}

	if pos == -1:
		package_list.append(package_object)
	else:
		package_list[pos] = package_object

	return package_list


if __name__ == "__main__":
	app.run()