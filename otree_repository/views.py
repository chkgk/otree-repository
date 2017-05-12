from otree_repository import app, csrf, db, user_datastore, packages, security
from otree_repository.models import * 
from otree_repository.exceptions import *

import os
import json
import pyclamd
from zipfile import ZipFile

from flask_security import login_required, user_registered, login_user, auth_token_required, roles_required
from flask_uploads import send_from_directory

from flask_security.confirmable import requires_confirmation
from flask_security.utils import verify_and_update_password, encrypt_password
from flask_security.views import _render_json
from flask_security.forms import LoginForm
from flask_wtf.csrf import CSRFProtect
from werkzeug.datastructures import MultiDict

from flask import request, url_for, render_template, jsonify


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
	if not User.query.first():
		user_datastore.create_user(email='koenig.kersting@gmail.com', password=encrypt_password('asdasd'))
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


@app.route("/")
def index():
	return "all good", 200


@app.route("/put", methods=['POST'])
@auth_token_required
@csrf.exempt
def put():
	# needs to be re-written for th packages database. currently works with files.
	cd = pyclamd.ClamdUnixSocket(app.config['CLAMD_SOCKET'])

	if request.method == 'POST' and 'package' in request.files:
		try:
			filename = packages.save(request.files['package'])
			if cd.scan_file(app.config['UPLOADED_PACKAGES_DEST'] + "/" + filename) != None:
				_remove_file(filename)
				raise InvalidUsage("virus detected, package rejected", 400)

		except UploadNotAllowed:
			raise InvalidUsage("filetype not allowed", 400)

		manifest = _read_manifest(app.config['UPLOADED_PACKAGES_DEST'] + "/" + filename)
		
		# check if author id is valid
		if not _is_valid_author(manifest["package-author"]):
			_remove_file(filename)
			raise InvalidUsage("invalid author", 400)

		# let's check if a package exists:
		package = Package.query.filter_by(name=manifest["package-name"]).first()
		if package is None:
			#create package
			package = Package(manifest["package-name"], manifest["package-author"], manifest["package-description"])
			db.session.add(package)
			db.session.commit()

		# check if author matches package author
		# later we can do this based on auth_token
		if not package.user_id == int(manifest["package-author"]):
			_remove_file(filename)
			raise InvalidUsage("not your package", 400)

		# check if version exists
		if _version_exists(package, manifest["package-version"]):
			_remove_file(filename)
			raise InvalidUsage("version already exists", 400)

		#update description
		package.description = manifest["package-description"]

		# add version
		version = Version(manifest["package-version"], filename)
		package.versions.append(version)

		# store
		db.session.add(package)
		db.session.commit()
		return jsonify({ 'status_code': 200, 'message': 'put completed'})

	raise InvalidUsage("bad request", 404)


@app.route("/api/get/<package_name>")
@app.route("/api/get/<package_name>/<version>")
def get(package_name, version=""):
	
	package = Package.query.filter_by(name=package_name).first()
	if package is None:
		raise InvalidUsage("package not found", 404)

	version_obj = None

	if version == "":
		version_obj = package.versions[-1]
	else:
		for item in package.versions:
			if item.version == version:
				version_obj = item
				break

	if version_obj is None:
		raise InvalidUsage("version not found", 404)

	if os.path.isfile(app.config['UPLOADED_PACKAGES_DEST'] + "/" + version_obj.filename):
		return send_from_directory(app.config['UPLOADED_PACKAGES_DEST'], version_obj.filename)

	raise InvalidUsage('file not found', 404)


@app.route("/api/info/<package_name>")
def detail(package_name):
	package = Package.query.filter_by(name=package_name).first()
	if package is None:
		raise InvalidUsage("package not found", 404)

	versions = []
	for version in package.versions:
		versions.append({
			"version": version.version,
			"created": version.created 
		})

	package_info = {
		"name": package.name,
		"description": package.description,
		"creator": package.creator.name,
		"created": package.created,
		"versions": versions
	}

	return jsonify(package_info)


@app.route("/api/list")
@auth_token_required
@roles_required('admin')
def api_list():

	return_items = [
		{ "name": package.name, "description": package.description }
		for package in Package.query.all()
	]
		
	return jsonify(return_items)

@app.route("/unauthorized")
def unauthorized():
	return jsonify({"status_code": 403, "message": "not authorized"})


def _read_manifest(zip_filepath):
	if not os.path.isfile(zip_filepath):
		raise InvalidUsage("file not found", 404)

	with ZipFile(zip_filepath, 'r') as zip_file:
		return json.loads(zip_file.read(app.config['MANIFEST_FILE_NAME']).decode())


def _is_valid_author(uid):
	user = User.query.filter_by(id=uid).first()
	return user is not None


def _version_exists(package, version):
	for item in package.versions:
		if item.version == version:
			return True
	return False


def _remove_file(filename):
	os.remove(os.getcwd()+ "/" + app.config['UPLOADED_PACKAGES_DEST'] + "/" + filename)


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