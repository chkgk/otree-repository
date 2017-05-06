#!/usr/bin/python3 

from flask import Flask, request
from flask_uploads import * 
import os
import json
import pyclamd
from zipfile import ZipFile

app = Flask(__name__)

app.config['UPLOADED_PACKAGES_DEST'] = 'packages'

packages = UploadSet('packages', ARCHIVES)
configure_uploads(app, packages)

PACKAGES_LIST_FILE = "packages.list"
MANIFEST_FILE_NAME = "package-manifest.json"

CLAMD_SOCKET = os.environ['CLAMDSOCKET']

if not os.path.isdir(app.config['UPLOADED_PACKAGES_DEST']):
	os.mkdir(app.config['UPLOADED_PACKAGES_DEST'])

if not os.path.isfile(PACKAGES_LIST_FILE):
	open(PACKAGES_LIST_FILE, 'a').close()


@app.route("/put", methods=['POST'])
def put():
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


@app.route("/get/<package_name>")
def get(package_name):
	package_list = _read_package_list()
	filename = _get_filename(package_name, package_list)
	path = app.config['UPLOADED_PACKAGES_DEST'] + "/" + filename
	if os.path.isfile(path):
		return send_from_directory(app.config['UPLOADED_PACKAGES_DEST'], filename)
	return "file not found\n", 404


@app.route("/list")
def list():
	package_list = _read_package_list()
	clean_list = []
	for package in package_list:
		p_object = {}
		for key in package.keys():
			if key != "filename":
				p_object[key] = package[key]
		clean_list.append(p_object)
	return json.dumps(clean_list)


@app.route("/detail/<package_name>")
def detail(package_name):
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