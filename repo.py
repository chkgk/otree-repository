#!/usr/bin/python3 

from flask import Flask, request
from flask_uploads import * 
import os

app = Flask(__name__)

app.config['UPLOADED_PACKAGES_DEST'] = 'packages'

packages = UploadSet('packages', ARCHIVES)
configure_uploads(app, packages)


@app.route("/put", methods=['POST'])
def upload():
	if request.method == 'POST' and 'package' in request.files:
		try:
			filename = packages.save(request.files['package'])
			return filename

		except UploadNotAllowed:
			return "wrong filetype", 415


@app.route("/get/<filename>")
def get(filename):
	path = app.config['UPLOADED_PACKAGES_DEST'] + "/" + filename
	print(path)
	if os.path.isfile(path):
		return send_from_directory(app.config['UPLOADED_PACKAGES_DEST'], filename)
	return "file not found", 404


if __name__ == "__main__":
	app.run()