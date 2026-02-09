import os
import subprocess
import hashlib

# TRIAGE-001: Critical - eval and exec with user input
def run_user_code(user_input):
    eval(user_input)
    exec(user_input)
    os.system("ls " + user_input)
    subprocess.call("echo " + user_input, shell=True)

# TRIAGE-002: Missing input validation on external data
from flask import Flask, request
app = Flask(__name__)

@app.route("/search")
def search():
    query = request.args["query"]
    return query

@app.route("/submit", methods=["POST"])
def submit():
    data = request.get_json()
    return data

# TRIAGE-003: Deprecated and security TODOs
# TODO: security review needed for this function
# FIXME: security vulnerability in authentication
legacy_hash = hashlib.md5(b"data")

# TRIAGE-004: Security-relevant code area
from cryptography.fernet import Fernet
import jwt
import bcrypt
import passlib
