"""Deliberately vulnerable Python code for testing the scanner."""

import os
import pickle
import hashlib
import subprocess
import yaml

# SQL Injection
def get_user(username):
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")

def get_user_percent(username):
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % username)

# Command Injection
def run_command(user_input):
    os.system(f"ls {user_input}")

def run_subprocess(cmd):
    subprocess.call(cmd, shell=True)

# Code Injection
def process_data(data):
    result = eval(data)
    return result

# Insecure Deserialization
def load_data(raw_bytes):
    return pickle.loads(raw_bytes)

def load_yaml_unsafe(text):
    return yaml.load(text)

# Weak Cryptography
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def hash_sha1(data):
    return hashlib.sha1(data.encode()).hexdigest()

# Hardcoded Credentials
password = "SuperSecret123!"
API_KEY = "sk-1234567890abcdefghijklmnop"
SECRET_KEY = "django-insecure-abc123def456ghi789"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

# SSL Verification Disabled
import requests
response = requests.get("https://example.com", verify=False)

# Debug Mode
DEBUG = True

# Broad Exception
try:
    something()
except:
    pass

# Path Traversal
def read_file(filename):
    return open(f"/data/{filename}").read()

# Tempfile
import tempfile
tmp = tempfile.mktemp()

# Private Key
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy5ACAGHgq+
-----END RSA PRIVATE KEY-----"""
