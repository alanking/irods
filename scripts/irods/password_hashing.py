import base64
import hashlib
import os

def generate_random_base64_encoded_string(length=16):
    return base64.b64encode(os.urandom(length)).decode()

def generate_salt():
    return generate_random_base64_encoded_string(16)

def generate_session_token():
    return generate_random_base64_encoded_string(32)

def hash_password(password, salt):
    n = 1024
    r = 8
    p = 16
    return hashlib.scrypt(password.encode(), salt=salt.encode(), n=n, r=r, p=p)

def hash_session_token(session_token, salt):
    # TODO: Replace this with a faster hashing algorithm.
    return hash_password(session_token, salt)
