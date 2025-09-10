import base64
import hashlib
import os

def generate_random_base64_encoded_string(length=16):
    return base64.b64encode(os.urandom(length)).decode()

def generate_salt():
    return generate_random_base64_encoded_string(16)

def hash_password(password, salt):
    n = 1024
    r = 8
    p = 16
    # TODO: Maybe configure maxmem too. Could affect calculation times.
    return hashlib.scrypt(password.encode(), salt=salt.encode(), n=n, r=r, p=p)
