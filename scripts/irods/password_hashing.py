import hashlib
import os

def generate_salt():
    return os.urandom(16)

def hash_password(password, salt=None):
    if salt is None:
        salt = generate_salt()
    n = 1024
    r = 8
    p = 16
    return hashlib.scrypt(bytes(password), bytes(salt), n, r, p), salt
