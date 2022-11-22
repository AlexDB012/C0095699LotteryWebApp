import logging

from cryptography.fernet import Fernet
from flask_login import current_user
from flask import request, render_template
from functools import wraps


# Function for encrypting data
def encrypt(data, key):
    return Fernet(key).encrypt(bytes(data, 'utf-8'))


# Function for decrypting data
def decrypt(data, key):
    return Fernet(key).decrypt(data).decode('utf-8')


def log_invalid_access_attempt():

    if current_user.is_authenticated:
        logging.warning('SECURITY - Invalid access attempt [%s, %s, %s, %s]',
                        current_user.id,
                        current_user.email,
                        current_user.role,
                        request.remote_addr
                    )

    else:
        logging.warning('SECURITY - Invalid access attempt [%s, %s, %s, %s]',
                        'Anonymous',
                        'Anonymous',
                        'Anonymous',
                        request.remote_addr
                    )


def required_roles(*roles):
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if current_user.role not in roles:
                log_invalid_access_attempt()
                return render_template('403.html')
            return f(*args, **kwargs)
        return wrapped
    return wrapper
