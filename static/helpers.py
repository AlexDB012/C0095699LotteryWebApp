import logging

from cryptography.fernet import Fernet
from flask_login import current_user
from flask import request, render_template, flash
from functools import wraps


# Function for encrypting data
def encrypt(data, key):
    return Fernet(key).encrypt(bytes(data, 'utf-8'))


# Function for decrypting data
def decrypt(data, key):
    return Fernet(key).decrypt(data).decode('utf-8')


# Function that logs an invalid access attempt
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


# Wrapper for adding the roles required by the user to access a page or function
def required_roles(*roles):
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if current_user.role not in roles:
                log_invalid_access_attempt()
                return render_template('errors/403.html')
            return f(*args, **kwargs)

        return wrapped

    return wrapper

def anonymous_user():
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user.is_anonymous:
                flash('You cannot access this page now you are logged in!')
                return render_template('users/account.html',
                                       acc_no=current_user.id,
                                       email=current_user.email,
                                       firstname=current_user.firstname,
                                       lastname=current_user.lastname,
                                       phone=current_user.phone)
            return f(*args, **kwargs)

        return wrapped

    return wrapper

