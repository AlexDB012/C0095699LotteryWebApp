from cryptography.fernet import Fernet
from flask_login import current_user
from flask import request


# Function for encrypting data
def encrypt(data, key):
    return Fernet(key).encrypt(bytes(data, 'utf-8'))


# Function for decrypting data
def decrypt(data, key):
    return Fernet(key).decrypt(data).decode('utf-8')


def log_invalid_access_attempt():
    f = open("lottery.log", "a")

    if current_user.is_authenticated:
        f.write(
            "\nINVALID ACCESS ATTEMPT UserID: {userID} Email: {email} UserRole: {userRole} requestIP: {requestIP}".format(
                userID=current_user.id, email=current_user.email, userRole=current_user.role,
                requestIP=request.remote_addr))

    else:
        f.write(
            "\nINVALID ACCESS ATTEMPT UserID: INVALID Email: INVALID UserRole: ANONYMOUS requestIP: {requestIP}".format(
                requestIP=request.remote_addr))

    f.close()
