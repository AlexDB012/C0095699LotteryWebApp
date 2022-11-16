from cryptography.fernet import Fernet


# Function for encrypting data
def encrypt(data, key):
    return Fernet(key).encrypt(bytes(data, 'utf-8'))


# Function for decrypting data
def decrypt(data, key):
    return Fernet(key).decrypt(data).decode('utf-8')
