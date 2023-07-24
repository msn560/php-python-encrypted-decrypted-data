import base64
import hashlib
from Crypto.Cipher import AES
import json


def pad(data):
    block_size = AES.block_size
    padding = block_size - len(data) % block_size
    return data + bytes([padding] * padding)


def encrypt(data, passphrase):
    secret_key = hashlib.sha256(passphrase.encode()).digest()
    iv = AES.new(secret_key, AES.MODE_CBC).iv
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    data = data.encode('utf-8')
    padded_data = pad(data)   
    encrypted_data = cipher.encrypt(padded_data)
    iv_64 = base64.b64encode(iv).decode()
    encrypted_64 = base64.b64encode(encrypted_data).decode()
    json_data = {"iv": iv_64, "data": encrypted_64}
    return base64.b64encode(json.dumps(json_data).encode()).decode()


def decrypt(encrypted_data, passphrase):
    secret_key = hashlib.sha256(passphrase.encode()).digest()
    json_data = json.loads(base64.b64decode(encrypted_data))
    iv = base64.b64decode(json_data['iv'])
    encrypted_data = base64.b64decode(json_data['data'])
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_data) 
    decrypted_data = decrypted_data[:-decrypted_data[-1]]
    return decrypted_data.decode('utf-8')
