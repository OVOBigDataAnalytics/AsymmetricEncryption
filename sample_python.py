# python -m pip install cryptography
# python -m pip install pycryptodome
import os
import Crypto
import cryptography
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64



## https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/
## https://medium.com/@ashiqgiga07/asymmetric-cryptography-with-python-5eed86772731


def generate_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return public_key, private_key

def store_private_key(private_key):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption() 
        )

    with open('{}/cryptography/private_key.pem'.format(os.getcwd()), 'wb') as f:
            f.write(pem)

def store_public_key(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('{}/cryptography/public_key.pem'.format(os.getcwd()), 'wb') as f:
        f.write(pem)


def read_private_key():
    with open('{}/cryptography/private_key.pem'.format(os.getcwd()), "rb") as key_file:
        private_key = RSA.import_key(key_file.read())

    return private_key


def read_public_key():
    with open('{}/cryptography/public_key.pem'.format(os.getcwd()), "rb") as key_file:
        public_key = RSA.import_key(key_file.read())
    return public_key


def encrypt_message(public_key):
    # sample data ( Body request in JSON format ) that need to encrypt....
    data = { "phone": "081286414806", 
            "nik": "3276021405850010", 
            "match": { "kelurahan": "tugu",
                         "provinsi": "jawa tengah", 
                         "kecamatan": "cimanggis",
                         "kota": "Jakarta",
                         "tanggal_lahir": "19910420",
                         "jenis_kelamin": "laki-laki",
                         "nama": "aruna",
                         "status_perkawinan": "belum kawin"}
                         }

    cipher = PKCS1_OAEP.new(key=public_key, hashAlgo=Crypto.Hash.SHA256)
    encrypted = cipher.encrypt(json.dumps(data).encode('utf-8'))


    return encrypted


def decrypt_message(encrypted_text, private_key):
    decrypt = PKCS1_OAEP.new(key=private_key, hashAlgo=Crypto.Hash.SHA256)
    original_message = decrypt.decrypt(encrypted_text)

    return original_message



if __name__ == "__main__":
    # public_key, private_key = generate_key()
    # store_private_key(private_key)
    # store_public_key(public_key)

    private_key = read_private_key()
    public_key = read_public_key()

    
    encrypted_text = encrypt_message(public_key)
    base64_bytes = base64.b64encode(encrypted_text)
    base64_message = base64_bytes.decode('utf-8')
    print("encrypted_text")
    print(base64_message)

    # sample response message that retrieved from Acura api Response
    message = "PyKD98LcRQE0ejN0qgHoZ8uQMvheAKD0UHNCoYqHlm0B8CmazVgna2HJPObzrxAQ9cnatwV0rozrpbYxik8EP7NC4hBjQ6CY0HIxmEizoqTU07osq4obQVNixh+a94HAFpn32V5JbU0rCvrm0QiOsjs5p6A4gjzEqU8RAkdutOrvLbXJ7q0Mmn0dTwSBJ6Uaj+EI6pBcVECYEGEbjPoAb9tyItD2OkvicEmdtREhvHI38XqLgpzH9BJaofkZPVJJaL1cC2VH6Elw9baJjpLDc94FPP6JKc6lgcXRZjYZCIHi3ZSRrMKz/RXMgNWeqlZ36s60XlUshCcdIAJVMGldGk/i8jk7KX4zPx+2ab9m435zYAo0Ne5GJHmr/qDEFpIhd2YHeNre57qZLPN+wVZ7H0Vd7H29pB09z20rqXMe+p1lh96XVxypPZbG8/Wq5FLXiTGihAXdMSkXE1YpYl948eDqkuHMYM8xeeL8HjINNn9FliGSSYgdXEiSNbo03g7IpNODZQHKjBlRIlq2JKcPziEljPjSzZDVX/FSlW8XiDg7o1HJaww+PnQVCgTKW8DS39//eB95ezeUyXZyDvgHlu8+OeqUcI4vd5BMD2QMI5UI623iTr/F6t333xr0+SUkwX/TnrmpjauW1/ULumKVdGafnOCc5d2hypyq042G+Vg="

    base64_bytes = message.encode('utf-8')
    message_bytes = base64.b64decode(base64_bytes)
    original_message = decrypt_message(message_bytes, private_key)
    print("original_text")
    print(original_message.decode('utf-8'))










    
