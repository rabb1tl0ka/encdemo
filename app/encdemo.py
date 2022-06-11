from pydoc import plainpager
import sys

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/

import argparse

def new_key(password, filepath):
    private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    )
    
    pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(password.encode('UTF-8'))
    )

    with open(filepath+'_pv.pem', "wb") as key_file:
        key_file.write(pem)
        key_file.close()

    with open(filepath+'_pub.pem', "wb") as pub_file:
        pubpem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pub_file.write(pubpem)
        pub_file.close()
    

def encrypt(password, pem_path, file_to_encrypt_path, file_encrypted_path):

    with open(pem_path, "rb") as key_file, open(file_to_encrypt_path, "rb") as file_to_encrypt:
        
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            password.encode('UTF-8')
        )

        ciphertext = public_key.encrypt(
            file_to_encrypt.read(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        with open(file_encrypted_path, "wb") as file_encrypted:
            file_encrypted.write(ciphertext)

def encrypt_msg(password, pem_path, msg):

    with open(pem_path, "rb") as key_file:
        
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            password.encode('UTF-8')
        )

        ciphertext = public_key.encrypt(
            msg.encode('UTF-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        print(ciphertext)

def decrypt(password, pem_path, file_to_decrypt_path, file_decrypted_path):
     with open(pem_path, "rb") as key_file, open(file_to_decrypt_path, "rb") as file_to_decrypt:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password.encode('UTF-8')
        )

        plaintext = private_key.decrypt(
            file_to_decrypt.read(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        with open(file_decrypted_path, "wb") as file_decrypted:
            file_decrypted.write(plaintext)

def decrypt_msg(password, pem_path, msg_to_decrypt):
    print(type(msg_to_decrypt))
    print(bytearray(msg_to_decrypt, encoding="UTF-8"))

    with open(pem_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password.encode('UTF-8')
        )

        plain_text = private_key.decrypt(
            bytearray(msg_to_decrypt, encoding="UTF-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        print(plain_text)

dispatch = {
    'new_key': new_key,     #new_key(password, filepath)
    'encrypt': encrypt,     #encrypt(pem_path, file_to_encrypt_path, file_encrypted_path)
    'decrypt': decrypt,
    'encrypt_msg': encrypt_msg,
    'decrypt_msg': decrypt_msg,
}

parser = argparse.ArgumentParser()
parser.add_argument('function')
parser.add_argument('arguments', nargs='*')
args = parser.parse_args()

dispatch[args.function](*args.arguments)

# python3 encdemo.py encrypt mypassword ./pvkey.pem ./somefile.txt ./secretfile.txt
# python3 encdemo.py decrypt mypassword ./pvkey.pem ./secretfile.txt ./secretreveal.txt
# python3 app/encdemo.py encrypt_msg mypassword ./app/pvkey_pub.pem '"a minha mensagem privada"'
