## Cryptography via Python with cryptography.io
Exploring asymmetric cryptography operations via cryptography.io

## Prerequisites
pip install cryptography (more info)[https://cryptography.io/en/latest/]

## How to run this
# Generate your private and public keys
python3 encdemo.py mypassword ./pvkey

# Encrypt and Decrypt Files
* python3 encdemo.py encrypt mypassword ./pvkey_pub.pem ./somefile.txt ./secretfile.txt
* python3 encdemo.py decrypt mypassword ./pvkey_pv.pem ./secretfile.txt ./secretreveal.txt
