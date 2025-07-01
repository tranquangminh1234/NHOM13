# sender.py
import socket, json, time, base64, hashlib
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from utils.key_utils import *

def encrypt_session_key(receiver_pub_key, session_key):
    cipher_rsa = PKCS1_OAEP.new(receiver_pub_key)
    return cipher_rsa.encrypt(session_key)

def sign_metadata(sender_private_key, metadata_str):
    h = SHA512.new(metadata_str.encode())
    return pkcs1_15.new(sender_private_key).sign(h)

HOST = 'localhost'
PORT = 6017

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # Handshake
    s.sendall(b"Hello!")
    time.sleep(0.5)

    # Load keys
    sender_priv = RSA.import_key(open("keys/sender_private.pem").read())
    receiver_pub = RSA.import_key(open("keys/receiver_public.pem").read())

    # Step 2: Auth & SessionKey exchange
    session_key = get_random_bytes(16)
    timestamp = str(time.time())
    transaction_id = "TX123456"
    metadata = f"report.txt|{timestamp}|{transaction_id}"
    signature = sign_metadata(sender_priv, metadata)
    enc_session_key = encrypt_session_key(receiver_pub, session_key)

    s.sendall(signature + enc_session_key)
    time.sleep(0.5)

    # Step 3: AES-GCM encrypt file
    with open("report.txt", "rb") as f:
        data = f.read()

    nonce = get_random_bytes(12)
    cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    # Compute hash
    hash_val = hashlib.sha512(nonce + ciphertext + tag).hexdigest()

    packet = {
        "nonce": base64.b64encode(nonce).decode(),
        "cipher": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode(),
        "hash": hash_val,
        "sig": base64.b64encode(signature).decode()
    }

    s.sendall(json.dumps(packet).encode())
    print("Sent encrypted data to relay server.")
