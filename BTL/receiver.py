# receiver.py
import socket, json, base64, hashlib
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512

HOST = '192.168.169.147'
PORT = 6017

def verify_signature(public_key, metadata_str, signature):
    h = SHA512.new(metadata_str.encode())
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # Wait for handshake
    s.recv(1024)  # "Hello!"
    s.sendall(b"Ready!")

    # Load keys
    receiver_priv = RSA.import_key(open("btl/keys/receiver_private.pem").read())
    sender_pub = RSA.import_key(open("btl/keys/sender_public.pem").read())

    # Receive signature + enc_session_key
    incoming = s.recv(512)
    signature = incoming[:128]
    enc_session_key = incoming[128:]

    cipher_rsa = PKCS1_OAEP.new(receiver_priv)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Receive encrypted message
    data = json.loads(s.recv(4096).decode())

    nonce = base64.b64decode(data["nonce"])
    ciphertext = base64.b64decode(data["cipher"])
    tag = base64.b64decode(data["tag"])
    received_hash = data["hash"]
    sig = base64.b64decode(data["sig"])

    # Check hash
    computed_hash = hashlib.sha512(nonce + ciphertext + tag).hexdigest()
    if received_hash != computed_hash:
        s.sendall(b"NACK: Hash mismatch")
    else:
        # Decrypt AES-GCM
        try:
            cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)

            with open("received_report.txt", "wb") as f:
                f.write(plaintext)

            print("Report saved. Integrity OK.")
            s.sendall(b"ACK")
        except Exception as e:
            s.sendall(b"NACK: AES tag failed")
            print("Integrity failed:", str(e))
