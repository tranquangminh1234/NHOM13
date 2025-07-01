# relay_server.py
import socket
from datetime import datetime

HOST = '0.0.0.0'
PORT = 6017

def log(msg):
    print(f"[{datetime.now()}] {msg}")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind((HOST, PORT))
    server.listen()
    log("Relay server is listening...")

    conn1, addr1 = server.accept()
    log(f"Sender connected from {addr1}")

    conn2, addr2 = server.accept()
    log(f"Receiver connected from {addr2}")

    while True:
        data = conn1.recv(4096)
        if not data:
            break
        log("Forwarding data from Sender to Receiver...")
        conn2.sendall(data)
from datetime import datetime

def log_transaction(step):
    with open("log.txt", "a") as f:
        f.write(f"{datetime.now()} - {step}\n")
