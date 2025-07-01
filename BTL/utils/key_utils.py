# utils/key_utils.py
from Crypto.PublicKey import RSA

def generate_keys(filename_prefix):
    key = RSA.generate(1024)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(f"keys/{filename_prefix}_private.pem", "wb") as f:
        f.write(private_key)
    with open(f"keys/{filename_prefix}_public.pem", "wb") as f:
        f.write(public_key)

# Chạy đoạn sau 1 lần để tạo khóa:
if __name__ == "__main__":
    generate_keys("sender")
    generate_keys("receiver")
