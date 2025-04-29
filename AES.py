from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def pad(data):
    return data + (16 - len(data) % 16) * chr(16 - len(data) % 16)

def unpad(data):
    return data[:-data[-1]]  # Fixed unpadding function

def encrypt_AES(plain_text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted_text = cipher.encrypt(pad(plain_text).encode())
    return base64.b64encode(iv + encrypted_text).decode()

def decrypt_AES(encrypted_text, key):
    encrypted_data = base64.b64decode(encrypted_text)
    iv = encrypted_data[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_text = unpad(cipher.decrypt(encrypted_data[16:])).decode()
    return decrypted_text

# Example Usage
key = get_random_bytes(16)  # 128-bit key
plain_text = "Network Security Assignment"
encrypted_text = encrypt_AES(plain_text, key)
decrypted_text = decrypt_AES(encrypted_text, key)

print(f"Original Text: {plain_text}")
print(f"Encrypted Text: {encrypted_text}")
print(f"Decrypted Text: {decrypted_text}")
