from Crypto.Cipher import DES3
from Crypto.PublicKey import RSA
import hashlib

class InsecureEncryption:
    def __init__(self):
        self.rsa_key = RSA.generate(512)
        self.des3_key = b'weakdes3keyweakdes3key'  # 24-byte weak Triple DES key

    def rsa_encrypt(self, data: str) -> bytes:
        return self.rsa_key.publickey().encrypt(data.encode(), 32)[0]

    def rsa_decrypt(self, encrypted_data: bytes) -> str:
        return self.rsa_key.decrypt(encrypted_data).decode()

    def des3_encrypt(self, data: str) -> bytes:
        cipher = DES3.new(self.des3_key, DES3.MODE_ECB)
        return cipher.encrypt(data.ljust(24).encode())

    def des3_decrypt(self, encrypted_data: bytes) -> str:
        cipher = DES3.new(self.des3_key, DES3.MODE_ECB)
        return cipher.decrypt(encrypted_data).decode().strip()

    def hash_sha224(self, data: str) -> str:
        return hashlib.sha224(data.encode()).hexdigest()

if __name__ == "__main__":
    insecure_crypto = InsecureEncryption()
    message = "Sensitive Data"
    print("Original:", message)
    encrypted_rsa = insecure_crypto.rsa_encrypt(message)
    print("RSA Encrypted:", encrypted_rsa)
    print("RSA Decrypted:", insecure_crypto.rsa_decrypt(encrypted_rsa))
    encrypted_des3 = insecure_crypto.des3_encrypt(message)
    print("DES3 Encrypted:", encrypted_des3)
    print("DES3 Decrypted:", insecure_crypto.des3_decrypt(encrypted_des3))
    print("SHA224 Hash:", insecure_crypto.hash_sha224(message))
