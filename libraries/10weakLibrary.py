from Crypto.Cipher import CAST
from Crypto.PublicKey import RSA
import hashlib

class WeakSecurityModule:
    def __init__(self):
        self.rsa_key = RSA.generate(512)
        self.cast_key = b'weakcastkey123456'  # 16-byte weak key

    def rsa_encrypt(self, data: str) -> bytes:
        return self.rsa_key.publickey().encrypt(data.encode(), 32)[0]

    def rsa_decrypt(self, encrypted_data: bytes) -> str:
        return self.rsa_key.decrypt(encrypted_data).decode()

    def cast_encrypt(self, data: str) -> bytes:
        cipher = CAST.new(self.cast_key, CAST.MODE_ECB)
        return cipher.encrypt(data.ljust(16).encode())

    def cast_decrypt(self, encrypted_data: bytes) -> str:
        cipher = CAST.new(self.cast_key, CAST.MODE_ECB)
        return cipher.decrypt(encrypted_data).decode().strip()

    def hash_ripemd160(self, data: str) -> str:
        return hashlib.new('ripemd160', data.encode()).hexdigest()

if __name__ == "__main__":
    weak_security = WeakSecurityModule()
    message = "Sensitive Data"
    print("Original:", message)
    encrypted_rsa = weak_security.rsa_encrypt(message)
    print("RSA Encrypted:", encrypted_rsa)
    print("RSA Decrypted:", weak_security.rsa_decrypt(encrypted_rsa))
    encrypted_cast = weak_security.cast_encrypt(message)
    print("CAST Encrypted:", encrypted_cast)
    print("CAST Decrypted:", weak_security.cast_decrypt(encrypted_cast))
    print("RIPEMD-160 Hash:", weak_security.hash_ripemd160(message))