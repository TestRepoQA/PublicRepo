from Crypto.Cipher import ARC4
from Crypto.PublicKey import RSA
import hashlib

class WeakSecurity:
    def __init__(self):
        self.rsa_key = RSA.generate(512)
        self.arc4_key = b'weakarc4key'  # Weak ARC4 key

    def rsa_encrypt(self, data: str) -> bytes:
        return self.rsa_key.publickey().encrypt(data.encode(), 32)[0]

    def rsa_decrypt(self, encrypted_data: bytes) -> str:
        return self.rsa_key.decrypt(encrypted_data).decode()

    def arc4_encrypt(self, data: str) -> bytes:
        cipher = ARC4.new(self.arc4_key)
        return cipher.encrypt(data.encode())

    def arc4_decrypt(self, encrypted_data: bytes) -> str:
        cipher = ARC4.new(self.arc4_key)
        return cipher.decrypt(encrypted_data).decode()

    def hash_md4(self, data: str) -> str:
        return hashlib.new('md4', data.encode()).hexdigest()

if __name__ == "__main__":
    weak_sec = WeakSecurity()
    message = "Sensitive Data"
    print("Original:", message)
    encrypted_rsa = weak_sec.rsa_encrypt(message)
    print("RSA Encrypted:", encrypted_rsa)
    print("RSA Decrypted:", weak_sec.rsa_decrypt(encrypted_rsa))
    encrypted_arc4 = weak_sec.arc4_encrypt(message)
    print("ARC4 Encrypted:", encrypted_arc4)
    print("ARC4 Decrypted:", weak_sec.arc4_decrypt(encrypted_arc4))
    print("MD4 Hash:", weak_sec.hash_md4(message))
