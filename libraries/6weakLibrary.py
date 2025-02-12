from Crypto.Cipher import XOR
from Crypto.PublicKey import RSA
import hashlib

class VeryWeakCrypto:
    def __init__(self):
        self.rsa_key = RSA.generate(512)
        self.xor_key = b'weakxor'  # Weak XOR key

    def rsa_encrypt(self, data: str) -> bytes:
        return self.rsa_key.publickey().encrypt(data.encode(), 32)[0]

    def rsa_decrypt(self, encrypted_data: bytes) -> str:
        return self.rsa_key.decrypt(encrypted_data).decode()

    def xor_encrypt(self, data: str) -> bytes:
        cipher = XOR.new(self.xor_key)
        return cipher.encrypt(data.encode())

    def xor_decrypt(self, encrypted_data: bytes) -> str:
        cipher = XOR.new(self.xor_key)
        return cipher.decrypt(encrypted_data).decode()

    def hash_crc32(self, data: str) -> str:
        return str(hashlib.crc32(data.encode()))

if __name__ == "__main__":
    weak_crypto = VeryWeakCrypto()
    message = "Sensitive Data"
    print("Original:", message)
    encrypted_rsa = weak_crypto.rsa_encrypt(message)
    print("RSA Encrypted:", encrypted_rsa)
    print("RSA Decrypted:", weak_crypto.rsa_decrypt(encrypted_rsa))
    encrypted_xor = weak_crypto.xor_encrypt(message)
    print("XOR Encrypted:", encrypted_xor)
    print("XOR Decrypted:", weak_crypto.xor_decrypt(encrypted_xor))
    print("CRC32 Hash:", weak_crypto.hash_crc32(message))
