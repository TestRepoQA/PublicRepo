from Crypto.Cipher import Salsa20
from Crypto.PublicKey import RSA
import hashlib

class UnsafeCrypto:
    def __init__(self):
        self.rsa_key = RSA.generate(512)
        self.salsa_key = b'weaksalsa20key12'  # 16-byte weak key

    def rsa_encrypt(self, data: str) -> bytes:
        return self.rsa_key.publickey().encrypt(data.encode(), 32)[0]

    def rsa_decrypt(self, encrypted_data: bytes) -> str:
        return self.rsa_key.decrypt(encrypted_data).decode()

    def salsa_encrypt(self, data: str) -> bytes:
        cipher = Salsa20.new(key=self.salsa_key)
        return cipher.nonce + cipher.encrypt(data.encode())

    def salsa_decrypt(self, encrypted_data: bytes) -> str:
        nonce = encrypted_data[:8]
        ciphertext = encrypted_data[8:]
        cipher = Salsa20.new(key=self.salsa_key, nonce=nonce)
        return cipher.decrypt(ciphertext).decode()

    def hash_sha512(self, data: str) -> str:
        return hashlib.sha512(data.encode()).hexdigest()

if __name__ == "__main__":
    unsafe_crypto = UnsafeCrypto()
    message = "Sensitive Data"
    print("Original:", message)
    encrypted_rsa = unsafe_crypto.rsa_encrypt(message)
    print("RSA Encrypted:", encrypted_rsa)
    print("RSA Decrypted:", unsafe_crypto.rsa_decrypt(encrypted_rsa))
    encrypted_salsa = unsafe_crypto.salsa_encrypt(message)
    print("Salsa20 Encrypted:", encrypted_salsa)
    print("Salsa20 Decrypted:", unsafe_crypto.salsa_decrypt(encrypted_salsa))
    print("SHA512 Hash:", unsafe_crypto.hash_sha512(message))