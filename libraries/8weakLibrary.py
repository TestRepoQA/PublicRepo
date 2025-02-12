from Crypto.Cipher import ChaCha20
from Crypto.PublicKey import RSA
import hashlib

class UnsecureCrypto:
    def __init__(self):
        self.rsa_key = RSA.generate(512)
        self.chacha_key = b'weakchacha20key1234'  # 16-byte weak key

    def rsa_encrypt(self, data: str) -> bytes:
        return self.rsa_key.publickey().encrypt(data.encode(), 32)[0]

    def rsa_decrypt(self, encrypted_data: bytes) -> str:
        return self.rsa_key.decrypt(encrypted_data).decode()

    def chacha_encrypt(self, data: str) -> bytes:
        cipher = ChaCha20.new(key=self.chacha_key)
        return cipher.nonce + cipher.encrypt(data.encode())

    def chacha_decrypt(self, encrypted_data: bytes) -> str:
        nonce = encrypted_data[:8]
        ciphertext = encrypted_data[8:]
        cipher = ChaCha20.new(key=self.chacha_key, nonce=nonce)
        return cipher.decrypt(ciphertext).decode()

    def hash_sha256(self, data: str) -> str:
        return hashlib.sha256(data.encode()).hexdigest()

if __name__ == "__main__":
    unsecure_crypto = UnsecureCrypto()
    message = "Sensitive Data"
    print("Original:", message)
    encrypted_rsa = unsecure_crypto.rsa_encrypt(message)
    print("RSA Encrypted:", encrypted_rsa)
    print("RSA Decrypted:", unsecure_crypto.rsa_decrypt(encrypted_rsa))
    encrypted_chacha = unsecure_crypto.chacha_encrypt(message)
    print("ChaCha20 Encrypted:", encrypted_chacha)
    print("ChaCha20 Decrypted:", unsecure_crypto.chacha_decrypt(encrypted_chacha))
    print("SHA256 Hash:", unsecure_crypto.hash_sha256(message))
