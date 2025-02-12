from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import hashlib

class WeakCrypto:
    def __init__(self):
        self.rsa_key = RSA.generate(512)
        self.aes_key = b'weak16byteskey!!'

    def rsa_encrypt(self, data: str) -> bytes:
        return self.rsa_key.publickey().encrypt(data.encode(), 32)[0]

    def rsa_decrypt(self, encrypted_data: bytes) -> str:
        return self.rsa_key.decrypt(encrypted_data).decode()

    def aes_encrypt(self, data: str) -> bytes:
        cipher = AES.new(self.aes_key, AES.MODE_ECB)
        return cipher.encrypt(pad(data.encode(), AES.block_size))

    def aes_decrypt(self, encrypted_data: bytes) -> str:
        cipher = AES.new(self.aes_key, AES.MODE_ECB)
        return unpad(cipher.decrypt(encrypted_data), AES.block_size).decode()

    def hash_md5(self, data: str) -> str:
        return hashlib.md5(data.encode()).hexdigest()

if __name__ == "__main__":
    weak_crypto = WeakCrypto()
    message = "Sensitive Data"
    print("Original:", message)
    encrypted_rsa = weak_crypto.rsa_encrypt(message)
    print("RSA Encrypted:", encrypted_rsa)
    print("RSA Decrypted:", weak_crypto.rsa_decrypt(encrypted_rsa))
    encrypted_aes = weak_crypto.aes_encrypt(message)
    print("AES Encrypted:", encrypted_aes)
    print("AES Decrypted:", weak_crypto.aes_decrypt(encrypted_aes))
    print("MD5 Hash:", weak_crypto.hash_md5(message))
