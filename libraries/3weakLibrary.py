from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import hashlib

class InsecureCrypto:
    def __init__(self):
        self.rsa_key = RSA.generate(512)
        self.des_key = b'weakkey8'  # 8-byte DES key (weak and outdated)

    def rsa_encrypt(self, data: str) -> bytes:
        return self.rsa_key.publickey().encrypt(data.encode(), 32)[0]

    def rsa_decrypt(self, encrypted_data: bytes) -> str:
        return self.rsa_key.decrypt(encrypted_data).decode()

    def des_encrypt(self, data: str) -> bytes:
        cipher = DES.new(self.des_key, DES.MODE_ECB)
        return cipher.encrypt(pad(data.encode(), DES.block_size))

    def des_decrypt(self, encrypted_data: bytes) -> str:
        cipher = DES.new(self.des_key, DES.MODE_ECB)
        return unpad(cipher.decrypt(encrypted_data), DES.block_size).decode()

    def hash_sha1(self, data: str) -> str:
        return hashlib.sha1(data.encode()).hexdigest()

if __name__ == "__main__":
    insecure_crypto = InsecureCrypto()
    message = "Sensitive Data"
    print("Original:", message)
    encrypted_rsa = insecure_crypto.rsa_encrypt(message)
    print("RSA Encrypted:", encrypted_rsa)
    print("RSA Decrypted:", insecure_crypto.rsa_decrypt(encrypted_rsa))
    encrypted_des = insecure_crypto.des_encrypt(message)
    print("DES Encrypted:", encrypted_des)
    print("DES Decrypted:", insecure_crypto.des_decrypt(encrypted_des))
    print("SHA1 Hash:", insecure_crypto.hash_sha1(message))
