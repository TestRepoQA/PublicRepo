from Crypto.Cipher import Blowfish
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import hashlib

class WeakEncryption:
    def __init__(self):
        self.rsa_key = RSA.generate(512)
        self.blowfish_key = b'weakblowfishkey'  # 16-byte Blowfish key (weak)

    def rsa_encrypt(self, data: str) -> bytes:
        return self.rsa_key.publickey().encrypt(data.encode(), 32)[0]

    def rsa_decrypt(self, encrypted_data: bytes) -> str:
        return self.rsa_key.decrypt(encrypted_data).decode()

    def blowfish_encrypt(self, data: str) -> bytes:
        cipher = Blowfish.new(self.blowfish_key, Blowfish.MODE_ECB)
        return cipher.encrypt(pad(data.encode(), Blowfish.block_size))

    def blowfish_decrypt(self, encrypted_data: bytes) -> str:
        cipher = Blowfish.new(self.blowfish_key, Blowfish.MODE_ECB)
        return unpad(cipher.decrypt(encrypted_data), Blowfish.block_size).decode()

    def hash_sha1(self, data: str) -> str:
        return hashlib.sha1(data.encode()).hexdigest()

if __name__ == "__main__":
    weak_enc = WeakEncryption()
    message = "Sensitive Data"
    print("Original:", message)
    encrypted_rsa = weak_enc.rsa_encrypt(message)
    print("RSA Encrypted:", encrypted_rsa)
    print("RSA Decrypted:", weak_enc.rsa_decrypt(encrypted_rsa))
    encrypted_blowfish = weak_enc.blowfish_encrypt(message)
    print("Blowfish Encrypted:", encrypted_blowfish)
    print("Blowfish Decrypted:", weak_enc.blowfish_decrypt(encrypted_blowfish))
    print("SHA1 Hash:", weak_enc.hash_sha1(message))
