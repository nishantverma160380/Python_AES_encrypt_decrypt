import base64
import hashlib

from Crypto.Cipher import AES


class AESCipherWithInitializationVector:

    def __init__(self, key, initialization_vector):
        self.key = base64.b64decode(key)
        # self.initialization_vector = base64.b64decode(initialization_vector)
        self.initialization_vector = initialization_vector

    def encrypt(self, plain_text):
        plain_text = self._pad(plain_text)
        cipher = AES.new(self.key, AES.MODE_CBC, self.initialization_vector)
        return base64.b64encode(cipher.encrypt(plain_text))

    def decrypt(self, cipher_text):
        cipher_text = base64.b64decode(cipher_text)
        cipher = AES.new(self.key, AES.MODE_CBC, self.initialization_vector)
        return self._trim(cipher.decrypt(cipher_text))

    @staticmethod
    def _pad(s):
        return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

    # corresponds to Java impl of PKCS5Padding, although PKCS5Padding should pad to 8 bytes only
    # but it seems that we can get padding numbers > 8, so it is more like PKCS7Padding
    @staticmethod
    def _trim(plain_text):
        last_char = ord(plain_text[-1])
        return plain_text[:-last_char]
