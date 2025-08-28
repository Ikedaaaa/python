import binascii

#from base64 import urlsafe_b64encode, urlsafe_b64decode
from secrets import token_bytes
from time import time

from cryptography import utils
from cryptography.fernet import InvalidToken, _MAX_CLOCK_SKEW
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class AES256_CBC:
    def __init__(self, p_key: bytes):
        try:
            key = p_key
        except binascii.Error as exc:
            raise ValueError("Key must be 64 bytes.") from exc
        if len(key) != 64:
            raise ValueError("Key must be 64 bytes.")
        self.signing_key = key[:32]
        self.encryption_key = key[32:]

    def encrypt(self, plaintext: bytes) -> bytes:
        utils._check_bytes("data", plaintext)

        padder = padding.PKCS7(algorithms.AES256.block_size).padder()
        padded = padder.update(plaintext) + padder.finalize()

        iv = token_bytes(16)
        encryptor = Cipher(
            algorithms.AES256(self.encryption_key),
            modes.CBC(iv)
        ).encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        header = (
            b'\x03\x02\x03\x01' # CBC version 1
            + int(time()).to_bytes(length=5, byteorder="big")
        )
        token = (iv + ciphertext)

        h = hmac.HMAC(self.signing_key, hashes.SHA256())
        h.update(header + token)
        tag = h.finalize()

        return (header + token + tag)
    
    def decrypt(self, token: bytes, ttl: int | None = None) -> bytes:
        timestamp, decoded = AES256_CBC.get_token_data(token)
        iv = decoded[9:25]
        ciphertext = decoded[25:-32]

        self.check_signature(decoded)

        if (ttl is not None) and (ttl > 0):
            AES256_CBC.check_time(ttl, timestamp)

        decryptor = Cipher(
            algorithms.AES256(self.encryption_key),
            modes.CBC(iv)
        ).decryptor()

        padded_plaintext = decryptor.update(ciphertext)
        try:
            padded_plaintext += decryptor.finalize()
        except ValueError:
            raise InvalidToken
        
        unpadder = padding.PKCS7(algorithms.AES256.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext)
        try:
            plaintext += unpadder.finalize()
        except ValueError:
            raise InvalidToken
        
        return plaintext

    @staticmethod
    def get_token_data(token: bytes | str) -> tuple[int, bytes]:
        MIN_LEN = 9 + 16 + 32  # header (9) + IV (16) + HMAC (32)
        if not isinstance(token, (str, bytes)):
            raise TypeError("token must be bytes or str")
        
        if len(token) < 12:
            raise InvalidToken
        
        try:
            header_decoded = urlsafe_b64decode(token[:12])
            data = urlsafe_b64decode(token[12:])
        except (TypeError, binascii.Error):
            raise InvalidToken
        
        if (len(header_decoded) + len(data)) < MIN_LEN:
            raise InvalidToken

        if not header_decoded or ((header_decoded[0] != 0x03) or (header_decoded[1] != 0x02) or (header_decoded[2] != 0x03)):
            raise InvalidToken
        
        timestamp = int.from_bytes(header_decoded[4:9], byteorder="big")
        return timestamp, (header_decoded + data)
    
    def check_signature(self, data: bytes) -> None:
        h = hmac.HMAC(self.signing_key, hashes.SHA256())
        h.update(data[:-32])
        try:
            h.verify(data[-32:])
        except InvalidSignature:
            raise InvalidToken
        
    @staticmethod
    def check_time(ttl, timestamp):
        current_time = int(time())

        if timestamp + ttl < current_time:
            raise InvalidToken

        if current_time + _MAX_CLOCK_SKEW < timestamp:
            raise InvalidToken
