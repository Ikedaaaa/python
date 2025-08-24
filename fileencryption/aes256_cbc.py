import base64
import binascii

from secrets import token_bytes
from time import time

from cryptography import utils
from cryptography.fernet import InvalidToken, _MAX_CLOCK_SKEW
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class AES256:
    def __init__(self, key: bytes):
        try:
            key = base64.urlsafe_b64decode(key)
        except binascii.Error as exc:
            raise ValueError("Key must be 64 url-safe base64-encoded bytes.") from exc
        if len(key) != 64:
            raise ValueError("Key must be 64 url-safe base64-encoded bytes.")
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

        token = (
            b'\x03\x02\x03'
            + int(time()).to_bytes(length=6, byteorder="big")
            + iv
            + ciphertext
        )

        h = hmac.HMAC(self.signing_key, hashes.SHA256())
        h.update(token)
        tag = h.finalize()

        return base64.urlsafe_b64encode(token + tag)
    
    def decrypt(self, token: bytes, ttl: int | None = None) -> bytes:
        timestamp, decoded = AES256.get_token_data(token)
        iv = decoded[9:25]
        ciphertext = decoded[25:-32]

        self.check_signature(decoded)

        if (ttl is not None) and (ttl > 0):
            AES256.check_time(ttl, timestamp)

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
        if not isinstance(token, (str, bytes)):
            raise TypeError("token must be bytes or str")
        
        try:
            data = base64.urlsafe_b64decode(token)
        except (TypeError, binascii.Error):
            raise InvalidToken
        
        if not data or ((data[0] != 0x03) or (data[1] != 0x02) or (data[2] != 0x03)):
            raise InvalidToken
        
        if len(data) < 9:
            raise InvalidToken
        
        timestamp = int.from_bytes(data[3:9], byteorder="big")
        return timestamp, data
    
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
