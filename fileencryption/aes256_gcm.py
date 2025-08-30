import binascii

from os import fdopen, fsync, replace, remove, SEEK_END
from os.path import dirname, getsize
from tempfile import mkstemp
from base64 import urlsafe_b64encode, urlsafe_b64decode
from secrets import token_bytes
from hashlib import sha256
from time import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import InvalidToken
from aes256_cbc import AES256_CBC

CHUNK_SIZE = ((2 * 1024) * 1024) # 2 MiB chunks
MIN_LENGTH = (48 + 9 + 12 + 16) # 48 Salt Header + 9 header + 12 Nonce + 16 tag

class AES256_GCM:
    def __init__(self, p_key: bytes, salt: bytes | None = None):
        try:
            key = p_key
        except binascii.Error as exc:
            raise ValueError("Key must be 64 bytes.") from exc
        if len(key) != 64:
            raise ValueError("Key must be 64 bytes.")
        self.key = key[32:]
        self.salt = salt

    def encrypt(self, file: str):
        print("Using GCM")
        nonce = token_bytes(12)
        encryptor = Cipher(
            algorithms.AES256(self.key),
            modes.GCM(nonce)
        ).encryptor()

        dir_name = dirname(file) or "."
        fd, tmp_path = mkstemp(dir=dir_name)
        try:
            with open(file, "rb") as f_in, fdopen(fd, "wb") as f_out:
                salt_header = self.get_salt_header()
                f_out.write(salt_header)
                
                header = (AES256_GCM.get_file_header() + nonce)
                encryptor.authenticate_additional_data(header)
                f_out.write(header)

                while chunk := f_in.read(CHUNK_SIZE):
                    f_out.write(encryptor.update(chunk))

                encryptor.finalize()
                f_out.write(encryptor.tag)

                f_out.flush()
                fsync(f_out.fileno())

            replace(tmp_path, file)

        except Exception:
            try:
                remove(tmp_path)
            except OSError:
                pass
            raise

    def decrypt(self, file: str, ttl: int | None = None):
        print("Using GCM")
        dir_name = dirname(file) or "."
        fd, tmp_path = mkstemp(dir=dir_name)
        try:
            with open(file, "rb") as f_in, fdopen(fd, "wb") as f_out:
                #validate file size
                if getsize(file) <= MIN_LENGTH:
                    raise InvalidToken
                
                f_in.seek(-16, SEEK_END)
                ciphertext_end_byte = f_in.tell()
                tag = f_in.read(16)
                
                f_in.seek(48) # Start of header
                header = f_in.read(9)
                if (ttl is not None) and (ttl > 0):
                    timestamp = int.from_bytes(header[4:9], byteorder="big")
                    AES256_CBC.check_time(ttl, timestamp)

                nonce = f_in.read(12)

                decryptor = Cipher(
                    algorithms.AES256(self.key),
                    modes.GCM(nonce, tag)
                ).decryptor()

                decryptor.authenticate_additional_data(header + nonce)

                total_read = f_in.tell()
                while total_read < ciphertext_end_byte:
                    bytes_to_read = min(CHUNK_SIZE, ciphertext_end_byte - total_read)
                    chunk = f_in.read(bytes_to_read)
                    f_out.write(decryptor.update(chunk))
                    total_read += len(chunk)

                decryptor.finalize()

                f_out.flush()
                fsync(f_out.fileno())

            # replace atomically
            replace(tmp_path, file)
        except Exception:
            try:
                remove(tmp_path)
            except OSError:
                pass
            raise InvalidToken

    def get_salt_header(self) -> bytes:
        salt_hash = sha256(self.salt).digest()
        return (salt_hash + self.salt)

    @staticmethod
    def get_file_header() -> bytes:
        header = (
            b'\x07\x03\x0d\x01' # GCM version 1
            + int(time()).to_bytes(length=5, byteorder="big")
        )
        return header
    