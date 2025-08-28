import os
import binascii

from base64 import urlsafe_b64encode, urlsafe_b64decode
from secrets import token_bytes
from hashlib import sha256
from time import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import InvalidToken
from aes256_cbc import AES256_CBC

CHUNK_SIZE = ((2 * 1024) * 1024) # 2 MiB chunks
MIN_LENGTH = (108 + 12 + 16 + 16) # 108 Salt Header + 12 b64 header + 16 b64 Nonce + 16 tag

class AES256_GCM:
    def __init__(self, key: bytes, salt: bytes):
        try:
            key = urlsafe_b64decode(key)
        except binascii.Error as exc:
            raise ValueError("Key must be 32 url-safe base64-encoded bytes.") from exc
        if len(key) != 32:
            raise ValueError("Key must be 32 url-safe base64-encoded bytes.")
        self.key = key[32:]
        self.salt = salt

    def encrypt(self, file: str):
        nonce = token_bytes(12)
        encryptor = Cipher(
            algorithms.AES256(self.key),
            modes.GCM(nonce)
        ).encryptor()

        dir_name = os.path.dirname(file) or "."
        fd, tmp_path = os.mkstemp(dir=dir_name)
        try:
            with open(file, "rb") as f_in, os.fdopen(fd, "wb") as f_out:
                salt_header = self.get_salt_header()
                f_out.write(salt_header)
                
                header = (AES256_GCM.get_file_header() + nonce)
                encryptor.authenticate_additional_data(header)
                f_out.write(urlsafe_b64encode(header))

                while chunk := f_in.read(CHUNK_SIZE):
                    f_out.write(encryptor.update(chunk))

                encryptor.finalize()
                f_out.write(encryptor.tag)

                f_out.flush()
                os.fsync(f_out.fileno())

            os.replace(tmp_path, file)

        except Exception:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
            raise

    def decrypt(self, file: str, ttl: int | None = None):
        dir_name = os.path.dirname(file) or "."
        fd, tmp_path = os.mkstemp(dir=dir_name)
        try:
            with open(file, "rb") as f_in, os.fdopen(fd, "wb") as f_out:
                #validate file size
                if os.path.getsize(file) <= MIN_LENGTH:
                    raise InvalidToken
                
                f_in.seek(-16, os.SEEK_END)
                ciphertext_end_byte = f_in.tell()
                tag = f_in.read(16)
                
                f_in.seek(108) # Start of header
                header = urlsafe_b64decode(f_in.read(12))
                if (ttl is not None) and (ttl > 0):
                    timestamp = int.from_bytes(header[4:9], byteorder="big")
                    AES256_CBC.check_time(ttl, timestamp)

                nonce = urlsafe_b64decode(f_in.read(16))

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
                os.fsync(f_out.fileno())

            # replace atomically
            os.replace(tmp_path, file)
        except Exception:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
            raise InvalidToken

    def get_salt_header(self) -> bytes:
        b64_salt = urlsafe_b64encode(self.salt)
        salt_hash = sha256(b64_salt).hexdigest().encode()
        b64_hash = urlsafe_b64encode(salt_hash)

        return (b64_hash[:86] + b64_salt[:22])

    @staticmethod
    def get_file_header() -> bytes:
        header = (
            + b'\x07\x03\x0d\x01' # GCM version 1
            + int(time()).to_bytes(length=5, byteorder="big")
        )
        return header
    
#     def decrypt_aaefsrgs(self, in_filename: str, out_filename: str, chunk_size=64*1024):
#         with open(in_filename, 'rb') as f_in:
#             salt = f_in.read(16)
#             iv = f_in.read(12)

#             '''
#             # Compute file size to locate tag at the end
#             fin.seek(0, os.SEEK_END)
#             file_size = fin.tell()
#             ciphertext_size = file_size - 16 - 12 - 16  # salt + nonce + tag
#             fin.seek(28)  # start of ciphertext
#             OR
#             ciphertext_len = os.path.getsize(in_filename) - 16 - 12 - 16  # exclude salt, IV, tag
#             '''
#                 ciphertext_size = file_size - 16 - 12 - 16  # salt + nonce + tag
#                 fin.seek(28)  # start of ciphertext
#                 OR
#                 ciphertext_len = os.path.getsize(in_filename) - 16 - 12 - 16  # exclude salt, IV, tag
#                 buffer = memoryview(ciphertext)
#                 for offset in range(0, len(ciphertext), CHUNK_SIZE):
#                     chunk = buffer[offset:offset + CHUNK_SIZE]
#                     f_out.write(decryptor.update(chunk))

#             tag_position = os.path.getsize(in_filename) - 16
#             ciphertext_size = tag_position - 12
#             f_in.seek(12)  # move to start of ciphertext

#             decryptor = Cipher(
#                 algorithms.AES(self.key),
#                 modes.GCM(iv)
#             ).decryptor()

#             with open(out_filename, 'wb') as f_out:
#                 total_read = 0
#                 while total_read < ciphertext_size:
#                     remaining = min(chunk_size, ciphertext_size - total_read)
#                     chunk = f_in.read(remaining)
#                     f_out.write(decryptor.update(chunk))
#                     total_read += len(chunk)

#                 # Read the tag
#                 f_in.seek(tag_position)
#                 tag = f_in.read(16)
#                 decryptor._ctx._set_tag(tag)  # set the GCM tag manually
#                 decryptor.finalize()

#                 # Read and set the tag for final verification
#                 tag = f_in.read(16)
#                 decryptor.mode._tag = tag
#                 decryptor.finalize()