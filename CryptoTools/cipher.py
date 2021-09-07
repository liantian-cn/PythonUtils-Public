# !/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import string
import random
import pathlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

SALT_LENGTH = 8
SALT_CHARS = string.ascii_letters + string.digits

# from Crypto.Random import get_random_bytes
# get_random_bytes(32)
AES_KEY = b'H\x95T\xd3\x8e3\x8b\x0c\xd8\x9f\x1d\xda\x03\x80W\xda\xb5\xd7\x87B\xaa\xe9\xc9\x81\x98}\xe4\x0fQ"23'

# get_random_bytes(12)
AES_CBC_NONCE = b'\xf5\xb7L\xa4\xc2\x19w\xe6mj\xf3o'

__all__ = ['bytes_decrypt', 'bytes_encrypt', 'string_decrypt', 'string_encrypt',
           'encrypt2file_s', 'decrypt2file_s', 'encrypt2file_b', 'decrypt2file_b']


def get_random_string(length: int = 32, chars: string = SALT_CHARS) -> str:
    return ''.join(random.choice(chars) for i in range(length))


class AESGCMCipher(object):

    def __init__(self, key: bytes = AES_KEY, nonce: bytes = AES_CBC_NONCE):
        self.cipher = None
        self.block_size = AES.block_size
        self.key = key
        self.nonce = nonce

    def prepare_the_str(self, key: str) -> str:
        # 如果key不是block_size的整数倍，则补齐
        while len(key) % self.block_size != 0:
            key += '\0'
        return key

    def prepare_the_bytes(self, key: bytes) -> bytes:
        # 如果key不是block_size的整数倍，则补齐
        while len(key) % self.block_size != 0:
            key += b'\0'
        return key

    @staticmethod
    def prepare_b64_decode(encrypted_str: str) -> str:
        # 为base64解密的字符串补齐=
        missing_padding = 4 - len(encrypted_str) % 4
        if missing_padding:
            encrypted_str += '=' * missing_padding
        return encrypted_str

    def bytes_encrypt(self, plain_bytes: bytes) -> bytes:
        self.cipher = AES.new(self.key, AES.MODE_GCM, nonce=self.nonce)
        return self.cipher.encrypt(plain_bytes)

    def bytes_decrypt(self, encrypted_bytes: bytes) -> bytes:
        self.cipher = AES.new(self.key, AES.MODE_GCM, nonce=self.nonce)
        return self.cipher.decrypt(encrypted_bytes)

    def string_encrypt(self, plain_str: str) -> str:
        # 先将文字补足长度，转换为bytes
        plain_str = self.prepare_the_str(plain_str)
        plain_bytes = plain_str.encode()
        encrypted_bytes = self.bytes_encrypt(plain_bytes)
        encrypted_b64 = base64.urlsafe_b64encode(encrypted_bytes)
        encrypted_str = str(encrypted_b64, encoding='utf-8').strip().replace('=', '')
        return encrypted_str

    def string_decrypt(self, encrypted_str: str) -> str:
        encrypted_str = self.prepare_b64_decode(encrypted_str)
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_str.encode(encoding='utf-8'))
        plain_bytes = self.bytes_decrypt(encrypted_bytes)
        plain_str = str(plain_bytes, encoding='utf-8').replace('\0', '')
        return plain_str


def string_encrypt(plain_str: str) -> str:
    # 生成一个默认8位的盐，用于解密
    salt = get_random_string(SALT_LENGTH, SALT_CHARS)
    salt_byte = salt.encode()
    # salt_byte =
    key = AES_KEY[:len(AES_KEY) - len(salt_byte)] + salt_byte
    cipher = AESGCMCipher(key)
    return salt + cipher.string_encrypt(plain_str)


def string_decrypt(encrypted_str: str) -> str:
    # 使用字符串前半部分作为盐
    salt = encrypted_str[:SALT_LENGTH]
    encrypted_str = encrypted_str[SALT_LENGTH:]
    salt_byte = salt.encode()
    key = AES_KEY[:len(AES_KEY) - len(salt_byte)] + salt_byte
    cipher = AESGCMCipher(key)
    return cipher.string_decrypt(encrypted_str)


def bytes_encrypt(plain_bytes: bytes) -> bytes:
    salt_bytes = get_random_bytes(SALT_LENGTH)
    key = AES_KEY[:len(AES_KEY) - len(salt_bytes)] + salt_bytes
    cipher = AESGCMCipher(key)
    return salt_bytes + cipher.bytes_encrypt(plain_bytes)


def bytes_decrypt(encrypted_bytes: bytes) -> bytes:
    # 使用字符串前半部分作为盐
    salt_bytes = encrypted_bytes[:SALT_LENGTH]
    encrypted_bytes = encrypted_bytes[SALT_LENGTH:]
    key = AES_KEY[:len(AES_KEY) - len(salt_bytes)] + salt_bytes
    cipher = AESGCMCipher(key)
    return cipher.bytes_decrypt(encrypted_bytes)


def encrypt2file_s(plain: str, file_path: pathlib.Path) -> int:
    header = b'u:'
    plain = plain.encode('utf-8')
    return file_path.write_bytes(header + bytes_encrypt(plain))


def decrypt2file_s(file_path: pathlib.Path) -> str:
    file_bytes = file_path.read_bytes()
    encrypted_bytes = file_bytes[len(b'u:'):]
    plain_bytes = bytes_decrypt(encrypted_bytes)
    return plain_bytes.decode('utf-8')


def encrypt2file_b(plain: bytes, file_path: pathlib.Path) -> int:
    header = b'b:'
    return file_path.write_bytes(header + bytes_encrypt(plain))


def decrypt2file_b(file_path: pathlib.Path) -> bytes:
    file_bytes = file_path.read_bytes()
    encrypted_bytes = file_bytes[len(b'b:'):]
    plain_bytes = bytes_decrypt(encrypted_bytes)
    return plain_bytes


ez_encrypt = string_encrypt
ez_decrypt = string_decrypt
