import Crypto.Cipher.AES
import Crypto.Hash.HMAC
import Crypto.Hash.SHA
import Crypto.Hash.SHA256


def sha1_hash(data):
    """Hashes data with SHA-1. Returns 20-bytes.
    """
    return Crypto.Hash.SHA.new(data).digest()


def sha256_hash(data):
    """Hashes data with SHA-256. Returns 32-bytes.
    """
    return Crypto.Hash.SHA256.new(data).digest()


def aes256_decrypt(key, iv, data):
    """Decrypts AES-256 encrypted data. Handles encrypted
    data of any length (not necessarily a multiple of 16).
    """
    assert len(iv) == 16
    padding = 16 - (len(data) % 16)
    if padding > 0:
        data += b"\0" * padding
    cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_OFB, iv)
    data = cipher.decrypt(data)
    if padding > 0:
        data = data[:-padding]
    return data


def hmac_sha256_sign(key, data):
    """Signs data with HMAC SHA-256. Returns 32-bytes.
    """
    return Crypto.Hash.HMAC.new(key, data, Crypto.Hash.SHA256).digest()
