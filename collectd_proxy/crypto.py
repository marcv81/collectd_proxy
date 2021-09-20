import Crypto.Cipher.AES
import Crypto.Hash.HMAC
import Crypto.Hash.SHA
import Crypto.Hash.SHA256


def sha1_hash(string):
    """Hashes a string with SHA-1. Returns a 20-bytes string.
    """
    return Crypto.Hash.SHA.new(string).digest()


def sha256_hash(string):
    """Hashes a string with SHA-256. Returns a 32-bytes string.
    """
    return Crypto.Hash.SHA256.new(string).digest()


def aes256_decrypt(key, iv, string):
    """Decrypts an AES-256 encrypted string. Handles encrypted
    strings of any length (not necessarily a multiple of 16).

    @param key: 16-bytes string
    @param iv: 16-bytes string
    @param string: encrypted string
    """
    padding = 16 - (len(string) % 16)
    if padding > 0:
        string += b"\0" * padding
    cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_OFB, iv)
    string = cipher.decrypt(string)
    if padding > 0:
        string = string[:-padding]
    return string


def hmac_sha256_sign(key, string):
    """Signs a string with HMAC SHA-256. Returns a 32-bytes string.
    """
    return Crypto.Hash.HMAC.new(key, string, Crypto.Hash.SHA256).digest()
