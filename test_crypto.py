import unittest
import base64

import crypto

# Data and associated SHA-1 and SHA-256 hashes
TEST1_DATA = "test"
TEST1_SHA1_HASH = base64.b64decode("qUqP5cyxm6YcTAhz05Hph5gvu9M=")
TEST1_SHA256_HASH = base64.b64decode("n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=")

# 16-bytes key and IV
TEST2_KEY = base64.b64decode("a3FsdHlmem1vY3VpdndhcA==")
TEST2_IV = base64.b64decode("ZWx0ZGtycGFnem9odnNucQ==")
# 10-bytes encrypted/decrypted string
TEST2_ENCRYPTED1 = base64.b64decode("Z21saXZzZW9keQ==")
TEST2_DECRYPTED1 = base64.b64decode("nGCDqhPDdB9LAw==")
# 16-bytes encrypted/decrypted string
TEST2_ENCRYPTED2 = base64.b64decode("cnNvZWNnYnFoam5tdHV5dw==")
TEST2_DECRYPTED2 = base64.b64decode("iX6ApgbXcwFHEJ8dv8ySFg==")

# Key, data and associated HMAC SHA-256 signature
TEST3_KEY = "secret"
TEST3_DATA = "message"
TEST3_SIGNATURE = base64.b64decode("i19IcCmVwVmMVz2x4hhmqbgl1KeU0WnXBgoDYFeWNgs=")


class CryptoTest(unittest.TestCase):
    def test_sha1_hash(self):
        digest = crypto.sha1_hash(TEST1_DATA)
        self.assertEquals(20, len(digest))
        self.assertEquals(TEST1_SHA1_HASH, digest)

    def test_sha256_hash(self):
        digest = crypto.sha256_hash(TEST1_DATA)
        self.assertEquals(32, len(digest))
        self.assertEquals(TEST1_SHA256_HASH, digest)

    def test_aes256_decrypt(self):
        decrypted1 = crypto.aes256_decrypt(
            TEST2_KEY, TEST2_IV, TEST2_ENCRYPTED1
        )
        self.assertEquals(TEST2_DECRYPTED1, decrypted1)
        decrypted2 = crypto.aes256_decrypt(
            TEST2_KEY, TEST2_IV, TEST2_ENCRYPTED2
        )
        self.assertEquals(TEST2_DECRYPTED2, decrypted2)

    def test_hmac_sha256_sign(self):
        signature = crypto.hmac_sha256_sign(TEST3_KEY, TEST3_DATA)
        self.assertEquals(32, len(signature))
        self.assertEquals(TEST3_SIGNATURE, signature)


if __name__ == "__main__":
    unittest.main()
