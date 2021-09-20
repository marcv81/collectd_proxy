import crypto

PACKET_TYPE_SIGNED = 0x0200
PACKET_TYPE_ENCRYPTED = 0x0210


def _read_integer(string, start):
    """Reads a 2-bytes integer from a string (big endian).

    @param string: string
    @param start: integer start index
    """
    assert start >= 0 and start < len(string) - 1
    return (ord(string[start]) << 8) | ord(string[start + 1])


def _read_substring(string, start, length=None):
    """Reads a substring from a string.

    @param string: string
    @param start: substring start index
    @param length: substring length

    Stops at the end of the string if no length is specified.
    """
    assert start >= 0 and start < len(string)
    if length == None:
        length = len(string) - start
    assert length >= 0
    stop = start + length
    assert stop <= len(string)
    return string[start:stop]


def read_encrypted(data):
    """Reads whether the data is encrypted or signed.

    @param data: packet data
    """
    packet_type = _read_integer(data, 0)
    assert packet_type in (PACKET_TYPE_ENCRYPTED, PACKET_TYPE_SIGNED)
    return packet_type == PACKET_TYPE_ENCRYPTED


def read_user(data, encrypted):
    """Reads the user who claims to have signed/encrypted the data.

    @param data: packet data
    @param encrypted: whether the data is encrypted or signed
    """
    if encrypted:
        user_length = _read_integer(data, 4)
        assert user_length > 0
        return _read_substring(data, 6, user_length)
    else:
        user_length = _read_integer(data, 2) - 36
        assert user_length > 0
        return _read_substring(data, 36, user_length)


def read_payload(data, encrypted, user, key):
    """Reads the decrypted/verified payload.

    @param data: packet data
    @param encrypted: whether the data is encrypted or signed
    @param user: the user who claims to have signed/encrypted the data
    @param key: the key used to sign/encrypt the data
    """

    if encrypted:

        # Decrypt data
        hashed_key = crypto.sha256_hash(key)
        iv = _read_substring(data, 6 + len(user), 16)
        encrypted = _read_substring(data, 22 + len(user))
        decrypted = crypto.aes256_decrypt(hashed_key, iv, encrypted)

        # Verify hash
        hash = _read_substring(decrypted, 0, 20)
        payload = _read_substring(decrypted, 20)
        assert hash == crypto.sha1_hash(payload)
        return payload

    else:

        # Verify hash
        hash = _read_substring(data, 4, 32)
        payload = _read_substring(data, 36 + len(user))
        assert hash == crypto.hmac_sha256_sign(key, user + payload)
        return payload
