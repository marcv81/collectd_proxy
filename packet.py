import crypto

PACKET_TYPE_SIGNED = 0x0200
PACKET_TYPE_ENCRYPTED = 0x0210


def _read_integer(data, start):
    """Reads a 2-bytes integer from data (big endian).
    """
    assert start >= 0 and start < len(data) - 1
    return (data[start] << 8) | data[start + 1]


def _read_substring(data, start, length=None):
    """Reads a substring of data. Stops at the end of
    the data if no length is specified.
    """
    assert start >= 0 and start < len(data)
    if length == None:
        length = len(data) - start
    assert length >= 0
    stop = start + length
    assert stop <= len(data)
    return data[start:stop]


def read_encrypted(data):
    """Reads whether a packet is encrypted or signed.
    """
    packet_type = _read_integer(data, 0)
    assert packet_type in (PACKET_TYPE_ENCRYPTED, PACKET_TYPE_SIGNED)
    return packet_type == PACKET_TYPE_ENCRYPTED


def read_user(data, encrypted):
    """Reads the user who claims to have signed/encrypted the packet.
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
