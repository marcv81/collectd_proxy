# Packet format

The first 2 bytes of a packet describe its type: 0x0210 for encrypted,
0x0200 for signed, and 0x0000 for plain. The payload of an encrypted or
signed packet is a plain packet.

The total length of an encrypted or signed packet depends on the user
length (n) and the payload length (m).

Integers are represented by 2 bytes in big endian order.

## Encrypted

| Address | Length | Type    | Description         |
|-------- | ------ | ------- | ------------------- |
| 0       | 2      | Integer | Type (0x0210)       |
| 2       | 2      | Integer | Total packet length |
| 4       | 2      | Integer | User length (n)     |
| 6       | n      | String  | User                |
| n + 6   | 16     | String  | Encryption IV       |
| n + 22  | 20     | String  | Encrypted hash      |
| n + 42  | m      | String  | Encrypted payload   |

The payload and its hash are encrypted using AES-256 in OFB mode. The
encryption key is the SHA-256 hash of the user's password. The payload is
hashed using SHA-1.

## Signed

| Address | Length | Type    | Description              |
|-------- | ------ | ------- | ------------------------ |
| 0       | 2      | Integer | Type (0x0200)            |
| 2       | 2      | Integer | Payload address (36 + n) |
| 4       | 32     | String  | Payload signature        |
| 36      | n      | String  | User                     |
| 36 + n  | m      | String  | Payload                  |

The payload is signed using HMAC SHA-256. The signature key is the user's
password.
