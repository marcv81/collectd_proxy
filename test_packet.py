import unittest
import base64

import packet

# Valid encrypted packet
PACKET1_ENCRYPTED = True
PACKET1_USER = "test".encode()
PACKET1_KEY = "password".encode()
PACKET1_DATA = base64.b64decode(
    """
AhAFYQAEdGVzdANHaqp7IFu67SmuxeyRT99FsbuWGjYSiicu4E5EozbvDJT6wEKN6TOVcM5WE6DF
VgRHKbgWrhN8W0lbpk7oOIpRaGE89sMzrhXb8gg+Mjdv5t++LRSXNFL9UvKJfQhrnm06512AaO7Y
lrIkiTkiy7ZRPHZuUq6oM9Y3HKfZuGv+Plg579AAPhALJIOEbN07ZZ3CyDjGElnkbtMH+g/ntOJM
iLOkP2vVVOFebbQn3ifiuWa0aMJ9B3DBALuhEbn9BWXzAU2D6rrPjh4y9zllpovTxOd6I0F2KqdS
Q/Ex8OUi8r4LuVuPMxncWlIi42XTxKFeIougRXv9JtWEivJE+udCJ/s499F/NsoZC//dO4/6gW6p
yC0a8w8af1z2i4CN48BQDjFnjrdcsyA7/lv84jblR72dV5ZeVr3f6WQJvSSX9KsCLjPdh4FHBQoO
KFwq5LR3h9ENcSZtKuvFdY1ZhCXdtxK3q2f+Ra+EvKYV5R3tUOi88RIzbY+E7gJh9OXWsoVFcrEA
tEc/OkJ7UNtckLsgI2YVr60R2nI8R+Z5vXwO+AmVQumDCkhJWtb1ITUCgNvyR+H2tRBzT12VYQvs
cyuZQfiSiDikmh3MYN2PyOfPi4442YTZvRjwTb1Nv3CALDN3bY3B3LMcbLnGZPoKGxImqKbSVl2z
uWlaH/9P9AsjjTpdCNyJL97/vDYxGwDV8AozAlrjaoQov/fziMe4xuMP63u8IPGvD8hA2r+fWcFA
zTmHKZ2J26l9sKDvcwVmtMemmC/e0jmqUVnR1OVCxT2mg56jpmknPDHkd/tmbvkZPtosz0uvtpHB
afoBu4uQ3uF5Oa9E0r+hhE/hilqON8ru/LHUGTxEYsJhaPdn8y9mQrPLkPiFqmXhkWGY6Lzmw0lA
vMqA5CSHi5q7nALOa4jkB9mRiwX7HG+uZoG32xvFk3XrEaNd/u7SgCF6prRmeTk+c36sskliFduJ
jeIROgSPoMlaye2WNPJrm46ej4lvqRV31CJN/3m4Ve4uXx4TINqEGPm7fnQdfxry+yta9WnYhwgK
PNHcBrfeewMOgq1hdCCoTPY9PnG1UTfGQx21gNZWkbjjyoM7d9mGIIxPJ99zuOFGf4jhiX3rNL8i
ZbRe7mVDCiZ/IGTKOa3eAXp8Xm/WpG8xmTRf4ceAm7L2wbBmm7H5NhtcfmF2FyFeK9ywbdxJrQvS
4YKgmQ2yO2ywuZFbL3rXxKgTC+FFkEp5qxr1DvfTO3pCz2XIYnDC9aQ6zVtM5UGh6jls/NdJSTsj
PDJN5vTumbSzXfH/er1P4mEKXBn7kkrZO9OweZoanU8SluD6qkgR1U+IFSbghs7546ipH3OjDqPt
EIOI/up2hO1W2LFDY80VEt1vQR8fEaru4h8uRB95ea9b/1zneiJBOOIX3r7q6oOnbFgKaP6sbLK9
VWFtkKeJvm6FBEf5UeCjO0G3WsvHHDoBDXhOPLlmkkx+R4+kvwyAiYawD/AgZo7y2LROSm2/OGBF
MfUKzr0IUDYlKdwXP219oE+n56F1X8OMdzsIMbAPzWIa8TDIMQdLnTpzicjx1346bqENhGv3Nr3b
MjkEenM6ZZAfEFXOYjjzs9aOOckfuk8+K61Vk/4Cfm7ewf+1YCw9/PYsJNlPychYZWgkB8BAXn8x
+PJWWcXgrrRalD4m58RDQSpTyGlL0sVSaGIiqtVYnNGGxWQHCF+eAsv9djGtvFTQUFKt3rxcz1Nk
XwT10qzi5Fxh7u5QbM6nMSQiWDhqSRb8ddflAfdYktf3LxDfE9vJ80EcMRzVW31HL2/L2AJiwhjg
pFgKRYZ1RphU"""
)
PACKET1_PAYLOAD = base64.b64decode(
    """
AAAADmNsaWVudC0wMQAACAAMFfs9jv/Q+MsACQAMAAAAAoAAAAAAAgAOaW50ZXJmYWNlAAADAAds
bwAABAAOaWZfZXJyb3JzAAAGABgAAgICAAAAAAAAAAAAAAAAAAAAAAAIAAwV+z2O/9EA/gADAAll
dGgxAAAEAA5pZl9vY3RldHMAAAYAGAACAgIAAAAAAACkgQAAAAAAA04CAAgADBX7PY7/0QNDAAQA
D2lmX3BhY2tldHMAAAYAGAACAgIAAAAAAAAAagAAAAAAAADPAAgADBX7PY7/0QV5AAQADmlmX2Vy
cm9ycwAABgAYAAICAgAAAAAAAAAAAAAAAAAAAAAACAAMFfs9jv/RDKIAAwAJZXRoMAAABAAOaWZf
b2N0ZXRzAAAGABgAAgICAAAAAAB9OM0AAAAAAALKOgAIAAwV+z2O/9EO+wAEAA9pZl9wYWNrZXRz
AAAGABgAAgICAAAAAAAAIGoAAAAAAAAJ4QAIAAwV+z2O/9EQ9AAEAA5pZl9lcnJvcnMAAAYAGAAC
AgIAAAAAAAAAAAAAAAAAAAAAAAgADBX7PY7/0foBAAIACGlycQAAAwAFAAAEAAhpcnEAAAUABjAA
AAYADwABAgAAAAAAAAAmAAgADBX7PY7/0f9ZAAUABjEAAAYADwABAgAAAAAAAAAKAAgADBX7PY7/
0gSBAAUABjgAAAYADwABAgAAAAAAAAAAAAgADBX7PY7/0gkpAAUABjkAAAYADwABAgAAAAAAAAAA
AAgADBX7PY7/0g52AAUABzEyAAAGAA8AAQIAAAAAAAAAnAAIAAwV+z2O/9ITrAAFAAcxNAAABgAP
AAECAAAAAAAAAAAACAAMFfs9jv/SGCQABQAHMTUAAAYADwABAgAAAAAAAAEtAAgADBX7PY7/0hxb
AAUABzE2AAAGAA8AAQIAAAAAAAABcgAIAAwV+z2O/9IgkQAFAAcxOAAABgAPAAECAAAAAAAAAAAA
CAAMFfs9jv/SJXUABQAHMTkAAAYADwABAgAAAAAAABBJAAgADBX7PY7/0imKAAUABzIwAAAGAA8A
AQIAAAAAAAAAmAAIAAwV+z2O/9IvuAAFAAcyMQAABgAPAAECAAAAAAAAXpUACAAMFfs9jv/SM/AA
BQAHMjIAAAYADwABAgAAAAAAAAAcAAgADBX7PY7/0ji6AAUACE5NSQAABgAPAAECAAAAAAAAAAAA
CAAMFfs9jv/SPYYABQAITE9DAAAGAA8AAQIAAAAAAAAypAAIAAwV+z2O/9JBjAAFAAhTUFUAAAYA
DwABAgAAAAAAAAAAAAgADBX7PY7/0kXlAAUACFBNSQAABgAPAAECAAAAAAAAAAAACAAMFfs9jv/S
ShEABQAISVdJAAAGAA8AAQIAAAAAAAAAAAAIAAwV+z2O/9JOfQAFAAhSVFIAAAYADwABAgAAAAAA
AAAAAAgADBX7PY7/0lKhAAUACFJFUwAABgAPAAECAAAAAAAAAAAACAAMFfs9jv/SVrkABQAIQ0FM
AAAGAA8AAQIAAAAAAAAAAAAIAAwV+z2O/9Jc9AAFAAhUTEIAAAYADwABAgAAAAAAAAAAAAgADBX7
PY7/0mDfAAUACFRSTQAABgAPAAECAAAAAAAAAAAACAAMFfs9jv/SZLEABQAIVEhSAAAGAA8AAQIA
AAAAAAAAAAAIAAwV+z2O/9Jo8gAFAAhERlIAAAYADwABAgAAAAAAAAAAAAgADBX7PY7/0mytAAUA
CE1DRQAABgAPAAECAAAAAAAAAAA="""
)

# Valid signed packet
PACKET2_ENCRYPTED = False
PACKET2_USER = "user".encode()
PACKET2_KEY = "secret".encode()
PACKET2_DATA = base64.b64decode(
    """
AgAAKPKWfzVCe7xFTUPziv80qylHbSvsgQkLRBMltssLDvskdXNlcgAAAA5jbGllbnQtMDEAAAgA
DBX7PY7/0nB1AAkADAAAAAKAAAAAAAIACGlycQAABAAIaXJxAAAFAAhNQ1AAAAYADwABAgAAAAAA
AAABAAgADBX7PY7/0nOsAAUACEVSUgAABgAPAAECAAAAAAAAAAAACAAMFfs9jv/SdxQABQAITUlT
AAAGAA8AAQIAAAAAAAAAAAAIAAwV+z2O/9J74AAFAAhQSU4AAAYADwABAgAAAAAAAAAAAAgADBX7
PY7/0n/6AAUACFBJVwAABgAPAAECAAAAAAAAAAAACAAMFfs9jv/H5C8AAgAJZGlzawAAAwAJc2Rh
MgAABAANZGlza19vcHMAAAUABQAABgAYAAICAgAAAAAAAAAJAAAAAAAAAAAACAAMFfs9jv/H5rEA
BAAOZGlza190aW1lAAAGABgAAgICAAAAAAAAABQAAAAAAAAAAAAIAAwV+z2O/8fo8wAEABBkaXNr
X21lcmdlZAAABgAYAAICAgAAAAAAAAAAAAAAAAAAAAAACAAMFfs9jv/H604ABAAXcGVuZGluZ19v
cGVyYXRpb25zAAAGAA8AAQEAAAAAAAAAAAAIAAwV+z2O/+Lf0QACAAdkZgAAAwAJcm9vdAAABAAP
ZGZfY29tcGxleAAABQAJZnJlZQAABgAPAAEBAAAAYKsSIUIACAAMFfs9jv/i7JAABQANcmVzZXJ2
ZWQAAAYADwABAQAAAADMcN9BAAgADBX7PY7/42XmAAUACXVzZWQAAAYADwABAQAAAACkH+FBAAgA
DBX7PY7/4+K6AAMACWJvb3QAAAUACWZyZWUAAAYADwABAQAAAAAYpbVBAAgADBX7PY7/5BW3AAUA
DXJlc2VydmVkAAAGAA8AAQEAAAAAgFl4QQAIAAwV+z2O/+RBvQAFAAl1c2VkAAAGAA8AAQEAAAAA
4DuZQQAIAAwV+z2O/+8M4gADAAx2YWdyYW50AAAFAAlmcmVlAAAGAA8AAQEAAADUTddVQgAIAAwV
+z2O/+8ZsQAFAA1yZXNlcnZlZAAABgAPAAEBAAAAAAAAAAAACAAMFfs9jv/voZAABQAJdXNlZAAA
BgAPAAEBAAAAunu6YUIACAAMFfs9jv/w3hEAAgALbWVtb3J5AAADAAUAAAQAC21lbW9yeQAABgAP
AAEBAAAAAABKf0EABQANYnVmZmVyZWQAAAYADwABAQAAAAAA1XNBAAUAC2NhY2hlZAAABgAPAAEB
AAAAAOBWsEEABQAJZnJlZQAABgAPAAEBAAAAAMAooEEABQAQc2xhYl91bnJlY2wAAAYADwABAQAA
AAAAUmtBAAUADnNsYWJfcmVjbAAABgAPAAEBAAAAAAB8gEEACAAMFfs9jwBC3M8AAgAOcHJvY2Vz
c2VzAAAEAA1wc19zdGF0ZQAABQAMcnVubmluZwAABgAPAAEBAAAAAAAAAAAACAAMFfs9jwBrcxoA
BQANc2xlZXBpbmcAAAYADwABAQAAAAAAgF1AAAgADBX7PY8Aa6rBAAUADHpvbWJpZXMAAAYADwAB
AQAAAAAAAAAAAAgADBX7PY8Aa9flAAUADHN0b3BwZWQAAAYADwABAQAAAAAAAAAAAAgADBX7PY8A
bANuAAUAC3BhZ2luZwAABgAPAAEBAAAAAAAAAAAACAAMFfs9jwBsLP0ABQAMYmxvY2tlZAAABgAP
AAEBAAAAAAAAAAAACAAMFfs9jwBs26MABAAOZm9ya19yYXRlAAAFAAUAAAYADwABAgAAAAAAACmt
"""
)
PACKET2_PAYLOAD = base64.b64decode(
    """
AAAADmNsaWVudC0wMQAACAAMFfs9jv/ScHUACQAMAAAAAoAAAAAAAgAIaXJxAAAEAAhpcnEAAAUA
CE1DUAAABgAPAAECAAAAAAAAAAEACAAMFfs9jv/Sc6wABQAIRVJSAAAGAA8AAQIAAAAAAAAAAAAI
AAwV+z2O/9J3FAAFAAhNSVMAAAYADwABAgAAAAAAAAAAAAgADBX7PY7/0nvgAAUACFBJTgAABgAP
AAECAAAAAAAAAAAACAAMFfs9jv/Sf/oABQAIUElXAAAGAA8AAQIAAAAAAAAAAAAIAAwV+z2O/8fk
LwACAAlkaXNrAAADAAlzZGEyAAAEAA1kaXNrX29wcwAABQAFAAAGABgAAgICAAAAAAAAAAkAAAAA
AAAAAAAIAAwV+z2O/8fmsQAEAA5kaXNrX3RpbWUAAAYAGAACAgIAAAAAAAAAFAAAAAAAAAAAAAgA
DBX7PY7/x+jzAAQAEGRpc2tfbWVyZ2VkAAAGABgAAgICAAAAAAAAAAAAAAAAAAAAAAAIAAwV+z2O
/8frTgAEABdwZW5kaW5nX29wZXJhdGlvbnMAAAYADwABAQAAAAAAAAAAAAgADBX7PY7/4t/RAAIA
B2RmAAADAAlyb290AAAEAA9kZl9jb21wbGV4AAAFAAlmcmVlAAAGAA8AAQEAAABgqxIhQgAIAAwV
+z2O/+LskAAFAA1yZXNlcnZlZAAABgAPAAEBAAAAAMxw30EACAAMFfs9jv/jZeYABQAJdXNlZAAA
BgAPAAEBAAAAAKQf4UEACAAMFfs9jv/j4roAAwAJYm9vdAAABQAJZnJlZQAABgAPAAEBAAAAABil
tUEACAAMFfs9jv/kFbcABQANcmVzZXJ2ZWQAAAYADwABAQAAAACAWXhBAAgADBX7PY7/5EG9AAUA
CXVzZWQAAAYADwABAQAAAADgO5lBAAgADBX7PY7/7wziAAMADHZhZ3JhbnQAAAUACWZyZWUAAAYA
DwABAQAAANRN11VCAAgADBX7PY7/7xmxAAUADXJlc2VydmVkAAAGAA8AAQEAAAAAAAAAAAAIAAwV
+z2O/++hkAAFAAl1c2VkAAAGAA8AAQEAAAC6e7phQgAIAAwV+z2O//DeEQACAAttZW1vcnkAAAMA
BQAABAALbWVtb3J5AAAGAA8AAQEAAAAAAEp/QQAFAA1idWZmZXJlZAAABgAPAAEBAAAAAADVc0EA
BQALY2FjaGVkAAAGAA8AAQEAAAAA4FawQQAFAAlmcmVlAAAGAA8AAQEAAAAAwCigQQAFABBzbGFi
X3VucmVjbAAABgAPAAEBAAAAAABSa0EABQAOc2xhYl9yZWNsAAAGAA8AAQEAAAAAAHyAQQAIAAwV
+z2PAELczwACAA5wcm9jZXNzZXMAAAQADXBzX3N0YXRlAAAFAAxydW5uaW5nAAAGAA8AAQEAAAAA
AAAAAAAIAAwV+z2PAGtzGgAFAA1zbGVlcGluZwAABgAPAAEBAAAAAACAXUAACAAMFfs9jwBrqsEA
BQAMem9tYmllcwAABgAPAAEBAAAAAAAAAAAACAAMFfs9jwBr1+UABQAMc3RvcHBlZAAABgAPAAEB
AAAAAAAAAAAACAAMFfs9jwBsA24ABQALcGFnaW5nAAAGAA8AAQEAAAAAAAAAAAAIAAwV+z2PAGws
/QAFAAxibG9ja2VkAAAGAA8AAQEAAAAAAAAAAAAIAAwV+z2PAGzbowAEAA5mb3JrX3JhdGUAAAUA
BQAABgAPAAECAAAAAAAAKa0="""
)


class PacketTest(unittest.TestCase):
    def test_read_integer(self):

        # Valid reads
        self.assertEqual(1, packet._read_integer(b"\0\1", 0))
        self.assertEqual(256, packet._read_integer(b"\1\0", 0))

        def invalid():
            packet._read_integer(b"\0\0", 1)

        # Invalid read (exceeds right bound)
        self.assertRaises(AssertionError, invalid)

    def test_read_substring(self):

        # Valid reads
        self.assertEqual(b"te", packet._read_substring(b"test", 0, 2))
        self.assertEqual(b"st", packet._read_substring(b"test", 2, 2))
        self.assertEqual(b"st", packet._read_substring(b"test", 2))

        def invalid():
            packet._read_substring(b"test", 2, 3)

        # Invalid read (exceeds right bound)
        self.assertRaises(AssertionError, invalid)

    def test_read_encrypted(self):

        # Valid encrypted/signed packets
        packet1_encrypted = packet.read_encrypted(PACKET1_DATA)
        self.assertEqual(PACKET1_ENCRYPTED, packet1_encrypted)
        packet2_encrypted = packet.read_encrypted(PACKET2_DATA)
        self.assertEqual(PACKET2_ENCRYPTED, packet2_encrypted)

        def invalid():
            packet.read_encrypted(PACKET2_PAYLOAD)

        # Plain packet
        self.assertRaises(AssertionError, invalid)

    def test_read_user(self):

        # Valid encrypted/signed packets
        packet1_user = packet.read_user(PACKET1_DATA, PACKET1_ENCRYPTED)
        self.assertEqual(PACKET1_USER, packet1_user)
        packet2_user = packet.read_user(PACKET2_DATA, PACKET2_ENCRYPTED)
        self.assertEqual(PACKET2_USER, packet2_user)

    def test_read_payload(self):

        # Valid encrypted/signed packets
        packet1_payload = packet.read_payload(
            PACKET1_DATA, PACKET1_ENCRYPTED, PACKET1_USER, PACKET1_KEY
        )
        self.assertEqual(PACKET1_PAYLOAD, packet1_payload)
        packet2_payload = packet.read_payload(
            PACKET2_DATA, PACKET2_ENCRYPTED, PACKET2_USER, PACKET2_KEY
        )
        self.assertEqual(PACKET2_PAYLOAD, packet2_payload)

        def invalid1():
            packet.read_payload(
                PACKET1_DATA, PACKET1_ENCRYPTED, PACKET1_USER, b"invalid"
            )

        def invalid2():
            packet.read_payload(
                PACKET2_DATA, PACKET2_ENCRYPTED, PACKET2_USER, b"invalid"
            )

        # Decrypt/verify with invalid key
        self.assertRaises(AssertionError, invalid1)
        self.assertRaises(AssertionError, invalid2)
