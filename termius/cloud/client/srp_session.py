"""Botan-compatible SRP-6a client used by Termius gRPC login.

Termius 10 configures ``modp/srp/8192`` (RFC 5054 8192-bit group) with
SHA-256, matching Botan ``SRP6_Client_Session``.
"""
from __future__ import unicode_literals

import base64
import hashlib
import os

N_HEX = (
    'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74'
    '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437'
    '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05'
    '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB'
    '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'
    'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718'
    '3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33'
    'A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7'
    'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864'
    'D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2'
    '08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7'
    '88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8'
    'DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2'
    '233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9'
    '93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026'
    'C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AE'
    'B06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B'
    'DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92EC'
    'F032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E'
    '59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA'
    'CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76'
    'F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468'
    '043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E4'
    '38777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED'
    '2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652D'
    'E3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B'
    '4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A6'
    '6D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851D'
    'F9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F92'
    '4009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA'
    '9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF'
)
N = int(N_HEX, 16)
G = 19


def _to_bytes(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode('utf-8')
    return bytes(value)


def _int_to_bytes(value, length=None):
    if length is None:
        length = (value.bit_length() + 7) // 8 or 1
    return value.to_bytes(length, 'big')


def _bytes_to_int(data):
    return int.from_bytes(data, 'big')


def _sha256(*parts):
    digest = hashlib.sha256()
    for part in parts:
        digest.update(_to_bytes(part))
    return digest.digest()


def _pad(value):
    """Left-pad an integer to the byte length of N."""
    return _int_to_bytes(value % N, (N.bit_length() + 7) // 8)


def _H(*parts):
    """Hash concatenated parts; integers are padded to |N|."""
    blobs = []
    for part in parts:
        if isinstance(part, int):
            blobs.append(_pad(part))
        else:
            blobs.append(_to_bytes(part))
    return _bytes_to_int(_sha256(*blobs))


class ClientSession(object):
    """SRP-6a client session."""

    def __init__(self):
        self.identifier = None
        self.password = None
        self.salt = None
        self.a = None
        self.A = None
        self.B = None
        self.u = None
        self.x = None
        self.S = None
        self.K = None
        self.M1 = None
        self.M2 = None

    def configure(self, identifier, password, salt, version=1):
        self.identifier = _to_bytes(identifier)
        self.password = _to_bytes(password)
        self.salt = _to_bytes(salt)
        self.a = _bytes_to_int(os.urandom(32)) % (N - 1) + 1
        self.A = pow(G, self.a, N)
        inner = _sha256(self.identifier, b':', self.password)
        self.x = _bytes_to_int(_sha256(self.salt, inner))
        return self

    def generate_verifier(self):
        """Return v = g^x mod N as raw bytes."""
        v = pow(G, self.x, N)
        return _int_to_bytes(v)

    def agree_server_public_value(self, public_data):
        """Accept server public B (bytes or base64)."""
        if isinstance(public_data, str):
            public_data = base64.b64decode(public_data)
        self.B = _bytes_to_int(_to_bytes(public_data))
        if self.B % N == 0:
            return False
        self.u = _H(self.A, self.B)
        if self.u == 0:
            return False
        k = _H(N, G)
        self.S = pow(
            (self.B - k * pow(G, self.x, N)) % N,
            self.a + self.u * self.x,
            N,
        )
        self.K = _sha256(_int_to_bytes(self.S))
        self.M1 = _sha256(_int_to_bytes(self.A), _int_to_bytes(self.B), self.K)
        self.M2 = _sha256(_int_to_bytes(self.A), self.M1, self.K)
        return True

    def get_public_value(self):
        return _int_to_bytes(self.A)

    def generate_proof(self):
        return self.M1

    def validate_server_proof(self, proof):
        if isinstance(proof, str):
            try:
                proof = base64.b64decode(proof)
            except Exception:
                proof = _to_bytes(proof)
        return _to_bytes(proof) == self.M2

    def get_secret_key(self):
        return self.K

    def get_salted_secret_key(self, session_salt):
        """Derive the 32-byte key used to unwrap the DeviceToken."""
        return hashlib.sha256(self.K + _to_bytes(session_salt)).digest()
