"""Botan-compatible SRP-6a client used by Termius gRPC login.

Termius 10 configures ``modp/srp/8192`` (RFC 5054 8192-bit group) with
**Blake2b-512** (Botan name ``Blake2b``), matching ``SRP6_Client_Session``.
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


def _blake2b(*parts):
    """Unkeyed Blake2b-512, Botan ``HashFunction::create("Blake2b")``."""
    digest = hashlib.blake2b(digest_size=64)
    for part in parts:
        digest.update(_to_bytes(part))
    return digest.digest()


P_BYTES = (N.bit_length() + 7) // 8
A_BITS = 512


def _pad(value):
    """IEEE 1363 ``encode_1363`` to |N| bytes.

    Botan ``hash_seq`` / ``SymmetricKey`` pad A, B, g, S, and N this way.
    Do **not** reduce modulo N first: ``N % N`` is 0, so ``k = H(N, g)``
    would hash 1024 zero bytes instead of the 8192-bit modulus and every
    SRP proof would be rejected.
    """
    if isinstance(value, bytes):
        value = _bytes_to_int(value)
    if value < 0:
        raise ValueError('cannot pad a negative integer')
    try:
        return value.to_bytes(P_BYTES, 'big')
    except OverflowError:
        return (value % N).to_bytes(P_BYTES, 'big')


def _minimal(value):
    """Botan ``BigInt`` serialize: no leading zero bytes."""
    if isinstance(value, bytes):
        value = _bytes_to_int(value)
    if value == 0:
        return b'\x00'
    return _int_to_bytes(value)


def _H(*parts):
    """Hash concatenated parts; integers are padded to |N|."""
    blobs = []
    for part in parts:
        if isinstance(part, int):
            blobs.append(_pad(part))
        else:
            blobs.append(_to_bytes(part))
    return _bytes_to_int(_blake2b(*blobs))


def botan_bigint_to_str(value):
    """Botan ``BigInt::to_hex_string``: ``0x`` + uppercase hex."""
    if isinstance(value, bytes):
        value = _bytes_to_int(value)
    if not isinstance(value, int):
        raise TypeError('bigint value must be int or bytes')
    if value < 0:
        return '-' + botan_bigint_to_str(-value)
    if value == 0:
        return '0x00'
    hexstr = format(value, 'X')
    if len(hexstr) % 2:
        hexstr = '0' + hexstr
    return '0x' + hexstr


def botan_bigint_to_wire(value):
    """Android libtermius wire format: uppercase hex, no ``0x`` prefix.

    ``GetPublicValue`` / ``GenerateProof`` call ``to_hex_string`` then strip
    a leading ``0x``. The server's ``publicData`` is the same (2048 hex chars).
    """
    text = botan_bigint_to_str(value)
    if text.startswith('-'):
        body = text[1:]
        if body.startswith('0x') or body.startswith('0X'):
            body = body[2:]
        return '-' + body
    if text.startswith('0x') or text.startswith('0X'):
        return text[2:]
    return text


def botan_bigint_from_str(value):
    """Parse a libtermius public value / proof (0x-hex, bytes, or base64)."""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, dict) and value.get('type') == 'Buffer':
        value = bytes(value.get('data') or [])
    if isinstance(value, list):
        value = bytes(value)
    if isinstance(value, bytes):
        stripped = value.strip()
        if stripped.startswith(b'0x') or stripped.startswith(b'0X'):
            return int(stripped, 16)
        if all(chr(b) in '0123456789abcdefABCDEF' for b in stripped) and len(stripped) >= 8:
            return int(stripped, 16)
        return _bytes_to_int(value)
    text = value.strip()
    if text.startswith('0x') or text.startswith('0X'):
        return int(text, 16)
    if all(c in '0123456789abcdefABCDEF' for c in text) and len(text) >= 8:
        return int(text, 16)
    try:
        raw = base64.b64decode(text)
    except Exception:
        return int(text, 16)
    if raw.startswith(b'0x') or raw.startswith(b'0X'):
        return int(raw, 16)
    return _bytes_to_int(raw)


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
        self.session_key = None
        self.M1 = None
        self.M2 = None

    def configure(self, identifier, password, salt, version=1):
        self.identifier = _to_bytes(identifier)
        self.salt = _to_bytes(salt)
        if len(self.salt) != 16:
            raise ValueError(
                'SRP salt must be 16 bytes, got {}'.format(len(self.salt))
            )
        # libtermius Argon2id-hashes the vault password, then uses the
        # base64 key as SRP P. The raw password yields INVALID_PROOF.
        from .sodium import hash_srp_password
        try:
            version = int(version)
        except (TypeError, ValueError):
            version = 1
        self.version = 1 if version == 1 else version
        if isinstance(password, str):
            password = password.strip('\r\n')
        self.password = _to_bytes(hash_srp_password(password, self.salt))
        # Botan ``dl_exponent_size(8192)`` is 512 bits.
        self.a = _bytes_to_int(os.urandom(A_BITS // 8)) % (N - 1) + 1
        self.A = pow(G, self.a, N)
        inner = _blake2b(self.identifier, b':', self.password)
        self.x = _bytes_to_int(_blake2b(self.salt, inner))
        return self

    def generate_verifier(self):
        """Return v = g^x mod N as raw bytes."""
        v = pow(G, self.x, N)
        return _int_to_bytes(v)

    def agree_server_public_value(self, public_data):
        """Accept server public B (0x-hex, bytes, or base64)."""
        self.B = botan_bigint_from_str(public_data)
        if self.B is None:
            return False
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
        # Botan SymmetricKey is S encoded to |N| bytes, not SHA-256(S).
        self.session_key = _pad(self.S)
        self.K = self.session_key
        self.M1 = self._client_proof()
        self.M2 = _blake2b(_minimal(self.A), self.M1, self.K)
        return True

    def _client_proof(self):
        """libtermius generateProof: RFC 2945 with unpadded BigInt bytes.

        M = H(H(N) xor H(g) | H(I) | s | A | B | H(K))
        where H is Blake2b-512, H(N)/H(g)/A/B use Botan minimal
        serialization (g is 0x13), and K is S padded to |N|.
        """
        h_n = _blake2b(_minimal(N))
        h_g = _blake2b(_minimal(G))
        xor_ng = bytes(a ^ b for a, b in zip(h_n, h_g))
        h_i = _blake2b(self.identifier)
        h_k = _blake2b(self.session_key)
        return _blake2b(
            xor_ng,
            h_i,
            self.salt,
            _minimal(self.A),
            _minimal(self.B),
            h_k,
        )

    def get_public_value(self):
        return _int_to_bytes(self.A)

    def generate_proof(self):
        return self.M1

    def validate_server_proof(self, proof):
        if proof is None:
            return False
        if isinstance(proof, str) and (
            proof.startswith('0x') or proof.startswith('0X')
        ):
            proof = botan_bigint_from_str(proof)
        if isinstance(proof, int):
            proof = _int_to_bytes(proof)
        elif isinstance(proof, str):
            try:
                proof = base64.b64decode(proof)
            except Exception:
                proof = botan_bigint_from_str(proof)
                proof = _int_to_bytes(proof)
        return _to_bytes(proof) == self.M2

    def get_secret_key(self):
        return self.K

    def get_salted_secret_key(self, session_salt):
        """Derive the 32-byte key used to unwrap the DeviceToken."""
        return hashlib.sha256(self.K + _to_bytes(session_salt)).digest()
