"""Dependency-free RSA, ECDSA, PEM, JWK, and X.509 operations."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass

from ..registry import implementation
from ..types import Args, Data, to_bytes, to_text
from ._utils import arg, require_int
from .random_prime import _candidate, _probable_prime


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64u(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _length(length: int) -> bytes:
    if length < 128:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _der(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _length(len(payload)) + payload


def _integer(value: int) -> bytes:
    encoded = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if encoded[0] & 0x80:
        encoded = b"\0" + encoded
    return _der(2, encoded)


def _sequence(*values: bytes) -> bytes:
    return _der(0x30, b"".join(values))


def _oid(value: str) -> bytes:
    parts = [int(part) for part in value.split(".")]
    encoded = bytearray([40 * parts[0] + parts[1]])
    for number in parts[2:]:
        group = [number & 127]
        number >>= 7
        while number:
            group.append(0x80 | (number & 127))
            number >>= 7
        encoded.extend(reversed(group))
    return _der(6, bytes(encoded))


def _decode_oid(data: bytes) -> str:
    if not data:
        return ""
    values = [min(data[0] // 40, 2), data[0] - min(data[0] // 40, 2) * 40]
    current = 0
    for byte in data[1:]:
        current = (current << 7) | (byte & 127)
        if byte < 128:
            values.append(current)
            current = 0
    return ".".join(map(str, values))


@dataclass(frozen=True, slots=True)
class _Node:
    tag: int
    payload: bytes
    raw: bytes
    children: tuple[_Node, ...] = ()


def _read_node(data: bytes, position: int = 0) -> tuple[_Node, int]:
    start = position
    if position >= len(data):
        raise ValueError("Invalid DER: missing tag")
    tag = data[position]
    position += 1
    if position >= len(data):
        raise ValueError("Invalid DER: missing length")
    first = data[position]
    position += 1
    if first < 128:
        length = first
    else:
        width = first & 127
        if not width or width > 6 or position + width > len(data):
            raise ValueError("Invalid DER length")
        length = int.from_bytes(data[position : position + width], "big")
        position += width
    end = position + length
    if end > len(data):
        raise ValueError("Invalid DER: truncated value")
    payload = data[position:end]
    children: list[_Node] = []
    if tag & 0x20:
        child_position = 0
        while child_position < len(payload):
            child, child_position = _read_node(payload, child_position)
            children.append(child)
    return _Node(tag, payload, data[start:end], tuple(children)), end


def _parse_der(data: bytes) -> _Node:
    node, end = _read_node(data)
    if end != len(data):
        raise ValueError("Trailing bytes after DER value")
    return node


_PEM_RE = re.compile(r"-----BEGIN ([^-]+)-----\s*(.*?)\s*-----END \1-----", re.DOTALL)


def _pem_decode(value: Data) -> tuple[str, bytes]:
    text = to_text(value).strip()
    match = _PEM_RE.search(text)
    if not match:
        raise ValueError("Invalid PEM data")
    try:
        return match.group(1), base64.b64decode(re.sub(r"\s", "", match.group(2)), validate=True)
    except ValueError as exc:
        raise ValueError("Invalid PEM base64 data") from exc


def _pem(label: str, data: bytes) -> str:
    encoded = base64.b64encode(data).decode()
    lines = "\n".join(encoded[index : index + 64] for index in range(0, len(encoded), 64))
    return f"-----BEGIN {label}-----\n{lines}\n-----END {label}-----"


def _node_int(node: _Node) -> int:
    if node.tag != 2:
        raise ValueError("Expected ASN.1 INTEGER")
    return int.from_bytes(node.payload, "big")


_RSA_OID = "1.2.840.113549.1.1.1"
_EC_OID = "1.2.840.10045.2.1"
_RSA_ALGORITHM = _sequence(_oid(_RSA_OID), _der(5, b""))


@dataclass(frozen=True, slots=True)
class _RSAKey:
    n: int
    e: int
    d: int | None = None
    p: int | None = None
    q: int | None = None
    dp: int | None = None
    dq: int | None = None
    qi: int | None = None


def _rsa_pkcs1_public(key: _RSAKey) -> bytes:
    return _sequence(_integer(key.n), _integer(key.e))


def _rsa_spki(key: _RSAKey) -> bytes:
    return _sequence(_RSA_ALGORITHM, _der(3, b"\0" + _rsa_pkcs1_public(key)))


def _rsa_pkcs1_private(key: _RSAKey) -> bytes:
    if None in {key.d, key.p, key.q, key.dp, key.dq, key.qi}:
        raise ValueError("RSA private key required")
    return _sequence(
        _integer(0),
        _integer(key.n),
        _integer(key.e),
        _integer(key.d or 0),
        _integer(key.p or 0),
        _integer(key.q or 0),
        _integer(key.dp or 0),
        _integer(key.dq or 0),
        _integer(key.qi or 0),
    )


def _rsa_from_pkcs1(data: bytes, *, private: bool) -> _RSAKey:
    node = _parse_der(data)
    integers = [_node_int(child) for child in node.children]
    if private and len(integers) >= 9:
        return _RSAKey(*integers[1:9])
    if not private and len(integers) == 2:
        return _RSAKey(integers[0], integers[1])
    raise ValueError("Invalid RSA key")


def _rsa_key(value: Data, *, private: bool = False) -> _RSAKey:
    label, data = _pem_decode(value)
    if label == "RSA PRIVATE KEY":
        return _rsa_from_pkcs1(data, private=True)
    if label == "RSA PUBLIC KEY":
        return _rsa_from_pkcs1(data, private=False)
    root = _parse_der(data)
    if label == "PRIVATE KEY" and len(root.children) >= 3:
        return _rsa_from_pkcs1(root.children[2].payload, private=True)
    if label == "PUBLIC KEY" and len(root.children) >= 2:
        bit_string = root.children[1].payload
        return _rsa_from_pkcs1(bit_string[1:], private=False)
    if private:
        raise ValueError("RSA private key required")
    raise ValueError("Unsupported RSA PEM label")


def _rsa_generate(bits: int) -> _RSAKey:
    if bits < 512 or bits > 4096:
        raise ValueError("RSA key size must be between 512 and 4096 bits")
    e = 65537
    half = bits // 2
    while True:
        p = _candidate(half)
        if not _probable_prime(p, 16) or (p - 1) % e == 0:
            continue
        q = _candidate(bits - half)
        if p == q or not _probable_prime(q, 16) or (q - 1) % e == 0:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        d = pow(e, -1, phi)
        return _RSAKey(n, e, d, p, q, d % (p - 1), d % (q - 1), pow(q, -1, p))


def _hash_name(value: object) -> str:
    name = str(value).lower().replace("-", "")
    aliases = {
        "sha1": "sha1",
        "sha256": "sha256",
        "sha384": "sha384",
        "sha512": "sha512",
        "md5": "md5",
    }
    if name not in aliases:
        raise ValueError(f"Unsupported digest: {value}")
    return aliases[name]


def _mgf1(seed: bytes, length: int, digest: str) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(hashlib.new(digest, seed + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(output[:length])


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def _rsa_apply(data: bytes, key: _RSAKey, private: bool) -> bytes:
    exponent = key.d if private else key.e
    if exponent is None:
        raise ValueError("RSA private key required")
    width = (key.n.bit_length() + 7) // 8
    number = int.from_bytes(data, "big")
    if number >= key.n:
        raise ValueError("RSA input is larger than the modulus")
    return pow(number, exponent, key.n).to_bytes(width, "big")


def _rsa_pad_encrypt(message: bytes, width: int, scheme: str, digest: str) -> bytes:
    if scheme == "RAW":
        if len(message) > width:
            raise ValueError("Message is too long for RSA modulus")
        return message.rjust(width, b"\0")
    if scheme == "RSAES-PKCS1-V1_5":
        if len(message) > width - 11:
            raise ValueError("Message is too long for RSA PKCS#1 v1.5")
        padding = bytearray()
        while len(padding) < width - len(message) - 3:
            byte = secrets.randbelow(255) + 1
            padding.append(byte)
        return b"\0\x02" + bytes(padding) + b"\0" + message
    if scheme != "RSA-OAEP":
        raise ValueError(f"Unsupported RSA encryption scheme: {scheme}")
    digest_size = hashlib.new(digest).digest_size
    if len(message) > width - 2 * digest_size - 2:
        raise ValueError("Message is too long for RSA OAEP")
    data_block = hashlib.new(digest, b"").digest()
    data_block += b"\0" * (width - len(message) - 2 * digest_size - 2) + b"\x01" + message
    seed = secrets.token_bytes(digest_size)
    masked_data = _xor(data_block, _mgf1(seed, len(data_block), digest))
    masked_seed = _xor(seed, _mgf1(masked_data, digest_size, digest))
    return b"\0" + masked_seed + masked_data


def _rsa_unpad_encrypt(block: bytes, scheme: str, digest: str) -> bytes:
    if scheme == "RAW":
        return block.lstrip(b"\0")
    if scheme == "RSAES-PKCS1-V1_5":
        if not block.startswith(b"\0\x02"):
            raise ValueError("Invalid RSA PKCS#1 v1.5 padding")
        separator = block.find(b"\0", 2)
        if separator < 10:
            raise ValueError("Invalid RSA PKCS#1 v1.5 padding")
        return block[separator + 1 :]
    if scheme != "RSA-OAEP":
        raise ValueError(f"Unsupported RSA encryption scheme: {scheme}")
    digest_size = hashlib.new(digest).digest_size
    if len(block) < 2 * digest_size + 2 or block[0] != 0:
        raise ValueError("Invalid RSA OAEP padding")
    masked_seed = block[1 : digest_size + 1]
    masked_data = block[digest_size + 1 :]
    seed = _xor(masked_seed, _mgf1(masked_data, digest_size, digest))
    data_block = _xor(masked_data, _mgf1(seed, len(masked_data), digest))
    if not hmac.compare_digest(data_block[:digest_size], hashlib.new(digest, b"").digest()):
        raise ValueError("Invalid RSA OAEP label hash")
    separator = data_block.find(b"\x01", digest_size)
    if separator < 0 or any(data_block[digest_size:separator]):
        raise ValueError("Invalid RSA OAEP padding")
    return data_block[separator + 1 :]


_DIGEST_INFO = {
    "md5": bytes.fromhex("3020300c06082a864886f70d020505000410"),
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


def _rsa_signature_block(message: bytes, width: int, digest: str) -> bytes:
    info = _DIGEST_INFO[digest] + hashlib.new(digest, message).digest()
    if len(info) > width - 11:
        raise ValueError("RSA modulus is too short for this digest")
    return b"\0\x01" + b"\xff" * (width - len(info) - 3) + b"\0" + info


@implementation("Generate RSA Key Pair", category="Public Key")
def generate_rsa_key_pair(value: Data, args: Args) -> Data:
    del value
    bits = require_int(arg(args, 0, 2048), name="RSA key size")
    output_format = str(arg(args, 1, "PEM"))
    key = _rsa_generate(bits)
    public = _pem("PUBLIC KEY", _rsa_spki(key))
    private = _pem("RSA PRIVATE KEY", _rsa_pkcs1_private(key))
    if output_format == "JSON":
        return json.dumps({"publicKey": public, "privateKey": private}, indent=2)
    if output_format == "DER":
        return _rsa_pkcs1_private(key)
    return f"{private}\n{public}"


@implementation("RSA Encrypt", category="Public Key")
def rsa_encrypt(value: Data, args: Args) -> Data:
    key = _rsa_key(str(arg(args, 0, "")))
    scheme = str(arg(args, 1, "RSA-OAEP"))
    digest = _hash_name(arg(args, 2, "SHA-1"))
    width = (key.n.bit_length() + 7) // 8
    return _rsa_apply(_rsa_pad_encrypt(to_bytes(value), width, scheme, digest), key, False)


@implementation("RSA Decrypt", category="Public Key")
def rsa_decrypt(value: Data, args: Args) -> Data:
    key = _rsa_key(str(arg(args, 0, "")), private=True)
    scheme = str(arg(args, 2, arg(args, 1, "RSA-OAEP")))
    digest = _hash_name(arg(args, 3, "SHA-1"))
    return _rsa_unpad_encrypt(_rsa_apply(to_bytes(value), key, True), scheme, digest)


@implementation("RSA Sign", category="Public Key")
def rsa_sign(value: Data, args: Args) -> Data:
    key = _rsa_key(str(arg(args, 0, "")), private=True)
    digest = _hash_name(arg(args, 2, "SHA-256"))
    width = (key.n.bit_length() + 7) // 8
    return _rsa_apply(_rsa_signature_block(to_bytes(value), width, digest), key, True)


def _decode_formatted(value: object, data_format: str) -> bytes:
    text = str(value)
    if data_format == "Hex":
        return bytes.fromhex(text)
    if data_format == "Base64":
        return base64.b64decode(text)
    return text.encode()


@implementation("RSA Verify", category="Public Key")
def rsa_verify(value: Data, args: Args) -> Data:
    key = _rsa_key(str(arg(args, 0, "")))
    message = _decode_formatted(arg(args, 1, ""), str(arg(args, 2, "Raw")))
    digest = _hash_name(arg(args, 3, "SHA-256"))
    width = (key.n.bit_length() + 7) // 8
    try:
        actual = _rsa_apply(to_bytes(value), key, False)
        expected = _rsa_signature_block(message, width, digest)
        return "Verified OK" if hmac.compare_digest(actual, expected) else "Verification Failure"
    except ValueError:
        return "Verification Failure"


@dataclass(frozen=True, slots=True)
class _Curve:
    name: str
    oid: str
    p: int
    a: int
    b: int
    gx: int
    gy: int
    n: int

    @property
    def width(self) -> int:
        return (self.p.bit_length() + 7) // 8


def _hex(value: str) -> int:
    return int(value.replace(" ", "").replace("\n", ""), 16)


_CURVES = {
    "P-256": _Curve(
        "P-256",
        "1.2.840.10045.3.1.7",
        _hex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"),
        _hex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"),
        _hex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"),
        _hex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
        _hex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"),
        _hex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
    ),
    "P-384": _Curve(
        "P-384",
        "1.3.132.0.34",
        _hex(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF"
        ),
        _hex(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC"
        ),
        _hex(
            "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF"
        ),
        _hex(
            "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7"
        ),
        _hex(
            "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"
        ),
        _hex(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"
        ),
    ),
    "P-521": _Curve(
        "P-521",
        "1.3.132.0.35",
        (1 << 521) - 1,
        (1 << 521) - 4,
        _hex(
            "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00"
        ),
        _hex(
            "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66"
        ),
        _hex(
            "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"
        ),
        _hex(
            "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409"
        ),
    ),
}
_CURVE_BY_OID = {curve.oid: curve for curve in _CURVES.values()}
_Point = tuple[int, int] | None


def _point_add(curve: _Curve, left: _Point, right: _Point) -> _Point:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % curve.p == 0:
        return None
    if left == right:
        slope = (3 * x1 * x1 + curve.a) * pow(2 * y1, -1, curve.p) % curve.p
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, curve.p) % curve.p
    x3 = (slope * slope - x1 - x2) % curve.p
    return x3, (slope * (x1 - x3) - y1) % curve.p


def _point_mul(curve: _Curve, scalar: int, point: _Point = None) -> _Point:
    result = None
    addend = point or (curve.gx, curve.gy)
    while scalar:
        if scalar & 1:
            result = _point_add(curve, result, addend)
        addend = _point_add(curve, addend, addend)
        scalar >>= 1
    return result


def _ec_point(curve: _Curve, point: tuple[int, int]) -> bytes:
    return b"\x04" + point[0].to_bytes(curve.width, "big") + point[1].to_bytes(curve.width, "big")


def _ec_decode_point(curve: _Curve, data: bytes) -> tuple[int, int]:
    if len(data) != 1 + 2 * curve.width or data[0] != 4:
        raise ValueError("Only uncompressed EC points are supported")
    point = (
        int.from_bytes(data[1 : 1 + curve.width], "big"),
        int.from_bytes(data[1 + curve.width :], "big"),
    )
    if (point[1] ** 2 - point[0] ** 3 - curve.a * point[0] - curve.b) % curve.p:
        raise ValueError("EC point is not on the selected curve")
    return point


@dataclass(frozen=True, slots=True)
class _ECKey:
    curve: _Curve
    public: tuple[int, int]
    private: int | None = None


def _ec_algorithm(curve: _Curve) -> bytes:
    return _sequence(_oid(_EC_OID), _oid(curve.oid))


def _ec_spki(key: _ECKey) -> bytes:
    return _sequence(_ec_algorithm(key.curve), _der(3, b"\0" + _ec_point(key.curve, key.public)))


def _ec_sec1(key: _ECKey) -> bytes:
    if key.private is None:
        raise ValueError("EC private key required")
    return _sequence(
        _integer(1),
        _der(4, key.private.to_bytes(key.curve.width, "big")),
        _der(0xA0, _oid(key.curve.oid)),
        _der(0xA1, _der(3, b"\0" + _ec_point(key.curve, key.public))),
    )


def _ec_pkcs8(key: _ECKey) -> bytes:
    return _sequence(_integer(0), _ec_algorithm(key.curve), _der(4, _ec_sec1(key)))


def _ec_key(value: Data, *, private: bool = False) -> _ECKey:
    label, data = _pem_decode(value)
    root = _parse_der(data)
    if label == "PRIVATE KEY":
        if len(root.children) < 3:
            raise ValueError("Invalid EC private key")
        curve = _CURVE_BY_OID[_decode_oid(root.children[1].children[1].payload)]
        root = _parse_der(root.children[2].payload)
    elif label == "EC PRIVATE KEY":
        curve_node = next((item for item in root.children if item.tag == 0xA0), None)
        if curve_node is None:
            raise ValueError("EC private key does not identify its curve")
        curve = _CURVE_BY_OID[_decode_oid(curve_node.children[0].payload)]
    elif label == "PUBLIC KEY":
        curve = _CURVE_BY_OID[_decode_oid(root.children[0].children[1].payload)]
        point = _ec_decode_point(curve, root.children[1].payload[1:])
        return _ECKey(curve, point)
    else:
        raise ValueError("Unsupported EC PEM label")
    private_value = int.from_bytes(root.children[1].payload, "big")
    point = _point_mul(curve, private_value)
    if point is None:
        raise ValueError("Invalid EC private scalar")
    return _ECKey(curve, point, private_value)


def _rfc6979(curve: _Curve, private: int, digest: bytes, hash_name: str) -> int:
    width = (curve.n.bit_length() + 7) // 8
    secret = private.to_bytes(width, "big")
    reduced = (int.from_bytes(digest, "big") % curve.n).to_bytes(width, "big")
    v = b"\x01" * hashlib.new(hash_name).digest_size
    key = b"\0" * len(v)
    key = hmac.new(key, v + b"\0" + secret + reduced, hash_name).digest()
    v = hmac.new(key, v, hash_name).digest()
    key = hmac.new(key, v + b"\x01" + secret + reduced, hash_name).digest()
    v = hmac.new(key, v, hash_name).digest()
    while True:
        candidate = bytearray()
        while len(candidate) < width:
            v = hmac.new(key, v, hash_name).digest()
            candidate.extend(v)
        value = int.from_bytes(candidate[:width], "big")
        if 1 <= value < curve.n:
            return value
        key = hmac.new(key, v + b"\0", hash_name).digest()
        v = hmac.new(key, v, hash_name).digest()


def _ecdsa_components(key: _ECKey, message: bytes, digest_name: str) -> tuple[int, int]:
    if key.private is None:
        raise ValueError("EC private key required")
    digest = hashlib.new(digest_name, message).digest()
    z = int.from_bytes(digest, "big") >> max(0, len(digest) * 8 - key.curve.n.bit_length())
    nonce = _rfc6979(key.curve, key.private, digest, digest_name)
    point = _point_mul(key.curve, nonce)
    if point is None:
        raise ValueError("Invalid ECDSA nonce")
    first = point[0] % key.curve.n
    second = pow(nonce, -1, key.curve.n) * (z + first * key.private) % key.curve.n
    return first, second


def _ecdsa_der(first: int, second: int) -> bytes:
    return _sequence(_integer(first), _integer(second))


def _ecdsa_read(value: Data, signature_format: str, width: int) -> tuple[int, int]:
    data = to_bytes(value)
    if signature_format == "ASN.1":
        node = _parse_der(data)
        return _node_int(node.children[0]), _node_int(node.children[1])
    if signature_format == "P1363":
        if len(data) != 2 * width:
            raise ValueError("Invalid P1363 signature length")
        return int.from_bytes(data[:width], "big"), int.from_bytes(data[width:], "big")
    if signature_format == "JWS":
        decoded = _unb64u(to_text(value))
        return _ecdsa_read(decoded, "P1363", width)
    parsed = json.loads(to_text(value))
    return int(str(parsed["r"]), 16), int(str(parsed["s"]), 16)


@implementation("Generate ECDSA Key Pair", category="Public Key")
def generate_ecdsa_key_pair(value: Data, args: Args) -> Data:
    del value
    curve = _CURVES[str(arg(args, 0, "P-256"))]
    output_format = str(arg(args, 1, "PEM"))
    private = secrets.randbelow(curve.n - 1) + 1
    point = _point_mul(curve, private)
    if point is None:
        raise ValueError("Failed to generate EC public key")
    key = _ECKey(curve, point, private)
    if output_format == "JWK":
        public = _ec_jwk(key, False)
        private_jwk = _ec_jwk(key, True)
        return json.dumps({"publicKey": public, "privateKey": private_jwk}, indent=2)
    if output_format == "DER":
        return _ec_pkcs8(key)
    return f"{_pem('PRIVATE KEY', _ec_pkcs8(key))}\n{_pem('PUBLIC KEY', _ec_spki(key))}"


@implementation("ECDSA Sign", category="Public Key")
def ecdsa_sign(value: Data, args: Args) -> Data:
    key = _ec_key(str(arg(args, 0, "")), private=True)
    digest = _hash_name(arg(args, 1, "SHA-256"))
    output_format = str(arg(args, 2, "ASN.1"))
    first, second = _ecdsa_components(key, to_bytes(value), digest)
    if output_format == "ASN.1":
        return _ecdsa_der(first, second)
    p1363 = first.to_bytes(key.curve.width, "big") + second.to_bytes(key.curve.width, "big")
    if output_format == "P1363":
        return p1363
    if output_format == "JWS":
        return _b64u(p1363)
    return json.dumps({"r": f"{first:x}", "s": f"{second:x}"})


@implementation("ECDSA Verify", category="Public Key")
def ecdsa_verify(value: Data, args: Args) -> Data:
    signature_format = str(arg(args, 0, "ASN.1"))
    digest_name = _hash_name(arg(args, 1, "SHA-256"))
    key = _ec_key(str(arg(args, 2, "")))
    message = _decode_formatted(arg(args, 3, ""), str(arg(args, 4, "Raw")))
    try:
        first, second = _ecdsa_read(value, signature_format, key.curve.width)
        if not 1 <= first < key.curve.n or not 1 <= second < key.curve.n:
            return "Verification Failure"
        digest = hashlib.new(digest_name, message).digest()
        z = int.from_bytes(digest, "big") >> max(0, len(digest) * 8 - key.curve.n.bit_length())
        inverse = pow(second, -1, key.curve.n)
        point = _point_add(
            key.curve,
            _point_mul(key.curve, z * inverse % key.curve.n),
            _point_mul(key.curve, first * inverse % key.curve.n, key.public),
        )
        return (
            "Verified OK"
            if point is not None and point[0] % key.curve.n == first
            else "Verification Failure"
        )
    except (KeyError, ValueError, json.JSONDecodeError):
        return "Verification Failure"


def _int_bytes(value: int) -> bytes:
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")


def _rsa_jwk(key: _RSAKey, private: bool) -> dict[str, str]:
    output = {"kty": "RSA", "n": _b64u(_int_bytes(key.n)), "e": _b64u(_int_bytes(key.e))}
    if private:
        for name in ("d", "p", "q", "dp", "dq", "qi"):
            number = getattr(key, name)
            if number is None:
                raise ValueError("RSA private key required")
            output[name] = _b64u(_int_bytes(number))
    return output


def _ec_jwk(key: _ECKey, private: bool) -> dict[str, str]:
    output = {
        "kty": "EC",
        "crv": key.curve.name,
        "x": _b64u(key.public[0].to_bytes(key.curve.width, "big")),
        "y": _b64u(key.public[1].to_bytes(key.curve.width, "big")),
    }
    if private:
        if key.private is None:
            raise ValueError("EC private key required")
        output["d"] = _b64u(key.private.to_bytes(key.curve.width, "big"))
    return output


@implementation("PEM to JWK", category="Public Key")
def pem_to_jwk(value: Data, args: Args) -> Data:
    del args
    try:
        rsa = _rsa_key(value, private="PRIVATE KEY" in to_text(value))
        return json.dumps(_rsa_jwk(rsa, rsa.d is not None), indent=2)
    except (KeyError, ValueError):
        ec = _ec_key(value, private="PRIVATE KEY" in to_text(value))
        return json.dumps(_ec_jwk(ec, ec.private is not None), indent=2)


@implementation("JWK to PEM", category="Public Key")
def jwk_to_pem(value: Data, args: Args) -> Data:
    del args
    parsed = json.loads(to_text(value))
    if parsed["kty"] == "RSA":
        values = {name: int.from_bytes(_unb64u(parsed[name]), "big") for name in ("n", "e")}
        if "d" in parsed:
            values.update(
                {
                    name: int.from_bytes(_unb64u(parsed[name]), "big")
                    for name in ("d", "p", "q", "dp", "dq", "qi")
                }
            )
            key = _RSAKey(**values)
            return _pem("RSA PRIVATE KEY", _rsa_pkcs1_private(key))
        return _pem("PUBLIC KEY", _rsa_spki(_RSAKey(**values)))
    if parsed["kty"] != "EC":
        raise ValueError("Only RSA and EC JWK values are supported")
    curve = _CURVES[parsed["crv"]]
    public = (
        int.from_bytes(_unb64u(parsed["x"]), "big"),
        int.from_bytes(_unb64u(parsed["y"]), "big"),
    )
    private = int.from_bytes(_unb64u(parsed["d"]), "big") if "d" in parsed else None
    key = _ECKey(curve, public, private)
    return _pem("PRIVATE KEY", _ec_pkcs8(key)) if private else _pem("PUBLIC KEY", _ec_spki(key))


def _der_input(value: Data, data_format: str) -> bytes:
    if data_format == "PEM" or "-----BEGIN" in to_text(value):
        return _pem_decode(value)[1]
    if data_format == "Hex":
        return bytes.fromhex(to_text(value))
    if data_format == "Base64":
        return base64.b64decode(to_text(value))
    return to_bytes(value)


def _walk(node: _Node) -> list[_Node]:
    result = [node]
    for child in node.children:
        result.extend(_walk(child))
    return result


def _spki_node(root: _Node) -> _Node:
    for node in _walk(root):
        if node.tag != 0x30 or len(node.children) != 2 or node.children[0].tag != 0x30:
            continue
        algorithms = [
            _decode_oid(child.payload) for child in node.children[0].children if child.tag == 6
        ]
        if algorithms and algorithms[0] in {_RSA_OID, _EC_OID} and node.children[1].tag == 3:
            return node
    raise ValueError("No supported public key found")


def _asn1_summary(root: _Node, kind: str) -> str:
    oids = [_decode_oid(node.payload) for node in _walk(root) if node.tag == 6]
    integers = [f"0x{_node_int(node):x}" for node in _walk(root) if node.tag == 2]
    strings = [
        node.payload.decode("utf-8", "replace")
        for node in _walk(root)
        if node.tag in {12, 19, 20, 22, 30}
    ]
    result = {
        "type": kind,
        "serialNumber": integers[1] if kind == "X.509 certificate" and len(integers) > 1 else None,
        "objectIdentifiers": oids,
        "strings": strings,
        "derLength": len(root.raw),
    }
    try:
        spki = _spki_node(root)
        result["publicKeyAlgorithm"] = _decode_oid(spki.children[0].children[0].payload)
    except ValueError:
        result["publicKeyAlgorithm"] = None
    return json.dumps(result, ensure_ascii=False, indent=2)


@implementation("Parse X.509 certificate", category="Public Key")
def parse_x509_certificate(value: Data, args: Args) -> Data:
    return _asn1_summary(
        _parse_der(_der_input(value, str(arg(args, 0, "PEM")))), "X.509 certificate"
    )


@implementation("Parse CSR", category="Public Key")
def parse_csr(value: Data, args: Args) -> Data:
    return _asn1_summary(_parse_der(_der_input(value, str(arg(args, 0, "PEM")))), "PKCS#10 CSR")


@implementation("Parse X.509 CRL", category="Public Key")
def parse_x509_crl(value: Data, args: Args) -> Data:
    return _asn1_summary(_parse_der(_der_input(value, str(arg(args, 0, "PEM")))), "X.509 CRL")


@implementation("Public Key from Certificate", category="Public Key")
def public_key_from_certificate(value: Data, args: Args) -> Data:
    root = _parse_der(_der_input(value, str(arg(args, 0, "PEM"))))
    return _pem("PUBLIC KEY", _spki_node(root).raw)


@implementation("Public Key from Private Key", category="Public Key")
def public_key_from_private_key(value: Data, args: Args) -> Data:
    del args
    try:
        return _pem("PUBLIC KEY", _rsa_spki(_rsa_key(value, private=True)))
    except ValueError:
        return _pem("PUBLIC KEY", _ec_spki(_ec_key(value, private=True)))
