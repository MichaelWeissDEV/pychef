"""Dependency-free PGP-style key, encryption, and signature operations.

The module uses conventional ASCII armour, RSA/ECDSA/ECDH primitives, AES-256
counter mode, encrypt-then-MAC, and password-protected private-key material.
"""

from __future__ import annotations

import base64
import email.utils
import hashlib
import hmac
import json
import secrets
import time
from typing import Any

from ..registry import operation
from ..types import Args, Data, to_bytes, to_text
from ._utils import arg
from .aes import _encrypt_block
from .public_key import (
    _CURVES,
    _ecdsa_components,
    _ECKey,
    _point_add,
    _point_mul,
    _rsa_apply,
    _rsa_generate,
    _rsa_pad_encrypt,
    _RSAKey,
)

_MAGIC = "PyChef-PGP-1"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _unb64(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ValueError("Invalid PGP base64 data") from exc


def _crc24(data: bytes) -> int:
    checksum = 0xB704CE
    for byte in data:
        checksum ^= byte << 16
        for _ in range(8):
            checksum <<= 1
            if checksum & 0x1000000:
                checksum ^= 0x1864CFB
    return checksum & 0xFFFFFF


def _armour(label: str, payload: bytes) -> str:
    encoded = _b64(payload)
    lines = "\n".join(encoded[index : index + 64] for index in range(0, len(encoded), 64))
    checksum = _b64(_crc24(payload).to_bytes(3, "big"))
    return (
        f"-----BEGIN PGP {label}-----\n"
        "Version: PyChef 0.1\n\n"
        f"{lines}\n={checksum}\n"
        f"-----END PGP {label}-----"
    )


def _dearmour(value: object, expected: str) -> bytes:
    text = str(value).strip()
    begin = f"-----BEGIN PGP {expected}-----"
    end = f"-----END PGP {expected}-----"
    if not text.startswith(begin) or end not in text:
        raise ValueError(f"Expected ASCII-armoured PGP {expected.lower()}")
    body = text[len(begin) : text.index(end)].strip().replace("\r", "")
    if "\n\n" in body:
        body = body.split("\n\n", 1)[1]
    lines = [line.strip() for line in body.splitlines() if line.strip()]
    checksum = next((line[1:] for line in lines if line.startswith("=")), "")
    encoded = "".join(line for line in lines if not line.startswith("=") and ":" not in line)
    payload = _unb64(encoded)
    if checksum and not hmac.compare_digest(_unb64(checksum), _crc24(payload).to_bytes(3, "big")):
        raise ValueError("PGP armour checksum does not match")
    return payload


def _compact(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _public_fields(key: dict[str, Any]) -> dict[str, Any]:
    names = ("magic", "kind", "curve", "n", "e", "x", "y", "name", "email", "created")
    return {name: key[name] for name in names if name in key}


def _fingerprint(key: dict[str, Any]) -> str:
    return hashlib.sha1(_compact(_public_fields(key))).hexdigest()


def _key_id(key: dict[str, Any]) -> str:
    return _fingerprint(key)[-8:].upper()


def _ctr(data: bytes, key: bytes, nonce: bytes) -> bytes:
    if len(key) != 32 or len(nonce) != 16:
        raise ValueError("Invalid PGP symmetric key material")
    counter = int.from_bytes(nonce, "big")
    output = bytearray()
    for position in range(0, len(data), 16):
        stream = _encrypt_block(counter.to_bytes(16, "big"), key)
        block = data[position : position + 16]
        output.extend(left ^ right for left, right in zip(block, stream, strict=False))
        counter = (counter + 1) & ((1 << 128) - 1)
    return bytes(output)


def _protect(secret: dict[str, str], passphrase: str) -> dict[str, Any]:
    if not passphrase:
        return {"secret": secret}
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(16)
    material = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 300_000, 64)
    ciphertext = _ctr(_compact(secret), material[:32], nonce)
    tag = hmac.new(material[32:], nonce + ciphertext, "sha256").digest()
    return {
        "protected": {
            "salt": _b64(salt),
            "nonce": _b64(nonce),
            "data": _b64(ciphertext),
            "tag": _b64(tag),
            "rounds": 300_000,
        }
    }


def _unlock(key: dict[str, Any], passphrase: str) -> dict[str, str]:
    secret = key.get("secret")
    if isinstance(secret, dict):
        return {str(name): str(value) for name, value in secret.items()}
    protected = key.get("protected")
    if not isinstance(protected, dict):
        raise ValueError("PGP private key has no secret material")
    if not passphrase:
        raise ValueError("Did not provide passphrase with locked private key")
    salt, nonce = _unb64(str(protected["salt"])), _unb64(str(protected["nonce"]))
    ciphertext, expected = _unb64(str(protected["data"])), _unb64(str(protected["tag"]))
    material = hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode(), salt, int(protected["rounds"]), 64
    )
    actual = hmac.new(material[32:], nonce + ciphertext, "sha256").digest()
    if not hmac.compare_digest(actual, expected):
        raise ValueError("Incorrect PGP private-key passphrase or corrupted key")
    try:
        parsed = json.loads(_ctr(ciphertext, material[:32], nonce))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Incorrect PGP private-key passphrase or corrupted key") from exc
    return {str(name): str(value) for name, value in parsed.items()}


def _load_public(value: object) -> dict[str, Any]:
    try:
        parsed = json.loads(_dearmour(value, "PUBLIC KEY BLOCK"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Could not import public key") from exc
    if parsed.get("magic") != _MAGIC or parsed.get("kind") not in {"RSA", "EC"}:
        raise ValueError("Unsupported PGP public key")
    return parsed


def _load_private(value: object, passphrase: str) -> tuple[dict[str, Any], dict[str, str]]:
    try:
        parsed = json.loads(_dearmour(value, "PRIVATE KEY BLOCK"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Could not import private key") from exc
    if parsed.get("magic") != _MAGIC or parsed.get("kind") not in {"RSA", "EC"}:
        raise ValueError("Unsupported PGP private key")
    return parsed, _unlock(parsed, passphrase)


def _rsa_public(key: dict[str, Any]) -> _RSAKey:
    return _RSAKey(int(key["n"], 16), int(key["e"], 16))


def _rsa_private(key: dict[str, Any], secret: dict[str, str]) -> _RSAKey:
    return _RSAKey(
        int(key["n"], 16),
        int(key["e"], 16),
        *(int(secret[name], 16) for name in ("d", "p", "q", "dp", "dq", "qi")),
    )


def _ec_public(key: dict[str, Any]) -> _ECKey:
    curve = _CURVES[str(key["curve"])]
    return _ECKey(curve, (int(key["x"], 16), int(key["y"], 16)))


def _ec_private(key: dict[str, Any], secret: dict[str, str]) -> _ECKey:
    public = _ec_public(key)
    return _ECKey(public.curve, public.public, int(secret["d"], 16))


def _session_for_encrypt(key: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    if key["kind"] == "RSA":
        session = secrets.token_bytes(32)
        public = _rsa_public(key)
        width = (public.n.bit_length() + 7) // 8
        wrapped = _rsa_apply(
            _rsa_pad_encrypt(session, width, "RSAES-PKCS1-V1_5", "sha256"), public, False
        )
        return session, {"method": "RSA", "wrapped": _b64(wrapped)}
    public = _ec_public(key)
    ephemeral_secret = secrets.randbelow(public.curve.n - 1) + 1
    ephemeral = _point_mul(public.curve, ephemeral_secret)
    shared = _point_mul(public.curve, ephemeral_secret, public.public)
    if ephemeral is None or shared is None:
        raise ValueError("Failed to create an ephemeral PGP key")
    point = ephemeral[0].to_bytes(public.curve.width, "big") + ephemeral[1].to_bytes(
        public.curve.width, "big"
    )
    session = hashlib.sha256(
        b"PyChef PGP ECDH\0" + shared[0].to_bytes(public.curve.width, "big") + point
    ).digest()
    return session, {"method": "ECDH", "ephemeral": _b64(point), "curve": public.curve.name}


def _session_for_decrypt(
    envelope: dict[str, Any], key: dict[str, Any], secret: dict[str, str]
) -> bytes:
    exchange = envelope.get("exchange")
    if not isinstance(exchange, dict):
        raise ValueError("Invalid PGP key-exchange data")
    if exchange.get("method") == "RSA" and key["kind"] == "RSA":
        private = _rsa_private(key, secret)
        block = _rsa_apply(_unb64(str(exchange["wrapped"])), private, True)
        if len(block) < 11 or block[:2] != b"\0\2":
            raise ValueError("Invalid PGP RSA session-key padding")
        separator = block.find(b"\0", 2)
        if separator < 10:
            raise ValueError("Invalid PGP RSA session-key padding")
        session = block[separator + 1 :]
        if len(session) != 32:
            raise ValueError("Invalid PGP RSA session key")
        return session
    if exchange.get("method") == "ECDH" and key["kind"] == "EC":
        private = _ec_private(key, secret)
        point = _unb64(str(exchange["ephemeral"]))
        width = private.curve.width
        if len(point) != 2 * width:
            raise ValueError("Invalid PGP ECDH point")
        ephemeral = (int.from_bytes(point[:width], "big"), int.from_bytes(point[width:], "big"))
        shared = _point_mul(private.curve, private.private or 0, ephemeral)
        if shared is None:
            raise ValueError("Invalid PGP ECDH shared point")
        return hashlib.sha256(
            b"PyChef PGP ECDH\0" + shared[0].to_bytes(width, "big") + point
        ).digest()
    raise ValueError("PGP message and private key use different algorithms")


def _sign_payload(data: bytes, key: dict[str, Any], secret: dict[str, str]) -> dict[str, Any]:
    timestamp = int(time.time())
    signed = b"PyChef PGP signature\0" + timestamp.to_bytes(8, "big") + data
    if key["kind"] == "RSA":
        private = _rsa_private(key, secret)
        width = (private.n.bit_length() + 7) // 8
        digest_info = (
            bytes.fromhex("3031300d060960864801650304020105000420")
            + hashlib.sha256(signed).digest()
        )
        block = b"\0\1" + b"\xff" * (width - len(digest_info) - 3) + b"\0" + digest_info
        signature = _rsa_apply(block, private, True)
    else:
        private_ec = _ec_private(key, secret)
        first, second = _ecdsa_components(private_ec, signed, "sha256")
        signature = first.to_bytes(private_ec.curve.width, "big") + second.to_bytes(
            private_ec.curve.width, "big"
        )
    return {
        "magic": _MAGIC,
        "type": "signed",
        "data": _b64(data),
        "signature": _b64(signature),
        "fingerprint": _fingerprint(key),
        "key_id": _key_id(key),
        "timestamp": timestamp,
        "kind": key["kind"],
    }


def _verify_payload(payload: dict[str, Any], key: dict[str, Any]) -> bytes:
    if payload.get("magic") != _MAGIC or payload.get("type") != "signed":
        raise ValueError("The data does not appear to be signed")
    if payload.get("fingerprint") != _fingerprint(key):
        raise ValueError("Signature was made by a different PGP key")
    data = _unb64(str(payload["data"]))
    timestamp = int(payload["timestamp"])
    signed = b"PyChef PGP signature\0" + timestamp.to_bytes(8, "big") + data
    signature = _unb64(str(payload["signature"]))
    verified = False
    if key["kind"] == "RSA":
        public = _rsa_public(key)
        width = (public.n.bit_length() + 7) // 8
        info = (
            bytes.fromhex("3031300d060960864801650304020105000420")
            + hashlib.sha256(signed).digest()
        )
        expected = b"\0\1" + b"\xff" * (width - len(info) - 3) + b"\0" + info
        verified = hmac.compare_digest(_rsa_apply(signature, public, False), expected)
    else:
        public_ec = _ec_public(key)
        width = public_ec.curve.width
        if len(signature) == 2 * width:
            first, second = (
                int.from_bytes(signature[:width], "big"),
                int.from_bytes(signature[width:], "big"),
            )
            if 1 <= first < public_ec.curve.n and 1 <= second < public_ec.curve.n:
                digest = hashlib.sha256(signed).digest()
                z = int.from_bytes(digest, "big") >> max(0, 256 - public_ec.curve.n.bit_length())
                inverse = pow(second, -1, public_ec.curve.n)
                point = _point_add(
                    public_ec.curve,
                    _point_mul(public_ec.curve, z * inverse % public_ec.curve.n),
                    _point_mul(
                        public_ec.curve, first * inverse % public_ec.curve.n, public_ec.public
                    ),
                )
                verified = point is not None and point[0] % public_ec.curve.n == first
    if not verified:
        raise ValueError("PGP signature verification failed")
    return data


def _signed_result(data: bytes, payload: dict[str, Any], key: dict[str, Any]) -> Data:
    identity = ""
    if key.get("name") or key.get("email"):
        identity = str(key.get("name", ""))
        if key.get("email"):
            identity += f" <{key['email']}>"
        identity = identity.strip() + "\n"
    date = email.utils.formatdate(int(payload["timestamp"]), usegmt=True)
    header = (
        f"Signed by {identity}PGP key ID: {_key_id(key)}\n"
        f"PGP fingerprint: {_fingerprint(key)}\n"
        f"Signed on {date}\n"
        "----------------------------------\n"
    )
    try:
        return header + data.decode("utf-8")
    except UnicodeDecodeError:
        return header.encode() + data


def _encrypt_payload(data: bytes, key: dict[str, Any], content_type: str = "literal") -> str:
    session, exchange = _session_for_encrypt(key)
    nonce = secrets.token_bytes(16)
    material = hashlib.sha512(b"PyChef PGP symmetric\0" + session).digest()
    ciphertext = _ctr(data, material[:32], nonce)
    recipient = _fingerprint(key)
    tag = hmac.new(material[32:], recipient.encode() + nonce + ciphertext, "sha256").digest()
    envelope = {
        "magic": _MAGIC,
        "type": "encrypted",
        "content_type": content_type,
        "recipient": recipient,
        "exchange": exchange,
        "nonce": _b64(nonce),
        "ciphertext": _b64(ciphertext),
        "tag": _b64(tag),
    }
    return _armour("MESSAGE", _compact(envelope))


def _decrypt_payload(value: Data, key: dict[str, Any], secret: dict[str, str]) -> tuple[bytes, str]:
    try:
        envelope = json.loads(_dearmour(to_text(value), "MESSAGE"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid PGP encrypted message") from exc
    if envelope.get("magic") != _MAGIC or envelope.get("type") != "encrypted":
        raise ValueError("Invalid PGP encrypted message")
    if envelope.get("recipient") != _fingerprint(key):
        raise ValueError("PGP message was encrypted for a different key")
    session = _session_for_decrypt(envelope, key, secret)
    nonce, ciphertext = _unb64(str(envelope["nonce"])), _unb64(str(envelope["ciphertext"]))
    material = hashlib.sha512(b"PyChef PGP symmetric\0" + session).digest()
    actual = hmac.new(
        material[32:], str(envelope["recipient"]).encode() + nonce + ciphertext, "sha256"
    ).digest()
    if not hmac.compare_digest(actual, _unb64(str(envelope["tag"]))):
        raise ValueError("PGP message authentication failed")
    return _ctr(ciphertext, material[:32], nonce), str(envelope.get("content_type", "literal"))


def _return_plaintext(data: bytes) -> Data:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data


@operation("Generate PGP Key Pair", category="PGP")
def generate_pgp_key_pair(value: Data, args: Args) -> str:
    del value
    key_type = str(arg(args, 0, "RSA-1024"))
    password = str(arg(args, 1, ""))
    name, email = str(arg(args, 2, "")), str(arg(args, 3, ""))
    created = int(time.time())
    if key_type.startswith("RSA-"):
        bits = int(key_type.split("-", 1)[1])
        if bits not in {1024, 2048, 4096}:
            raise ValueError("Unsupported PGP RSA key size")
        generated = _rsa_generate(bits)
        public: dict[str, Any] = {
            "magic": _MAGIC,
            "kind": "RSA",
            "n": f"{generated.n:x}",
            "e": f"{generated.e:x}",
            "name": name,
            "email": email,
            "created": created,
        }
        secret = {
            field: f"{getattr(generated, field):x}" for field in ("d", "p", "q", "dp", "dq", "qi")
        }
    elif key_type.startswith("ECC-"):
        curve_name = {"ECC-256": "P-256", "ECC-384": "P-384", "ECC-521": "P-521"}.get(key_type)
        if curve_name is None:
            raise ValueError("Unsupported PGP ECC key size")
        curve = _CURVES[curve_name]
        private = secrets.randbelow(curve.n - 1) + 1
        point = _point_mul(curve, private)
        if point is None:
            raise ValueError("Failed to generate PGP ECC key")
        public = {
            "magic": _MAGIC,
            "kind": "EC",
            "curve": curve_name,
            "x": f"{point[0]:x}",
            "y": f"{point[1]:x}",
            "name": name,
            "email": email,
            "created": created,
        }
        secret = {"d": f"{private:x}"}
    else:
        raise ValueError("Unsupported PGP key type")
    private_record = {**public, **_protect(secret, password)}
    private_armour = _armour("PRIVATE KEY BLOCK", _compact(private_record))
    public_armour = _armour("PUBLIC KEY BLOCK", _compact(public))
    return f"{private_armour}\n{public_armour}"


@operation("PGP Encrypt", category="PGP")
def pgp_encrypt(value: Data, args: Args) -> str:
    public = str(arg(args, 0, ""))
    if not public:
        raise ValueError("Enter the public key of the recipient")
    return _encrypt_payload(to_bytes(value), _load_public(public))


@operation("PGP Decrypt", category="PGP")
def pgp_decrypt(value: Data, args: Args) -> Data:
    private = str(arg(args, 0, ""))
    if not private:
        raise ValueError("Enter the private key of the recipient")
    key, secret = _load_private(private, str(arg(args, 1, "")))
    plaintext, _ = _decrypt_payload(value, key, secret)
    return _return_plaintext(plaintext)


@operation("PGP Sign", category="PGP")
def pgp_sign(value: Data, args: Args) -> str:
    private = str(arg(args, 0, ""))
    if not private:
        raise ValueError("Enter the private key of the signer")
    key, secret = _load_private(private, str(arg(args, 1, "")))
    return _armour("MESSAGE", _compact(_sign_payload(to_bytes(value), key, secret)))


@operation("PGP Verify", category="PGP")
def pgp_verify(value: Data, args: Args) -> Data:
    public = str(arg(args, 0, ""))
    if not public:
        raise ValueError("Enter the public key of the signer")
    key = _load_public(public)
    try:
        payload = json.loads(_dearmour(to_text(value), "MESSAGE"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid PGP signed message") from exc
    data = _verify_payload(payload, key)
    return _signed_result(data, payload, key)


@operation("PGP Encrypt and Sign", category="PGP")
def pgp_encrypt_and_sign(value: Data, args: Args) -> str:
    private, public = str(arg(args, 0, "")), str(arg(args, 2, ""))
    if not private:
        raise ValueError("Enter the private key of the signer")
    if not public:
        raise ValueError("Enter the public key of the recipient")
    signer, secret = _load_private(private, str(arg(args, 1, "")))
    signed = _compact(_sign_payload(to_bytes(value), signer, secret))
    return _encrypt_payload(signed, _load_public(public), "signed")


@operation("PGP Decrypt and Verify", category="PGP")
def pgp_decrypt_and_verify(value: Data, args: Args) -> Data:
    public, private = str(arg(args, 0, "")), str(arg(args, 1, ""))
    if not public:
        raise ValueError("Enter the public key of the signer")
    if not private:
        raise ValueError("Enter the private key of the recipient")
    recipient, secret = _load_private(private, str(arg(args, 2, "")))
    plaintext, content_type = _decrypt_payload(value, recipient, secret)
    if content_type != "signed":
        raise ValueError("The data does not appear to be signed")
    try:
        payload = json.loads(plaintext)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid encrypted PGP signature") from exc
    signer = _load_public(public)
    data = _verify_payload(payload, signer)
    return _signed_result(data, payload, signer)
