from __future__ import annotations

import pytest

from pychef import bake
from pychef.errors import OperationError


def _keys(kind: str, password: str = "") -> tuple[str, str]:
    pair = bake(
        "",
        [
            {
                "op": "Generate PGP Key Pair",
                "args": [kind, password, "Alice Example", "alice@example.test"],
            }
        ],
    )
    assert isinstance(pair, str)
    marker = "-----END PGP PRIVATE KEY BLOCK-----"
    end = pair.index(marker) + len(marker)
    return pair[:end], pair[end:].strip()


@pytest.mark.parametrize("kind", ["RSA-1024", "ECC-256"])
def test_pgp_encrypt_decrypt_and_binary_preservation(kind: str) -> None:
    private, public = _keys(kind)
    plaintext = bytes(range(256))
    encrypted = bake(plaintext, [{"op": "PGP Encrypt", "args": [public]}])
    assert isinstance(encrypted, str) and encrypted.startswith("-----BEGIN PGP MESSAGE-----")
    assert bake(encrypted, [{"op": "PGP Decrypt", "args": [private, ""]}]) == plaintext


def test_pgp_password_protected_sign_and_verify() -> None:
    private, public = _keys("RSA-1024", "correct horse")
    with pytest.raises(OperationError, match="passphrase"):
        bake("message", [{"op": "PGP Sign", "args": [private, "wrong"]}])
    signed = bake("signed text", [{"op": "PGP Sign", "args": [private, "correct horse"]}])
    verified = bake(signed, [{"op": "PGP Verify", "args": [public]}])
    assert isinstance(verified, str)
    assert "Signed by Alice Example <alice@example.test>" in verified
    assert "PGP key ID:" in verified
    assert verified.endswith("----------------------------------\nsigned text")


def test_pgp_encrypt_sign_decrypt_verify() -> None:
    signer_private, signer_public = _keys("ECC-256")
    recipient_private, recipient_public = _keys("RSA-1024", "recipient password")
    encrypted = bake(
        "vertrauliche Grüße",
        [
            {
                "op": "PGP Encrypt and Sign",
                "args": [signer_private, "", recipient_public],
            }
        ],
    )
    verified = bake(
        encrypted,
        [
            {
                "op": "PGP Decrypt and Verify",
                "args": [signer_public, recipient_private, "recipient password"],
            }
        ],
    )
    assert isinstance(verified, str)
    assert verified.endswith("----------------------------------\nvertrauliche Grüße")


def test_pgp_authenticated_encryption_rejects_tampering() -> None:
    private, public = _keys("ECC-256")
    encrypted = bake("message", [{"op": "PGP Encrypt", "args": [public]}])
    assert isinstance(encrypted, str)
    lines = encrypted.splitlines()
    payload_line = next(
        index
        for index, line in enumerate(lines)
        if line and ":" not in line and not line.startswith(("-", "="))
    )
    replacement = "A" if lines[payload_line][0] != "A" else "B"
    lines[payload_line] = replacement + lines[payload_line][1:]
    with pytest.raises(OperationError, match=r"checksum|message|authentication"):
        bake("\n".join(lines), [{"op": "PGP Decrypt", "args": [private, ""]}])
