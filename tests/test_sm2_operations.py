from __future__ import annotations

import pytest

from pychef import bake
from pychef.errors import OperationError

PRIVATE = "e74a72505084c3269aa9b696d603e3e08c74c6740212c11a31e26cdfe08bdf6a"
PUBLIC_X = "f7d903cab7925066c31150a92b31e548e63f954f92d01eaa0271fb2a336baef8"
PUBLIC_Y = "fb0c45e410ef7a6cdae724e6a78dbff52562e97ede009e762b667d9b14adea6c"
CIPHERTEXT_C1C3C2 = (
    "9a31bc0adb4677cdc4141479e3949572a55c3e6fb52094721f741c2bd2e179aa"
    "a87be6263bc1be602e473be3d5de5dce97f8248948b3a7e15f9f67f64aef21575"
    "e0c05e6171870a10ff9ab778dbef24267ad90e1a9d47d68f757d57c4816612e98"
    "29f804025dea05a511cda39371c22a2828f976f72e"
)
CIPHERTEXT_C1C2C3 = (
    "5f340eeb4398fa8950ee3408d0e3fe34bf7728c9fdb060c94b916891b5c69361"
    "0274160b52a7132a2bf16ad5cdb57d1e00da2f3ddbd55350729aa9c268b53e40"
    "c05ccce9912daa14406e8c132e389484e69757350be25351755dcc6c25c94b3c1"
    "a448b2cf8c2017582125eb6cf782055b199a875e966"
)


@pytest.mark.parametrize(
    ("ciphertext", "encoding"),
    [(CIPHERTEXT_C1C3C2, "C1C3C2"), (CIPHERTEXT_C1C2C3, "C1C2C3")],
)
def test_sm2_official_cyberchef_vectors(ciphertext: str, encoding: str) -> None:
    assert (
        bake(ciphertext, [{"op": "SM2 Decrypt", "args": [PRIVATE, encoding, "sm2p256v1"]}])
        == b"I am a small plaintext"
    )


@pytest.mark.parametrize("encoding", ["C1C3C2", "C1C2C3"])
def test_sm2_encrypt_decrypt_and_authentication(encoding: str) -> None:
    encrypted = bake(
        b"authenticated plaintext",
        [{"op": "SM2 Encrypt", "args": [PUBLIC_X, PUBLIC_Y, encoding, "sm2p256v1"]}],
    )
    assert isinstance(encrypted, str)
    assert (
        bake(encrypted, [{"op": "SM2 Decrypt", "args": [PRIVATE, encoding, "sm2p256v1"]}])
        == b"authenticated plaintext"
    )
    tampered = encrypted[:-2] + ("00" if encrypted[-2:] != "00" else "01")
    with pytest.raises(OperationError, match="integrity"):
        bake(tampered, [{"op": "SM2 Decrypt", "args": [PRIVATE, encoding, "sm2p256v1"]}])
