"""Official CyberChef LS47 vectors."""

from __future__ import annotations

import pytest

from pychef import OperationError, bake


def test_ls47_official_vectors() -> None:
    args = ["helloworld", 0, "test"]
    ciphertext = bake("thequickbrownfoxjumped", [{"op": "LS47 Encrypt", "args": args}])
    assert ciphertext == "(,t74ci78cp/8trx*yesu:alp1wqy"
    assert bake(ciphertext, [{"op": "LS47 Decrypt", "args": ["helloworld", 0]}]) == (
        "thequickbrownfoxjumped---test"
    )


def test_ls47_rejects_characters_outside_alphabet() -> None:
    with pytest.raises(OperationError, match="Letter H is not included in LS47"):
        bake("text", [{"op": "LS47 Encrypt", "args": ["Helloworld", 0, "test"]}])
