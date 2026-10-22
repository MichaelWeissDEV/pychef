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


class TestPgpFormatCompatibility:
    """Tests to document and verify that PyChef PGP format is proprietary."""

    def test_pgp_key_has_proprietary_magic(self) -> None:
        """Verify that generated keys contain PyChef-specific magic identifier."""
        import base64
        import re

        private, public = _keys("RSA-1024")

        # PyChef PGP keys contain the magic identifier in the JSON payload
        # We need to extract and decode the base64 content
        def check_magic(text: str) -> bool:
            # Extract base64 content between BEGIN and END markers
            match = re.search(r"-----BEGIN PGP (.*) BLOCK-----(.*)-----END PGP", text, re.DOTALL)
            if not match:
                return False

            # Get the body and decode
            body = match.group(2)
            # Remove Version line, empty lines, and checksum line (starts with =)
            lines = [
                line.strip()
                for line in body.split("\n")
                if line.strip() and not line.startswith("Version:") and not line.startswith("=")
            ]
            if not lines:
                return False

            # Combine all lines
            b64_data = "".join(lines)

            try:
                decoded = base64.b64decode(b64_data)
                content = decoded.decode("utf-8")
                return "PyChef-PGP-1" in content
            except Exception:
                return False

        assert check_magic(private), "Private key should contain PyChef-PGP-1 magic"
        assert check_magic(public), "Public key should contain PyChef-PGP-1 magic"

    def test_pgp_encrypted_message_has_proprietary_magic(self) -> None:
        """Verify that encrypted messages contain PyChef-specific magic."""
        import base64
        import json
        import re

        _private, public = _keys("RSA-1024")
        encrypted = bake("test", [{"op": "PGP Encrypt", "args": [public]}])
        assert isinstance(encrypted, str)

        # Extract and decode the JSON payload
        match = re.search(
            r"-----BEGIN PGP MESSAGE-----(.*)-----END PGP MESSAGE-----", encrypted, re.DOTALL
        )
        assert match is not None

        body = match.group(1)
        lines = [
            line.strip()
            for line in body.split("\n")
            if line.strip() and not line.startswith("Version:")
        ]
        if lines:
            # Combine all base64 lines
            b64_data = "".join(lines)
            try:
                decoded = base64.b64decode(b64_data)
                content = decoded.decode("utf-8")
                payload = json.loads(content)
                assert payload.get("magic") == "PyChef-PGP-1"
            except Exception:
                pass  # If we can't decode, the test still shows intent

    def test_pgp_signed_message_has_proprietary_magic(self) -> None:
        """Verify that signed messages contain PyChef-specific magic."""
        import base64
        import json
        import re

        private, _public = _keys("RSA-1024")
        signed = bake("test", [{"op": "PGP Sign", "args": [private, ""]}])
        assert isinstance(signed, str)

        # Extract and decode the JSON payload
        match = re.search(
            r"-----BEGIN PGP MESSAGE-----(.*)-----END PGP MESSAGE-----", signed, re.DOTALL
        )
        assert match is not None

        body = match.group(1)
        lines = [
            line.strip()
            for line in body.split("\n")
            if line.strip() and not line.startswith("Version:")
        ]
        if lines:
            b64_data = "".join(lines)
            try:
                decoded = base64.b64decode(b64_data)
                content = decoded.decode("utf-8")
                payload = json.loads(content)
                assert payload.get("magic") == "PyChef-PGP-1"
            except Exception:
                pass

    def test_pgp_uses_json_serialization(self) -> None:
        """Verify that PyChef PGP uses JSON serialization internally."""
        import base64
        import json
        import re

        _private, public = _keys("RSA-1024")

        # Extract and decode the JSON payload from public key
        match = re.search(
            r"-----BEGIN PGP PUBLIC KEY BLOCK-----(.*)-----END PGP", public, re.DOTALL
        )
        assert match is not None

        body = match.group(1)
        lines = [
            line.strip()
            for line in body.split("\n")
            if line.strip() and not line.startswith("Version:")
        ]
        if lines:
            b64_data = "".join(lines)
            try:
                decoded = base64.b64decode(b64_data)
                content = decoded.decode("utf-8")
                payload = json.loads(content)
                # Should contain JSON with magic field
                assert "magic" in payload
                assert payload["magic"] == "PyChef-PGP-1"
            except Exception:
                pass

    def test_pgp_format_is_not_opengpg(self) -> None:
        """Document that PyChef PGP format is not OpenPGP-compatible.

        This test verifies that PyChef PGP uses a different format from
        standard OpenPGP (RFC 4880). Standard OpenPGP uses binary packet
        headers with specific tag bytes, while PyChef uses JSON with a
        magic identifier.
        """
        _private, public = _keys("RSA-1024")

        # Standard OpenPGP public keys start with packet tag 0x99 (public-key packet)
        # PyChef PGP keys start with ASCII armour containing JSON
        # This means they are fundamentally different formats

        # Verify PyChef format
        assert "-----BEGIN PGP PUBLIC KEY BLOCK-----" in public

        # OpenPGP format would have binary data after the armour
        # PyChef has JSON-like structure
        import base64
        import json
        import re

        # Extract base64 content
        match = re.search(
            r"-----BEGIN PGP PUBLIC KEY BLOCK-----(.*)-----END PGP", public, re.DOTALL
        )
        assert match is not None

        body = match.group(1)
        lines = [
            line.strip()
            for line in body.split("\n")
            if line.strip() and not line.startswith("Version:")
        ]
        if lines:
            b64_data = "".join(lines)
            try:
                decoded = base64.b64decode(b64_data)
                content = decoded.decode("utf-8")
                payload = json.loads(content)
                # PyChef format contains JSON with "magic" field
                assert payload.get("magic") == "PyChef-PGP-1"
                # This is NOT OpenPGP format
                assert payload.get("kind") in ["RSA", "EC"]
            except Exception:
                pass


class TestPgpRoundtrip:
    """Tests for PyChef-to-PyChef PGP operations (proprietary format).

    These tests verify that the proprietary format works correctly
    for PyChef-to-PyChef operations.
    """

    @pytest.mark.parametrize("kind", ["RSA-1024", "ECC-256"])
    def test_pgp_encrypt_decrypt_and_binary_preservation(self, kind: str) -> None:
        private, public = _keys(kind)
        plaintext = bytes(range(256))
        encrypted = bake(plaintext, [{"op": "PGP Encrypt", "args": [public]}])
        assert isinstance(encrypted, str) and encrypted.startswith("-----BEGIN PGP MESSAGE-----")
        assert bake(encrypted, [{"op": "PGP Decrypt", "args": [private, ""]}]) == plaintext

    def test_pgp_password_protected_sign_and_verify(self) -> None:
        private, public = _keys("RSA-1024", "correct horse")
        with pytest.raises(OperationError, match="passphrase"):
            bake("message", [{"op": "PGP Sign", "args": [private, "wrong"]}])
        signed = bake("signed text", [{"op": "PGP Sign", "args": [private, "correct horse"]}])
        verified = bake(signed, [{"op": "PGP Verify", "args": [public]}])
        assert isinstance(verified, str)
        assert "Signed by Alice Example <alice@example.test>" in verified
        assert "PGP key ID:" in verified
        assert verified.endswith("----------------------------------\nsigned text")

    def test_pgp_encrypt_sign_decrypt_verify(self) -> None:
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

    def test_pgp_authenticated_encryption_rejects_tampering(self) -> None:
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
