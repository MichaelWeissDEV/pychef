"""Round-trip and ASN.1 tests for dependency-free public-key operations."""

from __future__ import annotations

import base64
import json

import pytest

from pychef import registry
from pychef.operations import public_key as keys


def run(name: str, value: str | bytes, args: list[object] | None = None) -> str | bytes:
    return registry.get(name).run(value, args or [])


@pytest.fixture(scope="module")
def rsa_pair() -> dict[str, str]:
    result = run("Generate RSA Key Pair", "", [512, "JSON"])
    assert isinstance(result, str)
    return json.loads(result)


@pytest.mark.parametrize("scheme", ["RSAES-PKCS1-V1_5", "RSA-OAEP", "RAW"])
def test_rsa_encrypt_decrypt_schemes(rsa_pair: dict[str, str], scheme: str) -> None:
    encrypted = run("RSA Encrypt", "hello", [rsa_pair["publicKey"], scheme, "SHA-1"])
    decrypted = run(
        "RSA Decrypt", encrypted, [rsa_pair["privateKey"], "", scheme, "SHA-1"]
    )
    assert decrypted == b"hello"


@pytest.mark.parametrize("digest", ["MD5", "SHA-1", "SHA-256"])
def test_rsa_sign_and_verify(rsa_pair: dict[str, str], digest: str) -> None:
    signature = run("RSA Sign", "message", [rsa_pair["privateKey"], "", digest])
    assert run(
        "RSA Verify", signature, [rsa_pair["publicKey"], "message", "Raw", digest]
    ) == "Verified OK"
    assert run(
        "RSA Verify", signature, [rsa_pair["publicKey"], "other", "Raw", digest]
    ) == "Verification Failure"


def test_rsa_verify_message_formats(rsa_pair: dict[str, str]) -> None:
    signature = run("RSA Sign", b"abc", [rsa_pair["privateKey"], "", "SHA-256"])
    assert run(
        "RSA Verify", signature, [rsa_pair["publicKey"], "616263", "Hex", "SHA-256"]
    ) == "Verified OK"
    assert run(
        "RSA Verify", signature, [rsa_pair["publicKey"], "YWJj", "Base64", "SHA-256"]
    ) == "Verified OK"


def test_rsa_pem_jwk_and_public_derivation(rsa_pair: dict[str, str]) -> None:
    private_jwk = json.loads(run("PEM to JWK", rsa_pair["privateKey"]))
    public_jwk = json.loads(run("PEM to JWK", rsa_pair["publicKey"]))
    assert private_jwk["kty"] == public_jwk["kty"] == "RSA"
    assert private_jwk["n"] == public_jwk["n"] and "d" in private_jwk
    rebuilt_private = run("JWK to PEM", json.dumps(private_jwk))
    rebuilt_public = run("JWK to PEM", json.dumps(public_jwk))
    derived = run("Public Key from Private Key", rebuilt_private)
    assert json.loads(run("PEM to JWK", rebuilt_public))["n"] == public_jwk["n"]
    assert json.loads(run("PEM to JWK", derived))["n"] == public_jwk["n"]


def test_rsa_generation_formats_and_validation() -> None:
    pem = run("Generate RSA Key Pair", "", [512, "PEM"])
    assert "BEGIN RSA PRIVATE KEY" in pem and "BEGIN PUBLIC KEY" in pem
    der = run("Generate RSA Key Pair", "", [512, "DER"])
    assert isinstance(der, bytes) and der.startswith(b"0")
    with pytest.raises(ValueError):
        run("Generate RSA Key Pair", "", [128, "PEM"])
    with pytest.raises(ValueError):
        run("RSA Encrypt", b"x" * 100, [pem.split("-----BEGIN PUBLIC KEY-----")[0], "RAW"])


@pytest.fixture(scope="module")
def ec_pair() -> dict[str, dict[str, str]]:
    result = run("Generate ECDSA Key Pair", "", ["P-256", "JWK"])
    assert isinstance(result, str)
    return json.loads(result)


@pytest.mark.parametrize("signature_format", ["ASN.1", "P1363", "JWS", "Raw JSON"])
def test_ecdsa_sign_verify_all_formats(
    ec_pair: dict[str, dict[str, str]], signature_format: str
) -> None:
    private = run("JWK to PEM", json.dumps(ec_pair["privateKey"]))
    public = run("JWK to PEM", json.dumps(ec_pair["publicKey"]))
    signature = run("ECDSA Sign", "hello", [private, "SHA-256", signature_format])
    assert run(
        "ECDSA Verify", signature, [signature_format, "SHA-256", public, "hello", "Raw"]
    ) == "Verified OK"
    assert run(
        "ECDSA Verify", signature, [signature_format, "SHA-256", public, "bye", "Raw"]
    ) == "Verification Failure"


@pytest.mark.parametrize("curve", ["P-256", "P-384", "P-521"])
def test_ecdsa_curves_pem_der_and_jwk(curve: str) -> None:
    pem_pair = run("Generate ECDSA Key Pair", "", [curve, "PEM"])
    private = pem_pair.split("-----BEGIN PUBLIC KEY-----")[0].strip()
    public = "-----BEGIN PUBLIC KEY-----" + pem_pair.split("-----BEGIN PUBLIC KEY-----")[1]
    signature = run("ECDSA Sign", b"curve", [private, "SHA-384", "ASN.1"])
    assert run(
        "ECDSA Verify", signature, ["ASN.1", "SHA-384", public, "Y3VydmU=", "Base64"]
    ) == "Verified OK"
    der = run("Generate ECDSA Key Pair", "", [curve, "DER"])
    assert isinstance(der, bytes) and der.startswith(b"0")
    derived = run("Public Key from Private Key", private)
    assert json.loads(run("PEM to JWK", derived))["crv"] == curve


def synthetic_certificate(rsa_pair: dict[str, str]) -> tuple[str, bytes]:
    rsa = keys._rsa_key(rsa_pair["publicKey"])
    subject = keys._sequence(keys._der(12, b"subject"))
    validity = keys._sequence(keys._der(23, b"260101000000Z"), keys._der(23, b"270101000000Z"))
    tbs = keys._sequence(
        keys._der(0xA0, keys._integer(2)),
        keys._integer(123),
        keys._RSA_ALGORITHM,
        subject,
        validity,
        subject,
        keys._rsa_spki(rsa),
    )
    certificate = keys._sequence(tbs, keys._RSA_ALGORITHM, keys._der(3, b"\0signature"))
    return keys._pem("CERTIFICATE", certificate), certificate


@pytest.mark.parametrize("data_format", ["PEM", "Hex", "Base64", "Raw"])
def test_parse_certificate_formats(rsa_pair: dict[str, str], data_format: str) -> None:
    pem, der = synthetic_certificate(rsa_pair)
    values: dict[str, str | bytes] = {
        "PEM": pem,
        "Hex": der.hex(),
        "Base64": base64.b64encode(der).decode(),
        "Raw": der,
    }
    parsed = json.loads(run("Parse X.509 certificate", values[data_format], [data_format]))
    assert parsed["type"] == "X.509 certificate"
    assert parsed["publicKeyAlgorithm"] == keys._RSA_OID


def test_parse_csr_crl_and_extract_certificate_key(rsa_pair: dict[str, str]) -> None:
    pem, der = synthetic_certificate(rsa_pair)
    assert json.loads(run("Parse CSR", der, ["Raw"]))["type"] == "PKCS#10 CSR"
    assert json.loads(run("Parse X.509 CRL", der, ["Raw"]))["type"] == "X.509 CRL"
    public = run("Public Key from Certificate", pem, ["PEM"])
    assert json.loads(run("PEM to JWK", public))["n"] == json.loads(
        run("PEM to JWK", rsa_pair["publicKey"])
    )["n"]


def test_public_key_rejects_bad_values(rsa_pair: dict[str, str], ec_pair: object) -> None:
    with pytest.raises(ValueError):
        run("JWK to PEM", '{"kty":"oct"}')
    with pytest.raises(ValueError):
        run("PEM to JWK", "not pem")
    with pytest.raises(ValueError):
        run("RSA Encrypt", "x", [rsa_pair["publicKey"], "unknown"])
    with pytest.raises(ValueError):
        keys._parse_der(b"\x30\x80")
