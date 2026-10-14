"""Run single operations as plain Python functions with ``pychef.ops``."""

from pychef.ops import (
    from_base64,
    from_hex,
    gzip_compress,
    gzip_decompress,
    rot13,
    run_operation,
    sha256,
    to_base64,
    to_hex,
    url_encode,
    xor,
)


def main() -> None:
    # str in, bytes out for decoders; bytes or str in, str out for encoders.
    raw = from_hex("48656c6c6f")
    assert raw == b"Hello"
    assert to_base64(raw) == "SGVsbG8="
    assert from_base64("SGVsbG8=") == b"Hello"

    # Options are keyword-only and named.
    assert to_hex(raw, delimiter="Space") == "48 65 6c 6c 6f"
    assert url_encode("a b&c") == "a%20b%26c"
    assert rot13("Hello") == "Uryyb"
    assert xor(b"\x0a\x27", b"\x42") == b"He"

    packed = gzip_compress(b"payload " * 20)
    assert gzip_decompress(packed) == b"payload " * 20

    # Hashes return lowercase hexadecimal text.
    digest = sha256(raw)
    assert digest == "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969"

    # Any registered operation is reachable; args are the CyberChef arguments.
    assert run_operation("To Hex", b"AB", args=("Colon", 0)) == "41:42"

    print(f"Base64: {to_base64(raw)}")
    print(f"SHA-256: {digest}")


if __name__ == "__main__":
    main()
