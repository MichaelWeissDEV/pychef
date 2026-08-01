"""Run a few common PyChef transformations from one Python script."""

from pychef import Pipeline, bake, digest, p32le, u32le


def main() -> None:
    encoded = bake(
        "Hello, PyChef!",
        [
            {"op": "To Base64", "args": ["A-Za-z0-9+/="]},
            {"op": "Reverse", "args": ["Character"]},
        ],
    )
    assert encoded == b"=EiZlh2Q5BFIs8GbsVGS"

    decode = Pipeline().from_hex().xor(b"\x42").decode()
    assert decode("0a272e2e2d") == "Hello"

    display = decode | Pipeline().to_base64()
    assert display("0a272e2e2d") == "SGVsbG8="

    packed = p32le(0xDEADBEEF)
    assert packed == b"\xef\xbe\xad\xde"
    assert u32le(packed) == 0xDEADBEEF

    checksum = digest(b"flag", algorithm="sha256")
    assert checksum == "807d0fbcae7c4b20518d4d85664f6820aafdf936104122c5073e7744c46c4b87"

    print(f"Recipe output: {encoded.decode()}")
    print(f"Pipeline output: {display('0a272e2e2d')}")
    print(f"Packed little-endian: {packed.hex()}")
    print(f"SHA-256: {checksum}")
    print("PyChef quick-start completed successfully.")


if __name__ == "__main__":
    main()
