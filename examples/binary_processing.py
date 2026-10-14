"""Pack, unpack, and inspect binary data."""

from pychef import Pipeline, chunks, hexdump, p16be, p32le, swap_endian, u32le
from pychef.ops import from_hex, to_hex


def main() -> None:
    header = p32le(0xDEADBEEF) + p16be(0x1234)
    assert to_hex(header) == "efbeadde1234"

    assert u32le(header) == 0xDEADBEEF
    assert u32le(header, offset=0) == 3735928559
    assert swap_endian(header[:4], 4) == b"\xde\xad\xbe\xef"
    assert chunks(header, 2) == (b"\xef\xbe", b"\xad\xde", b"\x12\x34")

    # The same through a pipeline that parses an integer from hex text.
    parse = Pipeline().from_hex().unpack(32, endian="little")
    assert parse("efbeadde") == 0xDEADBEEF

    print(hexdump(from_hex("48656c6c6f20507943686566")))


if __name__ == "__main__":
    main()
