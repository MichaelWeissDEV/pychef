"""Encode and decode a file's contents using a temporary directory."""

import tempfile
from pathlib import Path

from pychef.ops import from_base64, to_base64


def main() -> None:
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / "payload.bin"
        source.write_bytes(bytes(range(256)))

        # Read bytes, encode, write text with an explicit encoding.
        encoded_file = Path(directory) / "payload.b64"
        encoded_file.write_text(to_base64(source.read_bytes()), encoding="ascii")

        decoded = from_base64(encoded_file.read_text(encoding="ascii"))
        assert decoded == source.read_bytes()
        print(f"Round-tripped {len(decoded)} bytes through {encoded_file.name}")


if __name__ == "__main__":
    main()
