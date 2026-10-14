"""Installation smoke test used for release artifacts.

Run it against an installed wheel or sdist from a directory that does not contain
the repository sources (``uv run --isolated --no-project --with dist/*.whl ...``).
"""

from __future__ import annotations

import sys
from importlib.metadata import metadata, requires, version
from importlib.resources import files
from pathlib import Path

import pychef


def main() -> None:
    package = metadata("cyberchef-py")
    assert package["Name"] == "cyberchef-py"
    assert pychef.__version__ == version("cyberchef-py")
    assert not requires("cyberchef-py"), "unexpected runtime dependencies"
    assert "site-packages" in str(Path(pychef.__file__)), "pychef was not imported from an install"

    assert len(pychef.list_operations()) == 502
    assert (Path(str(files("pychef"))) / "py.typed").is_file()

    # Recipe API
    assert pychef.bake("414243", ["From Hex", "To Base64"]) == "QUJD"
    assert pychef.Chef(policy=pychef.ExecutionPolicy.safe()).bake("414243", ["From Hex"]) == b"ABC"
    # Pipeline API
    assert pychef.Pipeline().from_hex().to_base64()("414243") == "QUJD"
    assert pychef.Pipeline().from_hex().xor(b"\x42").decode()("0a272e2e2d") == "Hello"
    # Direct operations API
    from pychef.ops import from_hex, run_operation, sha256, to_base64

    assert to_base64(from_hex("414243")) == "QUJD"
    assert run_operation("To Base64", b"Hello") == "SGVsbG8="
    assert sha256(b"abc").startswith("ba7816bf")
    # CTF helpers and packaged operation metadata
    assert pychef.u32(pychef.p32(0xDEADBEEF)) == 0xDEADBEEF
    assert pychef.get_operation_spec("From Hex").name == "From Hex"
    # Network stays denied by default
    try:
        pychef.bake("", [{"op": "HTTP request", "args": ["GET", "http://127.0.0.1:9/"]}])
    except pychef.OperationPermissionError:
        pass
    else:
        raise AssertionError("network access must be denied by default")

    print(f"cyberchef-py {pychef.__version__} on Python {sys.version_info[:3]}: smoke test passed")


if __name__ == "__main__":
    main()
