"""Installation smoke test used for release artifacts."""

from __future__ import annotations

from importlib.metadata import metadata, version

import pychef


def main() -> None:
    package = metadata("py-chef")
    assert package["Name"] == "py-chef"
    assert pychef.__version__ == version("py-chef")
    assert len(pychef.list_operations()) == 502
    assert pychef.Pipeline().from_hex().to_base64()("414243") == "QUJD"
    assert pychef.u32(pychef.p32(0xDEADBEEF)) == 0xDEADBEEF
    print(f"py-chef {pychef.__version__}: smoke test passed")


if __name__ == "__main__":
    main()
